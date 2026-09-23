//! Signed, versioned publication metadata for read-only ScanPack consumers.
//!
//! The manifest is deliberately independent from wallet secrets. A Cuprate
//! writer signs an immutable generation after every referenced package is
//! durable, then atomically replaces `current-manifest.json`. Workers pin the
//! writer's Ed25519 public key and reject mixed, stale, or tampered data.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub const MANIFEST_SCHEMA_VERSION: u32 = 1;
pub const CURRENT_MANIFEST_FILE: &str = "current-manifest.json";
pub const STATUS_SCHEMA_VERSION: u32 = 1;
pub const CURRENT_STATUS_FILE: &str = "current-status.json";
const SIGNING_DOMAIN: &[u8] = b"TEX8-SCANPACK-GENERATION-MANIFEST-V1\0";
const STATUS_SIGNING_DOMAIN: &[u8] = b"TEX8-SCANPACK-CURRENT-STATUS-V1\0";
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PACKS: usize = 100_000;
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackDescriptor {
    pub file: String,
    pub start_height: u64,
    pub end_height: u64,
    pub sha256: String,
    pub start_block_hash: String,
    pub end_block_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ManifestBody {
    pub schema_version: u32,
    pub network: String,
    pub generation: u64,
    pub previous_generation: Option<u64>,
    pub previous_manifest_hash: Option<String>,
    pub published_at_unix_seconds: u64,
    /// First height whose canonical block may differ from the prior
    /// generation. `None` means an append-only publication.
    pub replaces_from_height: Option<u64>,
    pub start_height: u64,
    pub end_height: u64,
    pub blocks_per_pack: u32,
    pub start_block_hash: String,
    pub end_block_hash: String,
    pub packs: Vec<PackDescriptor>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedManifest {
    pub body: ManifestBody,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedManifest {
    pub signed: SignedManifest,
    pub manifest_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StatusBody {
    pub schema_version: u32,
    pub network: String,
    pub manifest_generation: u64,
    pub manifest_hash: String,
    pub manifest_end_height: u64,
    pub manifest_canonical: bool,
    pub canonical_height: u64,
    pub canonical_tip_hash: String,
    pub observed_at_unix_seconds: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignedStatus {
    pub body: StatusBody,
    pub signature: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedStatus {
    pub signed: SignedStatus,
}

impl SignedManifest {
    pub fn sign(body: ManifestBody, signing_key: &SigningKey) -> Result<Self> {
        validate_body(&body)?;
        let signature = signing_key.sign(&signing_bytes(&body)?);
        Ok(Self {
            body,
            signature: hex::encode(signature.to_bytes()),
        })
    }

    pub fn verify(self, verifying_key: &VerifyingKey) -> Result<VerifiedManifest> {
        validate_body(&self.body)?;
        let signature_bytes = decode_fixed::<64>("manifest signature", &self.signature)?;
        let signature = Signature::from_bytes(&signature_bytes);
        let signed_bytes = signing_bytes(&self.body)?;
        verifying_key
            .verify(&signed_bytes, &signature)
            .context("ScanPack generation signature is invalid")?;
        let manifest_hash = hex::encode(Sha256::digest(&signed_bytes));
        Ok(VerifiedManifest {
            signed: self,
            manifest_hash,
        })
    }
}

impl SignedStatus {
    pub fn sign(body: StatusBody, signing_key: &SigningKey) -> Result<Self> {
        validate_status_body(&body)?;
        let signature = signing_key.sign(&status_signing_bytes(&body)?);
        Ok(Self {
            body,
            signature: hex::encode(signature.to_bytes()),
        })
    }

    pub fn verify(self, verifying_key: &VerifyingKey) -> Result<VerifiedStatus> {
        validate_status_body(&self.body)?;
        let signature_bytes = decode_fixed::<64>("ScanPack status signature", &self.signature)?;
        let signature = Signature::from_bytes(&signature_bytes);
        verifying_key
            .verify(&status_signing_bytes(&self.body)?, &signature)
            .context("ScanPack status signature is invalid")?;
        Ok(VerifiedStatus { signed: self })
    }
}

pub fn load_verified_manifest(
    directory: &Path,
    verifying_key: &VerifyingKey,
) -> Result<VerifiedManifest> {
    load_verified_manifest_path(&directory.join(CURRENT_MANIFEST_FILE), verifying_key)
}

pub fn load_verified_manifest_generation(
    directory: &Path,
    generation: u64,
    verifying_key: &VerifyingKey,
) -> Result<VerifiedManifest> {
    if generation == 0 {
        bail!("ScanPack manifest generation must be positive");
    }
    load_verified_manifest_path(
        &directory.join(format!("manifest-{generation:020}.json")),
        verifying_key,
    )
}

pub fn load_verified_status(
    directory: &Path,
    verifying_key: &VerifyingKey,
) -> Result<VerifiedStatus> {
    let path = directory.join(CURRENT_STATUS_FILE);
    let mut file = open_read_only(&path)?;
    let length = file.metadata()?.len();
    if length == 0 || length > MAX_MANIFEST_BYTES {
        bail!("ScanPack status size is invalid");
    }
    let mut bytes = Vec::with_capacity(usize::try_from(length)?);
    file.read_to_end(&mut bytes)?;
    let signed: SignedStatus =
        serde_json::from_slice(&bytes).context("ScanPack status JSON is invalid")?;
    signed.verify(verifying_key)
}

fn load_verified_manifest_path(
    path: &Path,
    verifying_key: &VerifyingKey,
) -> Result<VerifiedManifest> {
    let mut file = open_read_only(path)?;
    let length = file.metadata()?.len();
    if length == 0 || length > MAX_MANIFEST_BYTES {
        bail!("ScanPack manifest size is invalid");
    }
    let mut bytes = Vec::with_capacity(usize::try_from(length)?);
    file.read_to_end(&mut bytes)?;
    let signed: SignedManifest =
        serde_json::from_slice(&bytes).context("ScanPack manifest JSON is invalid")?;
    signed.verify(verifying_key)
}

pub fn publish_manifest_atomic(
    directory: &Path,
    signed: &SignedManifest,
    verifying_key: &VerifyingKey,
) -> Result<PathBuf> {
    let verified = signed.clone().verify(verifying_key)?;
    fs::create_dir_all(directory)?;
    set_private_directory_permissions(directory)?;

    let history_name = format!("manifest-{:020}.json", signed.body.generation);
    let history_path = directory.join(&history_name);
    let bytes = serde_json::to_vec_pretty(signed)?;
    ensure_immutable_compatible(&history_path, &bytes)?;

    let current_path = directory.join(CURRENT_MANIFEST_FILE);
    let temporary_path = directory.join(format!(
        ".current-manifest-{}-{}-{}-{}.tmp",
        std::process::id(),
        signed.body.generation,
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    write_replaceable(&temporary_path, &bytes)?;
    fs::rename(&temporary_path, &current_path)?;
    sync_directory(directory)?;

    let loaded = load_verified_manifest(directory, verifying_key)?;
    if loaded.manifest_hash != verified.manifest_hash {
        bail!("atomically published ScanPack manifest does not match");
    }
    // `current-manifest.json` is the atomic commit point. Keeping immutable
    // history afterward means a crash can leave history temporarily missing,
    // but can never expose an uncommitted generation to readers.
    write_immutable(&history_path, &bytes)?;
    sync_directory(directory)?;
    Ok(history_path)
}

pub fn publish_status_atomic(
    directory: &Path,
    signed: &SignedStatus,
    verifying_key: &VerifyingKey,
) -> Result<()> {
    signed.clone().verify(verifying_key)?;
    fs::create_dir_all(directory)?;
    set_private_directory_permissions(directory)?;
    let bytes = serde_json::to_vec_pretty(signed)?;
    let temporary_path = unique_temporary_path(directory, ".current-status", 0);
    write_replaceable(&temporary_path, &bytes)?;
    let current_path = directory.join(CURRENT_STATUS_FILE);
    fs::rename(&temporary_path, &current_path)?;
    sync_directory(directory)?;
    if load_verified_status(directory, verifying_key)?.signed != *signed {
        bail!("atomically published ScanPack status does not match");
    }
    Ok(())
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file = open_read_only(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex::encode(digest.finalize()))
}

pub fn verify_pack_file(directory: &Path, descriptor: &PackDescriptor) -> Result<PathBuf> {
    validate_pack(descriptor)?;
    let path = directory.join(&descriptor.file);
    let actual = sha256_file(&path)?;
    if actual != descriptor.sha256 {
        bail!("ScanPack package hash mismatch for {}", descriptor.file);
    }
    Ok(path)
}

/// Immutable package names bind the start height to the complete file hash.
/// A writer crash can therefore never replace bytes referenced by an older
/// valid manifest.
pub fn pack_file_name(start_height: u64, sha256: &str) -> Result<String> {
    validate_hex_32("ScanPack package hash", sha256)?;
    Ok(format!("pack-{start_height:020}-{sha256}.mwsp"))
}

fn signing_bytes(body: &ManifestBody) -> Result<Vec<u8>> {
    let mut bytes = Vec::from(SIGNING_DOMAIN);
    bytes.extend_from_slice(&serde_json::to_vec(body)?);
    Ok(bytes)
}

fn status_signing_bytes(body: &StatusBody) -> Result<Vec<u8>> {
    let mut bytes = Vec::from(STATUS_SIGNING_DOMAIN);
    bytes.extend_from_slice(&serde_json::to_vec(body)?);
    Ok(bytes)
}

fn validate_body(body: &ManifestBody) -> Result<()> {
    if body.schema_version != MANIFEST_SCHEMA_VERSION {
        bail!("unsupported ScanPack manifest schema");
    }
    if !matches!(body.network.as_str(), "mainnet" | "testnet" | "stagenet") {
        bail!("invalid ScanPack manifest network");
    }
    if body.generation == 0 {
        bail!("ScanPack generation must be positive");
    }
    match body.generation {
        1 if body.previous_generation.is_some() || body.previous_manifest_hash.is_some() => {
            bail!("first ScanPack generation cannot have a parent")
        }
        1 => {}
        generation => {
            if body.previous_generation != Some(generation - 1) {
                bail!("ScanPack generation parent is not consecutive");
            }
            validate_hex_32(
                "previous ScanPack manifest hash",
                body.previous_manifest_hash.as_deref().unwrap_or_default(),
            )?;
        }
    }
    if body.packs.is_empty() || body.packs.len() > MAX_PACKS {
        bail!("ScanPack manifest package count is invalid");
    }
    if body.blocks_per_pack == 0 || body.blocks_per_pack > 10_000 {
        bail!("ScanPack blocks-per-package value is invalid");
    }

    let mut expected_start = body.start_height;
    for (index, pack) in body.packs.iter().enumerate() {
        validate_pack(pack)?;
        if pack.start_height != expected_start {
            bail!("ScanPack manifest contains a gap or overlap");
        }
        let block_count = pack.end_height - pack.start_height;
        if block_count > u64::from(body.blocks_per_pack)
            || (index + 1 < body.packs.len() && block_count != u64::from(body.blocks_per_pack))
        {
            bail!("ScanPack package size does not match its manifest");
        }
        expected_start = pack.end_height;
    }
    if expected_start != body.end_height || body.start_height >= body.end_height {
        bail!("ScanPack manifest height interval is invalid");
    }
    let first = &body.packs[0];
    let last = body.packs.last().expect("non-empty checked");
    if first.start_block_hash != body.start_block_hash || last.end_block_hash != body.end_block_hash
    {
        bail!("ScanPack manifest boundary hashes do not match its packages");
    }
    validate_hex_32("ScanPack start block hash", &body.start_block_hash)?;
    validate_hex_32("ScanPack end block hash", &body.end_block_hash)?;
    if let Some(height) = body.replaces_from_height {
        if body.generation == 1 || height < body.start_height || height > body.end_height {
            bail!("ScanPack reorg invalidation height is invalid");
        }
    }
    Ok(())
}

fn validate_status_body(body: &StatusBody) -> Result<()> {
    if body.schema_version != STATUS_SCHEMA_VERSION {
        bail!("unsupported ScanPack status schema");
    }
    if !matches!(body.network.as_str(), "mainnet" | "testnet" | "stagenet") {
        bail!("invalid ScanPack status network");
    }
    if body.manifest_generation == 0
        || body.manifest_end_height == 0
        || body.canonical_height < body.manifest_end_height
        || body.observed_at_unix_seconds == 0
    {
        bail!("invalid ScanPack status heights or generation");
    }
    validate_hex_32("ScanPack status manifest hash", &body.manifest_hash)?;
    validate_hex_32(
        "ScanPack status canonical tip hash",
        &body.canonical_tip_hash,
    )
}

fn validate_pack(pack: &PackDescriptor) -> Result<()> {
    if pack.start_height >= pack.end_height {
        bail!("ScanPack package interval is invalid");
    }
    let expected = pack_file_name(pack.start_height, &pack.sha256)?;
    if pack.file != expected {
        bail!("ScanPack package filename is not canonical");
    }
    validate_hex_32("ScanPack package hash", &pack.sha256)?;
    validate_hex_32("ScanPack package start block hash", &pack.start_block_hash)?;
    validate_hex_32("ScanPack package end block hash", &pack.end_block_hash)
}

fn validate_hex_32(label: &str, value: &str) -> Result<()> {
    let _ = decode_fixed::<32>(label, value)?;
    if value.bytes().any(|byte| byte.is_ascii_uppercase()) {
        bail!("{label} must be lowercase hex");
    }
    Ok(())
}

fn decode_fixed<const N: usize>(label: &str, value: &str) -> Result<[u8; N]> {
    let decoded = hex::decode(value).with_context(|| format!("{label} is not hex"))?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("{label} has the wrong length"))
}

fn open_read_only(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .with_context(|| format!("failed to securely open {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("expected a regular file: {}", path.display());
    }
    #[cfg(unix)]
    if metadata.permissions().mode() & 0o022 != 0 {
        bail!(
            "refusing group/world-writable ScanPack file: {}",
            path.display()
        );
    }
    Ok(file)
}

fn write_immutable(path: &Path, bytes: &[u8]) -> Result<()> {
    match OpenOptions::new().write(true).create_new(true).open(path) {
        Ok(mut file) => {
            set_private_file_permissions(&file)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut existing = Vec::new();
            open_read_only(path)?.read_to_end(&mut existing)?;
            if existing != bytes {
                bail!("ScanPack generation history is immutable");
            }
            Ok(())
        }
        Err(error) => Err(error.into()),
    }
}

fn ensure_immutable_compatible(path: &Path, bytes: &[u8]) -> Result<()> {
    match open_read_only(path) {
        Ok(mut file) => {
            let mut existing = Vec::new();
            file.read_to_end(&mut existing)?;
            if existing != bytes {
                bail!("ScanPack generation history is immutable");
            }
            Ok(())
        }
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn write_replaceable(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    set_private_file_permissions(&file)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn unique_temporary_path(directory: &Path, prefix: &str, generation: u64) -> PathBuf {
    directory.join(format!(
        "{prefix}-{}-{generation}-{}-{}.tmp",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos(),
        TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

fn set_private_file_permissions(file: &File) -> Result<()> {
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn set_private_directory_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn body() -> ManifestBody {
        let start = "11".repeat(32);
        let end = "22".repeat(32);
        ManifestBody {
            schema_version: MANIFEST_SCHEMA_VERSION,
            network: "mainnet".to_owned(),
            generation: 1,
            previous_generation: None,
            previous_manifest_hash: None,
            published_at_unix_seconds: 1_700_000_000,
            replaces_from_height: None,
            start_height: 100,
            end_height: 102,
            blocks_per_pack: 2,
            start_block_hash: start.clone(),
            end_block_hash: end.clone(),
            packs: vec![PackDescriptor {
                file: format!("pack-{:020}-{}.mwsp", 100, "33".repeat(32)),
                start_height: 100,
                end_height: 102,
                sha256: "33".repeat(32),
                start_block_hash: start,
                end_block_hash: end,
            }],
        }
    }

    #[test]
    fn signs_verifies_and_rejects_tampering() {
        let key = SigningKey::from_bytes(&[7; 32]);
        let signed = SignedManifest::sign(body(), &key).unwrap();
        assert!(signed.clone().verify(&key.verifying_key()).is_ok());

        let mut tampered = signed;
        tampered.body.end_height += 1;
        assert!(tampered.verify(&key.verifying_key()).is_err());
    }

    #[test]
    fn publishes_current_and_immutable_history_atomically() {
        let directory = tempdir().unwrap();
        let key = SigningKey::from_bytes(&[9; 32]);
        let signed = SignedManifest::sign(body(), &key).unwrap();
        let history =
            publish_manifest_atomic(directory.path(), &signed, &key.verifying_key()).unwrap();
        assert!(history.exists());
        assert_eq!(
            load_verified_manifest(directory.path(), &key.verifying_key())
                .unwrap()
                .signed,
            signed
        );

        let mut conflicting = signed;
        conflicting.body.published_at_unix_seconds += 1;
        conflicting = SignedManifest::sign(conflicting.body, &key).unwrap();
        assert!(
            publish_manifest_atomic(directory.path(), &conflicting, &key.verifying_key()).is_err()
        );
    }

    #[test]
    fn rejects_noncanonical_package_paths() {
        let key = SigningKey::from_bytes(&[4; 32]);
        let mut invalid = body();
        invalid.packs[0].file = format!("../pack-{:020}-{}.mwsp", 100, "33".repeat(32));
        assert!(SignedManifest::sign(invalid, &key).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinked_and_writable_manifest_files() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = tempdir().unwrap();
        let external = directory.path().join("external.json");
        fs::write(&external, b"{}").unwrap();
        symlink(&external, directory.path().join(CURRENT_MANIFEST_FILE)).unwrap();
        let key = SigningKey::from_bytes(&[5; 32]);
        assert!(load_verified_manifest(directory.path(), &key.verifying_key()).is_err());

        fs::remove_file(directory.path().join(CURRENT_MANIFEST_FILE)).unwrap();
        let signed = SignedManifest::sign(body(), &key).unwrap();
        let current = directory.path().join(CURRENT_MANIFEST_FILE);
        fs::write(&current, serde_json::to_vec(&signed).unwrap()).unwrap();
        fs::set_permissions(&current, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(load_verified_manifest(directory.path(), &key.verifying_key()).is_err());
    }

    #[test]
    fn signs_publishes_and_rejects_tampered_status() {
        let directory = tempdir().unwrap();
        let key = SigningKey::from_bytes(&[6; 32]);
        let status = SignedStatus::sign(
            StatusBody {
                schema_version: STATUS_SCHEMA_VERSION,
                network: "mainnet".to_owned(),
                manifest_generation: 4,
                manifest_hash: "44".repeat(32),
                manifest_end_height: 200,
                manifest_canonical: true,
                canonical_height: 203,
                canonical_tip_hash: "55".repeat(32),
                observed_at_unix_seconds: 1_700_000_001,
            },
            &key,
        )
        .unwrap();
        publish_status_atomic(directory.path(), &status, &key.verifying_key()).unwrap();
        assert_eq!(
            load_verified_status(directory.path(), &key.verifying_key())
                .unwrap()
                .signed,
            status
        );

        let current = directory.path().join(CURRENT_STATUS_FILE);
        let mut bytes = fs::read(&current).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&current, bytes).unwrap();
        assert!(load_verified_status(directory.path(), &key.verifying_key()).is_err());
    }
}
