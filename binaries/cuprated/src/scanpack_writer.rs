//! Optional, Cuprate-owned writer for immutable wallet ScanPack generations.
//!
//! The writer reads directly from Cuprate's canonical blockchain database.
//! Hosted view-key workers receive only a read-only bind mount containing the
//! signed packages; they never receive a database handle or the signing key.

use std::{
    env,
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use ed25519_dalek::SigningKey;
use fs2::FileExt;
use monero_oxide::block::Block;
use tower::ServiceExt;
use zeroize::Zeroize;

use cuprate_blockchain::service::BlockchainReadHandle;
use cuprate_p2p_core::Network;
use cuprate_types::{
    blockchain::{BlockchainReadRequest, BlockchainResponse},
    rpc::{BlockOutputIndices, TxOutputIndices},
    BlockCompleteEntry, Chain, TransactionBlobs,
};
use scanpack_format::{
    load_verified_manifest, load_verified_manifest_generation, pack_file_name,
    publish_manifest_atomic, publish_status_atomic, sha256_file, ManifestBody, PackDescriptor,
    SignedManifest, SignedStatus, StatusBody, VerifiedManifest, CURRENT_MANIFEST_FILE,
    MANIFEST_SCHEMA_VERSION, STATUS_SCHEMA_VERSION,
};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const DIRECTORY_ENV: &str = "CUPRATE_SCANPACK_DIRECTORY";
const SIGNING_KEY_FILE_ENV: &str = "CUPRATE_SCANPACK_SIGNING_KEY_FILE";
const START_HEIGHT_ENV: &str = "CUPRATE_SCANPACK_START_HEIGHT";
const BLOCKS_PER_PACK_ENV: &str = "CUPRATE_SCANPACK_BLOCKS_PER_PACK";
const INTERVAL_MS_ENV: &str = "CUPRATE_SCANPACK_INTERVAL_MS";
const DEFAULT_BLOCKS_PER_PACK: u32 = 2_048;
const DEFAULT_INTERVAL_MS: u64 = 5_000;
const MAX_BLOCKS_PER_PACK: u32 = 10_000;
const LOCK_FILE: &str = ".scanpack-writer.lock";
const MAGIC: &[u8; 8] = b"MWSPACK1";
const FORMAT_VERSION: u32 = 1;

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct ScanPackWriterConfig {
    directory: PathBuf,
    network: Network,
    start_height: u64,
    blocks_per_pack: u32,
    interval: Duration,
}

impl ScanPackWriterConfig {
    fn from_environment(network: Network) -> Result<Option<(Self, SigningKey)>> {
        let Some(directory) = env::var_os(DIRECTORY_ENV) else {
            let partial = [
                SIGNING_KEY_FILE_ENV,
                START_HEIGHT_ENV,
                BLOCKS_PER_PACK_ENV,
                INTERVAL_MS_ENV,
            ]
            .into_iter()
            .any(|name| env::var_os(name).is_some());
            if partial {
                bail!("{DIRECTORY_ENV} is required when ScanPack writer settings are present");
            }
            return Ok(None);
        };
        if directory.is_empty() {
            bail!("{DIRECTORY_ENV} must not be empty");
        }
        let signing_key_file = env::var_os(SIGNING_KEY_FILE_ENV)
            .context(format!("{SIGNING_KEY_FILE_ENV} is required"))?;
        if signing_key_file.is_empty() {
            bail!("{SIGNING_KEY_FILE_ENV} must not be empty");
        }
        let start_height = env_u64(START_HEIGHT_ENV, 0)?;
        let blocks_per_pack = env_u32(BLOCKS_PER_PACK_ENV, DEFAULT_BLOCKS_PER_PACK)?;
        if blocks_per_pack == 0 || blocks_per_pack > MAX_BLOCKS_PER_PACK {
            bail!("{BLOCKS_PER_PACK_ENV} must be between 1 and {MAX_BLOCKS_PER_PACK}");
        }
        let interval_ms = env_u64(INTERVAL_MS_ENV, DEFAULT_INTERVAL_MS)?;
        if interval_ms < 250 {
            bail!("{INTERVAL_MS_ENV} must be at least 250");
        }

        let config = Self {
            directory: PathBuf::from(directory),
            network,
            start_height,
            blocks_per_pack,
            interval: Duration::from_millis(interval_ms),
        };
        prepare_directory(&config.directory)?;
        let signing_key = load_signing_key(Path::new(&signing_key_file))?;
        Ok(Some((config, signing_key)))
    }
}

/// Start the optional writer if `CUPRATE_SCANPACK_DIRECTORY` is configured.
/// Invalid partial configuration fails Cuprate startup rather than silently
/// exposing an unsigned or stale sidecar.
pub fn start_from_environment(
    network: Network,
    blockchain_read: BlockchainReadHandle,
) -> Result<()> {
    let Some((config, signing_key)) = ScanPackWriterConfig::from_environment(network)? else {
        return Ok(());
    };
    let lease = acquire_writer_lease(&config.directory)?;
    let public_key = hex::encode(signing_key.verifying_key().to_bytes());
    tracing::info!(
        directory = %config.directory.display(),
        network = network_name(config.network),
        start_height = config.start_height,
        blocks_per_pack = config.blocks_per_pack,
        public_key = public_key,
        "starting signed Cuprate ScanPack writer"
    );

    let writer = ScanPackWriter {
        chain: CuprateChain { blockchain_read },
        config,
        signing_key,
    };
    tokio::spawn(async move {
        let _lease = lease;
        writer.run().await;
    });
    Ok(())
}

struct ScanPackWriter<C> {
    chain: C,
    config: ScanPackWriterConfig,
    signing_key: SigningKey,
}

#[derive(Debug, Eq, PartialEq)]
struct PublicationOutcome {
    generation: u64,
    start_height: u64,
    end_height: u64,
    written_packs: usize,
    replaces_from_height: Option<u64>,
}

impl<C: ScanPackChain> ScanPackWriter<C> {
    async fn run(self) {
        let mut interval = tokio::time::interval(self.config.interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            match self.publish_once().await {
                Ok(Some(outcome)) => tracing::info!(
                    generation = outcome.generation,
                    start_height = outcome.start_height,
                    end_height = outcome.end_height,
                    written_packs = outcome.written_packs,
                    replaces_from_height = ?outcome.replaces_from_height,
                    "published signed Cuprate ScanPack generation"
                ),
                Ok(None) => {}
                Err(error) => tracing::error!(
                    error = %error,
                    "Cuprate ScanPack publication failed closed; current signed generation remains authoritative"
                ),
            }
        }
    }

    async fn publish_once(&self) -> Result<Option<PublicationOutcome>> {
        prepare_directory(&self.config.directory)?;
        let verifying_key = self.signing_key.verifying_key();
        let current = load_current_if_present(&self.config.directory, &verifying_key)?;
        if let Some(current) = &current {
            self.validate_current(current)?;
            repair_or_verify_history(&self.config.directory, current, &verifying_key)?;
        }

        let snapshot_end = self.chain.chain_height().await?;
        if snapshot_end <= self.config.start_height {
            return Ok(None);
        }
        let snapshot_tip = self.chain.block_hash(snapshot_end - 1).await?;
        let current_canonical = if let Some(current) = &current {
            self.manifest_is_canonical(current, snapshot_end).await?
        } else {
            false
        };
        if let Some(current) = &current {
            if current.signed.body.end_height <= snapshot_end {
                self.publish_status(current, snapshot_end, snapshot_tip, current_canonical)?;
            }
        }

        let plan = self
            .publication_plan(current.as_ref(), snapshot_end, current_canonical)
            .await?;
        let Some(plan) = plan else {
            return Ok(None);
        };

        let generation = current.as_ref().map_or(Ok(1), |manifest| {
            manifest
                .signed
                .body
                .generation
                .checked_add(1)
                .context("ScanPack generation overflow")
        })?;
        let mut descriptors = plan.prefix;
        let mut written_packs = 0;
        let pack_size = u64::from(self.config.blocks_per_pack);
        let mut next_height = plan.rebuild_start;
        while next_height < snapshot_end {
            let end_height = next_height.saturating_add(pack_size).min(snapshot_end);
            let data = self.chain.pack(next_height, end_height).await?;
            let descriptor = write_pack_atomic(
                &self.config.directory,
                generation,
                next_height,
                end_height,
                &data,
            )?;
            descriptors.push(descriptor);
            written_packs += 1;
            next_height = end_height;
        }
        if descriptors.is_empty() {
            bail!("ScanPack publication would contain no packages");
        }

        let first = descriptors.first().expect("checked non-empty");
        let last = descriptors.last().expect("checked non-empty");
        if first.start_height != self.config.start_height || last.end_height != snapshot_end {
            bail!("ScanPack publication plan does not cover its complete interval");
        }

        // The database service does not expose a long-lived cross-request read
        // transaction. Guard the assembled snapshot with its tip hash before
        // and immediately after the atomic manifest commit.
        let canonical_tip = self.chain.block_hash(snapshot_end - 1).await?;
        if hex::encode(canonical_tip) != last.end_block_hash {
            bail!("canonical chain changed while assembling ScanPack packages");
        }

        let body = ManifestBody {
            schema_version: MANIFEST_SCHEMA_VERSION,
            network: network_name(self.config.network).to_owned(),
            generation,
            previous_generation: current
                .as_ref()
                .map(|manifest| manifest.signed.body.generation),
            previous_manifest_hash: current
                .as_ref()
                .map(|manifest| manifest.manifest_hash.clone()),
            published_at_unix_seconds: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .context("system clock is before Unix epoch")?
                .as_secs(),
            replaces_from_height: plan.replaces_from_height,
            start_height: self.config.start_height,
            end_height: snapshot_end,
            blocks_per_pack: self.config.blocks_per_pack,
            start_block_hash: first.start_block_hash.clone(),
            end_block_hash: last.end_block_hash.clone(),
            packs: descriptors,
        };
        let signed = SignedManifest::sign(body, &self.signing_key)?;
        publish_manifest_atomic(&self.config.directory, &signed, &verifying_key)?;

        let post_commit_tip = self.chain.block_hash(snapshot_end - 1).await?;
        if hex::encode(post_commit_tip) != signed.body.end_block_hash {
            bail!(
                "canonical chain changed during ScanPack commit; the next pass must publish a corrective generation"
            );
        }
        let published = load_verified_manifest(&self.config.directory, &verifying_key)?;
        self.publish_status(&published, snapshot_end, post_commit_tip, true)?;

        Ok(Some(PublicationOutcome {
            generation,
            start_height: self.config.start_height,
            end_height: snapshot_end,
            written_packs,
            replaces_from_height: plan.replaces_from_height,
        }))
    }

    async fn manifest_is_canonical(
        &self,
        manifest: &VerifiedManifest,
        snapshot_end: u64,
    ) -> Result<bool> {
        let body = &manifest.signed.body;
        if body.end_height > snapshot_end {
            return Ok(false);
        }
        Ok(hex::encode(self.chain.block_hash(body.end_height - 1).await?) == body.end_block_hash)
    }

    fn publish_status(
        &self,
        manifest: &VerifiedManifest,
        canonical_height: u64,
        canonical_tip_hash: [u8; 32],
        manifest_canonical: bool,
    ) -> Result<()> {
        let status = SignedStatus::sign(
            StatusBody {
                schema_version: STATUS_SCHEMA_VERSION,
                network: network_name(self.config.network).to_owned(),
                manifest_generation: manifest.signed.body.generation,
                manifest_hash: manifest.manifest_hash.clone(),
                manifest_end_height: manifest.signed.body.end_height,
                manifest_canonical,
                canonical_height,
                canonical_tip_hash: hex::encode(canonical_tip_hash),
                observed_at_unix_seconds: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .context("system clock is before Unix epoch")?
                    .as_secs(),
            },
            &self.signing_key,
        )?;
        publish_status_atomic(
            &self.config.directory,
            &status,
            &self.signing_key.verifying_key(),
        )
    }

    fn validate_current(&self, current: &VerifiedManifest) -> Result<()> {
        let body = &current.signed.body;
        if body.network != network_name(self.config.network) {
            bail!("existing ScanPack manifest belongs to another network");
        }
        if body.start_height != self.config.start_height {
            bail!("existing ScanPack manifest has a different configured start height");
        }
        if body.blocks_per_pack != self.config.blocks_per_pack {
            bail!("existing ScanPack manifest has a different package size");
        }
        Ok(())
    }

    async fn publication_plan(
        &self,
        current: Option<&VerifiedManifest>,
        snapshot_end: u64,
        old_tip_matches: bool,
    ) -> Result<Option<PublicationPlan>> {
        let Some(current) = current else {
            return Ok(Some(PublicationPlan {
                prefix: Vec::new(),
                rebuild_start: self.config.start_height,
                replaces_from_height: None,
            }));
        };
        let body = &current.signed.body;
        if old_tip_matches {
            if body.end_height == snapshot_end {
                return Ok(None);
            }
            let last = body.packs.last().expect("signed manifest has packages");
            let last_count = last.end_height - last.start_height;
            if last_count < u64::from(self.config.blocks_per_pack) {
                return Ok(Some(PublicationPlan {
                    prefix: body.packs[..body.packs.len() - 1].to_vec(),
                    rebuild_start: last.start_height,
                    replaces_from_height: None,
                }));
            }
            return Ok(Some(PublicationPlan {
                prefix: body.packs.clone(),
                rebuild_start: body.end_height,
                replaces_from_height: None,
            }));
        }

        for (index, descriptor) in body.packs.iter().enumerate().rev() {
            if descriptor.end_height > snapshot_end {
                continue;
            }
            let hash = self.chain.block_hash(descriptor.end_height - 1).await?;
            if hex::encode(hash) == descriptor.end_block_hash {
                let rebuild_start = descriptor.end_height;
                return Ok(Some(PublicationPlan {
                    prefix: body.packs[..=index].to_vec(),
                    rebuild_start,
                    replaces_from_height: Some(rebuild_start),
                }));
            }
        }

        Ok(Some(PublicationPlan {
            prefix: Vec::new(),
            rebuild_start: self.config.start_height,
            replaces_from_height: Some(self.config.start_height),
        }))
    }
}

struct PublicationPlan {
    prefix: Vec<PackDescriptor>,
    rebuild_start: u64,
    replaces_from_height: Option<u64>,
}

#[derive(Clone)]
struct CuprateChain {
    blockchain_read: BlockchainReadHandle,
}

struct PackData {
    blocks: Vec<BlockCompleteEntry>,
    output_indices: Vec<BlockOutputIndices>,
}

#[async_trait]
trait ScanPackChain: Clone + Send + Sync + 'static {
    async fn chain_height(&self) -> Result<u64>;
    async fn block_hash(&self, height: u64) -> Result<[u8; 32]>;
    async fn pack(&self, start_height: u64, end_height: u64) -> Result<PackData>;
}

#[async_trait]
impl ScanPackChain for CuprateChain {
    async fn chain_height(&self) -> Result<u64> {
        let response = self
            .blockchain_read
            .clone()
            .oneshot(BlockchainReadRequest::ChainHeight)
            .await
            .context("failed to read Cuprate chain height")?;
        let BlockchainResponse::ChainHeight(height, _) = response else {
            bail!("unexpected Cuprate chain-height response");
        };
        u64::try_from(height).context("Cuprate chain height does not fit u64")
    }

    async fn block_hash(&self, height: u64) -> Result<[u8; 32]> {
        let height = usize::try_from(height).context("block height does not fit usize")?;
        let response = self
            .blockchain_read
            .clone()
            .oneshot(BlockchainReadRequest::BlockHash(height, Chain::Main))
            .await
            .context("failed to read canonical Cuprate block hash")?;
        let BlockchainResponse::BlockHash(hash) = response else {
            bail!("unexpected Cuprate block-hash response");
        };
        Ok(hash)
    }

    async fn pack(&self, start_height: u64, end_height: u64) -> Result<PackData> {
        if start_height >= end_height {
            bail!("invalid Cuprate ScanPack interval");
        }
        let heights = (start_height..end_height)
            .map(|height| usize::try_from(height).context("block height does not fit usize"))
            .collect::<Result<Vec<_>>>()?;
        let response = self
            .blockchain_read
            .clone()
            .oneshot(BlockchainReadRequest::BlockCompleteEntriesByHeightPruned(
                heights,
            ))
            .await
            .context("failed to read pruned blocks from Cuprate")?;
        let BlockchainResponse::BlockCompleteEntriesByHeight(blocks) = response else {
            bail!("unexpected Cuprate block response");
        };
        if blocks.len() != usize::try_from(end_height - start_height)? {
            bail!("Cuprate returned an incomplete ScanPack interval");
        }

        let mut parsed = Vec::with_capacity(blocks.len());
        let mut transaction_hashes = Vec::new();
        for entry in &blocks {
            let mut bytes = entry.block.as_ref();
            let block =
                Block::read(&mut bytes).context("Cuprate returned an invalid block blob")?;
            if !bytes.is_empty() {
                bail!("Cuprate block blob has trailing bytes");
            }
            transaction_hashes.push(block.miner_transaction().hash());
            transaction_hashes.extend(block.transactions.iter().copied());
            parsed.push(block);
        }

        let response = self
            .blockchain_read
            .clone()
            .oneshot(BlockchainReadRequest::TxOutputIndexesBatch(
                transaction_hashes,
            ))
            .await
            .context("failed to read transaction output indices from Cuprate")?;
        let BlockchainResponse::TxOutputIndexesBatch(all_indices) = response else {
            bail!("unexpected Cuprate output-index response");
        };

        let mut cursor: usize = 0;
        let mut output_indices = Vec::with_capacity(parsed.len());
        for block in &parsed {
            let count = block.transactions.len() + 1;
            let end = cursor
                .checked_add(count)
                .context("output-index cursor overflow")?;
            let block_indices = all_indices
                .get(cursor..end)
                .context("Cuprate returned incomplete output indices")?
                .iter()
                .cloned()
                .map(|indices| TxOutputIndices { indices })
                .collect();
            output_indices.push(BlockOutputIndices {
                indices: block_indices,
            });
            cursor = end;
        }
        if cursor != all_indices.len() {
            bail!("Cuprate returned excess output indices");
        }
        Ok(PackData {
            blocks,
            output_indices,
        })
    }
}

fn write_pack_atomic(
    directory: &Path,
    generation: u64,
    start_height: u64,
    end_height: u64,
    data: &PackData,
) -> Result<PackDescriptor> {
    validate_pack_data(start_height, end_height, data)?;
    let (temporary_path, mut file) = create_temporary_pack(directory, generation, start_height)?;
    let write_result = (|| -> Result<()> {
        file.write_all(MAGIC)?;
        write_u32(&mut file, FORMAT_VERSION)?;
        write_u64(&mut file, start_height)?;
        write_u64(&mut file, end_height)?;
        write_u32(&mut file, u32::try_from(data.blocks.len())?)?;
        for (entry, block_indices) in data.blocks.iter().zip(&data.output_indices) {
            file.write_all(&[u8::from(entry.pruned)])?;
            write_u64(&mut file, entry.block_weight)?;
            write_bytes(&mut file, &entry.block)?;
            match &entry.txs {
                TransactionBlobs::Normal(transactions) => {
                    file.write_all(&[0])?;
                    write_u32(&mut file, u32::try_from(transactions.len())?)?;
                    for transaction in transactions {
                        write_bytes(&mut file, transaction)?;
                    }
                }
                TransactionBlobs::Pruned(transactions) => {
                    file.write_all(&[1])?;
                    write_u32(&mut file, u32::try_from(transactions.len())?)?;
                    for transaction in transactions {
                        write_bytes(&mut file, &transaction.blob)?;
                        file.write_all(&*transaction.prunable_hash)?;
                    }
                }
                TransactionBlobs::None => {
                    file.write_all(&[2])?;
                    write_u32(&mut file, 0)?;
                }
            }
            write_u32(&mut file, u32::try_from(block_indices.indices.len())?)?;
            for transaction in &block_indices.indices {
                write_u32(&mut file, u32::try_from(transaction.indices.len())?)?;
                for index in &transaction.indices {
                    write_u64(&mut file, *index)?;
                }
            }
        }
        file.sync_all()?;
        Ok(())
    })();
    drop(file);
    if let Err(error) = write_result {
        drop(fs::remove_file(&temporary_path));
        return Err(error);
    }

    let sha256 = sha256_file(&temporary_path)?;
    let file_name = pack_file_name(start_height, &sha256)?;
    let final_path = directory.join(&file_name);
    match fs::hard_link(&temporary_path, &final_path) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            if sha256_file(&final_path)? != sha256 {
                drop(fs::remove_file(&temporary_path));
                bail!("immutable ScanPack filename collision");
            }
        }
        Err(error) => {
            drop(fs::remove_file(&temporary_path));
            return Err(error).context("failed to publish immutable ScanPack package");
        }
    }
    fs::remove_file(&temporary_path)?;
    sync_directory(directory)?;

    let hashes = data
        .blocks
        .iter()
        .map(block_hash)
        .collect::<Result<Vec<_>>>()?;
    Ok(PackDescriptor {
        file: file_name,
        start_height,
        end_height,
        sha256,
        start_block_hash: hex::encode(hashes.first().expect("validated non-empty")),
        end_block_hash: hex::encode(hashes.last().expect("validated non-empty")),
    })
}

fn validate_pack_data(start_height: u64, end_height: u64, data: &PackData) -> Result<()> {
    if data.blocks.is_empty()
        || data.blocks.len() != data.output_indices.len()
        || end_height.checked_sub(start_height) != Some(u64::try_from(data.blocks.len())?)
        || data.blocks.len() > usize::try_from(MAX_BLOCKS_PER_PACK)?
    {
        bail!("invalid ScanPack package dimensions");
    }
    for (entry, indices) in data.blocks.iter().zip(&data.output_indices) {
        let mut bytes = entry.block.as_ref();
        let block = Block::read(&mut bytes).context("invalid block in ScanPack package")?;
        if !bytes.is_empty() {
            bail!("ScanPack block has trailing bytes");
        }
        if indices.indices.len() != block.transactions.len() + 1 {
            bail!("ScanPack output-index count does not match block transactions");
        }
        match &entry.txs {
            TransactionBlobs::Normal(txs) if txs.len() == block.transactions.len() => {}
            TransactionBlobs::Pruned(txs) if txs.len() == block.transactions.len() => {}
            TransactionBlobs::None if block.transactions.is_empty() => {}
            _ => bail!("ScanPack transaction blob count does not match block"),
        }
    }
    Ok(())
}

fn block_hash(entry: &BlockCompleteEntry) -> Result<[u8; 32]> {
    let mut bytes = entry.block.as_ref();
    let block = Block::read(&mut bytes).context("invalid block in ScanPack package")?;
    if !bytes.is_empty() {
        bail!("ScanPack block has trailing bytes");
    }
    Ok(block.hash())
}

fn create_temporary_pack(
    directory: &Path,
    generation: u64,
    start_height: u64,
) -> Result<(PathBuf, File)> {
    for _ in 0..100 {
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = directory.join(format!(
            ".scanpack-{}-{generation}-{start_height}-{counter}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        match options.open(&path) {
            Ok(file) => {
                set_private_file_permissions(&file)?;
                return Ok((path, file));
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    bail!("could not allocate a unique ScanPack temporary file")
}

fn load_current_if_present(
    directory: &Path,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<Option<VerifiedManifest>> {
    match load_verified_manifest(directory, verifying_key) {
        Ok(manifest) => Ok(Some(manifest)),
        Err(error) if is_not_found(&error) => Ok(None),
        Err(error) => Err(error),
    }
}

fn repair_or_verify_history(
    directory: &Path,
    current: &VerifiedManifest,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<()> {
    match load_verified_manifest_generation(
        directory,
        current.signed.body.generation,
        verifying_key,
    ) {
        Ok(history) if history.manifest_hash == current.manifest_hash => Ok(()),
        Ok(_) => bail!("current ScanPack manifest conflicts with immutable history"),
        Err(error) if is_not_found(&error) => {
            publish_manifest_atomic(directory, &current.signed, verifying_key)?;
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn prepare_directory(path: &Path) -> Result<()> {
    fs::create_dir_all(path)
        .with_context(|| format!("failed to create ScanPack directory {}", path.display()))?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("ScanPack output path must be a real directory");
    }
    #[cfg(unix)]
    {
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        let secured = fs::metadata(path)?;
        if secured.mode() & 0o077 != 0 {
            bail!("ScanPack directory permissions must be 0700");
        }
    }
    Ok(())
}

fn acquire_writer_lease(directory: &Path) -> Result<File> {
    let path = directory.join(LOCK_FILE);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = options.open(&path)?;
    if !file.metadata()?.is_file() {
        bail!("ScanPack writer lease must be a regular file");
    }
    set_private_file_permissions(&file)?;
    file.try_lock_exclusive()
        .context("another Cuprate ScanPack writer already holds the directory lease")?;
    file.set_len(0)?;
    (&file).write_all(std::process::id().to_string().as_bytes())?;
    file.sync_all()?;
    Ok(file)
}

fn load_signing_key(path: &Path) -> Result<SigningKey> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to securely open signing key {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        bail!("ScanPack signing key must be a regular file");
    }
    #[cfg(unix)]
    if metadata.mode() & 0o077 != 0 {
        bail!("ScanPack signing key permissions must not grant group or world access");
    }
    if metadata.len() > 1_024 {
        bail!("ScanPack signing key file is too large");
    }
    let mut material = Vec::new();
    file.read_to_end(&mut material)?;
    let mut key_bytes = if material.len() == 32 {
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&material);
        bytes
    } else {
        let text = std::str::from_utf8(&material)
            .context("ScanPack signing key must be 32 raw bytes or lowercase hex")?
            .trim();
        if text.bytes().any(|byte| byte.is_ascii_uppercase()) {
            bail!("ScanPack signing key hex must be lowercase");
        }
        hex::decode(text)
            .context("ScanPack signing key is not valid hex")?
            .try_into()
            .map_err(|_| anyhow::anyhow!("ScanPack signing key must contain exactly 32 bytes"))?
    };
    material.zeroize();
    let key = SigningKey::from_bytes(&key_bytes);
    key_bytes.zeroize();
    Ok(key)
}

fn set_private_file_permissions(file: &File) -> Result<()> {
    #[cfg(unix)]
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

fn write_u32(writer: &mut impl Write, value: u32) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_u64(writer: &mut impl Write, value: u64) -> io::Result<()> {
    writer.write_all(&value.to_le_bytes())
}

fn write_bytes(writer: &mut impl Write, bytes: &[u8]) -> Result<()> {
    write_u32(writer, u32::try_from(bytes.len())?)?;
    writer.write_all(bytes)?;
    Ok(())
}

fn env_u64(name: &str, default: u64) -> Result<u64> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .with_context(|| format!("{name} must be an unsigned integer")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error.into()),
    }
}

fn env_u32(name: &str, default: u32) -> Result<u32> {
    let value = env_u64(name, u64::from(default))?;
    u32::try_from(value).with_context(|| format!("{name} is too large"))
}

fn network_name(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Stagenet => "stagenet",
    }
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|source| source.downcast_ref::<io::Error>())
        .any(|io| io.kind() == io::ErrorKind::NotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use monero_oxide::{
        block::BlockHeader,
        transaction::{Input, Timelock, Transaction, TransactionPrefix},
    };
    use std::sync::{Arc, RwLock};
    use tempfile::tempdir;

    #[derive(Clone)]
    struct FakeChain {
        blocks: Arc<RwLock<Vec<BlockCompleteEntry>>>,
    }

    impl FakeChain {
        fn new(count: usize) -> Self {
            let chain = Self {
                blocks: Arc::new(RwLock::new(Vec::new())),
            };
            chain.extend(count, 1);
            chain
        }

        fn extend(&self, count: usize, nonce_base: u32) {
            let mut blocks = self.blocks.write().unwrap();
            let mut previous = blocks
                .last()
                .map(block_hash)
                .transpose()
                .unwrap()
                .unwrap_or([0; 32]);
            for offset in 0..count {
                let entry = test_entry(previous, nonce_base + u32::try_from(offset).unwrap());
                previous = block_hash(&entry).unwrap();
                blocks.push(entry);
            }
        }

        fn replace_from(&self, height: usize, count: usize, nonce_base: u32) {
            self.blocks.write().unwrap().truncate(height);
            self.extend(count, nonce_base);
        }
    }

    #[async_trait]
    impl ScanPackChain for FakeChain {
        async fn chain_height(&self) -> Result<u64> {
            Ok(u64::try_from(self.blocks.read().unwrap().len())?)
        }

        async fn block_hash(&self, height: u64) -> Result<[u8; 32]> {
            let blocks = self.blocks.read().unwrap();
            block_hash(
                blocks
                    .get(usize::try_from(height)?)
                    .context("fake block height is unavailable")?,
            )
        }

        async fn pack(&self, start_height: u64, end_height: u64) -> Result<PackData> {
            let blocks = self.blocks.read().unwrap();
            let selected =
                blocks[usize::try_from(start_height)?..usize::try_from(end_height)?].to_vec();
            Ok(PackData {
                output_indices: selected
                    .iter()
                    .map(|_| BlockOutputIndices {
                        indices: vec![TxOutputIndices {
                            indices: Vec::new(),
                        }],
                    })
                    .collect(),
                blocks: selected,
            })
        }
    }

    fn test_entry(previous: [u8; 32], nonce: u32) -> BlockCompleteEntry {
        let miner = Transaction::V1 {
            prefix: TransactionPrefix {
                additional_timelock: Timelock::None,
                inputs: vec![Input::Gen(1)],
                outputs: vec![],
                extra: vec![],
            },
            signatures: vec![],
        };
        let block = Block::new(
            BlockHeader {
                hardfork_version: 16,
                hardfork_signal: 16,
                timestamp: u64::from(nonce),
                previous,
                nonce,
            },
            miner,
            vec![],
        )
        .unwrap();
        BlockCompleteEntry {
            pruned: true,
            block: Bytes::from(block.serialize()),
            block_weight: 0,
            txs: TransactionBlobs::None,
        }
    }

    fn writer(directory: &Path, chain: FakeChain) -> ScanPackWriter<FakeChain> {
        prepare_directory(directory).unwrap();
        ScanPackWriter {
            chain,
            config: ScanPackWriterConfig {
                directory: directory.to_owned(),
                network: Network::Mainnet,
                start_height: 0,
                blocks_per_pack: 2,
                interval: Duration::from_secs(1),
            },
            signing_key: SigningKey::from_bytes(&[23; 32]),
        }
    }

    #[tokio::test]
    async fn publishes_append_and_reorg_generations() {
        let directory = tempdir().unwrap();
        let chain = FakeChain::new(5);
        let writer = writer(directory.path(), chain.clone());

        let first = writer.publish_once().await.unwrap().unwrap();
        assert_eq!(
            first,
            PublicationOutcome {
                generation: 1,
                start_height: 0,
                end_height: 5,
                written_packs: 3,
                replaces_from_height: None,
            }
        );
        let manifest =
            load_verified_manifest(directory.path(), &writer.signing_key.verifying_key()).unwrap();
        assert_eq!(manifest.signed.body.packs.len(), 3);
        for descriptor in &manifest.signed.body.packs {
            assert!(descriptor.file.contains(&descriptor.sha256));
            scanpack_format::verify_pack_file(directory.path(), descriptor).unwrap();
        }

        chain.extend(2, 100);
        let append = writer.publish_once().await.unwrap().unwrap();
        assert_eq!(append.generation, 2);
        assert_eq!(append.end_height, 7);
        assert_eq!(append.written_packs, 2);
        assert_eq!(append.replaces_from_height, None);

        chain.replace_from(5, 3, 500);
        let reorg = writer.publish_once().await.unwrap().unwrap();
        assert_eq!(reorg.generation, 3);
        assert_eq!(reorg.end_height, 8);
        assert_eq!(reorg.replaces_from_height, Some(4));
        let corrected =
            load_verified_manifest(directory.path(), &writer.signing_key.verifying_key()).unwrap();
        assert_eq!(corrected.signed.body.previous_generation, Some(2));
        assert_eq!(
            corrected.signed.body.previous_manifest_hash,
            Some(
                load_verified_manifest_generation(
                    directory.path(),
                    2,
                    &writer.signing_key.verifying_key(),
                )
                .unwrap()
                .manifest_hash
            )
        );
    }

    #[tokio::test]
    async fn orphan_package_is_never_visible_without_manifest_commit() {
        let directory = tempdir().unwrap();
        prepare_directory(directory.path()).unwrap();
        let chain = FakeChain::new(2);
        let data = chain.pack(0, 2).await.unwrap();
        let descriptor = write_pack_atomic(directory.path(), 1, 0, 2, &data).unwrap();
        assert!(directory.path().join(&descriptor.file).exists());
        let key = SigningKey::from_bytes(&[31; 32]);
        assert!(load_verified_manifest(directory.path(), &key.verifying_key()).is_err());
    }

    #[tokio::test]
    async fn tampered_package_fails_hash_verification() {
        let directory = tempdir().unwrap();
        let chain = FakeChain::new(2);
        let writer = writer(directory.path(), chain);
        writer.publish_once().await.unwrap().unwrap();
        let manifest =
            load_verified_manifest(directory.path(), &writer.signing_key.verifying_key()).unwrap();
        let descriptor = &manifest.signed.body.packs[0];
        let path = directory.path().join(&descriptor.file);
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(&[0xff]).unwrap();
        file.sync_all().unwrap();
        assert!(scanpack_format::verify_pack_file(directory.path(), descriptor).is_err());
    }
}
