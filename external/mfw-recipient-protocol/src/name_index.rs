use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::name::{
    AddressKind, CanonicalName, CommitRecord, LegacyNameRecord, NameOperation, NameProtocolError,
    NameRecord, Network, PublicAddress,
};

const INDEX_FILE_VERSION: u8 = 1;
const INDEX_CHECKSUM_DOMAIN: &[u8] = b"TEX8/MFW/name-index-file/v1";
const RESERVED_MANIFEST_DOMAIN: &[u8] = b"TEX8/MFW/reserved-name-manifest/v1";
const REGISTRY_DESCRIPTOR_DOMAIN: &[u8] = b"TEX8/MFW/registry-descriptor/v1";
const MAX_INDEX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const LEGACY_MAINNET_CLAIM_CUTOFF_HEIGHT: u64 = 3_741_022;
const LEGACY_COMMIT_PAYMENT_ATOMIC: u64 = 1;
pub const MAX_TERM_YEARS: u64 = 1_000;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProtocolParameters {
    pub network: Network,
    pub activation_height: u64,
    /// SHA-256 descriptor of the frozen Registry public address and published
    /// private view key used by the chain adapter.
    pub registry_descriptor_hash: [u8; 32],
    pub annual_fee_atomic: u64,
    pub blocks_per_year: u64,
    pub final_confirmations: u64,
    pub commit_min_confirmations: u64,
    pub commit_reveal_window: u64,
    pub max_term_years: u64,
    pub reserved_names: BTreeSet<CanonicalName>,
    pub reserved_name_manifest_hash: [u8; 32],
}

impl ProtocolParameters {
    pub fn v1(
        network: Network,
        activation_height: u64,
        registry_descriptor_hash: [u8; 32],
        reserved_names: BTreeSet<CanonicalName>,
    ) -> Self {
        let reserved_name_manifest_hash = reserved_manifest_hash(&reserved_names);
        Self {
            network,
            activation_height,
            registry_descriptor_hash,
            annual_fee_atomic: 10_000_000_000,
            blocks_per_year: 262_800,
            final_confirmations: 15,
            commit_min_confirmations: 15,
            commit_reveal_window: 720,
            max_term_years: MAX_TERM_YEARS,
            reserved_names,
            reserved_name_manifest_hash,
        }
    }

    fn validate(&self) -> Result<(), NameIndexError> {
        if self.annual_fee_atomic == 0
            || self.blocks_per_year == 0
            || self.final_confirmations == 0
            || self.commit_min_confirmations == 0
            || self.commit_reveal_window < self.commit_min_confirmations
            || self.max_term_years != MAX_TERM_YEARS
            || self.registry_descriptor_hash == [0; 32]
            || self.reserved_name_manifest_hash != reserved_manifest_hash(&self.reserved_names)
        {
            return Err(NameIndexError::InvalidParameters);
        }
        Ok(())
    }
}

pub fn registry_descriptor_hash(
    network: Network,
    registry_address: PublicAddress,
    published_private_view_key: [u8; 32],
) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(REGISTRY_DESCRIPTOR_DOMAIN);
    digest.update([network as u8, registry_address.kind as u8]);
    digest.update(registry_address.public_spend_key);
    digest.update(registry_address.public_view_key);
    digest.update(published_private_view_key);
    digest.finalize().into()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IndexedTransaction {
    pub txid: [u8; 32],
    /// All MFW payloads extracted from this transaction's `tx_extra`.
    /// Exactly one is required; this grouping prevents one Registry output
    /// from being credited to multiple claims in the same transaction.
    pub payloads: Vec<Vec<u8>>,
    /// Amount independently proven as received by the frozen Registry address.
    /// The chain adapter must set this to zero when no such output exists.
    pub registry_received_atomic: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockInput {
    pub height: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
    pub transactions: Vec<IndexedTransaction>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum ResolutionStatus {
    NotFound,
    Reserved,
    Provisional,
    Finalized,
    Expired,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resolution {
    pub name: CanonicalName,
    pub address: Option<PublicAddress>,
    pub owner_public_key: Option<[u8; 32]>,
    pub sequence: Option<u32>,
    pub record_height: Option<u64>,
    pub source_txid: Option<[u8; 32]>,
    pub record_payload: Option<Vec<u8>>,
    pub signing_owner_public_key: Option<[u8; 32]>,
    pub record_block_hash: Option<[u8; 32]>,
    pub chain_tip_hash: Option<[u8; 32]>,
    pub expiry_height: Option<u64>,
    pub chain_tip_height: Option<u64>,
    pub confirmations: u64,
    pub status: ResolutionStatus,
}

impl Resolution {
    pub fn is_safe_for_payment(&self) -> bool {
        self.status == ResolutionStatus::Finalized && self.address.is_some()
    }
}

#[derive(Clone, Debug)]
struct CommitEvidence {
    height: u64,
    txid: [u8; 32],
    registry_received_atomic: u64,
}

#[derive(Clone, Debug)]
enum IndexedNameRecord {
    Signed(NameRecord),
    Legacy(LegacyNameRecord),
}

impl IndexedNameRecord {
    fn address(&self) -> PublicAddress {
        match self {
            Self::Signed(record) => record.address,
            Self::Legacy(record) => record.address,
        }
    }

    fn owner_public_key(&self) -> Option<[u8; 32]> {
        match self {
            Self::Signed(record) => Some(record.owner_public_key),
            Self::Legacy(_) => None,
        }
    }

    fn sequence(&self) -> Option<u32> {
        match self {
            Self::Signed(record) => Some(record.sequence),
            Self::Legacy(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
struct NameState {
    record: IndexedNameRecord,
    record_payload: Vec<u8>,
    signing_owner_public_key: Option<[u8; 32]>,
    record_height: u64,
    source_txid: [u8; 32],
    expiry_height: u64,
    revoked: bool,
}

#[derive(Clone, Debug, Default)]
struct ReplayState {
    commits: BTreeMap<[u8; 32], Vec<CommitEvidence>>,
    consumed_commits: BTreeSet<([u8; 32], u64, [u8; 32])>,
    names: BTreeMap<CanonicalName, NameState>,
    reverse_names: BTreeMap<(u8, [u8; 32], [u8; 32]), BTreeSet<CanonicalName>>,
    rejected_records: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedBody {
    version: u8,
    parameters: ProtocolParameters,
    blocks: Vec<BlockInput>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedEnvelope {
    checksum_hex: String,
    body: PersistedBody,
}

#[derive(Clone, Debug)]
pub struct NameIndex {
    parameters: ProtocolParameters,
    blocks: Vec<BlockInput>,
    replay: ReplayState,
}

impl NameIndex {
    pub fn new(parameters: ProtocolParameters) -> Result<Self, NameIndexError> {
        parameters.validate()?;
        Ok(Self {
            parameters,
            blocks: Vec::new(),
            replay: ReplayState::default(),
        })
    }

    pub fn parameters(&self) -> &ProtocolParameters {
        &self.parameters
    }

    pub fn tip_height(&self) -> Option<u64> {
        self.blocks.last().map(|block| block.height)
    }

    pub fn tip_hash(&self) -> Option<[u8; 32]> {
        self.blocks.last().map(|block| block.hash)
    }

    pub fn block_hash(&self, height: u64) -> Option<[u8; 32]> {
        let offset = height.checked_sub(self.parameters.activation_height)?;
        self.blocks
            .get(usize::try_from(offset).ok()?)
            .filter(|block| block.height == height)
            .map(|block| block.hash)
    }

    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    pub fn apply_block(&mut self, block: BlockInput) -> Result<(), NameIndexError> {
        if block.height < self.parameters.activation_height {
            return Err(NameIndexError::BeforeActivation);
        }
        if let Some(previous) = self.blocks.last() {
            let expected = previous
                .height
                .checked_add(1)
                .ok_or(NameIndexError::Overflow)?;
            if block.height != expected {
                return Err(NameIndexError::NonSequentialBlock {
                    expected,
                    actual: block.height,
                });
            }
            if block.parent_hash != previous.hash {
                return Err(NameIndexError::ParentHashMismatch);
            }
        } else if block.height != self.parameters.activation_height {
            return Err(NameIndexError::NonSequentialBlock {
                expected: self.parameters.activation_height,
                actual: block.height,
            });
        }
        if self.blocks.iter().any(|known| known.hash == block.hash) {
            return Err(NameIndexError::DuplicateBlockHash);
        }
        replay_block(&self.parameters, &mut self.replay, &block)?;
        self.blocks.push(block);
        Ok(())
    }

    /// Keep canonical blocks through `height`. Passing `None` removes all
    /// derived history. This is the only supported reorg mutation.
    pub fn rewind_to(&mut self, height: Option<u64>) -> Result<(), NameIndexError> {
        match height {
            Some(height) => self.blocks.retain(|block| block.height <= height),
            None => self.blocks.clear(),
        }
        self.replay = replay_blocks(&self.parameters, &self.blocks)?;
        Ok(())
    }

    pub fn rejected_record_count(&self) -> Result<u64, NameIndexError> {
        Ok(self.replay.rejected_records)
    }

    pub fn resolve(&self, input: &str) -> Result<Resolution, NameIndexError> {
        let name = CanonicalName::parse(input)?;
        if self.parameters.reserved_names.contains(&name) {
            return Ok(reserved(name, self.tip_height(), self.tip_hash()));
        }
        let Some(tip) = self.tip_height() else {
            return Ok(not_found(name, None, None));
        };
        let Some(full_state) = self.replay.names.get(&name) else {
            return Ok(not_found(name, Some(tip), self.tip_hash()));
        };

        let confirmations = tip
            .checked_sub(full_state.record_height)
            .and_then(|distance| distance.checked_add(1))
            .ok_or(NameIndexError::Overflow)?;
        let status = if full_state.revoked {
            if confirmations < self.parameters.final_confirmations {
                ResolutionStatus::Provisional
            } else {
                ResolutionStatus::Revoked
            }
        } else if tip >= full_state.expiry_height {
            ResolutionStatus::Expired
        } else if confirmations < self.parameters.final_confirmations {
            ResolutionStatus::Provisional
        } else {
            ResolutionStatus::Finalized
        };

        let resolving = !matches!(
            status,
            ResolutionStatus::Expired | ResolutionStatus::Revoked
        );
        Ok(Resolution {
            name,
            address: resolving.then_some(full_state.record.address()),
            owner_public_key: full_state.record.owner_public_key(),
            sequence: full_state.record.sequence(),
            record_height: Some(full_state.record_height),
            source_txid: Some(full_state.source_txid),
            record_payload: Some(full_state.record_payload.clone()),
            signing_owner_public_key: full_state.signing_owner_public_key,
            record_block_hash: self.block_hash(full_state.record_height),
            chain_tip_hash: self.tip_hash(),
            expiry_height: Some(full_state.expiry_height),
            chain_tip_height: Some(tip),
            confirmations,
            status,
        })
    }

    /// Returns only active, finalized public names whose canonical label
    /// starts with `prefix`. Suggestions intentionally contain no address or
    /// ownership metadata; payment still requires a separate exact resolve.
    pub fn suggest_names(
        &self,
        prefix: &str,
        maximum: usize,
    ) -> Result<Vec<String>, NameIndexError> {
        let normalized = prefix.trim().to_ascii_lowercase();
        if normalized.len() < 3
            || normalized.len() > 63
            || normalized.starts_with('-')
            || normalized.ends_with('-')
            || !normalized
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || maximum == 0
            || maximum > 10
        {
            return Err(NameIndexError::InvalidSuggestionQuery);
        }
        let mut names = Vec::with_capacity(maximum.min(self.replay.names.len()));
        for name in self.replay.names.keys() {
            if name.as_str().starts_with(&normalized)
                && self.resolve(name.as_str())?.is_safe_for_payment()
            {
                names.push(name.display_name());
                if names.len() == maximum {
                    break;
                }
            }
        }
        Ok(names)
    }

    /// Returns active, finalized names currently resolving to `address`.
    ///
    /// Reverse discovery is public metadata only. Callers which need to make a
    /// payment or restore owner UI state must still exact-resolve every
    /// returned name and verify its signed record. The hard result bound keeps
    /// the public resolver response and per-request work predictable.
    pub fn reverse_names(
        &self,
        address: PublicAddress,
        maximum: usize,
    ) -> Result<(Vec<String>, bool), NameIndexError> {
        address.validate()?;
        if maximum == 0 || maximum > 100 {
            return Err(NameIndexError::InvalidReverseQuery);
        }

        let candidates = self.replay.reverse_names.get(&reverse_address_key(address));
        let mut names = Vec::with_capacity(maximum.min(candidates.map_or(0, BTreeSet::len)));
        let mut truncated = false;
        for name in candidates.into_iter().flatten() {
            let resolution = self.resolve(name.as_str())?;
            if resolution.is_safe_for_payment() {
                if names.len() == maximum {
                    truncated = true;
                    break;
                }
                names.push(name.display_name());
            }
        }
        Ok((names, truncated))
    }

    pub fn save_atomic(&self, path: impl AsRef<Path>) -> Result<(), NameIndexError> {
        let path = path.as_ref();
        let body = PersistedBody {
            version: INDEX_FILE_VERSION,
            parameters: self.parameters.clone(),
            blocks: self.blocks.clone(),
        };
        let canonical_body = serde_json::to_vec(&body)?;
        if u64::try_from(canonical_body.len()).map_err(|_| NameIndexError::Overflow)?
            > MAX_INDEX_FILE_BYTES
        {
            return Err(NameIndexError::OversizedIndexFile);
        }
        let envelope = PersistedEnvelope {
            checksum_hex: checksum(&canonical_body),
            body,
        };
        let encoded = serde_json::to_vec(&envelope)?;
        if u64::try_from(encoded.len()).map_err(|_| NameIndexError::Overflow)?
            > MAX_INDEX_FILE_BYTES
        {
            return Err(NameIndexError::OversizedIndexFile);
        }
        let temporary = temporary_path(path)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(&encoded)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        if let Some(parent) = path.parent() {
            File::open(parent)?.sync_all()?;
        }
        Ok(())
    }

    /// Returns the stored `(height, hash)` spine after validating the
    /// canonical encoding, protocol parameters and file checksum. The caller
    /// can fetch those canonical hashes asynchronously before calling `load`.
    pub fn persisted_block_hashes(
        path: impl AsRef<Path>,
    ) -> Result<Vec<(u64, [u8; 32])>, NameIndexError> {
        let body = read_persisted_body(path.as_ref())?;
        let mut expected = body.parameters.activation_height;
        let mut hashes = Vec::with_capacity(body.blocks.len());
        for block in body.blocks {
            if block.height != expected {
                return Err(NameIndexError::NonSequentialBlock {
                    expected,
                    actual: block.height,
                });
            }
            hashes.push((block.height, block.hash));
            expected = expected.checked_add(1).ok_or(NameIndexError::Overflow)?;
        }
        Ok(hashes)
    }

    /// Load a cache only while comparing every stored block hash with the
    /// canonical database. A checksum alone is not an authority boundary.
    pub fn load<F>(path: impl AsRef<Path>, mut canonical_hash_at: F) -> Result<Self, NameIndexError>
    where
        F: FnMut(u64) -> Result<[u8; 32], NameIndexError>,
    {
        let body = read_persisted_body(path.as_ref())?;
        let mut index = Self::new(body.parameters)?;
        for block in body.blocks {
            if canonical_hash_at(block.height)? != block.hash {
                return Err(NameIndexError::CanonicalHashMismatch(block.height));
            }
            index.apply_block(block)?;
        }
        Ok(index)
    }
}

fn reverse_address_key(address: PublicAddress) -> (u8, [u8; 32], [u8; 32]) {
    let kind = match address.kind {
        AddressKind::Standard => 0,
        AddressKind::Subaddress => 1,
    };
    (kind, address.public_spend_key, address.public_view_key)
}

fn insert_name_state(state: &mut ReplayState, name: CanonicalName, value: NameState) {
    if let Some(previous) = state.names.get(&name) {
        let key = reverse_address_key(previous.record.address());
        if let Some(names) = state.reverse_names.get_mut(&key) {
            names.remove(&name);
            if names.is_empty() {
                state.reverse_names.remove(&key);
            }
        }
    }
    state
        .reverse_names
        .entry(reverse_address_key(value.record.address()))
        .or_default()
        .insert(name.clone());
    state.names.insert(name, value);
}

fn replay_blocks(
    parameters: &ProtocolParameters,
    blocks: &[BlockInput],
) -> Result<ReplayState, NameIndexError> {
    let mut state = ReplayState::default();
    for block in blocks {
        replay_block(parameters, &mut state, block)?;
    }
    Ok(state)
}

fn replay_block(
    parameters: &ProtocolParameters,
    state: &mut ReplayState,
    block: &BlockInput,
) -> Result<(), NameIndexError> {
    state.commits.retain(|_, evidence| {
        evidence.retain(|commit| {
            block.height.saturating_sub(commit.height) <= parameters.commit_reveal_window
        });
        !evidence.is_empty()
    });
    state.consumed_commits.retain(|(_, height, _)| {
        block.height.saturating_sub(*height) <= parameters.commit_reveal_window
    });
    for transaction in &block.transactions {
        let [payload] = transaction.payloads.as_slice() else {
            state.rejected_records = state
                .rejected_records
                .checked_add(1)
                .ok_or(NameIndexError::Overflow)?;
            continue;
        };
        if let Ok(commit) = CommitRecord::decode(payload) {
            state
                .commits
                .entry(commit.commitment)
                .or_default()
                .push(CommitEvidence {
                    height: block.height,
                    txid: transaction.txid,
                    registry_received_atomic: transaction.registry_received_atomic,
                });
            continue;
        }
        let result = if let Ok(record) = NameRecord::decode(payload) {
            apply_record(
                parameters,
                state,
                block.height,
                transaction,
                record,
                payload.clone(),
            )
        } else if let Ok(record) = LegacyNameRecord::decode(payload) {
            apply_legacy_claim(
                parameters,
                state,
                block.height,
                transaction,
                record,
                payload.clone(),
            )
        } else {
            Err(NameIndexError::Protocol(NameProtocolError::InvalidLength))
        };
        if result.is_err() {
            state.rejected_records = state
                .rejected_records
                .checked_add(1)
                .ok_or(NameIndexError::Overflow)?;
        }
    }
    Ok(())
}

fn read_persisted_body(path: &Path) -> Result<PersistedBody, NameIndexError> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_INDEX_FILE_BYTES {
        return Err(NameIndexError::OversizedIndexFile);
    }
    let mut encoded =
        Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| NameIndexError::Overflow)?);
    file.take(MAX_INDEX_FILE_BYTES.saturating_add(1))
        .read_to_end(&mut encoded)?;
    if u64::try_from(encoded.len()).map_err(|_| NameIndexError::Overflow)? > MAX_INDEX_FILE_BYTES {
        return Err(NameIndexError::OversizedIndexFile);
    }
    let envelope: PersistedEnvelope = serde_json::from_slice(&encoded)?;
    if envelope.body.version != INDEX_FILE_VERSION {
        return Err(NameIndexError::UnsupportedFileVersion);
    }
    let canonical_body = serde_json::to_vec(&envelope.body)?;
    if checksum(&canonical_body) != envelope.checksum_hex {
        return Err(NameIndexError::ChecksumMismatch);
    }
    envelope.body.parameters.validate()?;
    Ok(envelope.body)
}

fn apply_record(
    parameters: &ProtocolParameters,
    state: &mut ReplayState,
    height: u64,
    transaction: &IndexedTransaction,
    record: NameRecord,
    record_payload: Vec<u8>,
) -> Result<(), NameIndexError> {
    match record.operation {
        NameOperation::Claim => {
            record.verify_claim(parameters.network)?;
            if parameters.reserved_names.contains(&record.name) {
                return Err(NameIndexError::ReservedName);
            }
            let commitment = record.claim_commitment(parameters.network)?.commitment;
            let commit = state
                .commits
                .get(&commitment)
                .and_then(|candidates| {
                    candidates.iter().rev().find(|candidate| {
                        let age = height.saturating_sub(candidate.height);
                        candidate.height < height
                            && age >= parameters.commit_min_confirmations
                            && age <= parameters.commit_reveal_window
                            && !state.consumed_commits.contains(&(
                                commitment,
                                candidate.height,
                                candidate.txid,
                            ))
                    })
                })
                .cloned()
                .ok_or(NameIndexError::MissingMatureCommit)?;
            if let Some(existing) = state.names.get(&record.name) {
                if !existing.revoked && height < existing.expiry_height {
                    return Err(NameIndexError::NameAlreadyOwned);
                }
            }
            let years = paid_years(parameters, transaction.registry_received_atomic)?;
            let expiry_height = height
                .checked_add(
                    years
                        .checked_mul(parameters.blocks_per_year)
                        .ok_or(NameIndexError::Overflow)?,
                )
                .ok_or(NameIndexError::Overflow)?;
            state
                .consumed_commits
                .insert((commitment, commit.height, commit.txid));
            insert_name_state(
                state,
                record.name.clone(),
                NameState {
                    signing_owner_public_key: Some(record.owner_public_key),
                    record: IndexedNameRecord::Signed(record),
                    record_payload,
                    record_height: height,
                    source_txid: transaction.txid,
                    expiry_height,
                    revoked: false,
                },
            );
        }
        NameOperation::Update | NameOperation::Renew | NameOperation::Revoke => {
            let predecessor = state
                .names
                .get(&record.name)
                .cloned()
                .ok_or(NameIndexError::NameNotOwned)?;
            if predecessor.revoked || height >= predecessor.expiry_height {
                return Err(NameIndexError::NameNotOwned);
            }
            let IndexedNameRecord::Signed(predecessor_record) = &predecessor.record else {
                return Err(NameIndexError::LegacyRecordImmutable);
            };
            record.verify_transition(parameters.network, predecessor_record)?;
            if record.operation != NameOperation::Update
                && (record.owner_public_key != predecessor_record.owner_public_key
                    || record.address != predecessor_record.address)
            {
                return Err(NameIndexError::Protocol(
                    NameProtocolError::InvalidTransition,
                ));
            }
            let (expiry_height, revoked) = match record.operation {
                NameOperation::Update => {
                    require_zero_payment(transaction.registry_received_atomic)?;
                    (predecessor.expiry_height, false)
                }
                NameOperation::Renew => {
                    let years = paid_years(parameters, transaction.registry_received_atomic)?;
                    let base = predecessor.expiry_height.max(height);
                    (
                        base.checked_add(
                            years
                                .checked_mul(parameters.blocks_per_year)
                                .ok_or(NameIndexError::Overflow)?,
                        )
                        .ok_or(NameIndexError::Overflow)?,
                        false,
                    )
                }
                NameOperation::Revoke => {
                    require_zero_payment(transaction.registry_received_atomic)?;
                    (predecessor.expiry_height, true)
                }
                NameOperation::Claim => unreachable!(),
            };
            insert_name_state(
                state,
                record.name.clone(),
                NameState {
                    signing_owner_public_key: Some(predecessor_record.owner_public_key),
                    record: IndexedNameRecord::Signed(record),
                    record_payload,
                    record_height: height,
                    source_txid: transaction.txid,
                    expiry_height,
                    revoked,
                },
            );
        }
    }
    Ok(())
}

fn apply_legacy_claim(
    parameters: &ProtocolParameters,
    state: &mut ReplayState,
    height: u64,
    transaction: &IndexedTransaction,
    record: LegacyNameRecord,
    record_payload: Vec<u8>,
) -> Result<(), NameIndexError> {
    if parameters.network != Network::Mainnet || height > LEGACY_MAINNET_CLAIM_CUTOFF_HEIGHT {
        return Err(NameIndexError::LegacyClaimAfterCutoff);
    }
    record.verify(&record.name, parameters.network)?;
    if parameters.reserved_names.contains(&record.name) {
        return Err(NameIndexError::ReservedName);
    }
    let commitment = record.claim_commitment(parameters.network)?.commitment;
    let commit = state
        .commits
        .get(&commitment)
        .and_then(|candidates| {
            candidates.iter().rev().find(|candidate| {
                let age = height.saturating_sub(candidate.height);
                candidate.height < height
                    && age >= parameters.commit_min_confirmations
                    && age <= parameters.commit_reveal_window
                    && candidate.registry_received_atomic == LEGACY_COMMIT_PAYMENT_ATOMIC
                    && !state.consumed_commits.contains(&(
                        commitment,
                        candidate.height,
                        candidate.txid,
                    ))
            })
        })
        .cloned()
        .ok_or(NameIndexError::MissingMatureCommit)?;
    if let Some(existing) = state.names.get(&record.name) {
        if !existing.revoked && height < existing.expiry_height {
            return Err(NameIndexError::NameAlreadyOwned);
        }
    }
    let years = paid_years(parameters, transaction.registry_received_atomic)?;
    let expiry_height = height
        .checked_add(
            years
                .checked_mul(parameters.blocks_per_year)
                .ok_or(NameIndexError::Overflow)?,
        )
        .ok_or(NameIndexError::Overflow)?;
    state
        .consumed_commits
        .insert((commitment, commit.height, commit.txid));
    insert_name_state(
        state,
        record.name.clone(),
        NameState {
            record: IndexedNameRecord::Legacy(record),
            record_payload,
            signing_owner_public_key: None,
            record_height: height,
            source_txid: transaction.txid,
            expiry_height,
            revoked: false,
        },
    );
    Ok(())
}

fn paid_years(
    parameters: &ProtocolParameters,
    registry_received_atomic: u64,
) -> Result<u64, NameIndexError> {
    if registry_received_atomic == 0
        || !registry_received_atomic.is_multiple_of(parameters.annual_fee_atomic)
    {
        return Err(NameIndexError::InvalidRegistryPayment);
    }
    let years = registry_received_atomic / parameters.annual_fee_atomic;
    if years == 0 || years > parameters.max_term_years {
        return Err(NameIndexError::InvalidRegistryPayment);
    }
    Ok(years)
}

fn require_zero_payment(amount: u64) -> Result<(), NameIndexError> {
    if amount == 0 {
        Ok(())
    } else {
        Err(NameIndexError::UnexpectedRegistryPayment)
    }
}

fn not_found(
    name: CanonicalName,
    chain_tip_height: Option<u64>,
    chain_tip_hash: Option<[u8; 32]>,
) -> Resolution {
    Resolution {
        name,
        address: None,
        owner_public_key: None,
        sequence: None,
        record_height: None,
        source_txid: None,
        record_payload: None,
        signing_owner_public_key: None,
        record_block_hash: None,
        chain_tip_hash,
        expiry_height: None,
        chain_tip_height,
        confirmations: 0,
        status: ResolutionStatus::NotFound,
    }
}

fn reserved(
    name: CanonicalName,
    chain_tip_height: Option<u64>,
    chain_tip_hash: Option<[u8; 32]>,
) -> Resolution {
    Resolution {
        status: ResolutionStatus::Reserved,
        ..not_found(name, chain_tip_height, chain_tip_hash)
    }
}

fn checksum(body: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(INDEX_CHECKSUM_DOMAIN);
    digest.update(body);
    hex::encode(digest.finalize())
}

fn reserved_manifest_hash(names: &BTreeSet<CanonicalName>) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(RESERVED_MANIFEST_DOMAIN);
    for name in names {
        digest.update([u8::try_from(name.as_str().len()).expect("name length is bounded")]);
        digest.update(name.as_str().as_bytes());
    }
    digest.finalize().into()
}

fn temporary_path(path: &Path) -> Result<PathBuf, NameIndexError> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(NameIndexError::InvalidPath)?;
    let mut nonce = [0; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| NameIndexError::RandomnessUnavailable)?;
    Ok(path.with_file_name(format!(".{file_name}.{}.tmp", hex::encode(nonce))))
}

#[derive(Debug, Error)]
pub enum NameIndexError {
    #[error(transparent)]
    Protocol(#[from] NameProtocolError),
    #[error("invalid protocol parameters")]
    InvalidParameters,
    #[error("block is before protocol activation")]
    BeforeActivation,
    #[error("non-sequential block: expected {expected}, got {actual}")]
    NonSequentialBlock { expected: u64, actual: u64 },
    #[error("duplicate block hash")]
    DuplicateBlockHash,
    #[error("block parent hash does not match the canonical predecessor")]
    ParentHashMismatch,
    #[error("cached block at height {0} does not match the canonical database")]
    CanonicalHashMismatch(u64),
    #[error("missing mature, unconsumed commit")]
    MissingMatureCommit,
    #[error("name is already owned")]
    NameAlreadyOwned,
    #[error("name is reserved by the frozen protocol manifest")]
    ReservedName,
    #[error("name is not currently owned")]
    NameNotOwned,
    #[error("immutable legacy claim does not support owner transitions")]
    LegacyRecordImmutable,
    #[error("legacy claim is after the frozen Mainnet compatibility cutoff")]
    LegacyClaimAfterCutoff,
    #[error("invalid Registry payment")]
    InvalidRegistryPayment,
    #[error("unexpected Registry payment")]
    UnexpectedRegistryPayment,
    #[error("invalid name suggestion query")]
    InvalidSuggestionQuery,
    #[error("invalid reverse name query")]
    InvalidReverseQuery,
    #[error("integer overflow")]
    Overflow,
    #[error("invalid persistence path")]
    InvalidPath,
    #[error("unsupported index file version")]
    UnsupportedFileVersion,
    #[error("index checksum mismatch")]
    ChecksumMismatch,
    #[error("index file exceeds the hard size limit")]
    OversizedIndexFile,
    #[error("secure randomness unavailable")]
    RandomnessUnavailable,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name::{AddressKind, NameSigningKey};
    use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
    use tempfile::tempdir;

    fn address(seed: u64) -> PublicAddress {
        PublicAddress::new(
            AddressKind::Subaddress,
            (Scalar::from(seed + 1) * ED25519_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
            (Scalar::from(seed + 2) * ED25519_BASEPOINT_POINT)
                .compress()
                .to_bytes(),
        )
        .unwrap()
    }

    fn parameters() -> ProtocolParameters {
        let reserved_names = [CanonicalName::parse("admin").unwrap()]
            .into_iter()
            .collect();
        ProtocolParameters {
            network: Network::Mainnet,
            activation_height: 100,
            registry_descriptor_hash: [9; 32],
            annual_fee_atomic: 10,
            blocks_per_year: 100,
            final_confirmations: 15,
            commit_min_confirmations: 3,
            commit_reveal_window: 20,
            max_term_years: MAX_TERM_YEARS,
            reserved_name_manifest_hash: reserved_manifest_hash(&reserved_names),
            reserved_names,
        }
    }

    fn block(height: u64, transactions: Vec<IndexedTransaction>) -> BlockInput {
        let mut hash = [0_u8; 32];
        hash[..8].copy_from_slice(&height.to_be_bytes());
        let mut parent_hash = [0_u8; 32];
        parent_hash[..8].copy_from_slice(&height.saturating_sub(1).to_be_bytes());
        BlockInput {
            height,
            hash,
            parent_hash,
            transactions,
        }
    }

    fn transaction(id: u8, payload: Vec<u8>, registry_received_atomic: u64) -> IndexedTransaction {
        IndexedTransaction {
            txid: [id; 32],
            payloads: vec![payload],
            registry_received_atomic,
        }
    }

    fn hex32(value: &str) -> [u8; 32] {
        hex::decode(value).unwrap().try_into().unwrap()
    }

    fn apply_empty_until(index: &mut NameIndex, height: u64) {
        let start = index
            .tip_height()
            .map(|known| known + 1)
            .unwrap_or(index.parameters.activation_height);
        for next in start..=height {
            index.apply_block(block(next, vec![])).unwrap();
        }
    }

    #[test]
    fn commit_claim_confirmation_and_exact_fee_contract() {
        let mut index = NameIndex::new(parameters()).unwrap();
        let owner = NameSigningKey::from_bytes([1; 32]);
        let name = CanonicalName::parse("alice").unwrap();
        let salt = [2; 16];
        let claim =
            NameRecord::signed_claim(Network::Mainnet, name.clone(), address(1), salt, &owner)
                .unwrap();
        let commit = claim.claim_commitment(Network::Mainnet).unwrap();
        index
            .apply_block(block(100, vec![transaction(1, commit.encode(), 0)]))
            .unwrap();
        apply_empty_until(&mut index, 102);
        index
            .apply_block(block(
                103,
                vec![transaction(2, claim.encode().unwrap(), 20)],
            ))
            .unwrap();
        assert_eq!(
            index.resolve("alice.mfw").unwrap().status,
            ResolutionStatus::Provisional
        );
        apply_empty_until(&mut index, 117);
        let resolution = index.resolve("alice").unwrap();
        assert_eq!(resolution.status, ResolutionStatus::Finalized);
        assert_eq!(resolution.expiry_height, Some(303));
        assert!(resolution.is_safe_for_payment());
        assert_eq!(index.suggest_names("ali", 5).unwrap(), vec!["alice.mfw"]);
        assert_eq!(
            index.reverse_names(address(1), 100).unwrap(),
            (vec!["alice.mfw".to_owned()], false)
        );
        assert_eq!(
            index.reverse_names(address(2), 100).unwrap(),
            (vec![], false)
        );
        assert!(matches!(
            index.reverse_names(address(1), 0),
            Err(NameIndexError::InvalidReverseQuery)
        ));
        assert!(matches!(
            index.suggest_names("al", 5),
            Err(NameIndexError::InvalidSuggestionQuery)
        ));

        let mut unpaid = NameIndex::new(parameters()).unwrap();
        unpaid
            .apply_block(block(100, vec![transaction(3, commit.encode(), 0)]))
            .unwrap();
        apply_empty_until(&mut unpaid, 102);
        unpaid
            .apply_block(block(
                103,
                vec![transaction(4, claim.encode().unwrap(), 19)],
            ))
            .unwrap();
        let missing = unpaid.resolve("alice").unwrap();
        assert_eq!(missing.status, ResolutionStatus::NotFound);
        assert_eq!(missing.chain_tip_height, Some(103));
        assert_eq!(missing.chain_tip_hash, Some(block(103, vec![]).hash));
        assert_eq!(unpaid.rejected_record_count().unwrap(), 1);
    }

    #[test]
    fn live_immutable_registry_v1_claim_remains_resolvable() {
        const COMMIT_HEIGHT: u64 = 3_740_974;
        const CLAIM_HEIGHT: u64 = 3_741_022;
        let commit_payload = hex::decode(
            "4d46574e01015c3536d631cc4b83bd4c43975b68897e48bf5f5af37d9ce7c42cf85abc3d5580",
        )
        .unwrap();
        let claim_payload = hex::decode(
            "4d46574e010200047465783800d5b0c70a320e1994e0c2099c203496f51fa771db6f771fed1697756034e645c443edc33ddde609782fb5e14a4fe600ff3cef0f862b0c27f9e8e314e556f3ac08375d17430161c44634bece4fffc2bd48",
        )
        .unwrap();
        let mut live_parameters = parameters();
        live_parameters.activation_height = COMMIT_HEIGHT;
        live_parameters.annual_fee_atomic = 10_000_000_000;
        live_parameters.blocks_per_year = 262_800;
        live_parameters.commit_min_confirmations = 15;
        live_parameters.commit_reveal_window = 720;
        let mut index = NameIndex::new(live_parameters).unwrap();
        index
            .apply_block(block(
                COMMIT_HEIGHT,
                vec![IndexedTransaction {
                    txid: hex32("edd39ebca3bdd7d6dd4017064475bf646b4270cfe90dcc3c10c394a3e66bfd4c"),
                    payloads: vec![commit_payload],
                    registry_received_atomic: LEGACY_COMMIT_PAYMENT_ATOMIC,
                }],
            ))
            .unwrap();
        apply_empty_until(&mut index, CLAIM_HEIGHT - 1);
        index
            .apply_block(block(
                CLAIM_HEIGHT,
                vec![IndexedTransaction {
                    txid: hex32("19807de2aff8e88881eb4b7f13cb2b8eb59436e60778fc8087bd433528fa4301"),
                    payloads: vec![claim_payload.clone()],
                    registry_received_atomic: 10_000_000_000,
                }],
            ))
            .unwrap();
        apply_empty_until(&mut index, CLAIM_HEIGHT + 14);

        let resolution = index.resolve("tex8.mfw").unwrap();
        assert_eq!(resolution.status, ResolutionStatus::Finalized);
        assert_eq!(resolution.record_height, Some(CLAIM_HEIGHT));
        assert_eq!(resolution.expiry_height, Some(4_003_822));
        assert_eq!(
            resolution.source_txid,
            Some(hex32(
                "19807de2aff8e88881eb4b7f13cb2b8eb59436e60778fc8087bd433528fa4301"
            ))
        );
        assert_eq!(resolution.record_payload, Some(claim_payload));
        assert_eq!(resolution.owner_public_key, None);
        assert_eq!(resolution.sequence, None);
        assert_eq!(resolution.signing_owner_public_key, None);
        let resolved_address = resolution.address.unwrap();
        assert_eq!(
            resolved_address.public_spend_key,
            hex32("d5b0c70a320e1994e0c2099c203496f51fa771db6f771fed1697756034e645c4")
        );
        assert_eq!(
            resolved_address.public_view_key,
            hex32("43edc33ddde609782fb5e14a4fe600ff3cef0f862b0c27f9e8e314e556f3ac08")
        );
        assert_eq!(index.suggest_names("tex", 5).unwrap(), vec!["tex8.mfw"]);
        assert_eq!(
            index.resolve("test.mfw").unwrap().status,
            ResolutionStatus::NotFound
        );
        assert_eq!(index.rejected_record_count().unwrap(), 0);
    }

    #[test]
    fn immutable_registry_v1_claims_after_the_cutoff_are_rejected() {
        let commit_height = LEGACY_MAINNET_CLAIM_CUTOFF_HEIGHT - 15;
        let claim_height = LEGACY_MAINNET_CLAIM_CUTOFF_HEIGHT + 1;
        let commit_payload = hex::decode(
            "4d46574e01015c3536d631cc4b83bd4c43975b68897e48bf5f5af37d9ce7c42cf85abc3d5580",
        )
        .unwrap();
        let claim_payload = hex::decode(
            "4d46574e010200047465783800d5b0c70a320e1994e0c2099c203496f51fa771db6f771fed1697756034e645c443edc33ddde609782fb5e14a4fe600ff3cef0f862b0c27f9e8e314e556f3ac08375d17430161c44634bece4fffc2bd48",
        )
        .unwrap();
        let mut live_parameters = parameters();
        live_parameters.activation_height = commit_height;
        live_parameters.annual_fee_atomic = 10_000_000_000;
        live_parameters.commit_min_confirmations = 15;
        live_parameters.commit_reveal_window = 720;
        let mut index = NameIndex::new(live_parameters).unwrap();
        index
            .apply_block(block(
                commit_height,
                vec![transaction(1, commit_payload, LEGACY_COMMIT_PAYMENT_ATOMIC)],
            ))
            .unwrap();
        apply_empty_until(&mut index, claim_height - 1);
        index
            .apply_block(block(
                claim_height,
                vec![transaction(2, claim_payload, 10_000_000_000)],
            ))
            .unwrap();
        assert_eq!(
            index.resolve("tex8.mfw").unwrap().status,
            ResolutionStatus::NotFound
        );
        assert_eq!(index.rejected_record_count().unwrap(), 1);
    }

    #[test]
    fn copied_reveal_wrong_network_and_sequence_are_ignored() {
        let mut index = NameIndex::new(parameters()).unwrap();
        let owner = NameSigningKey::from_bytes([3; 32]);
        let attacker = NameSigningKey::from_bytes([4; 32]);
        let name = CanonicalName::parse("secure").unwrap();
        let claim =
            NameRecord::signed_claim(Network::Mainnet, name.clone(), address(3), [7; 16], &owner)
                .unwrap();
        let copied =
            NameRecord::signed_claim(Network::Mainnet, name, address(8), [7; 16], &attacker)
                .unwrap();
        index
            .apply_block(block(
                100,
                vec![transaction(
                    1,
                    claim.claim_commitment(Network::Mainnet).unwrap().encode(),
                    0,
                )],
            ))
            .unwrap();
        apply_empty_until(&mut index, 102);
        index
            .apply_block(block(
                103,
                vec![
                    transaction(2, copied.encode().unwrap(), 10),
                    transaction(3, claim.encode().unwrap(), 10),
                ],
            ))
            .unwrap();
        apply_empty_until(&mut index, 117);
        assert_eq!(
            index.resolve("secure").unwrap().address,
            Some(claim.address)
        );
        assert_eq!(index.rejected_record_count().unwrap(), 1);
    }

    #[test]
    fn reserved_names_are_rejected_by_the_frozen_manifest() {
        let mut index = NameIndex::new(parameters()).unwrap();
        let owner = NameSigningKey::from_bytes([30; 32]);
        let claim = NameRecord::signed_claim(
            Network::Mainnet,
            CanonicalName::parse("admin").unwrap(),
            address(30),
            [31; 16],
            &owner,
        )
        .unwrap();
        index
            .apply_block(block(
                100,
                vec![transaction(
                    1,
                    claim.claim_commitment(Network::Mainnet).unwrap().encode(),
                    0,
                )],
            ))
            .unwrap();
        apply_empty_until(&mut index, 102);
        index
            .apply_block(block(
                103,
                vec![transaction(2, claim.encode().unwrap(), 10)],
            ))
            .unwrap();
        assert_eq!(
            index.resolve("admin").unwrap().status,
            ResolutionStatus::Reserved
        );
    }

    #[test]
    fn one_payment_cannot_fund_multiple_payloads() {
        let mut index = NameIndex::new(parameters()).unwrap();
        let owner = NameSigningKey::from_bytes([40; 32]);
        let claim = NameRecord::signed_claim(
            Network::Mainnet,
            CanonicalName::parse("one-payment").unwrap(),
            address(40),
            [41; 16],
            &owner,
        )
        .unwrap();
        index
            .apply_block(block(
                100,
                vec![transaction(
                    1,
                    claim.claim_commitment(Network::Mainnet).unwrap().encode(),
                    0,
                )],
            ))
            .unwrap();
        apply_empty_until(&mut index, 102);
        let mut duplicate = transaction(2, claim.encode().unwrap(), 10);
        duplicate.payloads.push(claim.encode().unwrap());
        index.apply_block(block(103, vec![duplicate])).unwrap();
        assert_eq!(
            index.resolve("one-payment").unwrap().status,
            ResolutionStatus::NotFound
        );
    }

    #[test]
    fn update_revoke_and_reorg_restore_exact_state() {
        let mut index = NameIndex::new(parameters()).unwrap();
        let owner = NameSigningKey::from_bytes([5; 32]);
        let name = CanonicalName::parse("rollback").unwrap();
        let claim =
            NameRecord::signed_claim(Network::Mainnet, name.clone(), address(10), [8; 16], &owner)
                .unwrap();
        index
            .apply_block(block(
                100,
                vec![transaction(
                    1,
                    claim.claim_commitment(Network::Mainnet).unwrap().encode(),
                    0,
                )],
            ))
            .unwrap();
        apply_empty_until(&mut index, 102);
        index
            .apply_block(block(
                103,
                vec![transaction(2, claim.encode().unwrap(), 10)],
            ))
            .unwrap();
        apply_empty_until(&mut index, 117);
        let stable = index.resolve("rollback").unwrap();

        let update = NameRecord::signed_transition(
            Network::Mainnet,
            NameOperation::Update,
            1,
            name,
            owner.public_key(),
            address(20),
            &claim,
            &owner,
        )
        .unwrap();
        index
            .apply_block(block(
                118,
                vec![transaction(3, update.encode().unwrap(), 0)],
            ))
            .unwrap();
        assert_eq!(
            index.resolve("rollback").unwrap().status,
            ResolutionStatus::Provisional
        );
        assert!(index.reverse_names(address(10), 100).unwrap().0.is_empty());
        assert!(index.reverse_names(address(20), 100).unwrap().0.is_empty());
        index.rewind_to(Some(117)).unwrap();
        assert_eq!(index.resolve("rollback").unwrap(), stable);
        assert_eq!(
            index.reverse_names(address(10), 100).unwrap().0,
            vec!["rollback.mfw"]
        );

        index
            .apply_block(block(
                118,
                vec![transaction(4, update.encode().unwrap(), 0)],
            ))
            .unwrap();
        apply_empty_until(&mut index, 132);
        assert_eq!(
            index.resolve("rollback").unwrap().address,
            Some(update.address)
        );
        assert!(index.reverse_names(address(10), 100).unwrap().0.is_empty());
        assert_eq!(
            index.reverse_names(address(20), 100).unwrap().0,
            vec!["rollback.mfw"]
        );
    }

    #[test]
    fn renew_cannot_smuggle_an_update_and_revoke_is_finality_gated() {
        let mut index = NameIndex::new(parameters()).unwrap();
        let owner = NameSigningKey::from_bytes([50; 32]);
        let name = CanonicalName::parse("lifecycle").unwrap();
        let claim = NameRecord::signed_claim(
            Network::Mainnet,
            name.clone(),
            address(50),
            [51; 16],
            &owner,
        )
        .unwrap();
        index
            .apply_block(block(
                100,
                vec![transaction(
                    1,
                    claim.claim_commitment(Network::Mainnet).unwrap().encode(),
                    0,
                )],
            ))
            .unwrap();
        apply_empty_until(&mut index, 102);
        index
            .apply_block(block(
                103,
                vec![transaction(2, claim.encode().unwrap(), 10)],
            ))
            .unwrap();
        apply_empty_until(&mut index, 117);

        let smuggled_update = NameRecord::signed_transition(
            Network::Mainnet,
            NameOperation::Renew,
            1,
            name.clone(),
            owner.public_key(),
            address(99),
            &claim,
            &owner,
        )
        .unwrap();
        let renewal = NameRecord::signed_transition(
            Network::Mainnet,
            NameOperation::Renew,
            1,
            name.clone(),
            owner.public_key(),
            claim.address,
            &claim,
            &owner,
        )
        .unwrap();
        index
            .apply_block(block(
                118,
                vec![
                    transaction(3, smuggled_update.encode().unwrap(), 10),
                    transaction(4, renewal.encode().unwrap(), 10),
                ],
            ))
            .unwrap();
        apply_empty_until(&mut index, 132);
        let renewed = index.resolve("lifecycle").unwrap();
        assert_eq!(renewed.status, ResolutionStatus::Finalized);
        assert_eq!(renewed.address, Some(claim.address));
        assert_eq!(renewed.expiry_height, Some(303));
        assert_eq!(index.rejected_record_count().unwrap(), 1);

        let revoke = NameRecord::signed_transition(
            Network::Mainnet,
            NameOperation::Revoke,
            2,
            name,
            owner.public_key(),
            renewal.address,
            &renewal,
            &owner,
        )
        .unwrap();
        index
            .apply_block(block(
                133,
                vec![transaction(5, revoke.encode().unwrap(), 0)],
            ))
            .unwrap();
        assert_eq!(
            index.resolve("lifecycle").unwrap().status,
            ResolutionStatus::Provisional
        );
        apply_empty_until(&mut index, 147);
        assert_eq!(
            index.resolve("lifecycle").unwrap().status,
            ResolutionStatus::Revoked
        );
        assert!(index
            .reverse_names(claim.address, 100)
            .unwrap()
            .0
            .is_empty());
        index.rewind_to(Some(132)).unwrap();
        assert_eq!(index.resolve("lifecycle").unwrap(), renewed);
        assert_eq!(
            index.reverse_names(claim.address, 100).unwrap().0,
            vec!["lifecycle.mfw"]
        );
    }

    #[test]
    fn persistence_is_reproducible_and_tamper_evident() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("name-index.json");
        let mut index = NameIndex::new(parameters()).unwrap();
        apply_empty_until(&mut index, 120);
        index.save_atomic(&path).unwrap();
        let loaded = NameIndex::load(&path, |height| {
            let mut hash = [0_u8; 32];
            hash[..8].copy_from_slice(&height.to_be_bytes());
            Ok(hash)
        })
        .unwrap();
        assert_eq!(loaded.parameters(), index.parameters());
        assert_eq!(loaded.block_count(), index.block_count());

        let mut bytes = fs::read(&path).unwrap();
        let position = bytes.iter().position(|byte| *byte == b'1').unwrap();
        bytes[position] = b'2';
        fs::write(&path, bytes).unwrap();
        assert!(NameIndex::load(&path, |_| Ok([0; 32])).is_err());
    }
}
