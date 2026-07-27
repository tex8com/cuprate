//! Optional derived `.mfw` index.
//!
//! This task has read-only access to Cuprate's canonical database. It scans
//! Registry outputs with the frozen public spend key and published private
//! view key, validates MFW records, and persists only a reproducible sidecar.
//! It is disabled unless the complete environment contract is present.

use std::{
    collections::{BTreeSet, HashMap},
    env,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};

use anyhow::{bail, Context, Result};
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, scalar::Scalar,
};
use mfw_recipient_protocol::{
    extract_mfw_payloads, registry_descriptor_hash, AddressKind, BlockInput, CanonicalName,
    IndexedTransaction, NameIndex, NameIndexError, Network as ProtocolNetwork, ProtocolParameters,
    PublicAddress,
};
use monero_oxide::{
    block::Block,
    transaction::{NotPruned, Pruned, Transaction},
};
use monero_rpc::ScannableBlock;
use monero_wallet::{Scanner, ViewPair};
use tokio::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use tower::ServiceExt;
use zeroize::Zeroizing;

use cuprate_blockchain::service::BlockchainReadHandle;
use cuprate_p2p_core::Network;
use cuprate_types::{
    blockchain::{BlockchainReadRequest, BlockchainResponse},
    BlockCompleteEntry, Chain, TransactionBlobs,
};

const INDEX_FILE_ENV: &str = "CUPRATE_MFW_NAME_INDEX_FILE";
const ACTIVATION_HEIGHT_ENV: &str = "CUPRATE_MFW_NAME_ACTIVATION_HEIGHT";
const REGISTRY_SPEND_PUBLIC_KEY_ENV: &str = "CUPRATE_MFW_REGISTRY_SPEND_PUBLIC_KEY";
const REGISTRY_VIEW_PRIVATE_KEY_ENV: &str = "CUPRATE_MFW_REGISTRY_VIEW_PRIVATE_KEY";
const POLL_INTERVAL_MS_ENV: &str = "CUPRATE_MFW_NAME_POLL_INTERVAL_MS";
const DEFAULT_POLL_INTERVAL_MS: u64 = 5_000;
const MAX_BLOCKS_PER_PASS: u64 = 256;

pub struct NameIndexState {
    index: RwLock<NameIndex>,
    ready: AtomicBool,
}

impl NameIndexState {
    fn new(index: NameIndex) -> Self {
        Self {
            index: RwLock::new(index),
            ready: AtomicBool::new(false),
        }
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub async fn read(&self) -> RwLockReadGuard<'_, NameIndex> {
        self.index.read().await
    }

    async fn write(&self) -> RwLockWriteGuard<'_, NameIndex> {
        self.index.write().await
    }

    fn set_ready(&self, ready: bool) {
        self.ready.store(ready, Ordering::Release);
    }
}

pub type SharedNameIndex = Arc<NameIndexState>;

struct NameIndexConfig {
    index_file: PathBuf,
    activation_height: u64,
    poll_interval: Duration,
    protocol_network: ProtocolNetwork,
    registry_address: PublicAddress,
    registry_private_view_key: Scalar,
}

impl NameIndexConfig {
    fn from_environment(network: Network) -> Result<Option<Self>> {
        let Some(index_file) = env::var_os(INDEX_FILE_ENV) else {
            let partial = [
                ACTIVATION_HEIGHT_ENV,
                REGISTRY_SPEND_PUBLIC_KEY_ENV,
                REGISTRY_VIEW_PRIVATE_KEY_ENV,
                POLL_INTERVAL_MS_ENV,
            ]
            .into_iter()
            .any(|name| env::var_os(name).is_some());
            if partial {
                bail!("{INDEX_FILE_ENV} is required when any MFW name setting is present");
            }
            return Ok(None);
        };
        if index_file.is_empty() {
            bail!("{INDEX_FILE_ENV} must not be empty");
        }
        let activation_height = required_u64(ACTIVATION_HEIGHT_ENV)?;
        let spend_public_key = required_hex_32(REGISTRY_SPEND_PUBLIC_KEY_ENV)?;
        let registry_private_view_key =
            Scalar::from_canonical_bytes(required_hex_32(REGISTRY_VIEW_PRIVATE_KEY_ENV)?)
                .into_option()
                .filter(|scalar| *scalar != Scalar::ZERO)
                .context("Registry private view key must be a non-zero canonical scalar")?;
        let spend_point = CompressedEdwardsY(spend_public_key)
            .decompress()
            .context("Registry public spend key is not a compressed Edwards point")?;
        let public_view_key = (&registry_private_view_key * ED25519_BASEPOINT_TABLE)
            .compress()
            .to_bytes();
        let registry_address =
            PublicAddress::new(AddressKind::Standard, spend_public_key, public_view_key)
                .context("Registry address contains an invalid public key")?;
        let poll_interval_ms = optional_u64(POLL_INTERVAL_MS_ENV, DEFAULT_POLL_INTERVAL_MS)?;
        if poll_interval_ms < 250 {
            bail!("{POLL_INTERVAL_MS_ENV} must be at least 250");
        }
        let protocol_network = match network {
            Network::Mainnet => ProtocolNetwork::Mainnet,
            Network::Testnet => ProtocolNetwork::Testnet,
            Network::Stagenet => ProtocolNetwork::Stagenet,
        };
        let index_file = PathBuf::from(index_file);
        prepare_index_parent(&index_file)?;
        Ok(Some(Self {
            index_file,
            activation_height,
            poll_interval: Duration::from_millis(poll_interval_ms),
            protocol_network,
            registry_address,
            registry_private_view_key,
        }))
    }

    fn protocol_parameters(&self) -> Result<ProtocolParameters> {
        let reserved_names = [
            "admin", "api", "help", "mfw", "monero", "security", "support", "tex8", "wallet", "www",
        ]
        .into_iter()
        .map(CanonicalName::parse)
        .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        let descriptor_hash = registry_descriptor_hash(
            self.protocol_network,
            self.registry_address,
            self.registry_private_view_key.to_bytes(),
        );
        Ok(ProtocolParameters::v1(
            self.protocol_network,
            self.activation_height,
            descriptor_hash,
            reserved_names,
        ))
    }
}

pub fn start_from_environment(
    network: Network,
    blockchain_read: BlockchainReadHandle,
) -> Result<Option<SharedNameIndex>> {
    let Some(config) = NameIndexConfig::from_environment(network)? else {
        tracing::info!("MFW derived name index disabled");
        return Ok(None);
    };
    let view_pair = ViewPair::new(
        CompressedEdwardsY(config.registry_address.public_spend_key)
            .decompress()
            .context("invalid Registry spend point")?,
        Zeroizing::new(config.registry_private_view_key),
    )
    .context("invalid Registry view pair")?;
    let index = Arc::new(NameIndexState::new(NameIndex::new(
        config.protocol_parameters()?,
    )?));
    let shared = Arc::clone(&index);
    tracing::info!(
        activation_height = config.activation_height,
        index_file = %config.index_file.display(),
        "starting canonical Cuprate MFW name index"
    );
    tokio::spawn(async move {
        NameIndexWorker {
            blockchain_read,
            config,
            index,
            scanner: Scanner::new(view_pair),
            initialized: false,
        }
        .run()
        .await;
    });
    Ok(Some(shared))
}

struct NameIndexWorker {
    blockchain_read: BlockchainReadHandle,
    config: NameIndexConfig,
    index: SharedNameIndex,
    scanner: Scanner,
    initialized: bool,
}

impl NameIndexWorker {
    async fn run(mut self) {
        loop {
            if let Err(error) = self.sync_once().await {
                self.index.set_ready(false);
                tracing::error!(?error, "MFW name index pass failed closed");
            }
            tokio::time::sleep(self.config.poll_interval).await;
        }
    }

    async fn sync_once(&mut self) -> Result<()> {
        self.restore_persisted_index().await?;
        let chain_height = self.chain_height().await?;
        if chain_height <= self.config.activation_height {
            self.index.set_ready(true);
            return Ok(());
        }
        self.rewind_reorg().await?;
        let start = self
            .index
            .read()
            .await
            .tip_height()
            .map_or(self.config.activation_height, |height| height + 1);
        if start >= chain_height {
            self.index.set_ready(true);
            return Ok(());
        }
        self.index.set_ready(false);
        let end = chain_height.min(start.saturating_add(MAX_BLOCKS_PER_PASS));
        let blocks = self.blocks(start, end).await?;
        let hashes = self.block_hashes(start, end).await?;
        if blocks.len() != hashes.len() {
            bail!("canonical block/hash response length mismatch");
        }
        let first_parent_hash = if start == 0 {
            [0; 32]
        } else {
            self.block_hash(start - 1).await?
        };
        let mut parent_hash = first_parent_hash;
        for ((offset, entry), expected_hash) in blocks.into_iter().enumerate().zip(hashes) {
            let height = start
                .checked_add(u64::try_from(offset)?)
                .context("height overflow")?;
            let input = self
                .derive_block(height, expected_hash, parent_hash, entry)
                .await?;
            self.index.write().await.apply_block(input)?;
            parent_hash = expected_hash;
        }
        if self.block_hash(end - 1).await? != parent_hash {
            bail!("canonical chain changed while deriving MFW name batch");
        }
        self.index
            .read()
            .await
            .save_atomic(&self.config.index_file)?;
        tracing::info!(
            indexed_through = end - 1,
            chain_tip = chain_height - 1,
            "advanced canonical MFW name index"
        );
        self.index.set_ready(end == chain_height);
        Ok(())
    }

    async fn restore_persisted_index(&mut self) -> Result<()> {
        if self.initialized {
            return Ok(());
        }
        let stored = match NameIndex::persisted_block_hashes(&self.config.index_file) {
            Ok(stored) => stored,
            Err(NameIndexError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {
                self.initialized = true;
                return Ok(());
            }
            Err(error) => {
                tracing::warn!(
                    ?error,
                    index_file = %self.config.index_file.display(),
                    "discarding invalid MFW name index cache; rebuilding from canonical data"
                );
                self.initialized = true;
                return Ok(());
            }
        };
        if stored.is_empty() {
            self.initialized = true;
            return Ok(());
        }

        // Validate every persisted block hash against Cuprate's canonical DB
        // before the cache becomes visible to RPC clients. Fetching bounded
        // ranges avoids an unbounded database response on long-lived nodes.
        for chunk in stored.chunks(4_096) {
            let start = chunk.first().expect("non-empty chunk").0;
            let end = chunk
                .last()
                .expect("non-empty chunk")
                .0
                .checked_add(1)
                .context("persisted height overflow")?;
            let canonical = self.block_hashes(start, end).await?;
            if canonical.len() != chunk.len()
                || canonical
                    .iter()
                    .zip(chunk)
                    .any(|(canonical_hash, (_, stored_hash))| canonical_hash != stored_hash)
            {
                tracing::warn!(
                    start,
                    end,
                    "discarding stale MFW name index cache after canonical hash mismatch"
                );
                self.initialized = true;
                return Ok(());
            }
        }

        let loaded = match NameIndex::load(&self.config.index_file, |height| {
            stored
                .binary_search_by_key(&height, |(stored_height, _)| *stored_height)
                .ok()
                .map(|position| stored[position].1)
                .ok_or(NameIndexError::CanonicalHashMismatch(height))
        }) {
            Ok(loaded) => loaded,
            Err(error) => {
                tracing::warn!(
                    ?error,
                    "MFW name index changed during validated load; rebuilding"
                );
                self.initialized = true;
                return Ok(());
            }
        };
        if loaded.parameters() != &self.config.protocol_parameters()? {
            tracing::warn!("discarding MFW name index cache with different frozen parameters");
            self.initialized = true;
            return Ok(());
        }
        let tip = loaded.tip_height();
        *self.index.write().await = loaded;
        tracing::info!(
            indexed_through = ?tip,
            "restored canonical-verified MFW name index cache"
        );
        self.initialized = true;
        Ok(())
    }

    async fn rewind_reorg(&mut self) -> Result<()> {
        loop {
            let (tip_height, tip_hash) = {
                let index = self.index.read().await;
                (index.tip_height(), index.tip_hash())
            };
            let (Some(height), Some(indexed_hash)) = (tip_height, tip_hash) else {
                return Ok(());
            };
            if height >= self.chain_height().await? {
                self.index.set_ready(false);
                self.index.write().await.rewind_to(height.checked_sub(1))?;
                continue;
            }
            if self.block_hash(height).await? == indexed_hash {
                return Ok(());
            }
            tracing::warn!(height, "rewinding orphaned MFW name index block");
            self.index.set_ready(false);
            self.index.write().await.rewind_to(height.checked_sub(1))?;
        }
    }

    async fn derive_block(
        &mut self,
        height: u64,
        expected_hash: [u8; 32],
        parent_hash: [u8; 32],
        entry: BlockCompleteEntry,
    ) -> Result<BlockInput> {
        let mut block_bytes = entry.block.as_ref();
        let block = Block::read(&mut block_bytes).context("invalid canonical block blob")?;
        if !block_bytes.is_empty() || block.hash() != expected_hash {
            bail!("canonical block blob/hash mismatch at height {height}");
        }
        let transactions = parse_pruned_transactions(entry.txs)?;
        if transactions.len() != block.transactions.len() {
            bail!("canonical transaction count mismatch at height {height}");
        }
        let mut candidates = Vec::new();
        for (txid, transaction) in block.transactions.iter().copied().zip(&transactions) {
            let payloads = match extract_mfw_payloads(&transaction.prefix().extra) {
                Ok(payloads) => payloads,
                Err(error) => {
                    tracing::debug!(height, txid = %hex::encode(txid), ?error, "ignored malformed MFW tx_extra");
                    continue;
                }
            };
            if !payloads.is_empty() {
                candidates.push((txid, payloads));
            }
        }
        if candidates.is_empty() {
            return Ok(BlockInput {
                height,
                hash: expected_hash,
                parent_hash,
                transactions: Vec::new(),
            });
        }
        let received = self
            .scan_registry_outputs(&block, transactions)
            .await
            .with_context(|| format!("failed to scan Registry outputs at height {height}"))?;
        let transactions = candidates
            .into_iter()
            .map(|(txid, payloads)| IndexedTransaction {
                txid,
                payloads,
                registry_received_atomic: received.get(&txid).copied().unwrap_or(0),
            })
            .collect();
        Ok(BlockInput {
            height,
            hash: expected_hash,
            parent_hash,
            transactions,
        })
    }

    async fn scan_registry_outputs(
        &mut self,
        block: &Block,
        transactions: Vec<Transaction<Pruned>>,
    ) -> Result<HashMap<[u8; 32], u64>> {
        let mut hashes = Vec::with_capacity(transactions.len() + 1);
        hashes.push(block.miner_transaction().hash());
        hashes.extend(block.transactions.iter().copied());
        let response = self
            .blockchain_read
            .clone()
            .oneshot(BlockchainReadRequest::TxOutputIndexesBatch(hashes))
            .await
            .context("failed to read output indices for Registry scan")?;
        let BlockchainResponse::TxOutputIndexesBatch(indices) = response else {
            bail!("unexpected output-index response");
        };
        let mut all_transactions = Vec::with_capacity(transactions.len() + 1);
        all_transactions.push(Transaction::<Pruned>::from(
            block.miner_transaction().clone(),
        ));
        all_transactions.extend(transactions.iter().cloned());
        if indices.len() != all_transactions.len() {
            bail!("output-index response count mismatch");
        }
        let first_ringct_index =
            all_transactions
                .iter()
                .zip(&indices)
                .find_map(|(transaction, tx_indices)| {
                    (transaction.version() == 2 && !transaction.prefix().outputs.is_empty())
                        .then(|| tx_indices.first().copied())
                        .flatten()
                });
        let outputs = self
            .scanner
            .scan(ScannableBlock {
                block: block.clone(),
                transactions,
                output_index_for_first_ringct_output: first_ringct_index,
            })
            .context("monero-wallet rejected canonical ScannableBlock")?
            .ignore_additional_timelock();
        let mut received = HashMap::new();
        for output in outputs {
            let amount = output.commitment().amount;
            let total = received.entry(output.transaction()).or_insert(0_u64);
            *total = total
                .checked_add(amount)
                .context("Registry transaction amount overflow")?;
        }
        Ok(received)
    }

    async fn chain_height(&self) -> Result<u64> {
        let response = self
            .blockchain_read
            .clone()
            .oneshot(BlockchainReadRequest::ChainHeight)
            .await
            .context("failed to read chain height")?;
        let BlockchainResponse::ChainHeight(height, _) = response else {
            bail!("unexpected chain-height response");
        };
        u64::try_from(height).context("chain height does not fit u64")
    }

    async fn block_hash(&self, height: u64) -> Result<[u8; 32]> {
        let response = self
            .blockchain_read
            .clone()
            .oneshot(BlockchainReadRequest::BlockHash(
                usize::try_from(height)?,
                Chain::Main,
            ))
            .await
            .context("failed to read canonical block hash")?;
        let BlockchainResponse::BlockHash(hash) = response else {
            bail!("unexpected block-hash response");
        };
        Ok(hash)
    }

    async fn block_hashes(&self, start: u64, end: u64) -> Result<Vec<[u8; 32]>> {
        let response = self
            .blockchain_read
            .clone()
            .oneshot(BlockchainReadRequest::BlockHashInRange(
                usize::try_from(start)?..usize::try_from(end)?,
                Chain::Main,
            ))
            .await
            .context("failed to read canonical block-hash range")?;
        let BlockchainResponse::BlockHashInRange(hashes) = response else {
            bail!("unexpected block-hash-range response");
        };
        Ok(hashes)
    }

    async fn blocks(&self, start: u64, end: u64) -> Result<Vec<BlockCompleteEntry>> {
        let heights = (start..end)
            .map(usize::try_from)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let response = self
            .blockchain_read
            .clone()
            .oneshot(BlockchainReadRequest::BlockCompleteEntriesByHeightPruned(
                heights,
            ))
            .await
            .context("failed to read canonical pruned blocks")?;
        let BlockchainResponse::BlockCompleteEntriesByHeight(blocks) = response else {
            bail!("unexpected canonical block response");
        };
        Ok(blocks)
    }
}

fn parse_pruned_transactions(blobs: TransactionBlobs) -> Result<Vec<Transaction<Pruned>>> {
    match blobs {
        TransactionBlobs::Pruned(entries) => entries
            .into_iter()
            .map(|entry| {
                let mut bytes = entry.blob.as_ref();
                let transaction = Transaction::<Pruned>::read(&mut bytes)
                    .context("invalid pruned transaction blob")?;
                if !bytes.is_empty() {
                    bail!("pruned transaction has trailing bytes");
                }
                Ok(transaction)
            })
            .collect(),
        TransactionBlobs::Normal(entries) => entries
            .into_iter()
            .map(|entry| {
                let mut bytes = entry.as_ref();
                let transaction = Transaction::<NotPruned>::read(&mut bytes)
                    .context("invalid full transaction blob")?;
                if !bytes.is_empty() {
                    bail!("full transaction has trailing bytes");
                }
                Ok(Transaction::<Pruned>::from(transaction))
            })
            .collect(),
        TransactionBlobs::None => Ok(Vec::new()),
    }
}

fn prepare_index_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .context("MFW name index path must have a parent directory")?;
    let metadata = std::fs::symlink_metadata(parent)
        .with_context(|| format!("cannot inspect MFW index directory {}", parent.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("MFW name index parent must be a real directory");
    }
    Ok(())
}

fn required_u64(name: &str) -> Result<u64> {
    env::var(name)
        .with_context(|| format!("{name} is required"))?
        .parse()
        .with_context(|| format!("{name} must be an unsigned integer"))
}

fn optional_u64(name: &str, default: u64) -> Result<u64> {
    match env::var(name) {
        Ok(value) => value
            .parse()
            .with_context(|| format!("{name} must be an unsigned integer")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(error).with_context(|| format!("cannot read {name}")),
    }
}

fn required_hex_32(name: &str) -> Result<[u8; 32]> {
    let value = env::var(name).with_context(|| format!("{name} is required"))?;
    if value.len() != 64
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    {
        bail!("{name} must be exactly 64 lowercase hexadecimal characters");
    }
    hex::decode(value)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must decode to exactly 32 bytes"))
}
