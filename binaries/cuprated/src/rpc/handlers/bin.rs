//! RPC request handler functions (binary endpoints).
//!
//! TODO:
//! Some handlers have `todo!()`s for other Cuprate internals that must be completed, see:
//! <https://github.com/Cuprate/cuprate/pull/355>

use std::num::NonZero;
use std::time::Instant;

use anyhow::{anyhow, Error};
use cuprate_constants::rpc::{
    GET_BLOCKS_BIN_LEGACY_DEFAULT_BLOCK_COUNT, GET_BLOCKS_BIN_MAX_BLOCK_COUNT,
    GET_BLOCKS_BIN_MAX_TX_COUNT, RESTRICTED_BLOCK_COUNT, RESTRICTED_TRANSACTIONS_COUNT,
};
use cuprate_fixed_bytes::ByteArrayVec;
use cuprate_helper::cast::{u64_to_usize, usize_to_u64};
use cuprate_rpc_interface::RpcHandler;
use cuprate_rpc_types::{
    base::{AccessResponseBase, ResponseBase},
    bin::{
        BinRequest, BinResponse, GetBlocksByHeightRequest, GetBlocksByHeightResponse,
        GetBlocksRequest, GetBlocksResponse, GetHashesRequest, GetHashesResponse,
        GetOutputIndexesRequest, GetOutputIndexesResponse, GetOutsRequest, GetOutsResponse,
        GetTransactionPoolHashesRequest, GetTransactionPoolHashesResponse,
    },
    json::{GetOutputDistributionRequest, GetOutputDistributionResponse},
    misc::RequestedInfo,
};
use cuprate_types::{
    rpc::{BlockOutputIndices, PoolInfo, PoolInfoExtent, TxOutputIndices},
    BlockCompleteEntry, TransactionBlobs,
};
use hex;
use monero_oxide::block::Block;

use crate::rpc::{
    handlers::{helper, shared, shared::not_available},
    scanpack::ScanPack,
    service::{blockchain, txpool},
    CupratedRpcHandler,
};

pub(crate) const GET_BLOCKS_BIN_MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;
const GET_BLOCKS_BIN_FETCH_BATCH: usize = 1000;

/// Per-request timings for the block-entry retrieval portion of a wallet-sync
/// response.  Kept separate from the legacy RPC response so instrumentation
/// cannot change its wire format or behaviour.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct BlockFetchMetrics {
    pub batch_count: usize,
    pub height_vector_ms: f64,
    pub database_ms: f64,
    pub cap_and_collect_ms: f64,
    pub returned_blocks: usize,
    pub returned_txs: usize,
    pub estimated_response_bytes: usize,
    pub limited_by_response_size: bool,
    pub limited_by_tx_count: bool,
}

/// Per-request timings for construction of output-index data.  These fields
/// make parsing, database lookup and reconstruction independently visible.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct OutputIndicesMetrics {
    pub parse_ms: f64,
    pub database_ms: f64,
    pub reconstruct_ms: f64,
    pub blocks: usize,
    pub transactions: usize,
    pub output_index_values: usize,
}

/// Map a [`BinRequest`] to the function that will lead to a [`BinResponse`].
pub async fn map_request(
    state: CupratedRpcHandler,
    request: BinRequest,
) -> Result<BinResponse, Error> {
    use BinRequest as Req;
    use BinResponse as Resp;

    Ok(match request {
        Req::GetBlocks(r) => Resp::GetBlocks(get_blocks(state, r).await?),
        Req::GetBlocksByHeight(r) => Resp::GetBlocksByHeight(get_blocks_by_height(state, r).await?),
        Req::GetHashes(r) => Resp::GetHashes(get_hashes(state, r).await?),
        Req::GetOutputIndexes(r) => Resp::GetOutputIndexes(get_output_indexes(state, r).await?),
        Req::GetOuts(r) => Resp::GetOuts(get_outs(state, r).await?),
        Req::GetTransactionPoolHashes(r) => {
            Resp::GetTransactionPoolHashes(get_transaction_pool_hashes(state, r).await?)
        }
        Req::GetOutputDistribution(r) => {
            Resp::GetOutputDistribution(get_output_distribution(state, r).await?)
        }
    })
}

/// <https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454/src/rpc/core_rpc_server.cpp#L611-L789>
async fn get_blocks(
    mut state: CupratedRpcHandler,
    request: GetBlocksRequest,
) -> Result<GetBlocksResponse, Error> {
    // Time should be set early:
    // <https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454/src/rpc/core_rpc_server.cpp#L628-L631>
    let daemon_time = cuprate_helper::time::current_unix_timestamp();

    let GetBlocksRequest {
        requested_info,
        block_ids,
        start_height,
        prune,
        no_miner_tx,
        pool_info_since,
        max_block_count,
    } = request;

    let block_hashes: Vec<[u8; 32]> = (&block_ids).into();
    drop(block_ids);
    {
        let first_hashes: Vec<String> = block_hashes
            .iter()
            .take(3)
            .map(|h| hex::encode(&h[..8]))
            .collect();
        let last_hashes: Vec<String> = block_hashes
            .iter()
            .rev()
            .take(3)
            .map(|h| hex::encode(&h[..8]))
            .collect();
        eprintln!(
            "[PERF GB] REQ start_height={} block_ids.len={} first3={:?} last3={:?}",
            start_height,
            block_hashes.len(),
            first_hashes,
            last_hashes
        );
    }

    let Some(requested_info) = RequestedInfo::from_u8(request.requested_info) else {
        return Err(anyhow!("Wrong requested info"));
    };

    let (get_blocks, get_pool) = match requested_info {
        RequestedInfo::BlocksOnly => (true, false),
        RequestedInfo::BlocksAndPool => (true, true),
        RequestedInfo::PoolOnly => (false, true),
    };

    let pool_info = if get_pool {
        let is_restricted = state.is_restricted();
        let include_sensitive_txs = !is_restricted;

        let max_tx_count = if is_restricted {
            RESTRICTED_TRANSACTIONS_COUNT
        } else {
            usize::MAX
        };

        txpool::pool_info(
            &mut state.txpool_read,
            include_sensitive_txs,
            max_tx_count,
            NonZero::new(u64_to_usize(pool_info_since)),
        )
        .await?
    } else {
        PoolInfo::None
    };

    let (pool_info_extent, added_pool_txs, remaining_added_pool_txids, removed_pool_txids) =
        split_pool_info(pool_info);

    let resp = GetBlocksResponse {
        base: helper::access_response_base(false),
        blocks: vec![],
        start_height: 0,
        current_height: 0,
        output_indices: vec![],
        daemon_time,
        pool_info_extent,
        added_pool_txs,
        remaining_added_pool_txids,
        removed_pool_txids,
    };

    if !get_blocks {
        return Ok(resp);
    }

    if let Some(block_id) = block_hashes.first() {
        let (height, hash) = helper::top_height(&mut state).await?;

        if hash == *block_id {
            return Ok(GetBlocksResponse {
                current_height: height + 1,
                ..resp
            });
        }
    }

    let max_blocks = effective_get_blocks_limit(max_block_count);

    let (first_known_height, chain_height) = if !block_hashes.is_empty() || start_height == 0 {
        let n_hashes = block_hashes.len();
        let (ids, fkh, ch) =
            blockchain::next_chain_entry(&mut state.blockchain_read, block_hashes, 1).await?;
        eprintln!(
            "[PERF GB] MATCH fkh={:?} chain_height={} returned_ids.len={} (from {} req-hashes)",
            fkh,
            ch,
            ids.len(),
            n_hashes
        );
        (fkh, ch)
    } else {
        let (tip_height, _) = helper::top_height(&mut state).await?;
        eprintln!(
            "[PERF GB] DIRECT start_height={} tip={}",
            start_height, tip_height
        );
        (None, usize::try_from(tip_height).unwrap() + 1)
    };

    let response_start_height = if start_height > 0 {
        u64_to_usize(start_height)
    } else {
        let Some(fkh) = first_known_height else {
            return Err(anyhow!("Block IDs were not sorted properly"));
        };
        fkh
    };

    let block_count = chain_height
        .saturating_sub(response_start_height)
        .min(u64_to_usize(max_blocks));

    let t_blocks = Instant::now();
    let (blocks, output_indices, block_metrics, index_metrics, scanpack_hit) =
        legacy_blocks_and_indices(
            &mut state,
            response_start_height,
            chain_height,
            block_count,
            prune,
            no_miner_tx,
            GET_BLOCKS_BIN_MAX_RESPONSE_BYTES,
            u64_to_usize(GET_BLOCKS_BIN_MAX_TX_COUNT),
        )
        .await?;
    eprintln!(
        "[RPC] GetBlocks: {} blocks, pruned={}, start={}, current_height={}, scanpack_hit={}",
        blocks.len(),
        prune,
        response_start_height,
        usize_to_u64(chain_height),
        scanpack_hit,
    );
    eprintln!(
        "[TIMING] block_fetch: {:.1}ms ({} blocks)",
        t_blocks.elapsed().as_secs_f64() * 1000.0,
        blocks.len()
    );
    eprintln!(
        "[TIMING] output_indices_total: {:.1}ms",
        index_metrics.parse_ms + index_metrics.database_ms + index_metrics.reconstruct_ms
    );
    eprintln!(
        "[SYNC_TRACE_SERVER_BIN_BLOCKS] start={} n_blocks={} scanpack_hit={} fetch_ms={:.3} fetch_batches={} fetch_heights_ms={:.3} fetch_db_ms={:.3} fetch_collect_ms={:.3} fetch_txs={} fetch_est_bytes={} idx_ms={:.3} idx_parse_ms={:.3} idx_db_ms={:.3} idx_reconstruct_ms={:.3} idx_txs={} idx_values={}",
        response_start_height,
        blocks.len(),
        scanpack_hit,
        t_blocks.elapsed().as_secs_f64() * 1000.0,
        block_metrics.batch_count,
        block_metrics.height_vector_ms,
        block_metrics.database_ms,
        block_metrics.cap_and_collect_ms,
        block_metrics.returned_txs,
        block_metrics.estimated_response_bytes,
        index_metrics.parse_ms + index_metrics.database_ms + index_metrics.reconstruct_ms,
        index_metrics.parse_ms,
        index_metrics.database_ms,
        index_metrics.reconstruct_ms,
        index_metrics.transactions,
        index_metrics.output_index_values,
    );

    Ok(GetBlocksResponse {
        blocks,
        start_height: usize_to_u64(response_start_height),
        current_height: usize_to_u64(chain_height),
        output_indices,
        ..resp
    })
}

fn effective_get_blocks_limit(max_block_count: u64) -> u64 {
    if max_block_count == 0 {
        GET_BLOCKS_BIN_LEGACY_DEFAULT_BLOCK_COUNT
    } else {
        max_block_count.min(GET_BLOCKS_BIN_MAX_BLOCK_COUNT)
    }
}

/// Serve a legacy `/get_blocks.bin` response from ScanPack only when its
/// payload is wire-compatible with the request. The locator/reorg decision is
/// deliberately made by the caller against the canonical chain first.
async fn legacy_blocks_and_indices(
    state: &mut CupratedRpcHandler,
    response_start_height: usize,
    chain_height: usize,
    block_count: usize,
    prune: bool,
    no_miner_tx: bool,
    max_response_bytes: usize,
    max_tx_count: usize,
) -> Result<
    (
        Vec<BlockCompleteEntry>,
        Vec<BlockOutputIndices>,
        BlockFetchMetrics,
        OutputIndicesMetrics,
        bool,
    ),
    Error,
> {
    // The builder persists pruned entries with miner output-indices included.
    // Any other legacy request keeps the established canonical-DB behaviour.
    if prune && !no_miner_tx {
        if let Some(store) = &state.wallet_scan_packs {
            if let Some(pack) =
                store.load_covering(u64::try_from(response_start_height)?, block_count)?
            {
                // Do not change a caller's requested range into a smaller
                // physical-cache response. A cross-pack request remains a
                // correct DB fallback until a multi-pack cache reader is
                // deliberately added and benchmarked.
                if pack.blocks.len() == block_count {
                    let (blocks, output_indices, block_metrics, index_metrics) =
                        capped_scanpack_response(pack, max_response_bytes, max_tx_count)?;
                    return Ok((blocks, output_indices, block_metrics, index_metrics, true));
                }
            }
        }
    }

    let (blocks, block_metrics) = capped_block_complete_entries_with_metrics(
        state,
        response_start_height,
        chain_height,
        block_count,
        prune,
        max_response_bytes,
        max_tx_count,
    )
    .await?;
    let (output_indices, index_metrics) =
        output_indices_for_blocks_with_metrics(state, &blocks, no_miner_tx).await?;
    Ok((blocks, output_indices, block_metrics, index_metrics, false))
}

/// Apply the legacy response caps to already prepared ScanPack data without
/// reparsing blocks or consulting the blockchain database.
fn capped_scanpack_response(
    pack: ScanPack,
    max_response_bytes: usize,
    max_tx_count: usize,
) -> Result<
    (
        Vec<BlockCompleteEntry>,
        Vec<BlockOutputIndices>,
        BlockFetchMetrics,
        OutputIndicesMetrics,
    ),
    Error,
> {
    if pack.blocks.len() != pack.output_indices.len() {
        return Err(anyhow!("scan pack block/index count mismatch"));
    }

    let mut blocks = Vec::with_capacity(pack.blocks.len());
    let mut output_indices = Vec::with_capacity(pack.output_indices.len());
    let mut response_bytes = 0_usize;
    let mut tx_count = 0_usize;
    let mut block_metrics = BlockFetchMetrics::default();

    for (block, indices) in pack.blocks.into_iter().zip(pack.output_indices) {
        let block_response_bytes = block_response_bytes(&block);
        let block_tx_count = block.txs.len();
        if !blocks.is_empty()
            && (response_bytes.saturating_add(block_response_bytes) > max_response_bytes
                || tx_count.saturating_add(block_tx_count) > max_tx_count)
        {
            block_metrics.limited_by_response_size =
                response_bytes.saturating_add(block_response_bytes) > max_response_bytes;
            block_metrics.limited_by_tx_count =
                tx_count.saturating_add(block_tx_count) > max_tx_count;
            break;
        }
        response_bytes = response_bytes.saturating_add(block_response_bytes);
        tx_count = tx_count.saturating_add(block_tx_count);
        blocks.push(block);
        output_indices.push(indices);
    }

    block_metrics.returned_blocks = blocks.len();
    block_metrics.returned_txs = tx_count;
    block_metrics.estimated_response_bytes = response_bytes;
    let index_metrics = OutputIndicesMetrics {
        blocks: output_indices.len(),
        transactions: output_indices.iter().map(|block| block.indices.len()).sum(),
        output_index_values: output_indices
            .iter()
            .flat_map(|block| &block.indices)
            .map(|tx| tx.indices.len())
            .sum(),
        ..OutputIndicesMetrics::default()
    };
    Ok((blocks, output_indices, block_metrics, index_metrics))
}

#[cfg(test)]
mod tests {
    use super::{capped_scanpack_response, effective_get_blocks_limit};
    use crate::rpc::scanpack::ScanPack;
    use cuprate_types::{
        rpc::{BlockOutputIndices, TxOutputIndices},
        BlockCompleteEntry,
    };

    fn scanpack(block_count: usize) -> ScanPack {
        ScanPack::new(
            100,
            (0..block_count)
                .map(|_| BlockCompleteEntry::default())
                .collect(),
            (0..block_count)
                .map(|_| BlockOutputIndices {
                    indices: vec![TxOutputIndices {
                        indices: vec![7, 11],
                    }],
                })
                .collect(),
        )
        .unwrap()
    }

    #[test]
    fn getblocks_zero_uses_monero_legacy_default() {
        assert_eq!(effective_get_blocks_limit(0), 1_000);
    }

    #[test]
    fn getblocks_explicit_limit_is_preserved_up_to_cuprate_ceiling() {
        assert_eq!(effective_get_blocks_limit(750), 750);
        assert_eq!(effective_get_blocks_limit(20_000), 10_000);
    }

    #[test]
    fn prepared_scanpack_keeps_block_index_alignment() {
        let (blocks, indices, block_metrics, index_metrics) =
            capped_scanpack_response(scanpack(2), usize::MAX, usize::MAX).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(indices.len(), 2);
        assert_eq!(block_metrics.returned_blocks, 2);
        assert_eq!(block_metrics.database_ms, 0.0);
        assert_eq!(index_metrics.database_ms, 0.0);
        assert_eq!(index_metrics.transactions, 2);
        assert_eq!(index_metrics.output_index_values, 4);
    }

    #[test]
    fn prepared_scanpack_respects_the_legacy_response_cap() {
        let (blocks, indices, block_metrics, _) =
            capped_scanpack_response(scanpack(2), 300, usize::MAX).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(indices.len(), 1);
        assert!(block_metrics.limited_by_response_size);
    }
}

fn split_pool_info(
    pool_info: PoolInfo,
) -> (
    u8,
    Vec<cuprate_types::rpc::PoolTxInfo>,
    ByteArrayVec<32>,
    ByteArrayVec<32>,
) {
    match pool_info {
        PoolInfo::None => (
            PoolInfoExtent::None.to_u8(),
            vec![],
            ByteArrayVec::default(),
            ByteArrayVec::default(),
        ),
        PoolInfo::Incremental(pool_info) => (
            PoolInfoExtent::Incremental.to_u8(),
            pool_info.added_pool_txs,
            pool_info.remaining_added_pool_txids,
            pool_info.removed_pool_txids,
        ),
        PoolInfo::Full(pool_info) => (
            PoolInfoExtent::Full.to_u8(),
            pool_info.added_pool_txs,
            pool_info.remaining_added_pool_txids,
            ByteArrayVec::default(),
        ),
    }
}

pub(crate) async fn capped_block_complete_entries(
    state: &mut CupratedRpcHandler,
    response_start_height: usize,
    chain_height: usize,
    block_count: usize,
    prune: bool,
    max_response_bytes: usize,
    max_tx_count: usize,
) -> Result<Vec<BlockCompleteEntry>, Error> {
    let (blocks, _) = capped_block_complete_entries_with_metrics(
        state,
        response_start_height,
        chain_height,
        block_count,
        prune,
        max_response_bytes,
        max_tx_count,
    )
    .await?;
    Ok(blocks)
}

pub(crate) async fn capped_block_complete_entries_with_metrics(
    state: &mut CupratedRpcHandler,
    response_start_height: usize,
    chain_height: usize,
    block_count: usize,
    prune: bool,
    max_response_bytes: usize,
    max_tx_count: usize,
) -> Result<(Vec<BlockCompleteEntry>, BlockFetchMetrics), Error> {
    let mut blocks = Vec::new();
    let mut metrics = BlockFetchMetrics::default();
    let mut response_bytes = 0_usize;
    let mut tx_count = 0_usize;
    let mut next_height = response_start_height;
    let end_height = response_start_height
        .saturating_add(block_count)
        .min(chain_height);

    while next_height < end_height {
        let t_heights = Instant::now();
        let batch_end = next_height
            .saturating_add(GET_BLOCKS_BIN_FETCH_BATCH)
            .min(end_height);
        let heights = (next_height..batch_end).map(usize_to_u64).collect();
        metrics.height_vector_ms += t_heights.elapsed().as_secs_f64() * 1000.0;
        metrics.batch_count += 1;
        let t_database = Instant::now();
        let batch = if prune {
            blockchain::block_complete_entries_by_height_pruned(&mut state.blockchain_read, heights)
                .await?
        } else {
            blockchain::block_complete_entries_by_height(&mut state.blockchain_read, heights)
                .await?
        };
        metrics.database_ms += t_database.elapsed().as_secs_f64() * 1000.0;

        let t_collect = Instant::now();
        for block in batch {
            let block_response_bytes = block_response_bytes(&block);
            let block_tx_count = block.txs.len();

            if !blocks.is_empty()
                && (response_bytes.saturating_add(block_response_bytes) > max_response_bytes
                    || tx_count.saturating_add(block_tx_count) > max_tx_count)
            {
                metrics.cap_and_collect_ms += t_collect.elapsed().as_secs_f64() * 1000.0;
                metrics.returned_blocks = blocks.len();
                metrics.returned_txs = tx_count;
                metrics.estimated_response_bytes = response_bytes;
                metrics.limited_by_response_size =
                    response_bytes.saturating_add(block_response_bytes) > max_response_bytes;
                metrics.limited_by_tx_count =
                    tx_count.saturating_add(block_tx_count) > max_tx_count;
                return Ok((blocks, metrics));
            }

            response_bytes = response_bytes.saturating_add(block_response_bytes);
            tx_count = tx_count.saturating_add(block_tx_count);
            blocks.push(block);
        }
        metrics.cap_and_collect_ms += t_collect.elapsed().as_secs_f64() * 1000.0;

        next_height = batch_end;
    }

    metrics.returned_blocks = blocks.len();
    metrics.returned_txs = tx_count;
    metrics.estimated_response_bytes = response_bytes;
    Ok((blocks, metrics))
}

/// Construct one wallet-sync response range directly from height-ordered
/// blockchain tables. This is the 1B fast path: it avoids reparsing blocks to
/// recover transaction hashes and avoids the `TxIds` hash-to-ID lookup table.
/// The returned blocks and index vectors remain wire-compatible with the
/// ordinary `/get_blocks.bin` response.
pub(crate) async fn capped_wallet_scan_range_with_metrics(
    state: &mut CupratedRpcHandler,
    response_start_height: usize,
    chain_height: usize,
    block_count: usize,
    prune: bool,
    no_miner_tx: bool,
    max_response_bytes: usize,
    max_tx_count: usize,
) -> Result<
    (
        Vec<BlockCompleteEntry>,
        Vec<BlockOutputIndices>,
        BlockFetchMetrics,
        OutputIndicesMetrics,
        bool,
    ),
    Error,
> {
    let end_height = response_start_height
        .saturating_add(block_count)
        .min(chain_height);
    let t_database = Instant::now();
    let range = blockchain::wallet_scan_range(
        &mut state.blockchain_read,
        response_start_height,
        end_height,
        prune,
    )
    .await?;
    let used_ordered_ranges = range.used_ordered_ranges;
    let database_ms = t_database.elapsed().as_secs_f64() * 1000.0;

    let mut fetch_metrics = BlockFetchMetrics {
        batch_count: 1,
        database_ms,
        ..BlockFetchMetrics::default()
    };
    let mut index_metrics = OutputIndicesMetrics {
        blocks: range.blocks.len(),
        ..OutputIndicesMetrics::default()
    };
    let mut blocks = Vec::with_capacity(range.blocks.len());
    let mut output_indices = Vec::with_capacity(range.blocks.len());
    let mut response_bytes = 0_usize;
    let mut tx_count = 0_usize;
    let t_collect = Instant::now();

    for (block, raw_indices) in range.blocks.into_iter().zip(range.output_indices) {
        let block_response_bytes = block_response_bytes(&block);
        let block_tx_count = block.txs.len();
        if !blocks.is_empty()
            && (response_bytes.saturating_add(block_response_bytes) > max_response_bytes
                || tx_count.saturating_add(block_tx_count) > max_tx_count)
        {
            fetch_metrics.limited_by_response_size =
                response_bytes.saturating_add(block_response_bytes) > max_response_bytes;
            fetch_metrics.limited_by_tx_count =
                tx_count.saturating_add(block_tx_count) > max_tx_count;
            break;
        }

        let mut per_block = Vec::with_capacity(raw_indices.len());
        for (position, indices) in raw_indices.into_iter().enumerate() {
            if no_miner_tx && position == 0 {
                per_block.push(TxOutputIndices { indices: vec![] });
            } else {
                index_metrics.transactions = index_metrics.transactions.saturating_add(1);
                index_metrics.output_index_values = index_metrics
                    .output_index_values
                    .saturating_add(indices.len());
                per_block.push(TxOutputIndices { indices });
            }
        }

        response_bytes = response_bytes.saturating_add(block_response_bytes);
        tx_count = tx_count.saturating_add(block_tx_count);
        blocks.push(block);
        output_indices.push(BlockOutputIndices { indices: per_block });
    }

    fetch_metrics.cap_and_collect_ms = t_collect.elapsed().as_secs_f64() * 1000.0;
    fetch_metrics.returned_blocks = blocks.len();
    fetch_metrics.returned_txs = tx_count;
    fetch_metrics.estimated_response_bytes = response_bytes;
    index_metrics.reconstruct_ms = fetch_metrics.cap_and_collect_ms;

    Ok((
        blocks,
        output_indices,
        fetch_metrics,
        index_metrics,
        used_ordered_ranges,
    ))
}

fn block_response_bytes(block: &BlockCompleteEntry) -> usize {
    let tx_bytes = match &block.txs {
        TransactionBlobs::Pruned(txs) => txs
            .iter()
            .map(|tx| tx.blob.len().saturating_add(32))
            .sum::<usize>(),
        TransactionBlobs::Normal(txs) => txs.iter().map(bytes::Bytes::len).sum::<usize>(),
        TransactionBlobs::None => 0,
    };

    block
        .block
        .len()
        .saturating_add(tx_bytes)
        .saturating_add(256)
}

pub(crate) async fn output_indices_for_blocks(
    state: &mut CupratedRpcHandler,
    blocks: &[BlockCompleteEntry],
    no_miner_tx: bool,
) -> Result<Vec<BlockOutputIndices>, Error> {
    let (output_indices, _) =
        output_indices_for_blocks_with_metrics(state, blocks, no_miner_tx).await?;
    Ok(output_indices)
}

pub(crate) async fn output_indices_for_blocks_with_metrics(
    state: &mut CupratedRpcHandler,
    blocks: &[BlockCompleteEntry],
    no_miner_tx: bool,
) -> Result<(Vec<BlockOutputIndices>, OutputIndicesMetrics), Error> {
    let t_idx = Instant::now();
    let mut metrics = OutputIndicesMetrics {
        blocks: blocks.len(),
        ..OutputIndicesMetrics::default()
    };

    // Parse all blocks and collect all tx hashes for a single batch lookup
    let mut all_blocks_parsed = Vec::with_capacity(blocks.len());
    let mut all_tx_hashes: Vec<[u8; 32]> = Vec::new();

    for block in blocks {
        let parsed_block = Block::read(&mut block.block.as_ref())?;
        if !no_miner_tx {
            all_tx_hashes.push(parsed_block.miner_transaction().hash());
        }
        for tx_hash in &parsed_block.transactions {
            all_tx_hashes.push(*tx_hash);
        }
        all_blocks_parsed.push(parsed_block);
    }

    let total_txs = all_tx_hashes.len();
    metrics.transactions = total_txs;
    metrics.parse_ms = t_idx.elapsed().as_secs_f64() * 1000.0;
    eprintln!(
        "[TIMING] index_parse: {:.1}ms ({} blocks, {} txs)",
        t_idx.elapsed().as_secs_f64() * 1000.0,
        blocks.len(),
        total_txs
    );

    // Single batch DB lookup for all output indices
    let t_db = Instant::now();
    let all_indices =
        blockchain::tx_output_indexes_batch(&mut state.blockchain_read, all_tx_hashes).await?;
    metrics.database_ms = t_db.elapsed().as_secs_f64() * 1000.0;
    eprintln!(
        "[TIMING] index_db_batch: {:.1}ms ({} lookups)",
        t_db.elapsed().as_secs_f64() * 1000.0,
        total_txs
    );

    // Reconstruct per-block output indices
    let t_reconstruct = Instant::now();
    let mut idx = 0;
    let mut output_indices = Vec::with_capacity(blocks.len());
    for parsed_block in &all_blocks_parsed {
        let mut block_indices = Vec::with_capacity(parsed_block.transactions.len() + 1);

        if no_miner_tx {
            block_indices.push(TxOutputIndices { indices: vec![] });
        } else {
            block_indices.push(TxOutputIndices {
                indices: all_indices[idx].clone(),
            });
            idx += 1;
        }

        for _ in &parsed_block.transactions {
            block_indices.push(TxOutputIndices {
                indices: all_indices[idx].clone(),
            });
            idx += 1;
        }

        output_indices.push(BlockOutputIndices {
            indices: block_indices,
        });
    }
    metrics.reconstruct_ms = t_reconstruct.elapsed().as_secs_f64() * 1000.0;
    metrics.output_index_values = all_indices.iter().map(Vec::len).sum();

    eprintln!(
        "[TIMING] index_total: {:.1}ms",
        t_idx.elapsed().as_secs_f64() * 1000.0
    );
    Ok((output_indices, metrics))
}

/// <https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454/src/rpc/core_rpc_server.cpp#L817-L857>
async fn get_blocks_by_height(
    mut state: CupratedRpcHandler,
    request: GetBlocksByHeightRequest,
) -> Result<GetBlocksByHeightResponse, Error> {
    if state.is_restricted() && request.heights.len() > RESTRICTED_BLOCK_COUNT {
        return Err(anyhow!("Too many blocks requested in restricted mode"));
    }

    let blocks =
        blockchain::block_complete_entries_by_height(&mut state.blockchain_read, request.heights)
            .await?;

    Ok(GetBlocksByHeightResponse {
        base: helper::access_response_base(false),
        blocks,
    })
}

/// <https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454/src/rpc/core_rpc_server.cpp#L859-L880>
async fn get_hashes(
    mut state: CupratedRpcHandler,
    request: GetHashesRequest,
) -> Result<GetHashesResponse, Error> {
    use cuprate_types::Chain;
    let t_total = Instant::now();
    eprintln!(
        "[RPC] GetHashes: block_ids.len()={}, start_height={}",
        request.block_ids.len(),
        request.start_height
    );
    let GetHashesRequest {
        start_height,
        block_ids,
    } = request;

    // PARALLEL FAST REFRESH: empty block_ids + start_height > 0 → bulk range lookup
    if block_ids.len() == 0 && start_height > 0 {
        use cuprate_types::blockchain::BlockchainReadRequest;
        use cuprate_types::blockchain::BlockchainResponse;
        use tower::{Service, ServiceExt};

        let t_chain_height = Instant::now();
        let (tip_height, _) = blockchain::chain_height(&mut state.blockchain_read).await?;
        let chain_height_ms = t_chain_height.elapsed().as_secs_f64() * 1000.0;
        if start_height >= tip_height {
            return Ok(GetHashesResponse {
                base: helper::access_response_base(false),
                m_block_ids: vec![].into(),
                current_height: tip_height,
                start_height,
            });
        }
        // 100k hashes = 3.2MB — way under 50MB content limit and 10× fewer round-trips
        const HASH_BATCH_MAX: u64 = 100_000;
        let count = (tip_height - start_height).min(HASH_BATCH_MAX);
        let start = u64_to_usize(start_height);
        let end = start + u64_to_usize(count);

        // Single service call, server-side LMDB batch read (parallelised via rayon)
        let t_range = Instant::now();
        let BlockchainResponse::BlockHashInRange(hashes) = state
            .blockchain_read
            .ready()
            .await?
            .call(BlockchainReadRequest::BlockHashInRange(
                start..end,
                Chain::Main,
            ))
            .await?
        else {
            return Err(anyhow!("unexpected blockchain response"));
        };
        let range_ms = t_range.elapsed().as_secs_f64() * 1000.0;

        eprintln!(
            "[RPC] GetHashes DIRECT-BULK: h={} count={} actual={} total_ms={:.1}",
            start_height,
            count,
            hashes.len(),
            t_total.elapsed().as_secs_f64() * 1000.0
        );
        eprintln!(
            "[SYNC_TRACE_SERVER_BIN_HASH] mode=direct_bulk start={} requested={} hashes={} chain_height_ms={:.3} range_db_ms={:.3} total_ms={:.3}",
            start_height,
            count,
            hashes.len(),
            chain_height_ms,
            range_ms,
            t_total.elapsed().as_secs_f64() * 1000.0,
        );
        return Ok(GetHashesResponse {
            base: helper::access_response_base(false),
            m_block_ids: hashes.into(),
            current_height: tip_height,
            start_height,
        });
    }

    // FIXME: impl `last()`
    let last = {
        let len = block_ids.len();

        if len == 0 {
            return Err(anyhow!("block_ids empty"));
        }

        block_ids[len - 1]
    };

    let hashes: Vec<[u8; 32]> = (&block_ids).into();

    let hash_count = hashes.len();
    let t_chain = Instant::now();
    let (m_block_ids, first_known_height, current_height) = blockchain::next_chain_entry(
        &mut state.blockchain_read,
        hashes,
        GET_BLOCKS_BIN_MAX_BLOCK_COUNT,
    )
    .await?;
    let chain_lookup_ms = t_chain.elapsed().as_secs_f64() * 1000.0;
    eprintln!(
        "[RPC] GetHashes: got {} hashes, first_known={:?}, current_height={}",
        m_block_ids.len(),
        first_known_height,
        current_height
    );
    let first_known_height =
        first_known_height.ok_or_else(|| anyhow!("Block IDs were not sorted properly"))?;

    eprintln!(
        "[RPC] GetHashes: responding with {} hashes, start_height={} total_ms={:.1}",
        m_block_ids.len(),
        first_known_height,
        t_total.elapsed().as_secs_f64() * 1000.0
    );
    eprintln!(
        "[SYNC_TRACE_SERVER_BIN_HASH] mode=chain_match request_hashes={} response_hashes={} start={} chain_lookup_ms={:.3} total_ms={:.3}",
        hash_count,
        m_block_ids.len(),
        first_known_height,
        chain_lookup_ms,
        t_total.elapsed().as_secs_f64() * 1000.0,
    );
    Ok(GetHashesResponse {
        base: helper::access_response_base(false),
        m_block_ids: m_block_ids.into(),
        current_height: usize_to_u64(current_height),
        start_height: usize_to_u64(first_known_height),
    })
}

/// <https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454/src/rpc/core_rpc_server.cpp#L959-L977>
async fn get_output_indexes(
    mut state: CupratedRpcHandler,
    request: GetOutputIndexesRequest,
) -> Result<GetOutputIndexesResponse, Error> {
    Ok(GetOutputIndexesResponse {
        base: helper::access_response_base(false),
        o_indexes: blockchain::tx_output_indexes(&mut state.blockchain_read, request.txid).await?,
    })
}

/// <https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454/src/rpc/core_rpc_server.cpp#L882-L910>
async fn get_outs(
    state: CupratedRpcHandler,
    request: GetOutsRequest,
) -> Result<GetOutsResponse, Error> {
    shared::get_outs(state, request).await
}

/// <https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454/src/rpc/core_rpc_server.cpp#L1689-L1711>
async fn get_transaction_pool_hashes(
    mut state: CupratedRpcHandler,
    _: GetTransactionPoolHashesRequest,
) -> Result<GetTransactionPoolHashesResponse, Error> {
    Ok(GetTransactionPoolHashesResponse {
        base: helper::access_response_base(false),
        tx_hashes: shared::get_transaction_pool_hashes(state)
            .await
            .map(ByteArrayVec::from)?,
    })
}

/// <https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454/src/rpc/core_rpc_server.cpp#L3352-L3398>
async fn get_output_distribution(
    state: CupratedRpcHandler,
    request: GetOutputDistributionRequest,
) -> Result<GetOutputDistributionResponse, Error> {
    shared::get_output_distribution(state, request).await
}
