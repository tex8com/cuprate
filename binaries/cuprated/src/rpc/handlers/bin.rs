//! RPC request handler functions (binary endpoints).
//!
//! TODO:
//! Some handlers have `todo!()`s for other Cuprate internals that must be completed, see:
//! <https://github.com/Cuprate/cuprate/pull/355>

use std::num::NonZero;
use std::time::Instant;

use anyhow::{anyhow, Error};
use cuprate_constants::rpc::{
    GET_BLOCKS_BIN_MAX_BLOCK_COUNT, GET_BLOCKS_BIN_MAX_TX_COUNT, RESTRICTED_BLOCK_COUNT,
    RESTRICTED_TRANSACTIONS_COUNT,
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
use monero_oxide::block::Block;

use crate::rpc::{
    handlers::{helper, shared, shared::not_available},
    service::{blockchain, txpool},
    CupratedRpcHandler,
};

const GET_BLOCKS_BIN_MAX_RESPONSE_BYTES: usize = 50 * 1024 * 1024;
const GET_BLOCKS_BIN_FETCH_BATCH: usize = 1000;

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

    let max_blocks = if max_block_count == 0 {
        GET_BLOCKS_BIN_MAX_BLOCK_COUNT
    } else {
        max_block_count.min(GET_BLOCKS_BIN_MAX_BLOCK_COUNT)
    };

    let (_, first_known_height, chain_height) =
        blockchain::next_chain_entry(&mut state.blockchain_read, block_hashes, 1).await?;

    let Some(first_known_height) = first_known_height else {
        return Err(anyhow!("Block IDs were not sorted properly"));
    };

    let response_start_height = if start_height > 0 {
        u64_to_usize(start_height)
    } else {
        first_known_height
    };

    let block_count = chain_height
        .saturating_sub(response_start_height)
        .min(u64_to_usize(max_blocks));

    let t_blocks = Instant::now();
    let blocks =
        capped_block_complete_entries(&mut state, response_start_height, chain_height, block_count, prune)
            .await?;
    eprintln!("[RPC] GetBlocks: {} blocks, pruned={}, start={}, current_height={}", blocks.len(), prune, response_start_height, usize_to_u64(chain_height));
    eprintln!("[TIMING] block_fetch: {:.1}ms ({} blocks)", t_blocks.elapsed().as_secs_f64() * 1000.0, blocks.len());
    let t_oi = Instant::now();
    let output_indices = output_indices_for_blocks(&mut state, &blocks, no_miner_tx).await?;
    eprintln!("[TIMING] output_indices_total: {:.1}ms", t_oi.elapsed().as_secs_f64() * 1000.0);

    Ok(GetBlocksResponse {
        blocks,
        start_height: usize_to_u64(response_start_height),
        current_height: usize_to_u64(chain_height),
        output_indices,
        ..resp
    })
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

async fn capped_block_complete_entries(
    state: &mut CupratedRpcHandler,
    response_start_height: usize,
    chain_height: usize,
    block_count: usize,
    prune: bool,
) -> Result<Vec<BlockCompleteEntry>, Error> {
    let mut blocks = Vec::new();
    let mut response_bytes = 0_usize;
    let mut tx_count = 0_usize;
    let mut next_height = response_start_height;
    let end_height = response_start_height
        .saturating_add(block_count)
        .min(chain_height);
    let max_tx_count = u64_to_usize(GET_BLOCKS_BIN_MAX_TX_COUNT);

    while next_height < end_height {
        let batch_end = next_height
            .saturating_add(GET_BLOCKS_BIN_FETCH_BATCH)
            .min(end_height);
        let heights = (next_height..batch_end).map(usize_to_u64).collect();
        let batch = if prune {
                blockchain::block_complete_entries_by_height_pruned(&mut state.blockchain_read, heights)
                    .await?
            } else {
                blockchain::block_complete_entries_by_height(&mut state.blockchain_read, heights)
                    .await?
            };

        for block in batch {
            let block_response_bytes = block_response_bytes(&block);
            let block_tx_count = block.txs.len();

            if !blocks.is_empty()
                && (response_bytes.saturating_add(block_response_bytes)
                    > GET_BLOCKS_BIN_MAX_RESPONSE_BYTES
                    || tx_count.saturating_add(block_tx_count) > max_tx_count)
            {
                return Ok(blocks);
            }

            response_bytes = response_bytes.saturating_add(block_response_bytes);
            tx_count = tx_count.saturating_add(block_tx_count);
                        blocks.push(block);
        }

        next_height = batch_end;
    }

    Ok(blocks)
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

async fn output_indices_for_blocks(
    state: &mut CupratedRpcHandler,
    blocks: &[BlockCompleteEntry],
    no_miner_tx: bool,
) -> Result<Vec<BlockOutputIndices>, Error> {
    let t_idx = Instant::now();

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
    eprintln!("[TIMING] index_parse: {:.1}ms ({} blocks, {} txs)", t_idx.elapsed().as_secs_f64() * 1000.0, blocks.len(), total_txs);

    // Single batch DB lookup for all output indices
    let t_db = Instant::now();
    let all_indices = blockchain::tx_output_indexes_batch(
        &mut state.blockchain_read,
        all_tx_hashes,
    ).await?;
    eprintln!("[TIMING] index_db_batch: {:.1}ms ({} lookups)", t_db.elapsed().as_secs_f64() * 1000.0, total_txs);

    // Reconstruct per-block output indices
    let mut idx = 0;
    let mut output_indices = Vec::with_capacity(blocks.len());
    for parsed_block in &all_blocks_parsed {
        let mut block_indices = Vec::with_capacity(parsed_block.transactions.len() + 1);

        if no_miner_tx {
            block_indices.push(TxOutputIndices { indices: vec![] });
        } else {
            block_indices.push(TxOutputIndices { indices: all_indices[idx].clone() });
            idx += 1;
        }

        for _ in &parsed_block.transactions {
            block_indices.push(TxOutputIndices { indices: all_indices[idx].clone() });
            idx += 1;
        }

        output_indices.push(BlockOutputIndices { indices: block_indices });
    }

    eprintln!("[TIMING] index_total: {:.1}ms", t_idx.elapsed().as_secs_f64() * 1000.0);
    Ok(output_indices)
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
    eprintln!("[RPC] GetHashes: block_ids.len()={}, start_height={}", request.block_ids.len(), request.start_height);
    let GetHashesRequest {
        start_height,
        block_ids,
    } = request;

    // FIXME: impl `last()`
    let last = {
        let len = block_ids.len();

        if len == 0 {
            return Err(anyhow!("block_ids empty"));
        }

        block_ids[len - 1]
    };

    let hashes: Vec<[u8; 32]> = (&block_ids).into();

    let (m_block_ids, first_known_height, current_height) = blockchain::next_chain_entry(
        &mut state.blockchain_read,
        hashes,
        GET_BLOCKS_BIN_MAX_BLOCK_COUNT,
    )
    .await?;
    eprintln!("[RPC] GetHashes: got {} hashes, first_known={:?}, current_height={}", m_block_ids.len(), first_known_height, current_height);
    let first_known_height =
        first_known_height.ok_or_else(|| anyhow!("Block IDs were not sorted properly"))?;

    eprintln!("[RPC] GetHashes: responding with {} hashes, start_height={}", m_block_ids.len(), first_known_height);
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
