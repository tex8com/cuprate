//! gRPC streaming RPC for high-throughput wallet sync.
//!
//! Server-streaming endpoint that pushes blocks at the speed the backend
//! produces them, throttled by HTTP/2 flow control. Coexists with the
//! legacy bin RPC; opt-in via a separate port (see [`crate::rpc::server`]).
//!
//! Each chunk's `payload` is the same epee-serialized `GetBlocksResponse`
//! the bin RPC returns — the wallet decodes it with its existing parser,
//! so no new payload deserializer is needed on the wallet side. The
//! protobuf layer is purely the envelope that gives us HTTP/2 multiplexing
//! plus server-streaming.

use std::pin::Pin;
use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::Error;
use cuprate_epee_encoding::to_bytes;
use cuprate_fixed_bytes::ByteArrayVec;
use cuprate_helper::cast::{u64_to_usize, usize_to_u64};
use cuprate_rpc_types::bin::GetBlocksResponse;
use cuprate_types::{
    BlockCompleteEntry,
    rpc::{BlockOutputIndices, PoolInfoExtent},
};
use futures::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::rpc::{
    handlers::{bin as bin_handlers, helper as bin_helper},
    CupratedRpcHandler,
};
use crate::config::WalletScanCacheConfig;

#[allow(
    clippy::unnecessary_qualifications,
    clippy::needless_lifetimes,
    clippy::derive_partial_eq_without_eq,
    clippy::wildcard_imports,
    clippy::missing_const_for_fn,
    clippy::default_trait_access,
    clippy::doc_markdown,
    clippy::ref_option,
    clippy::redundant_pub_crate,
    clippy::semicolon_if_nothing_returned,
    clippy::trivially_copy_pass_by_ref,
    clippy::use_self,
    clippy::uninlined_format_args,
    clippy::cast_lossless,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::elidable_lifetime_names,
    clippy::needless_pass_by_value,
    clippy::too_many_arguments,
    clippy::pedantic,
    clippy::nursery,
    clippy::style,
    clippy::complexity,
    clippy::perf,
    clippy::correctness,
    clippy::suspicious,
    clippy::restriction,
    missing_docs,
    unused_qualifications
)]
pub mod proto {
    tonic::include_proto!("cuprate.stream.v1");
}

use proto::block_stream_server::{BlockStream, BlockStreamServer};
use proto::{BlockChunk, StreamBlocksRequest};

const DEFAULT_CHUNK_BLOCKS: usize = 200;
const MIN_CHUNK_BLOCKS: usize = 16;
const MAX_CHUNK_BLOCKS: usize = 10000;
const MAX_GRPC_CHUNK_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
const MAX_GRPC_CHUNK_TX_COUNT: usize = 1_000_000;
pub const MAX_GRPC_MESSAGE_BYTES: usize = 1024 * 1024 * 1024;
pub const GRPC_HTTP2_STREAM_WINDOW_BYTES: u32 = 512 * 1024 * 1024;
pub const GRPC_HTTP2_CONNECTION_WINDOW_BYTES: u32 = 512 * 1024 * 1024;

/// mpsc capacity between producer task and HTTP/2 send loop. Small on
/// purpose in production, but high-throughput wallet restore tests need enough
/// room to absorb scanner stalls without immediately stalling HTTP/2.
const CHANNEL_CAPACITY: usize = 32;

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static ACTIVE_STREAMS: AtomicU64 = AtomicU64::new(0);

fn stream_pipeline_depth() -> usize {
    static DEPTH: OnceLock<usize> = OnceLock::new();
    *DEPTH.get_or_init(|| {
        std::env::var("CUPRATE_SYNC_PIPELINE_DEPTH")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(1)
            // The first variant intentionally has one fetch ahead. Wider
            // pipelines are enabled only after the depth-2 measurement.
            .clamp(1, 2)
    })
}

fn sync_range_reads_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        matches!(
            std::env::var("CUPRATE_SYNC_RANGE_READS")
                .as_deref()
                .map(str::trim),
            Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
        )
    })
}

struct FetchedChunk {
    top_h: u64,
    chain_height: usize,
    target_end: usize,
    start: usize,
    blocks: Vec<BlockCompleteEntry>,
    top_ms: f64,
    fetch_ms: f64,
    fetch_metrics: bin_handlers::BlockFetchMetrics,
    prepared_output_indices: Option<Vec<BlockOutputIndices>>,
    prepared_index_metrics: Option<bin_handlers::OutputIndicesMetrics>,
    range_read: bool,
    scanpack_hit: bool,
}

struct IndexedChunk {
    fetched: FetchedChunk,
    output_indices: Vec<BlockOutputIndices>,
    idx_ms: f64,
    index_metrics: bin_handlers::OutputIndicesMetrics,
}

#[derive(Clone)]
pub struct BlockStreamService {
    pub handler: CupratedRpcHandler,
}

#[tonic::async_trait]
impl BlockStream for BlockStreamService {
    type StreamBlocksStream =
        Pin<Box<dyn Stream<Item = Result<BlockChunk, Status>> + Send + 'static>>;

    async fn stream_blocks(
        &self,
        request: Request<StreamBlocksRequest>,
    ) -> Result<Response<Self::StreamBlocksStream>, Status> {
        let StreamBlocksRequest {
            start_height,
            stop_height,
            prune,
            chunk_blocks_hint,
            no_miner_tx,
            client_request_id,
        } = request.into_inner();

        let counter_id = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let server_req_id = format!("grpc-{counter_id}");
        let client_id_label = if client_request_id.is_empty() {
            "<none>".to_string()
        } else {
            client_request_id
        };

        let chunk_blocks = match chunk_blocks_hint {
            0 => DEFAULT_CHUNK_BLOCKS,
            n => (n as usize).clamp(MIN_CHUNK_BLOCKS, MAX_CHUNK_BLOCKS),
        };

        let active = ACTIVE_STREAMS.fetch_add(1, Ordering::SeqCst) + 1;
        let open_epoch_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);

        eprintln!(
            "[GRPC StreamBlocks] OPEN id={} client_req_id={} start={} stop={} prune={} no_miner_tx={} chunk_blocks={} max_chunk_bytes={} max_chunk_txs={} range_reads={} pipeline_depth={} active_streams={} open_epoch_ms={}",
            server_req_id, client_id_label, start_height, stop_height, prune, no_miner_tx,
            chunk_blocks, MAX_GRPC_CHUNK_RESPONSE_BYTES, MAX_GRPC_CHUNK_TX_COUNT,
            sync_range_reads_enabled(), stream_pipeline_depth(), active,
            open_epoch_ms,
        );

        let (tx, rx) = mpsc::channel::<Result<BlockChunk, Status>>(CHANNEL_CAPACITY);
        let mut handler = self.handler.clone();
        let id_for_task = server_req_id.clone();
        let id_for_close = server_req_id.clone();

        tokio::spawn(async move {
            let r = produce_block_stream(
                &mut handler,
                tx,
                start_height,
                stop_height,
                prune,
                chunk_blocks,
                no_miner_tx,
                &id_for_task,
            )
            .await;
            let active_after = ACTIVE_STREAMS.fetch_sub(1, Ordering::SeqCst) - 1;
            if let Err(e) = r {
                eprintln!(
                    "[GRPC StreamBlocks] CLOSE_ERR id={} active_remaining={} err={:?}",
                    id_for_close, active_after, e
                );
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

/// Build missing scan packs without blocking RPC serving. Existing packs are
/// immutable; a positive `max_blocks` turns the directory into a moving window.
pub fn spawn_scanpack_builder(mut state: CupratedRpcHandler, config: WalletScanCacheConfig) {
    let Some(store) = state.wallet_scan_packs.clone() else { return; };
    if !config.build_on_start { return; }
    let chunk_blocks = config.chunk_blocks.clamp(MIN_CHUNK_BLOCKS, MAX_CHUNK_BLOCKS);
    tokio::spawn(async move {
        loop {
            let Ok((top_height, _)) = bin_helper::top_height(&mut state).await else {
                eprintln!("[SCANPACK] unable to obtain chain tip; retrying");
                tokio::time::sleep(std::time::Duration::from_secs(config.build_poll_seconds.max(1))).await;
                continue;
            };
            let end = top_height.saturating_add(1);
            let start = if config.max_blocks < 0 {
                config.start_height.min(end)
            } else {
                end.saturating_sub(config.max_blocks as u64).max(config.start_height)
            };
            match store.remove_before(start) {
                Ok(removed) if removed > 0 => eprintln!("[SCANPACK] evicted {removed} packs below height {start}"),
                Ok(_) => (),
                Err(error) => eprintln!("[SCANPACK] eviction error: {error:#}"),
            }
            let mut height = start;
            let mut built = 0_u64;
            while height < end {
                if let Ok(Some(existing_end)) = store.covering_end(height) {
                    height = existing_end;
                    continue;
                }
                let count = usize::try_from(end.saturating_sub(height)).unwrap_or(usize::MAX).min(chunk_blocks);
                match bin_handlers::capped_wallet_scan_range_with_metrics(
                    &mut state, usize::try_from(height).unwrap(), usize::try_from(end).unwrap(), count,
                    true, false, MAX_GRPC_CHUNK_RESPONSE_BYTES, MAX_GRPC_CHUNK_TX_COUNT,
                ).await {
                    Ok((blocks, output_indices, _, _, _)) => match crate::rpc::scanpack::ScanPack::new(height, blocks, output_indices).and_then(|pack| store.write(&pack)) {
                        Ok(()) => { built += 1; height = height.saturating_add(u64::try_from(count).unwrap()); if built % 16 == 0 { eprintln!("[SCANPACK] built {built} packs; next_height={height} tip={end}"); } }
                        Err(error) => { eprintln!("[SCANPACK] write error at height {height}: {error:#}"); break; }
                    },
                    Err(error) => { eprintln!("[SCANPACK] build error at height {height}: {error:#}"); break; }
                }
                tokio::task::yield_now().await;
            }
            if built > 0 { eprintln!("[SCANPACK] pass complete: built={built} covered_until={height} tip={end}"); }
            tokio::time::sleep(std::time::Duration::from_secs(config.build_poll_seconds.max(1))).await;
        }
    });
}

async fn fetch_chunk(
    mut state: CupratedRpcHandler,
    start: usize,
    stop_height: u64,
    chunk_blocks: usize,
    prune: bool,
    no_miner_tx: bool,
) -> Result<Option<FetchedChunk>, Error> {
    let t_top = Instant::now();
    let (top_h, _) = bin_helper::top_height(&mut state).await?;
    let top_ms = t_top.elapsed().as_secs_f64() * 1000.0;
    let chain_height = u64_to_usize(top_h) + 1;
    let target_end = if stop_height == 0 {
        chain_height
    } else {
        (u64_to_usize(stop_height) + 1).min(chain_height)
    };

    if start >= target_end {
        return Ok(None);
    }

    let mut want = chunk_blocks.min(target_end - start);
    // Do not let a legacy response cross into the first cached height. The
    // following request will start exactly at the ScanPack boundary.
    if let Some(cache_start) = state
        .wallet_scan_packs
        .as_ref()
        .and_then(|store| store.cache_start_height())
    {
        if u64::try_from(start)? < cache_start
            && cache_start < u64::try_from(start.saturating_add(want))?
        {
            want = usize::try_from(cache_start)?.saturating_sub(start);
        }
    }
    let t_fetch = Instant::now();
    if let Some(store) = &state.wallet_scan_packs {
        if let Some(pack) = store.load_covering(u64::try_from(start)?, want)? {
            let block_count = pack.blocks.len();
            let tx_count = pack.blocks.iter().map(|block| block.txs.len()).sum();
            let index_values = pack.output_indices.iter().flat_map(|block| &block.indices)
                .map(|tx| tx.indices.len()).sum();
            return Ok(Some(FetchedChunk {
                top_h, chain_height, target_end, start, blocks: pack.blocks, top_ms,
                fetch_ms: t_fetch.elapsed().as_secs_f64() * 1000.0,
                fetch_metrics: bin_handlers::BlockFetchMetrics { returned_blocks: block_count, returned_txs: tx_count, ..Default::default() },
                prepared_output_indices: Some(pack.output_indices),
                prepared_index_metrics: Some(bin_handlers::OutputIndicesMetrics { blocks: block_count, transactions: tx_count, output_index_values: index_values, ..Default::default() }),
                range_read: false,
                scanpack_hit: true,
            }));
        }
    }
    let range_requested = sync_range_reads_enabled();
    let (blocks, fetch_metrics, prepared_output_indices, prepared_index_metrics, range_read) =
        if range_requested {
            let (blocks, output_indices, fetch_metrics, index_metrics, range_read) =
            bin_handlers::capped_wallet_scan_range_with_metrics(
                &mut state,
                start,
                chain_height,
                want,
                prune,
                no_miner_tx,
                MAX_GRPC_CHUNK_RESPONSE_BYTES,
                MAX_GRPC_CHUNK_TX_COUNT,
            )
            .await?;
            (
                blocks,
                fetch_metrics,
                Some(output_indices),
                Some(index_metrics),
                range_read,
            )
        } else {
            let (blocks, fetch_metrics) = bin_handlers::capped_block_complete_entries_with_metrics(
            &mut state,
            start,
            chain_height,
            want,
            prune,
            MAX_GRPC_CHUNK_RESPONSE_BYTES,
            MAX_GRPC_CHUNK_TX_COUNT,
        )
            .await?;
            (blocks, fetch_metrics, None, None, false)
        };

    Ok(Some(FetchedChunk {
        top_h,
        chain_height,
        target_end,
        start,
        blocks,
        top_ms,
        fetch_ms: t_fetch.elapsed().as_secs_f64() * 1000.0,
        fetch_metrics,
        prepared_output_indices,
        prepared_index_metrics,
        range_read,
        scanpack_hit: false,
    }))
}

async fn index_chunk(
    mut state: CupratedRpcHandler,
    mut fetched: FetchedChunk,
    no_miner_tx: bool,
) -> Result<IndexedChunk, Error> {
    if let (Some(output_indices), Some(index_metrics)) = (
        fetched.prepared_output_indices.take(),
        fetched.prepared_index_metrics.take(),
    ) {
        return Ok(IndexedChunk {
            fetched,
            output_indices,
            idx_ms: 0.0,
            index_metrics,
        });
    }
    let t_idx = Instant::now();
    let (output_indices, index_metrics) =
        bin_handlers::output_indices_for_blocks_with_metrics(
            &mut state,
            &fetched.blocks,
            no_miner_tx,
        )
        .await?;

    Ok(IndexedChunk {
        fetched,
        output_indices,
        idx_ms: t_idx.elapsed().as_secs_f64() * 1000.0,
        index_metrics,
    })
}

async fn produce_block_stream(
    state: &mut CupratedRpcHandler,
    tx: mpsc::Sender<Result<BlockChunk, Status>>,
    start_height: u64,
    stop_height: u64,
    prune: bool,
    chunk_blocks: usize,
    no_miner_tx: bool,
    server_req_id: &str,
) -> Result<(), Error> {
    let stream_t0 = Instant::now();
    let mut next_height = u64_to_usize(start_height);
    let mut chunk_seq: u64 = 0;
    let mut total_blocks: u64 = 0;
    let mut total_bytes: u64 = 0;
    let pipeline_depth = stream_pipeline_depth();
    let mut prefetched: Option<tokio::task::JoinHandle<Result<Option<FetchedChunk>, Error>>> =
        None;

    loop {
        let fetched = match prefetched.take() {
            Some(task) => task.await.map_err(|error| Error::msg(error.to_string()))??,
            None => {
                fetch_chunk(
                    state.clone(),
                    next_height,
                    stop_height,
                    chunk_blocks,
                    prune,
                    no_miner_tx,
                )
                .await?
            }
        };

        let Some(fetched) = fetched else {
            let total_ms = stream_t0.elapsed().as_secs_f64() * 1000.0;
            let avg_mbs = if total_ms > 0.0 {
                (total_bytes as f64 / 1024.0 / 1024.0) / (total_ms / 1000.0)
            } else {
                0.0
            };
            eprintln!(
                "[GRPC StreamBlocks] CLOSE id={} reason=tip_reached chunks={} blocks={} bytes={} total_ms={:.1} avg_mbs={:.2}",
                server_req_id, chunk_seq, total_blocks, total_bytes, total_ms, avg_mbs,
            );
            return Ok(());
        };

        let actual_blocks = fetched.blocks.len();

        if actual_blocks == 0 {
            eprintln!(
                "[GRPC StreamBlocks] CLOSE id={} reason=zero_blocks chunks={} blocks={} bytes={}",
                server_req_id, chunk_seq, total_blocks, total_bytes,
            );
            return Ok(());
        }

        let following_height = fetched.start + actual_blocks;
        if pipeline_depth == 2 && following_height < fetched.target_end {
            let state_for_prefetch = state.clone();
            prefetched = Some(tokio::spawn(async move {
                fetch_chunk(
                    state_for_prefetch,
                    following_height,
                    stop_height,
                    chunk_blocks,
                    prune,
                    no_miner_tx,
                )
                .await
            }));
        }

        let indexed = index_chunk(state.clone(), fetched, no_miner_tx).await?;
        let FetchedChunk {
            top_h,
            chain_height,
            start: response_start,
            blocks,
            top_ms,
            fetch_ms,
            fetch_metrics,
            range_read,
            scanpack_hit,
            ..
        } = indexed.fetched;
        let output_indices = indexed.output_indices;
        let idx_ms = indexed.idx_ms;
        let index_metrics = indexed.index_metrics;
        let response_start = usize_to_u64(response_start);
        let response_current = usize_to_u64(chain_height);

        let t_response = Instant::now();
        let resp = GetBlocksResponse {
            base: bin_helper::access_response_base(false),
            blocks,
            start_height: response_start,
            current_height: response_current,
            output_indices,
            daemon_time: cuprate_helper::time::current_unix_timestamp(),
            pool_info_extent: PoolInfoExtent::None.to_u8(),
            added_pool_txs: vec![],
            remaining_added_pool_txids: ByteArrayVec::default(),
            removed_pool_txids: ByteArrayVec::default(),
        };
        let response_build_ms = t_response.elapsed().as_secs_f64() * 1000.0;
        let t_enc = Instant::now();
        let payload_buf = match to_bytes(resp) {
            Ok(b) => b.freeze(),
            Err(e) => {
                eprintln!(
                    "[GRPC StreamBlocks] ENCODE_ERR id={} seq={} err={:?}",
                    server_req_id, chunk_seq, e
                );
                return Err(e.into());
            }
        };
        let enc_ms = t_enc.elapsed().as_secs_f64() * 1000.0;
        let payload_len = payload_buf.len();

        let queue_depth_before = CHANNEL_CAPACITY.saturating_sub(tx.capacity());
        let t_proto_copy = Instant::now();
        let chunk = BlockChunk {
            start_height: response_start,
            chunk_seq,
            chain_tip: top_h,
            server_request_id: server_req_id.to_string(),
            payload: payload_buf.to_vec(),
            n_blocks: actual_blocks as u32,
            payload_bytes: payload_len as u32,
        };
        let proto_copy_ms = t_proto_copy.elapsed().as_secs_f64() * 1000.0;

        let t_send = Instant::now();
        if tx.send(Ok(chunk)).await.is_err() {
            let total_ms = stream_t0.elapsed().as_secs_f64() * 1000.0;
            eprintln!(
                "[GRPC StreamBlocks] CLOSE id={} reason=client_disconnect chunks={} blocks={} bytes={} total_ms={:.1}",
                server_req_id, chunk_seq, total_blocks, total_bytes, total_ms,
            );
            return Ok(());
        }
        let send_ms = t_send.elapsed().as_secs_f64() * 1000.0;
        let queue_depth_after = CHANNEL_CAPACITY.saturating_sub(tx.capacity());

        total_blocks += actual_blocks as u64;
        total_bytes += payload_len as u64;
        let cum_ms = stream_t0.elapsed().as_secs_f64() * 1000.0;
        let cum_mbs = if cum_ms > 0.0 {
            (total_bytes as f64 / 1024.0 / 1024.0) / (cum_ms / 1000.0)
        } else {
            0.0
        };

        let upstream_ms = top_ms + fetch_ms + idx_ms + response_build_ms + enc_ms + proto_copy_ms;
        let bp_ratio = if upstream_ms > 1.0 {
            send_ms / upstream_ms
        } else {
            0.0
        };

        eprintln!(
            "[SYNC_TRACE_SERVER] id={} seq={} start={} n_blocks={} payload_bytes={} range_read={} scanpack_hit={} pipeline_depth={} top_ms={:.3} fetch_ms={:.3} fetch_batches={} fetch_heights_ms={:.3} fetch_db_ms={:.3} fetch_collect_ms={:.3} fetch_txs={} fetch_est_bytes={} fetch_limit_bytes={} fetch_limit_txs={} idx_ms={:.3} idx_parse_ms={:.3} idx_db_ms={:.3} idx_reconstruct_ms={:.3} idx_txs={} idx_values={} response_build_ms={:.3} epee_encode_ms={:.3} protobuf_copy_ms={:.3} queue_depth_before={} queue_depth_after={} queue_send_wait_ms={:.3} upstream_ms={:.3} bp_ratio={:.3} cum_ms={:.3} cum_bytes={} cum_mbs={:.3} chain_tip={}",
            server_req_id, chunk_seq, response_start, actual_blocks, payload_len,
            range_read, scanpack_hit, pipeline_depth,
            top_ms, fetch_ms, fetch_metrics.batch_count, fetch_metrics.height_vector_ms,
            fetch_metrics.database_ms, fetch_metrics.cap_and_collect_ms,
            fetch_metrics.returned_txs, fetch_metrics.estimated_response_bytes,
            fetch_metrics.limited_by_response_size, fetch_metrics.limited_by_tx_count,
            idx_ms, index_metrics.parse_ms, index_metrics.database_ms,
            index_metrics.reconstruct_ms, index_metrics.transactions,
            index_metrics.output_index_values, response_build_ms, enc_ms, proto_copy_ms,
            queue_depth_before, queue_depth_after, send_ms, upstream_ms, bp_ratio,
            cum_ms, total_bytes, cum_mbs, top_h,
        );

        if bp_ratio > 2.0 {
            eprintln!(
                "[GRPC StreamBlocks] BACKPRESSURE id={} seq={} send_ms={:.1} upstream_ms={:.1} ratio={:.2} -- client slower than server",
                server_req_id, chunk_seq, send_ms, upstream_ms, bp_ratio,
            );
        }

        chunk_seq += 1;
        next_height += actual_blocks;
    }
}

/// Build the tonic gRPC service ready to be added to a tonic Server.
pub fn block_stream_service(handler: CupratedRpcHandler) -> BlockStreamServer<BlockStreamService> {
    BlockStreamServer::new(BlockStreamService { handler })
        .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES)
        .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
}
