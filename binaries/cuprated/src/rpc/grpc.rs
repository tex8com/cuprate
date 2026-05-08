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
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::Error;
use cuprate_epee_encoding::to_bytes;
use cuprate_fixed_bytes::ByteArrayVec;
use cuprate_helper::cast::{u64_to_usize, usize_to_u64};
use cuprate_rpc_types::bin::GetBlocksResponse;
use cuprate_types::rpc::PoolInfoExtent;
use futures::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};

use crate::rpc::{
    handlers::{bin as bin_handlers, helper as bin_helper},
    CupratedRpcHandler,
};

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
            "[GRPC StreamBlocks] OPEN id={} client_req_id={} start={} stop={} prune={} no_miner_tx={} chunk_blocks={} max_chunk_bytes={} max_chunk_txs={} active_streams={} open_epoch_ms={}",
            server_req_id, client_id_label, start_height, stop_height, prune, no_miner_tx,
            chunk_blocks, MAX_GRPC_CHUNK_RESPONSE_BYTES, MAX_GRPC_CHUNK_TX_COUNT, active,
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

    loop {
        let (top_h, _) = bin_helper::top_height(state).await?;
        let chain_height = u64_to_usize(top_h) + 1;
        let target_end = if stop_height == 0 {
            chain_height
        } else {
            (u64_to_usize(stop_height) + 1).min(chain_height)
        };

        if next_height >= target_end {
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
        }

        let want = chunk_blocks.min(target_end - next_height);

        let t_db = Instant::now();
        let blocks = bin_handlers::capped_block_complete_entries(
            state,
            next_height,
            chain_height,
            want,
            prune,
            MAX_GRPC_CHUNK_RESPONSE_BYTES,
            MAX_GRPC_CHUNK_TX_COUNT,
        )
        .await?;
        let db_ms = t_db.elapsed().as_secs_f64() * 1000.0;
        let actual_blocks = blocks.len();

        if actual_blocks == 0 {
            eprintln!(
                "[GRPC StreamBlocks] CLOSE id={} reason=zero_blocks chunks={} blocks={} bytes={}",
                server_req_id, chunk_seq, total_blocks, total_bytes,
            );
            return Ok(());
        }

        let t_idx = Instant::now();
        let output_indices =
            bin_handlers::output_indices_for_blocks(state, &blocks, no_miner_tx).await?;
        let idx_ms = t_idx.elapsed().as_secs_f64() * 1000.0;

        let response_start = usize_to_u64(next_height);
        let response_current = usize_to_u64(chain_height);

        let t_enc = Instant::now();
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

        let chunk = BlockChunk {
            start_height: response_start,
            chunk_seq,
            chain_tip: top_h,
            server_request_id: server_req_id.to_string(),
            payload: payload_buf.to_vec(),
            n_blocks: actual_blocks as u32,
            payload_bytes: payload_len as u32,
        };

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

        total_blocks += actual_blocks as u64;
        total_bytes += payload_len as u64;
        let cum_ms = stream_t0.elapsed().as_secs_f64() * 1000.0;
        let cum_mbs = if cum_ms > 0.0 {
            (total_bytes as f64 / 1024.0 / 1024.0) / (cum_ms / 1000.0)
        } else {
            0.0
        };

        let upstream_ms = db_ms + idx_ms + enc_ms;
        let bp_ratio = if upstream_ms > 1.0 {
            send_ms / upstream_ms
        } else {
            0.0
        };

        eprintln!(
            "[GRPC StreamBlocks] CHUNK id={} seq={} start={} n_blocks={} payload_bytes={} db_ms={:.1} idx_ms={:.1} enc_ms={:.1} send_ms={:.1} bp_ratio={:.2} cum_ms={:.1} cum_bytes={} cum_mbs={:.2} chain_tip={}",
            server_req_id, chunk_seq, response_start, actual_blocks, payload_len,
            db_ms, idx_ms, enc_ms, send_ms, bp_ratio,
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
