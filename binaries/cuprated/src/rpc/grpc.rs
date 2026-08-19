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

use crate::mfw_name_index::SharedNameIndex;
use crate::rpc::{
    handlers::{bin as bin_handlers, helper as bin_helper},
    service::blockchain,
    CupratedRpcHandler,
};
use mfw_recipient_protocol::{Network as MfwNetwork, ResolutionStatus};

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
use proto::{
    BlockChunk, MfwNameStatus, ResolveMfwNameRequest, ResolveMfwNameResponse, StreamBlocksRequest,
};

// Conservative mobile-safe defaults. The server must never turn a client's
// optimistic hint into unbounded queued memory; an adaptive protocol, if
// introduced later, must remain within these hard caps.
const DEFAULT_CHUNK_BLOCKS: usize = 64;
const MIN_CHUNK_BLOCKS: usize = 16;
const MAX_CHUNK_BLOCKS: usize = 512;
const MAX_GRPC_CHUNK_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_GRPC_CHUNK_TX_COUNT: usize = 50_000;
pub const MAX_GRPC_MESSAGE_BYTES: usize = 16 * 1024 * 1024;
pub const GRPC_HTTP2_STREAM_WINDOW_BYTES: u32 = 16 * 1024 * 1024;
pub const GRPC_HTTP2_CONNECTION_WINDOW_BYTES: u32 = 512 * 1024 * 1024;

/// mpsc capacity between producer task and HTTP/2 send loop. Small on
/// purpose in production, but high-throughput wallet restore tests need enough
/// room to absorb scanner stalls without immediately stalling HTTP/2.
const CHANNEL_CAPACITY: usize = 4;
const LANE_CHANNEL_CAPACITY: usize = 2;
const MAX_CHAIN_LOCATOR_HASHES: usize = 256;
const MAX_LANE_COUNT: u32 = 6;
// Hard global admission gate for the experimental public service. Wallet-side
// pooling is bounded at six channels; this prevents one node from accepting
// an unbounded number of expensive block encoders at once.
const MAX_ACTIVE_STREAMS: u64 = 64;

static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(0);
static ACTIVE_STREAMS: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct ActiveStreamPermit {
    admitted_count: u64,
}

impl Drop for ActiveStreamPermit {
    fn drop(&mut self) {
        let previous = ACTIVE_STREAMS.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "active gRPC stream counter underflow");
    }
}

fn try_acquire_stream() -> Result<ActiveStreamPermit, Status> {
    let mut active = ACTIVE_STREAMS.load(Ordering::Acquire);
    loop {
        if active >= MAX_ACTIVE_STREAMS {
            return Err(Status::resource_exhausted(
                "gRPC block-stream capacity reached",
            ));
        }
        match ACTIVE_STREAMS.compare_exchange_weak(
            active,
            active + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                return Ok(ActiveStreamPermit {
                    admitted_count: active + 1,
                });
            }
            Err(now) => active = now,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LanePlan {
    stripe_span_blocks: u32,
    lane_index: u32,
    lane_count: u32,
}

impl LanePlan {
    fn from_request(request: &StreamBlocksRequest) -> Result<Self, Status> {
        if request.stop_height == 0 || request.stop_height < request.start_height {
            return Err(Status::invalid_argument(
                "StreamBlockLane requires a finite non-empty range",
            ));
        }
        if request.stripe_span_blocks < MIN_CHUNK_BLOCKS as u32
            || request.stripe_span_blocks > MAX_CHUNK_BLOCKS as u32
        {
            return Err(Status::invalid_argument(format!(
                "stripe_span_blocks must be between {MIN_CHUNK_BLOCKS} and {MAX_CHUNK_BLOCKS}"
            )));
        }
        if request.lane_count == 0 || request.lane_count > MAX_LANE_COUNT {
            return Err(Status::invalid_argument(
                "lane_count must be between 1 and 6",
            ));
        }
        if request.lane_index >= request.lane_count {
            return Err(Status::invalid_argument(
                "lane_index must be smaller than lane_count",
            ));
        }
        Ok(Self {
            stripe_span_blocks: request.stripe_span_blocks,
            lane_index: request.lane_index,
            lane_count: request.lane_count,
        })
    }

    fn first_height(self, range_start: usize) -> Result<usize, Status> {
        range_start
            .checked_add(
                u64_to_usize(u64::from(self.stripe_span_blocks))
                    .checked_mul(u64_to_usize(u64::from(self.lane_index)))
                    .ok_or_else(|| Status::out_of_range("lane start overflow"))?,
            )
            .ok_or_else(|| Status::out_of_range("lane start overflow"))
    }

    fn stripe_end(
        self,
        range_start: usize,
        next_height: usize,
        target_end: usize,
    ) -> Result<usize, Status> {
        let stripe_span = u64_to_usize(u64::from(self.stripe_span_blocks));
        let relative = next_height
            .checked_sub(range_start)
            .ok_or_else(|| Status::internal("lane height precedes range start"))?;
        let stripe_ordinal = relative / stripe_span;
        if stripe_ordinal % u64_to_usize(u64::from(self.lane_count))
            != u64_to_usize(u64::from(self.lane_index))
        {
            return Err(Status::internal("height is outside its assigned lane"));
        }
        let stripe_start = range_start
            .checked_add(
                stripe_ordinal
                    .checked_mul(stripe_span)
                    .ok_or_else(|| Status::out_of_range("lane stripe overflow"))?,
            )
            .ok_or_else(|| Status::out_of_range("lane stripe overflow"))?;
        Ok(stripe_start
            .checked_add(stripe_span)
            .unwrap_or(target_end)
            .min(target_end))
    }

    fn next_stripe_start(self, stripe_end: usize) -> Result<usize, Status> {
        let skipped_stripes = u64_to_usize(u64::from(self.lane_count - 1));
        let stripe_span = u64_to_usize(u64::from(self.stripe_span_blocks));
        stripe_end
            .checked_add(
                stripe_span
                    .checked_mul(skipped_stripes)
                    .ok_or_else(|| Status::out_of_range("lane stride overflow"))?,
            )
            .ok_or_else(|| Status::out_of_range("lane stride overflow"))
    }
}

fn reduced_chunk_blocks(actual_blocks: usize) -> Option<usize> {
    (actual_blocks > 1).then_some(actual_blocks.saturating_add(1) / 2)
}

type BlockChunkStream = Pin<Box<dyn Stream<Item = Result<BlockChunk, Status>> + Send + 'static>>;

#[derive(Clone)]
pub struct BlockStreamService {
    pub handler: CupratedRpcHandler,
    pub mfw_name_index: Option<SharedNameIndex>,
}

#[tonic::async_trait]
impl BlockStream for BlockStreamService {
    type StreamBlocksStream = BlockChunkStream;
    type StreamBlockLaneStream = BlockChunkStream;

    async fn stream_blocks(
        &self,
        request: Request<StreamBlocksRequest>,
    ) -> Result<Response<Self::StreamBlocksStream>, Status> {
        open_block_stream(self.handler.clone(), request.into_inner(), None).await
    }

    async fn stream_block_lane(
        &self,
        request: Request<StreamBlocksRequest>,
    ) -> Result<Response<Self::StreamBlockLaneStream>, Status> {
        let request = request.into_inner();
        let lane_plan = LanePlan::from_request(&request)?;
        open_block_stream(self.handler.clone(), request, Some(lane_plan)).await
    }

    async fn resolve_mfw_name(
        &self,
        request: Request<ResolveMfwNameRequest>,
    ) -> Result<Response<ResolveMfwNameResponse>, Status> {
        let index = self
            .mfw_name_index
            .as_ref()
            .ok_or_else(|| Status::unavailable("MFW name index is disabled"))?;
        if !index.is_ready() {
            return Err(Status::unavailable(
                "MFW name index is restoring or catching up",
            ));
        }
        let guard = index.read().await;
        if !index.is_ready() {
            return Err(Status::unavailable(
                "MFW name index changed while resolving",
            ));
        }
        let resolution = guard
            .resolve(&request.into_inner().name)
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let network = match guard.parameters().network {
            MfwNetwork::Mainnet => 0,
            MfwNetwork::Testnet => 1,
            MfwNetwork::Stagenet => 2,
        };
        let status = match resolution.status {
            ResolutionStatus::NotFound => MfwNameStatus::NotFound,
            ResolutionStatus::Reserved => MfwNameStatus::Reserved,
            ResolutionStatus::Provisional => MfwNameStatus::Provisional,
            ResolutionStatus::Finalized => MfwNameStatus::Finalized,
            ResolutionStatus::Expired => MfwNameStatus::Expired,
            ResolutionStatus::Revoked => MfwNameStatus::Revoked,
        };
        let (address_kind, public_spend_key, public_view_key) =
            resolution
                .address
                .map_or((0, Vec::new(), Vec::new()), |address| {
                    (
                        address.kind as u32,
                        address.public_spend_key.to_vec(),
                        address.public_view_key.to_vec(),
                    )
                });
        Ok(Response::new(ResolveMfwNameResponse {
            canonical_name: resolution.name.display_name(),
            status: status as i32,
            network,
            address_kind,
            public_spend_key,
            public_view_key,
            owner_public_key: resolution
                .owner_public_key
                .map_or_else(Vec::new, |value| value.to_vec()),
            sequence: resolution.sequence.unwrap_or(0),
            record_height: resolution.record_height.unwrap_or(0),
            source_txid: resolution
                .source_txid
                .map_or_else(Vec::new, |value| value.to_vec()),
            expiry_height: resolution.expiry_height.unwrap_or(0),
            chain_tip_height: resolution.chain_tip_height.unwrap_or(0),
            confirmations: resolution.confirmations,
            record_payload: resolution.record_payload.unwrap_or_default(),
            signing_owner_public_key: resolution
                .signing_owner_public_key
                .map_or_else(Vec::new, |value| value.to_vec()),
            record_block_hash: resolution
                .record_block_hash
                .map_or_else(Vec::new, |value| value.to_vec()),
            chain_tip_hash: resolution
                .chain_tip_hash
                .map_or_else(Vec::new, |value| value.to_vec()),
        }))
    }
}

async fn open_block_stream(
    mut handler: CupratedRpcHandler,
    request: StreamBlocksRequest,
    lane_plan: Option<LanePlan>,
) -> Result<Response<BlockChunkStream>, Status> {
    let StreamBlocksRequest {
        start_height,
        stop_height,
        prune,
        chunk_blocks_hint,
        no_miner_tx,
        client_request_id,
        chain_locator,
        ..
    } = request;

    let effective_start = resolve_stream_start(&mut handler, start_height, chain_locator).await?;
    let range_start = usize::try_from(effective_start)
        .map_err(|_| Status::out_of_range("start height does not fit this server"))?;
    let initial_height = match lane_plan {
        Some(plan) => plan.first_height(range_start)?,
        None => range_start,
    };

    // Admission happens only after all request validation and locator I/O.
    // The permit then owns the counter until the producer task exits on every
    // success, error, cancellation, or panic-unwind path.
    let active_permit = try_acquire_stream()?;
    let active = active_permit.admitted_count;
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
    let open_epoch_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let rpc_name = if lane_plan.is_some() {
        "StreamBlockLane"
    } else {
        "StreamBlocks"
    };
    let (stripe_span, lane_index, lane_count) = lane_plan.map_or((0, 0, 1), |plan| {
        (plan.stripe_span_blocks, plan.lane_index, plan.lane_count)
    });

    eprintln!(
        "[GRPC StreamBlocks] OPEN id={} rpc={} client_req_id={} start={} effective_start={} stop={} prune={} no_miner_tx={} chunk_blocks={} stripe_span={} lane_index={} lane_count={} max_chunk_bytes={} max_chunk_txs={} active_streams={} open_epoch_ms={}",
        server_req_id,
        rpc_name,
        client_id_label,
        start_height,
        effective_start,
        stop_height,
        prune,
        no_miner_tx,
        chunk_blocks,
        stripe_span,
        lane_index,
        lane_count,
        MAX_GRPC_CHUNK_RESPONSE_BYTES,
        MAX_GRPC_CHUNK_TX_COUNT,
        active,
        open_epoch_ms,
    );

    let channel_capacity = if lane_plan.is_some() {
        LANE_CHANNEL_CAPACITY
    } else {
        CHANNEL_CAPACITY
    };
    let (tx, rx) = mpsc::channel::<Result<BlockChunk, Status>>(channel_capacity);
    let id_for_task = server_req_id.clone();
    let id_for_close = server_req_id.clone();

    tokio::spawn(async move {
        let result = produce_block_stream(
            &mut handler,
            tx,
            range_start,
            initial_height,
            stop_height,
            prune,
            chunk_blocks,
            no_miner_tx,
            lane_plan,
            rpc_name,
            &id_for_task,
        )
        .await;
        drop(active_permit);
        let active_after = ACTIVE_STREAMS.load(Ordering::Acquire);
        if let Err(error) = result {
            eprintln!(
                "[GRPC StreamBlocks] CLOSE_ERR id={} active_remaining={} err={:?}",
                id_for_close, active_after, error
            );
        }
    });

    Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
}

async fn resolve_stream_start(
    state: &mut CupratedRpcHandler,
    requested_start: u64,
    chain_locator: Vec<Vec<u8>>,
) -> Result<u64, Status> {
    if chain_locator.is_empty() {
        return Ok(requested_start);
    }
    if chain_locator.len() > MAX_CHAIN_LOCATOR_HASHES {
        return Err(Status::invalid_argument("chain locator exceeds 256 hashes"));
    }

    let mut hashes = Vec::with_capacity(chain_locator.len());
    for hash in chain_locator {
        let bytes: [u8; 32] = hash
            .as_slice()
            .try_into()
            .map_err(|_| Status::invalid_argument("each chain locator hash must be 32 bytes"))?;
        hashes.push(bytes);
    }

    let (_, first_known_height, _) =
        blockchain::next_chain_entry(&mut state.blockchain_read, hashes, 1)
            .await
            .map_err(|error| Status::internal(format!("chain locator lookup failed: {error}")))?;

    select_stream_start(requested_start, first_known_height.map(usize_to_u64))
}

fn select_stream_start(
    requested_start: u64,
    first_known_height: Option<u64>,
) -> Result<u64, Status> {
    // Match getblocks.bin exactly: a non-zero explicit start remains the
    // response boundary after the locator has been validated. Only a request
    // without an explicit start derives its boundary from the common block.
    if requested_start > 0 {
        return Ok(requested_start);
    }
    first_known_height
        .ok_or_else(|| Status::failed_precondition("chain locator has no common block"))
}

async fn produce_block_stream(
    state: &mut CupratedRpcHandler,
    tx: mpsc::Sender<Result<BlockChunk, Status>>,
    range_start: usize,
    initial_height: usize,
    stop_height: u64,
    prune: bool,
    chunk_blocks: usize,
    no_miner_tx: bool,
    lane_plan: Option<LanePlan>,
    rpc_name: &'static str,
    server_req_id: &str,
) -> Result<(), Error> {
    let stream_t0 = Instant::now();
    let mut next_height = initial_height;
    let mut chunk_seq: u64 = 0;
    let mut total_blocks: u64 = 0;
    let mut total_bytes: u64 = 0;
    let mut next_chunk_blocks = chunk_blocks;

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
                "[GRPC {}] CLOSE id={} reason=tip_reached chunks={} blocks={} bytes={} total_ms={:.1} avg_mbs={:.2}",
                rpc_name, server_req_id, chunk_seq, total_blocks, total_bytes, total_ms, avg_mbs,
            );
            return Ok(());
        }

        let stripe_end = match lane_plan {
            Some(plan) => plan
                .stripe_end(range_start, next_height, target_end)
                .map_err(|status| anyhow::anyhow!(status.message().to_string()))?,
            None => target_end,
        };
        let want = next_chunk_blocks.min(stripe_end - next_height);

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
                "[GRPC {}] CLOSE id={} reason=zero_blocks chunks={} blocks={} bytes={}",
                rpc_name, server_req_id, chunk_seq, total_blocks, total_bytes,
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
                    "[GRPC {}] ENCODE_ERR id={} seq={} err={:?}",
                    rpc_name, server_req_id, chunk_seq, e
                );
                return Err(e.into());
            }
        };
        let enc_ms = t_enc.elapsed().as_secs_f64() * 1000.0;
        let payload_len = payload_buf.len();
        if payload_len > MAX_GRPC_CHUNK_RESPONSE_BYTES {
            let Some(reduced_blocks) = reduced_chunk_blocks(actual_blocks) else {
                return Err(Error::msg(format!(
                    "single-block encoded chunk exceeds RPC byte limit: {payload_len} > {MAX_GRPC_CHUNK_RESPONSE_BYTES}"
                )));
            };
            eprintln!(
                "[GRPC {}] SPLIT_OVERSIZED id={} seq={} start={} blocks={} payload_bytes={} max_bytes={} retry_blocks={}",
                rpc_name,
                server_req_id,
                chunk_seq,
                response_start,
                actual_blocks,
                payload_len,
                MAX_GRPC_CHUNK_RESPONSE_BYTES,
                reduced_blocks,
            );
            next_chunk_blocks = reduced_blocks;
            continue;
        }
        next_chunk_blocks = chunk_blocks;

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
                "[GRPC {}] CLOSE id={} reason=client_disconnect chunks={} blocks={} bytes={} total_ms={:.1}",
                rpc_name, server_req_id, chunk_seq, total_blocks, total_bytes, total_ms,
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
            "[GRPC {}] CHUNK id={} seq={} start={} n_blocks={} payload_bytes={} db_ms={:.1} idx_ms={:.1} enc_ms={:.1} send_ms={:.1} bp_ratio={:.2} cum_ms={:.1} cum_bytes={} cum_mbs={:.2} chain_tip={}",
            rpc_name, server_req_id, chunk_seq, response_start, actual_blocks, payload_len,
            db_ms, idx_ms, enc_ms, send_ms, bp_ratio,
            cum_ms, total_bytes, cum_mbs, top_h,
        );

        if bp_ratio > 2.0 {
            eprintln!(
                "[GRPC {}] BACKPRESSURE id={} seq={} send_ms={:.1} upstream_ms={:.1} ratio={:.2} -- client slower than server",
                rpc_name, server_req_id, chunk_seq, send_ms, upstream_ms, bp_ratio,
            );
        }

        chunk_seq += 1;
        next_height += actual_blocks;
        if next_height == stripe_end {
            if let Some(plan) = lane_plan {
                next_height = plan
                    .next_stripe_start(stripe_end)
                    .map_err(|status| anyhow::anyhow!(status.message().to_string()))?;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_stream_permit_releases_on_drop() {
        let before = ACTIVE_STREAMS.load(Ordering::Acquire);
        assert!(before < MAX_ACTIVE_STREAMS);
        let permit = try_acquire_stream().expect("stream slot should be available");
        assert_eq!(permit.admitted_count, before + 1);
        assert_eq!(ACTIVE_STREAMS.load(Ordering::Acquire), before + 1);
        drop(permit);
        assert_eq!(ACTIVE_STREAMS.load(Ordering::Acquire), before);
    }

    #[test]
    fn persistent_lanes_cover_each_height_exactly_once() {
        for stripe_span_blocks in [16u32, 64, 512] {
            for lane_count in 1u32..=MAX_LANE_COUNT {
                for range_len in [1usize, 15, 16, 17, 511, 512, 513, 4099] {
                    let range_start = 37usize;
                    let target_end = range_start + range_len;
                    let mut covered = Vec::new();

                    for lane_index in 0..lane_count {
                        let plan = LanePlan {
                            stripe_span_blocks,
                            lane_index,
                            lane_count,
                        };
                        let mut next = plan.first_height(range_start).expect("valid lane start");
                        while next < target_end {
                            let end = plan
                                .stripe_end(range_start, next, target_end)
                                .expect("valid lane stripe");
                            covered.extend(next..end);
                            next = plan.next_stripe_start(end).expect("valid lane stride");
                        }
                    }

                    covered.sort_unstable();
                    assert_eq!(
                        covered,
                        (range_start..target_end).collect::<Vec<_>>(),
                        "stripe_span={stripe_span_blocks} lane_count={lane_count} range_len={range_len}"
                    );
                }
            }
        }
    }

    #[test]
    fn persistent_lane_request_validation_is_bounded() {
        let mut request = StreamBlocksRequest {
            start_height: 100,
            stop_height: 5000,
            stripe_span_blocks: 512,
            lane_index: 5,
            lane_count: 6,
            ..StreamBlocksRequest::default()
        };
        assert!(LanePlan::from_request(&request).is_ok());

        request.lane_index = 6;
        assert_eq!(
            LanePlan::from_request(&request)
                .expect_err("out-of-range lane must fail")
                .code(),
            tonic::Code::InvalidArgument
        );
        request.lane_index = 0;
        request.lane_count = 0;
        assert!(LanePlan::from_request(&request).is_err());
        request.lane_count = 1;
        request.stripe_span_blocks = 0;
        assert!(LanePlan::from_request(&request).is_err());
        request.stripe_span_blocks = 512;
        request.stop_height = 0;
        assert!(LanePlan::from_request(&request).is_err());
    }

    #[test]
    fn explicit_stream_start_matches_bin_rpc_semantics() {
        assert_eq!(select_stream_start(3_741_930, Some(1)).unwrap(), 3_741_930);
        assert_eq!(select_stream_start(0, Some(123)).unwrap(), 123);
        assert!(select_stream_start(0, None).is_err());
    }

    #[test]
    fn oversized_chunks_are_reduced_until_one_block() {
        assert_eq!(reduced_chunk_blocks(512), Some(256));
        assert_eq!(reduced_chunk_blocks(3), Some(2));
        assert_eq!(reduced_chunk_blocks(2), Some(1));
        assert_eq!(reduced_chunk_blocks(1), None);
        assert_eq!(reduced_chunk_blocks(0), None);
    }
}

/// Build the tonic gRPC service ready to be added to a tonic Server.
pub fn block_stream_service(
    handler: CupratedRpcHandler,
    mfw_name_index: Option<SharedNameIndex>,
) -> BlockStreamServer<BlockStreamService> {
    BlockStreamServer::new(BlockStreamService {
        handler,
        mfw_name_index,
    })
    .max_encoding_message_size(MAX_GRPC_MESSAGE_BYTES)
    .max_decoding_message_size(MAX_GRPC_MESSAGE_BYTES)
}
