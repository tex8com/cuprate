//! Binary route functions.

//---------------------------------------------------------------------------------------------------- Import
use axum::{body::Bytes, extract::State, http::{StatusCode, HeaderMap, header}};
use tower::ServiceExt;
use std::sync::atomic::{AtomicU64, Ordering};

static ACTIVE_REQUESTS: AtomicU64 = AtomicU64::new(0);
static TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);

use cuprate_epee_encoding::from_bytes;
use cuprate_rpc_types::{
    bin::{
        BinRequest, BinResponse, GetBlocksByHeightRequest, GetBlocksRequest, GetHashesRequest,
        GetOutputIndexesRequest, GetOutsRequest, GetTransactionPoolHashesRequest,
    },
    json::GetOutputDistributionRequest,
    RpcCall,
};

use crate::rpc_handler::RpcHandler;

//---------------------------------------------------------------------------------------------------- gzip helper

/// Compress bytes with gzip if the client accepts it.
/// Returns (body, is_compressed, gzip_us).
fn maybe_gzip(data: Bytes, accept_encoding: Option<&str>) -> (Bytes, bool, u128) {
    let t0 = std::time::Instant::now();
    if let Some(ae) = accept_encoding {
        if ae.contains("gzip") && data.len() > 1024 {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            use std::io::Write;

            let mut encoder = GzEncoder::new(Vec::with_capacity(data.len() / 3), Compression::fast());
            if encoder.write_all(&data).is_ok() {
                if let Ok(compressed) = encoder.finish() {
                    if compressed.len() < data.len() {
                        let us = t0.elapsed().as_micros();
                        return (Bytes::from(compressed), true, us);
                    }
                }
            }
        }
    }
    (data, false, t0.elapsed().as_micros())
}

/// Build response with optional Content-Encoding: gzip header.
fn build_response(body: Bytes, compressed: bool) -> axum::response::Response {
    use axum::response::IntoResponse;
    if compressed {
        ([(header::CONTENT_ENCODING, "gzip")], body).into_response()
    } else {
        body.into_response()
    }
}

//---------------------------------------------------------------------------------------------------- Routes
/// This macro generates route functions that expect input.
macro_rules! generate_endpoints_with_input {
    ($(
        $endpoint:ident => $variant:ident
    ),*) => { paste::paste! {
        $(
            pub(crate) async fn $endpoint<H: RpcHandler>(
                State(handler): State<H>,
                headers: HeaderMap,
                mut request: Bytes,
            ) -> Result<axum::response::Response, StatusCode> {
                let _perf_total = std::time::Instant::now();
                let _active = ACTIVE_REQUESTS.fetch_add(1, Ordering::SeqCst) + 1;
                let _reqid = TOTAL_REQUESTS.fetch_add(1, Ordering::SeqCst);
                eprintln!("[PERF RPC] {} BEGIN id={} active={} req_bytes={}", stringify!($variant), _reqid, _active, request.len());
                let request = BinRequest::$variant(
                    from_bytes(&mut request).map_err(|e| { eprintln!("BIN RPC deserialization error: {e:?}, remaining_bytes={}", request.len()); StatusCode::INTERNAL_SERVER_ERROR })?
                );

                let _result = generate_endpoints_inner!($variant, handler, headers, request);
                let _active_after = ACTIVE_REQUESTS.fetch_sub(1, Ordering::SeqCst) - 1;
                eprintln!("[PERF RPC] {} END id={} active_remaining={} total_ms={:.1}", stringify!($variant), _reqid, _active_after, _perf_total.elapsed().as_secs_f64() * 1000.0);
                _result
            }
        )*
    }};
}

/// This macro generates route functions that expect _no_ input.
macro_rules! generate_endpoints_with_no_input {
    ($(
        $endpoint:ident => $variant:ident
    ),*) => { paste::paste! {
        $(
            pub(crate) async fn $endpoint<H: RpcHandler>(
                State(handler): State<H>,
                headers: HeaderMap,
            ) -> Result<axum::response::Response, StatusCode> {
                const REQUEST: BinRequest = BinRequest::$variant([<$variant Request>] {});
                generate_endpoints_inner!($variant, handler, headers, REQUEST)
            }
        )*
    }};
}

/// De-duplicated inner function body.
macro_rules! generate_endpoints_inner {
    ($variant:ident, $handler:ident, $headers:ident, $request:expr_2021) => {
        paste::paste! {
            {
                if [<$variant Request>]::IS_RESTRICTED && $handler.is_restricted() {
                    return Err(StatusCode::FORBIDDEN);
                }

                let response = $handler.oneshot($request).await.map_err(|e| { eprintln!("BIN RPC handler error: {e:?}"); StatusCode::INTERNAL_SERVER_ERROR })?;

                let BinResponse::$variant(response) = response else {
                    panic!("RPC handler returned incorrect response");
                };

                match cuprate_epee_encoding::to_bytes(response) {
                    Ok(bytes) => {
                        let frozen = bytes.freeze();
                        let uncompressed_size = frozen.len();
                        let accept_enc = $headers.get(header::ACCEPT_ENCODING)
                            .and_then(|v| v.to_str().ok());
                        let (body, compressed, gzip_us) = maybe_gzip(frozen, accept_enc);
                        let ratio = if compressed && uncompressed_size > 0 { (body.len() as f64) / (uncompressed_size as f64) } else { 1.0 };
                        eprintln!("[PERF RPC] {} uncompressed={} compressed={} gzip={} ratio={:.3} gzip_ms={:.2}", stringify!($variant), uncompressed_size, body.len(), compressed, ratio, (gzip_us as f64) / 1000.0);
                        Ok(build_response(body, compressed))
                    },
                    Err(e) => {
                        eprintln!("[BIN RPC] {} serialization error: {e:?}", stringify!($variant));
                        Err(StatusCode::INTERNAL_SERVER_ERROR)
                    },
                }
            }
        }
    };
}

generate_endpoints_with_input! {
    get_blocks => GetBlocks,
    get_blocks_by_height => GetBlocksByHeight,
    get_hashes => GetHashes,
    get_o_indexes => GetOutputIndexes,
    get_outs => GetOuts,
    get_output_distribution => GetOutputDistribution
}

generate_endpoints_with_no_input! {
    get_transaction_pool_hashes => GetTransactionPoolHashes
}

//---------------------------------------------------------------------------------------------------- Tests
#[cfg(test)]
mod test {
    // use super::*;
}
