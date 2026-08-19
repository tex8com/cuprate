//! Binary route functions.

//---------------------------------------------------------------------------------------------------- Import
use axum::{
    body::Bytes,
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
};
use std::sync::atomic::{AtomicU64, Ordering};
use tower::ServiceExt;

static ACTIVE_REQUESTS: AtomicU64 = AtomicU64::new(0);
static TOTAL_REQUESTS: AtomicU64 = AtomicU64::new(0);

use cuprate_epee_encoding::from_bytes;
use cuprate_rpc_types::{
    bin::{
        BinRequest, BinResponse, GetBlocksByHeightRequest, GetBlocksRequest, GetHashesRequest,
        GetOutputIndexesRequest, GetOutsRequest, GetTransactionPoolHashesRequest,
        GetTransactionPoolHashesResponse,
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

            let mut encoder =
                GzEncoder::new(Vec::with_capacity(data.len() / 3), Compression::fast());
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
                // Prefer the client-supplied X-Perf-Req-Id header for cross-machine correlation.
                // Fallback to internal counter when header missing.
                let _reqid: String = headers.get("x-perf-req-id")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| TOTAL_REQUESTS.fetch_add(1, Ordering::SeqCst).to_string());
                // Wall-clock epoch ms (matches wallet's send_epoch_ms / recv_epoch_ms).
                let _recv_epoch_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
                eprintln!("[PERF RPC] {} BEGIN id={} active={} req_bytes={} recv_epoch_ms={}", stringify!($variant), _reqid, _active, request.len(), _recv_epoch_ms);
                let request = BinRequest::$variant(
                    from_bytes(&mut request).map_err(|e| { eprintln!("BIN RPC deserialization error: {e:?}, remaining_bytes={}", request.len()); StatusCode::INTERNAL_SERVER_ERROR })?
                );

                let _result = generate_endpoints_inner!($variant, handler, headers, request);
                let _active_after = ACTIVE_REQUESTS.fetch_sub(1, Ordering::SeqCst) - 1;
                let _send_epoch_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis()).unwrap_or(0);
                eprintln!("[PERF RPC] {} END id={} active_remaining={} total_ms={:.1} recv_epoch_ms={} send_epoch_ms={}", stringify!($variant), _reqid, _active_after, _perf_total.elapsed().as_secs_f64() * 1000.0, _recv_epoch_ms, _send_epoch_ms);
                _result
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

/// Serve Monero's legacy pool-hash endpoint.
///
/// Despite its `.bin` suffix, upstream `monerod` maps this route through its
/// JSON serializer. The `tx_hashes` field is one JSON string containing the
/// raw concatenated 32-byte hashes, escaped with epee's byte-oriented rules.
/// Wallet Core therefore calls this endpoint through `invoke_http_json`.
pub(crate) async fn get_transaction_pool_hashes<H: RpcHandler>(
    State(handler): State<H>,
) -> Result<axum::response::Response, StatusCode> {
    eprintln!(
        "[MFN RPC] route=/get_transaction_pool_hashes.bin stage=request_received encoding=json"
    );

    const REQUEST: BinRequest =
        BinRequest::GetTransactionPoolHashes(GetTransactionPoolHashesRequest {});
    let response = handler.oneshot(REQUEST).await.map_err(|error| {
        eprintln!(
            "[MFN RPC] route=/get_transaction_pool_hashes.bin stage=handler_failed error={error:?}"
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let BinResponse::GetTransactionPoolHashes(response) = response else {
        panic!("RPC handler returned incorrect response");
    };
    let hash_count = response.tx_hashes.len();
    let body = transaction_pool_hashes_json_body(response);

    eprintln!(
        "[MFN RPC] route=/get_transaction_pool_hashes.bin stage=response_encoded encoding=json hash_count={} response_bytes={}",
        hash_count,
        body.len()
    );

    Ok(([(header::CONTENT_TYPE, "application/json")], body).into_response())
}

fn transaction_pool_hashes_json_body(response: GetTransactionPoolHashesResponse) -> Bytes {
    let mut body = Vec::new();
    body.extend_from_slice(
        br#"{"credits":0,"top_hash":"","status":"OK","untrusted":false,"tx_hashes":"#,
    );
    push_epee_json_string(&mut body, response.tx_hashes.take_bytes().as_ref());
    body.push(b'}');
    Bytes::from(body)
}

/// Match epee's `transform_to_escape_sequence` exactly. In particular, bytes
/// outside ASCII are retained verbatim because Monero's parser treats this as
/// a byte string rather than a Unicode JSON string.
fn push_epee_json_string(json: &mut Vec<u8>, bytes: &[u8]) {
    json.push(b'"');

    for byte in bytes {
        match *byte {
            b'\x08' => json.extend_from_slice(br"\b"),
            b'\x0c' => json.extend_from_slice(br"\f"),
            b'\n' => json.extend_from_slice(br"\n"),
            b'\r' => json.extend_from_slice(br"\r"),
            b'\t' => json.extend_from_slice(br"\t"),
            b'\x0b' => json.extend_from_slice(br"\v"),
            b'"' => json.extend_from_slice(br#"\""#),
            b'\\' => json.extend_from_slice(br"\\"),
            b'/' => json.extend_from_slice(br"\/"),
            byte => json.push(byte),
        }
    }

    json.push(b'"');
}

//---------------------------------------------------------------------------------------------------- Tests
#[cfg(test)]
mod test {
    use super::*;
    use crate::RpcHandlerDummy;

    #[tokio::test]
    async fn pool_hashes_route_is_json_end_to_end() {
        let response = get_transaction_pool_hashes(State(RpcHandlerDummy { restricted: false }))
            .await
            .expect("pool hashes route must succeed");

        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("response body must be readable");
        assert_eq!(
            body.as_ref(),
            br#"{"credits":0,"top_hash":"","status":"OK","untrusted":false,"tx_hashes":""}"#
        );
    }

    #[test]
    fn pool_hashes_route_uses_upstream_json_envelope() {
        let body = transaction_pool_hashes_json_body(GetTransactionPoolHashesResponse::default());

        assert_eq!(
            body.as_ref(),
            br#"{"credits":0,"top_hash":"","status":"OK","untrusted":false,"tx_hashes":""}"#
        );
    }

    #[test]
    fn pool_hashes_route_matches_epee_byte_escaping() {
        let mut hash = [0x41; 32];
        hash[..10].copy_from_slice(&[
            b'\x08', b'\x0c', b'\n', b'\r', b'\t', b'\x0b', b'"', b'\\', b'/', 0xff,
        ]);
        let response = GetTransactionPoolHashesResponse {
            tx_hashes: hash.into(),
            ..Default::default()
        };

        let body = transaction_pool_hashes_json_body(response);
        assert!(body.windows(19).any(|window| {
            window
                == [
                    b'\\', b'b', b'\\', b'f', b'\\', b'n', b'\\', b'r', b'\\', b't', b'\\', b'v',
                    b'\\', b'"', b'\\', b'\\', b'\\', b'/', 0xff,
                ]
        }));
        assert_eq!(body.last(), Some(&b'}'));
    }
}
