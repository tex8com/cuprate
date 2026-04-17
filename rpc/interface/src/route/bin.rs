//! Binary route functions.

//---------------------------------------------------------------------------------------------------- Import
use axum::{body::Bytes, extract::State, http::{StatusCode, HeaderMap, header}};
use tower::ServiceExt;

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
/// Returns (body, is_compressed).
fn maybe_gzip(data: Bytes, accept_encoding: Option<&str>) -> (Bytes, bool) {
    if let Some(ae) = accept_encoding {
        if ae.contains("gzip") && data.len() > 1024 {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            use std::io::Write;

            let mut encoder = GzEncoder::new(Vec::with_capacity(data.len() / 3), Compression::fast());
            if encoder.write_all(&data).is_ok() {
                if let Ok(compressed) = encoder.finish() {
                    if compressed.len() < data.len() {
                        return (Bytes::from(compressed), true);
                    }
                }
            }
        }
    }
    (data, false)
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
                eprintln!("[BIN RPC] {} called, request_body_size={}", stringify!($variant), request.len());
                let request = BinRequest::$variant(
                    from_bytes(&mut request).map_err(|e| { eprintln!("BIN RPC deserialization error: {e:?}, remaining_bytes={}", request.len()); StatusCode::INTERNAL_SERVER_ERROR })?
                );

                generate_endpoints_inner!($variant, handler, headers, request)
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
                        let accept_enc = $headers.get(header::ACCEPT_ENCODING)
                            .and_then(|v| v.to_str().ok());
                        let (body, compressed) = maybe_gzip(frozen, accept_enc);
                        if compressed {
                            eprintln!("[BIN RPC] {} response_size={} (gzip, uncompressed={})", stringify!($variant), body.len(), body.len());
                        } else {
                            eprintln!("[BIN RPC] {} response_size={}", stringify!($variant), body.len());
                        }
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
