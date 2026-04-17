//! Binary route functions.

//---------------------------------------------------------------------------------------------------- Import
use axum::{body::Bytes, extract::State, http::StatusCode};
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

//---------------------------------------------------------------------------------------------------- Routes
/// This macro generates route functions that expect input.
///
/// See below for usage.
macro_rules! generate_endpoints_with_input {
    ($(
        // Syntax:
        // Function name => Expected input type
        $endpoint:ident => $variant:ident
    ),*) => { paste::paste! {
        $(
            /// TODO
            pub(crate) async fn $endpoint<H: RpcHandler>(
                State(handler): State<H>,
                mut request: Bytes,
            ) -> Result<Bytes, StatusCode> {
                eprintln!("[BIN RPC] {} called, request_body_size={}", stringify!($variant), request.len());
                let request = BinRequest::$variant(
                    from_bytes(&mut request).map_err(|e| { eprintln!("BIN RPC deserialization error: {e:?}, remaining_bytes={}", request.len()); StatusCode::INTERNAL_SERVER_ERROR })?
                );

                generate_endpoints_inner!($variant, handler, request)
            }
        )*
    }};
}

/// This macro generates route functions that expect _no_ input.
///
/// See below for usage.
macro_rules! generate_endpoints_with_no_input {
    ($(
        // Syntax:
        // Function name => Expected input type (that is empty)
        $endpoint:ident => $variant:ident
    ),*) => { paste::paste! {
        $(
            /// TODO
            pub(crate) async fn $endpoint<H: RpcHandler>(
                State(handler): State<H>,
            ) -> Result<Bytes, StatusCode> {
                const REQUEST: BinRequest = BinRequest::$variant([<$variant Request>] {});
                generate_endpoints_inner!($variant, handler, REQUEST)
            }
        )*
    }};
}

/// De-duplicated inner function body for:
/// - [`generate_endpoints_with_input`]
/// - [`generate_endpoints_with_no_input`]
macro_rules! generate_endpoints_inner {
    ($variant:ident, $handler:ident, $request:expr_2021) => {
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
                        eprintln!("[BIN RPC] {} response_size={}", stringify!($variant), frozen.len());
                        Ok(frozen)
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
