//! JSON-RPC 2.0 endpoint route functions.

//---------------------------------------------------------------------------------------------------- Import
use axum::{
    body::Bytes,
    extract::State,
    http::{header, StatusCode},
    response::IntoResponse,
    Json,
};
use tower::ServiceExt;

use cuprate_json_rpc::{Id, Response};
use cuprate_rpc_types::{
    json::{GetTransactionPoolBacklogResponse, JsonRpcRequest, JsonRpcResponse},
    RpcCallValue,
};

use crate::rpc_handler::RpcHandler;

//---------------------------------------------------------------------------------------------------- Routes
/// The `/json_rpc` route function used in [`crate::RouterBuilder`].
pub(crate) async fn json_rpc<H: RpcHandler>(
    State(handler): State<H>,
    Json(request): Json<cuprate_json_rpc::Request<JsonRpcRequest>>,
) -> Result<axum::response::Response, StatusCode> {
    let is_txpool_backlog = matches!(&request.body, JsonRpcRequest::GetTransactionPoolBacklog(_));

    // TODO: <https://www.jsonrpc.org/specification#notification>
    //
    // JSON-RPC notifications (requests without `id`)
    // must not be responded too, although, the request's side-effects
    // must remain. How to do this considering this function will
    // always return and cause `axum` to respond?

    // JSON-RPC 2.0 rule:
    // If there was an error in detecting the `Request`'s ID,
    // the `Response` must contain an `Id::Null`
    let id = request.id.unwrap_or(Id::Null);

    // Return early if this RPC server is restricted and
    // the requested method is only for non-restricted RPC.
    //
    // INVARIANT:
    // The RPC handler functions in `cuprated` depend on this line existing,
    // the functions themselves do not check if they are being called
    // from an (un)restricted context. This line must be here or all
    // methods will be allowed to be called freely.
    if request.body.is_restricted() && handler.is_restricted() {
        // The error when a restricted JSON-RPC method is called as per:
        //
        // - <https://github.com/monero-project/monero/blob/893916ad091a92e765ce3241b94e706ad012b62a/contrib/epee/include/net/http_server_handlers_map2.h#L244-L252>
        // - <https://github.com/monero-project/monero/blob/cc73fe71162d564ffda8e549b79a350bca53c454/src/rpc/core_rpc_server.h#L188>
        return Ok(Json(Response::<JsonRpcResponse>::method_not_found(id)).into_response());
    }

    // Send request.
    let Ok(response) = handler.oneshot(request.body).await else {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    if is_txpool_backlog {
        let JsonRpcResponse::GetTransactionPoolBacklog(response) = response else {
            panic!("RPC handler returned incorrect response");
        };

        return json_rpc_txpool_backlog_response(id, response);
    }

    Ok(Json(Response::ok(id, response)).into_response())
}

fn json_rpc_txpool_backlog_response(
    id: Id,
    response: GetTransactionPoolBacklogResponse,
) -> Result<axum::response::Response, StatusCode> {
    let mut body = Vec::new();
    body.extend_from_slice(br#"{"jsonrpc":"2.0","id":"#);
    serde_json::to_writer(&mut body, &id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    body.extend_from_slice(br#","result":{"status":"#);
    serde_json::to_writer(&mut body, &response.base.status)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    body.extend_from_slice(br#","untrusted":"#);
    body.extend_from_slice(if response.base.untrusted {
        b"true"
    } else {
        b"false"
    });
    body.extend_from_slice(br#","credits":0,"top_hash":"","backlog":"#);

    let backlog = txpool_backlog_as_pod_blob(
        response
            .backlog
            .iter()
            .map(|entry| (entry.weight, entry.fee, entry.time_in_pool)),
    );
    push_epee_json_string(&mut body, &backlog);
    body.extend_from_slice(b"}}");

    Ok((
        [(header::CONTENT_TYPE, "application/json")],
        Bytes::from(body),
    )
        .into_response())
}

fn txpool_backlog_as_pod_blob(backlog: impl IntoIterator<Item = (u64, u64, u64)>) -> Vec<u8> {
    let mut bytes = Vec::new();

    for (weight, fee, time_in_pool) in backlog {
        bytes.extend_from_slice(&weight.to_le_bytes());
        bytes.extend_from_slice(&fee.to_le_bytes());
        bytes.extend_from_slice(&time_in_pool.to_le_bytes());
    }

    bytes
}

/// Match epee's byte-oriented JSON escaping used by upstream Monero.
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

    #[test]
    fn txpool_backlog_blob_matches_monero_pod_layout() {
        let blob = txpool_backlog_as_pod_blob([(1, 2, 3), (4, 5, 6)]);

        assert_eq!(blob.len(), 48);
        assert_eq!(&blob[0..8], &1_u64.to_le_bytes());
        assert_eq!(&blob[8..16], &2_u64.to_le_bytes());
        assert_eq!(&blob[16..24], &3_u64.to_le_bytes());
        assert_eq!(&blob[24..32], &4_u64.to_le_bytes());
        assert_eq!(&blob[32..40], &5_u64.to_le_bytes());
        assert_eq!(&blob[40..48], &6_u64.to_le_bytes());
    }

    #[tokio::test]
    async fn txpool_backlog_response_uses_monero_binary_string() {
        let response = json_rpc_txpool_backlog_response(
            Id::Null,
            GetTransactionPoolBacklogResponse::default(),
        )
        .expect("txpool backlog response must encode");
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .expect("response body must be readable");

        assert_eq!(
            body.as_ref(),
            br#"{"jsonrpc":"2.0","id":null,"result":{"status":"OK","untrusted":false,"credits":0,"top_hash":"","backlog":""}}"#
        );
    }
}
