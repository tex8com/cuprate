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
    Json(mut request): Json<serde_json::Value>,
) -> Result<axum::response::Response, StatusCode> {
    let is_txpool_backlog =
        request.get("method").and_then(|v| v.as_str()) == Some("get_txpool_backlog");

    if let Some(object) = request.as_object_mut() {
        if object.contains_key("method") && !object.contains_key("params") {
            object.insert(
                "params".to_string(),
                serde_json::Value::Object(Default::default()),
            );
        }
    }

    let request: cuprate_json_rpc::Request<JsonRpcRequest> = serde_json::from_value(request)
        .map_err(|e| {
            eprintln!("JSON-RPC deserialization error: {e:?}");
            StatusCode::UNPROCESSABLE_ENTITY
        })?;

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

    let backlog = txpool_backlog_as_pod_blob(&response.backlog);
    push_epee_json_string(&mut body, &backlog);
    body.extend_from_slice(b"}}");

    Ok((
        [(header::CONTENT_TYPE, "application/json")],
        Bytes::from(body),
    )
        .into_response())
}

fn txpool_backlog_as_pod_blob(backlog: &[cuprate_types::rpc::TxBacklogEntry]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(backlog.len() * 24);

    for entry in backlog {
        bytes.extend_from_slice(&entry.weight.to_le_bytes());
        bytes.extend_from_slice(&entry.fee.to_le_bytes());
        bytes.extend_from_slice(&entry.time_in_pool.to_le_bytes());
    }

    bytes
}

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
    // use super::*;
}
