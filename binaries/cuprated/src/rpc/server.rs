//! RPC server initialization and main loop.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

#[cfg(target_os = "linux")]
use std::ffi::CString;

use anyhow::Error;
use axum::{
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use mfw_recipient_protocol::{Network as MfwNetwork, Resolution, ResolutionStatus};
use serde::Serialize;
use tokio::net::TcpListener;
use tokio_stream::{wrappers::TcpListenerStream, StreamExt};
use tower::limit::rate::RateLimitLayer;
use tower_http::compression::CompressionLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{info, warn};

use cuprate_blockchain::service::BlockchainReadHandle;
use cuprate_consensus::BlockchainContextService;
use cuprate_helper::network::Network;
use cuprate_rpc_interface::{RouterBuilder, RpcHandler};
use cuprate_txpool::service::TxpoolReadHandle;

use crate::{
    config::{grpc_rpc_port, restricted_rpc_port, unrestricted_rpc_port, GrpcConfig, RpcConfig},
    mfw_name_index::SharedNameIndex,
    rpc::{grpc, rpc_handler::BlockchainManagerHandle, CupratedRpcHandler},
    txpool::IncomingTxHandler,
};

/// Initialize the RPC server(s).
///
/// # Panics
/// This function will panic if:
/// - the server(s) could not be started
/// - unrestricted RPC is started on non-local
///   address without override option
pub fn init_rpc_servers(
    config: RpcConfig,
    network: Network,
    blockchain_read: BlockchainReadHandle,
    blockchain_context: BlockchainContextService,
    txpool_read: TxpoolReadHandle,
    tx_handler: IncomingTxHandler,
    mfw_name_index: Option<SharedNameIndex>,
) {
    for ((enable, addr, port, request_byte_limit), restricted) in [
        (
            (
                config.unrestricted.enable,
                config.unrestricted.address,
                unrestricted_rpc_port(config.unrestricted.port, network),
                config.unrestricted.request_byte_limit,
            ),
            false,
        ),
        (
            (
                config.restricted.enable,
                config.restricted.address,
                restricted_rpc_port(config.restricted.port, network),
                config.restricted.request_byte_limit,
            ),
            true,
        ),
    ] {
        if !enable {
            info!(restricted, "Skipping RPC server");
            continue;
        }

        if !restricted && !cuprate_helper::net::ip_is_local(addr) {
            if config
                .unrestricted
                .i_know_what_im_doing_allow_public_unrestricted_rpc
            {
                warn!(
                    address = %addr,
                    "Starting unrestricted RPC on non-local address, this is dangerous!"
                );
            } else {
                panic!("Refusing to start unrestricted RPC on a non-local address ({addr})");
            }
        }

        let rpc_handler = CupratedRpcHandler::new(
            restricted,
            network,
            blockchain_read.clone(),
            blockchain_context.clone(),
            txpool_read.clone(),
            tx_handler.clone(),
        );
        let resolver_index = mfw_name_index.clone();

        tokio::task::spawn(async move {
            run_rpc_server(
                rpc_handler,
                resolver_index,
                restricted,
                SocketAddr::new(addr, port),
                request_byte_limit,
            )
            .await
            .unwrap();
        });
    }

    // Optional gRPC streaming server (opt-in, disabled by default).
    if config.grpc.enable {
        let grpc_handler = CupratedRpcHandler::new(
            false, // gRPC service is unrestricted (same data exposure as bin RPC unrestricted)
            network,
            blockchain_read.clone(),
            blockchain_context.clone(),
            txpool_read.clone(),
            tx_handler.clone(),
        );
        let grpc_addr = config.grpc.address;
        let grpc_port = grpc_rpc_port(config.grpc.port, network);
        let allow_public = config.grpc.i_know_what_im_doing_allow_public_grpc;
        if !cuprate_helper::net::ip_is_local(grpc_addr) && !allow_public {
            panic!("Refusing to start gRPC RPC on a non-local address ({grpc_addr}) without i_know_what_im_doing_allow_public_grpc");
        }
        if !cuprate_helper::net::ip_is_local(grpc_addr) {
            warn!(address = %grpc_addr, "Starting gRPC server on non-local address");
        }
        let bind = SocketAddr::new(grpc_addr, grpc_port);
        let tcp_congestion_control = config.grpc.tcp_congestion_control.clone();
        tokio::task::spawn(async move {
            if let Err(e) =
                run_grpc_server(grpc_handler, mfw_name_index, bind, tcp_congestion_control).await
            {
                eprintln!("[GRPC] server task exited with error: {e:?}");
            }
        });
    } else {
        info!("gRPC streaming RPC disabled (set rpc.grpc.enable = true to enable)");
    }
}

/// Initializes and runs the gRPC streaming RPC server (tonic, HTTP/2).
///
/// The function only returns when the server itself returns or an error
/// occurs. Coexists with the bin RPC axum server on a separate port.
async fn run_grpc_server(
    rpc_handler: CupratedRpcHandler,
    mfw_name_index: Option<SharedNameIndex>,
    address: SocketAddr,
    tcp_congestion_control: Option<String>,
) -> Result<(), Error> {
    use tonic::transport::Server;

    eprintln!("[GRPC] Starting BlockStream server at {address}");
    info!(
        address = %address,
        tcp_congestion_control = ?tcp_congestion_control,
        "Starting gRPC streaming server"
    );

    let svc = grpc::block_stream_service(rpc_handler, mfw_name_index);
    let listener = TcpListener::bind(address).await?;
    let incoming = TcpListenerStream::new(listener).map(move |connection| {
        let stream = connection?;
        if let Some(algorithm) = tcp_congestion_control.as_deref() {
            if let Err(error) = set_grpc_tcp_congestion_control(&stream, algorithm) {
                // Keep wallet data service available if the host kernel does
                // not expose the optional algorithm. The concrete socket
                // error is logged for benchmark evidence; P2P and the system
                // TCP default are never touched here.
                warn!(%error, %algorithm, "Unable to set wallet-gRPC TCP congestion control; using kernel default for this socket");
            }
        }
        Ok::<_, std::io::Error>(stream)
    });

    Server::builder()
        .initial_stream_window_size(Some(grpc::GRPC_HTTP2_STREAM_WINDOW_BYTES))
        .initial_connection_window_size(Some(grpc::GRPC_HTTP2_CONNECTION_WINDOW_BYTES))
        .add_service(svc)
        .serve_with_incoming(incoming)
        .await
        .map_err(|e| anyhow::anyhow!("tonic server error: {e}"))?;

    Ok(())
}

/// Sets congestion control on exactly one accepted wallet-gRPC TCP socket.
/// Linux owns the algorithm registry; no system-wide sysctl is changed.
#[cfg(target_os = "linux")]
fn set_grpc_tcp_congestion_control(
    stream: &tokio::net::TcpStream,
    algorithm: &str,
) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let algorithm = CString::new(algorithm).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "gRPC TCP congestion control must not contain a NUL byte",
        )
    })?;
    // SAFETY: the TCP stream owns a valid file descriptor for this entire
    // call. `algorithm` remains allocated for the pointer and length passed
    // to `setsockopt`, and TCP_CONGESTION expects a NUL-terminated name.
    let result = unsafe {
        libc::setsockopt(
            stream.as_raw_fd(),
            libc::IPPROTO_TCP,
            libc::TCP_CONGESTION,
            algorithm.as_ptr().cast(),
            algorithm.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn set_grpc_tcp_congestion_control(
    _stream: &tokio::net::TcpStream,
    _algorithm: &str,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "per-socket TCP congestion control is only implemented for Linux",
    ))
}

/// This initializes and runs an RPC server.
///
/// The function will only return when the server itself returns or an error occurs.
async fn run_rpc_server(
    rpc_handler: CupratedRpcHandler,
    mfw_name_index: Option<SharedNameIndex>,
    restricted: bool,
    address: SocketAddr,
    request_byte_limit: usize,
) -> Result<(), Error> {
    info!(
        restricted,
        address = %address,
        "Starting RPC server"
    );

    // TODO:
    // - add functions that are `all()` but for restricted RPC
    // - enable aliases automatically `other_get_height` + `other_getheight`?
    let router = RouterBuilder::new()
        .json_rpc()
        .other_get_height()
        .other_getheight()
        .other_get_transactions()
        .other_gettransactions()
        .other_is_key_image_spent()
        .other_send_raw_transaction()
        .other_sendrawtransaction()
        .other_get_transaction_pool()
        .other_get_transaction_pool_hashes()
        .other_get_transaction_pool_stats()
        .other_get_outs()
        .other_get_peer_list()
        .other_get_net_stats()
        .bin_get_blocks()
        .bin_getblocks()
        .bin_get_blocks_by_height()
        .bin_getblocks_by_height()
        .bin_get_hashes()
        .bin_gethashes()
        .bin_get_o_indexes()
        .bin_get_outs()
        .bin_get_transaction_pool_hashes()
        .bin_get_output_distribution()
        .fallback()
        .build()
        .route(
            "/get_info",
            axum::routing::any(get_info_proxy::<CupratedRpcHandler>),
        )
        .route(
            "/getinfo",
            axum::routing::any(get_info_proxy::<CupratedRpcHandler>),
        )
        // wallet2 performs its daemon capability handshake through this
        // legacy-compatible endpoint rather than through `/json_rpc`.
        // Keeping it alongside `/get_info` prevents clients from waiting for
        // their failed-request retry window before beginning a wallet refresh.
        .route(
            "/get_version",
            axum::routing::any(get_version_proxy::<CupratedRpcHandler>),
        )
        .route(
            "/getversion",
            axum::routing::any(get_version_proxy::<CupratedRpcHandler>),
        )
        .with_state(rpc_handler);
    let resolver_router = Router::new()
        .route("/v1/mfw/names/{name}", get(resolve_mfw_name_http))
        .route(
            "/v1/mfw/name-suggestions/{prefix}",
            get(suggest_mfw_names_http),
        )
        .with_state(mfw_name_index);
    let router = router.merge(resolver_router);

    // Add restrictive layers if restricted RPC.
    //
    // TODO: <https://github.com/Cuprate/cuprate/issues/445>
    let router = if request_byte_limit != 0 {
        router.layer(RequestBodyLimitLayer::new(request_byte_limit))
    } else {
        router
    };

    // Start the server.
    //
    // TODO: impl custom server code, don't use axum.
    let listener = TcpListener::bind(address).await?;
    axum::serve(listener, router).await?;

    Ok(())
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MfwNameHttpResponse {
    canonical_name: String,
    status: &'static str,
    network: &'static str,
    address_kind: u8,
    public_spend_key_hex: String,
    public_view_key_hex: String,
    owner_public_key_hex: String,
    sequence: u32,
    record_height: u64,
    source_txid_hex: String,
    expiry_height: u64,
    chain_tip_height: u64,
    confirmations: u64,
    record_payload_hex: String,
    signing_owner_public_key_hex: String,
    record_block_hash_hex: String,
    chain_tip_hash_hex: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct MfwNameSuggestionsHttpResponse {
    prefix: String,
    names: Vec<String>,
}

async fn suggest_mfw_names_http(
    State(index): State<Option<SharedNameIndex>>,
    Path(prefix): Path<String>,
) -> Result<Response, (StatusCode, &'static str)> {
    let index = index.ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "MFW name index is disabled",
    ))?;
    if !index.is_ready() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "MFW name index is restoring or catching up",
        ));
    }
    let guard = index.read().await;
    if !index.is_ready() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "MFW name index changed while suggesting",
        ));
    }
    let normalized = prefix.trim().to_ascii_lowercase();
    let names = guard
        .suggest_names(&normalized, 5)
        .map_err(|_| (StatusCode::BAD_REQUEST, "MFW name prefix is invalid"))?;
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    Ok((
        headers,
        Json(MfwNameSuggestionsHttpResponse {
            prefix: normalized,
            names,
        }),
    )
        .into_response())
}

async fn resolve_mfw_name_http(
    State(index): State<Option<SharedNameIndex>>,
    Path(name): Path<String>,
) -> Result<Response, (StatusCode, &'static str)> {
    let index = index.ok_or((
        StatusCode::SERVICE_UNAVAILABLE,
        "MFW name index is disabled",
    ))?;
    if !index.is_ready() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "MFW name index is restoring or catching up",
        ));
    }
    let guard = index.read().await;
    if !index.is_ready() {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "MFW name index changed while resolving",
        ));
    }
    let network = guard.parameters().network;
    let resolution = guard
        .resolve(&name)
        .map_err(|_| (StatusCode::BAD_REQUEST, "MFW name is invalid"))?;
    let mut headers = HeaderMap::new();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    Ok((headers, Json(mfw_http_response(network, resolution))).into_response())
}

fn mfw_http_response(network: MfwNetwork, resolution: Resolution) -> MfwNameHttpResponse {
    let (address_kind, public_spend_key_hex, public_view_key_hex) = resolution.address.map_or_else(
        || (0, String::new(), String::new()),
        |address| {
            (
                address.kind as u8,
                hex::encode(address.public_spend_key),
                hex::encode(address.public_view_key),
            )
        },
    );
    MfwNameHttpResponse {
        canonical_name: resolution.name.display_name(),
        status: match resolution.status {
            ResolutionStatus::NotFound => "not_found",
            ResolutionStatus::Reserved => "reserved",
            ResolutionStatus::Provisional => "provisional",
            ResolutionStatus::Finalized => "finalized",
            ResolutionStatus::Expired => "expired",
            ResolutionStatus::Revoked => "revoked",
        },
        network: match network {
            MfwNetwork::Mainnet => "mainnet",
            MfwNetwork::Testnet => "testnet",
            MfwNetwork::Stagenet => "stagenet",
        },
        address_kind,
        public_spend_key_hex,
        public_view_key_hex,
        owner_public_key_hex: resolution
            .owner_public_key
            .map_or_else(String::new, hex::encode),
        sequence: resolution.sequence.unwrap_or(0),
        record_height: resolution.record_height.unwrap_or(0),
        source_txid_hex: resolution.source_txid.map_or_else(String::new, hex::encode),
        expiry_height: resolution.expiry_height.unwrap_or(0),
        chain_tip_height: resolution.chain_tip_height.unwrap_or(0),
        confirmations: resolution.confirmations,
        record_payload_hex: resolution
            .record_payload
            .map_or_else(String::new, hex::encode),
        signing_owner_public_key_hex: resolution
            .signing_owner_public_key
            .map_or_else(String::new, hex::encode),
        record_block_hash_hex: resolution
            .record_block_hash
            .map_or_else(String::new, hex::encode),
        chain_tip_hash_hex: resolution
            .chain_tip_hash
            .map_or_else(String::new, hex::encode),
    }
}

/// Proxy /get_info to the JSON-RPC get_info handler.
/// The Monero wallet calls this endpoint directly (not via /json_rpc).
async fn get_info_proxy<H: cuprate_rpc_interface::RpcHandler>(
    State(handler): State<H>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    use cuprate_rpc_types::json::{JsonRpcRequest, JsonRpcResponse};
    use tower::ServiceExt;

    eprintln!("[RPC] /get_info endpoint called");

    let request = JsonRpcRequest::GetInfo(Default::default());

    let response = handler.oneshot(request).await.map_err(|e| {
        eprintln!("[RPC] /get_info handler error: {e:?}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let JsonRpcResponse::GetInfo(info) = response else {
        eprintln!("[RPC] /get_info wrong response variant");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    eprintln!("[RPC] /get_info success, height={}", info.height);

    // Serialize the response as JSON - the wallet expects a flat JSON object
    let json = serde_json::to_value(&info).map_err(|e| {
        eprintln!("[RPC] /get_info serialize error: {e:?}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(json))
}

/// Proxy the legacy `/get_version` endpoint to the JSON-RPC handler.
///
/// `wallet2` uses this direct daemon endpoint while it initializes a remote
/// node.  Cuprate already implements the canonical JSON-RPC method, so this
/// adapter preserves the expected flat JSON response without duplicating any
/// consensus or version logic.
async fn get_version_proxy<H: cuprate_rpc_interface::RpcHandler>(
    State(handler): State<H>,
) -> Result<Json<serde_json::Value>, StatusCode> {
    use cuprate_rpc_types::json::{JsonRpcRequest, JsonRpcResponse};
    use tower::ServiceExt;

    let response = handler
        .oneshot(JsonRpcRequest::GetVersion(Default::default()))
        .await
        .map_err(|error| {
            eprintln!("[RPC] /get_version handler error: {error:?}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let JsonRpcResponse::GetVersion(version) = response else {
        eprintln!("[RPC] /get_version wrong response variant");
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    };

    let json = serde_json::to_value(&version).map_err(|error| {
        eprintln!("[RPC] /get_version serialize error: {error:?}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(Json(json))
}

#[cfg(test)]
mod mfw_http_tests {
    use super::*;
    use mfw_recipient_protocol::{AddressKind, CanonicalName, PublicAddress};

    #[test]
    fn http_response_matches_wallet_json_contract() {
        let mut valid_point = [0x66; 32];
        valid_point[0] = 0x58;
        let resolution = Resolution {
            name: CanonicalName::parse("alice.mfw").unwrap(),
            address: Some(
                PublicAddress::new(AddressKind::Subaddress, valid_point, valid_point).unwrap(),
            ),
            owner_public_key: Some([3; 32]),
            sequence: Some(7),
            record_height: Some(100),
            source_txid: Some([4; 32]),
            record_payload: Some(vec![5; 189]),
            signing_owner_public_key: Some([6; 32]),
            record_block_hash: Some([7; 32]),
            chain_tip_hash: Some([8; 32]),
            expiry_height: Some(2_000),
            chain_tip_height: Some(114),
            confirmations: 15,
            status: ResolutionStatus::Finalized,
        };
        let value =
            serde_json::to_value(mfw_http_response(MfwNetwork::Mainnet, resolution)).unwrap();
        assert_eq!(value["canonicalName"], "alice.mfw");
        assert_eq!(value["status"], "finalized");
        assert_eq!(value["network"], "mainnet");
        assert_eq!(value["addressKind"], 1);
        assert_eq!(value["confirmations"], 15);
        assert_eq!(value["publicSpendKeyHex"], format!("58{}", "66".repeat(31)));
        assert_eq!(value["recordPayloadHex"], "05".repeat(189));
        assert_eq!(value["chainTipHashHex"], "08".repeat(32));
    }

    #[test]
    fn not_found_response_contains_no_record_material() {
        let resolution = Resolution {
            name: CanonicalName::parse("missing.mfw").unwrap(),
            address: None,
            owner_public_key: None,
            sequence: None,
            record_height: None,
            source_txid: None,
            record_payload: None,
            signing_owner_public_key: None,
            record_block_hash: None,
            chain_tip_hash: Some([9; 32]),
            expiry_height: None,
            chain_tip_height: Some(500),
            confirmations: 0,
            status: ResolutionStatus::NotFound,
        };
        let value =
            serde_json::to_value(mfw_http_response(MfwNetwork::Stagenet, resolution)).unwrap();
        assert_eq!(value["status"], "not_found");
        assert_eq!(value["network"], "stagenet");
        assert_eq!(value["ownerPublicKeyHex"], "");
        assert_eq!(value["recordPayloadHex"], "");
        assert_eq!(value["recordHeight"], 0);
        assert_eq!(value["chainTipHeight"], 500);
    }
}
