//! RPC server initialization and main loop.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use anyhow::Error;
use tokio::net::TcpListener;
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
    rpc::{grpc, rpc_handler::BlockchainManagerHandle, scanpack::ScanPackStore, CupratedRpcHandler},
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
) {
    let wallet_scan_packs = if config.wallet_scan_cache.enable {
        Some(ScanPackStore::open(config.wallet_scan_cache.directory.clone())
            .unwrap_or_else(|error| panic!("opening wallet scan cache failed: {error:#}")))
    } else {
        None
    };
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
            blockchain_read.clone(),
            blockchain_context.clone(),
            txpool_read.clone(),
            tx_handler.clone(),
            wallet_scan_packs.clone(),
        );

        tokio::task::spawn(async move {
            run_rpc_server(
                rpc_handler,
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
            blockchain_read.clone(),
            blockchain_context.clone(),
            txpool_read.clone(),
            tx_handler.clone(),
            wallet_scan_packs.clone(),
        );
        grpc::spawn_scanpack_builder(grpc_handler.clone(), config.wallet_scan_cache.clone());
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
        tokio::task::spawn(async move {
            if let Err(e) = run_grpc_server(grpc_handler, bind).await {
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
    address: SocketAddr,
) -> Result<(), Error> {
    use tonic::transport::Server;

    eprintln!("[GRPC] Starting BlockStream server at {address}");
    info!(address = %address, "Starting gRPC streaming server");

    let svc = grpc::block_stream_service(rpc_handler);

    Server::builder()
        .initial_stream_window_size(Some(grpc::GRPC_HTTP2_STREAM_WINDOW_BYTES))
        .initial_connection_window_size(Some(grpc::GRPC_HTTP2_CONNECTION_WINDOW_BYTES))
        .add_service(svc)
        .serve(address)
        .await
        .map_err(|e| anyhow::anyhow!("tonic server error: {e}"))?;

    Ok(())
}

/// This initializes and runs an RPC server.
///
/// The function will only return when the server itself returns or an error occurs.
async fn run_rpc_server(
    rpc_handler: CupratedRpcHandler,
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
        .with_state(rpc_handler);

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

/// Proxy /get_info to the JSON-RPC get_info handler.
/// The Monero wallet calls this endpoint directly (not via /json_rpc).
async fn get_info_proxy<H: cuprate_rpc_interface::RpcHandler>(
    axum::extract::State(handler): axum::extract::State<H>,
) -> Result<axum::Json<serde_json::Value>, axum::http::StatusCode> {
    use cuprate_rpc_types::json::{JsonRpcRequest, JsonRpcResponse};
    use tower::ServiceExt;

    eprintln!("[RPC] /get_info endpoint called");

    let request = JsonRpcRequest::GetInfo(Default::default());

    let response = handler.oneshot(request).await.map_err(|e| {
        eprintln!("[RPC] /get_info handler error: {e:?}");
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let JsonRpcResponse::GetInfo(info) = response else {
        eprintln!("[RPC] /get_info wrong response variant");
        return Err(axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    };

    eprintln!("[RPC] /get_info success, height={}", info.height);

    // Serialize the response as JSON - the wallet expects a flat JSON object
    let json = serde_json::to_value(&info).map_err(|e| {
        eprintln!("[RPC] /get_info serialize error: {e:?}");
        axum::http::StatusCode::INTERNAL_SERVER_ERROR
    })?;

    Ok(axum::Json(json))
}
