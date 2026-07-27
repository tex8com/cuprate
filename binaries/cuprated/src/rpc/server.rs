//! RPC server initialization and main loop.

use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};

#[cfg(target_os = "linux")]
use std::ffi::CString;

use anyhow::Error;
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
    rpc::{
        grpc, rpc_handler::BlockchainManagerHandle, scanpack::ScanPackStore, CupratedRpcHandler,
    },
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
    let wallet_scan_packs = if config.wallet_scan_cache.enable {
        Some(
            ScanPackStore::open(
                config.wallet_scan_cache.directory.clone(),
                config.wallet_scan_cache.start_height,
                config.wallet_scan_cache.max_blocks,
                config.wallet_scan_cache.chunk_blocks,
            )
            .unwrap_or_else(|error| panic!("opening wallet scan cache failed: {error:#}")),
        )
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
