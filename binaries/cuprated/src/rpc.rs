//! RPC
//!
//! Will contain the code to initiate the RPC and a request handler.

mod constants;
pub(crate) mod grpc;
mod handlers;
mod rpc_handler;
mod server;
mod service;

pub use rpc_handler::CupratedRpcHandler;
pub use server::init_rpc_servers;
