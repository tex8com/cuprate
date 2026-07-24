use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4},
    path::PathBuf,
    time::Duration,
};

use serde::{Deserialize, Serialize};

use cuprate_helper::network::Network;

use super::{default::DefaultOrCustom, macros::config_struct};

config_struct! {
    /// RPC config.
    #[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields, default)]
    pub struct RpcConfig {
        #[child = true]
        /// Configuration for the unrestricted RPC server.
        pub unrestricted: UnrestrictedRpcConfig,

        #[child = true]
        /// Configuration for the restricted RPC server.
        pub restricted: RestrictedRpcConfig,

        #[child = true]
        /// Configuration for the gRPC streaming RPC server (opt-in,
        /// disabled by default). Uses HTTP/2 multiplexing + server-streaming
        /// to remove the per-TCP-connection variance that limits the bin
        /// RPC. Compatible wallets can opt in for ~1.6-1.8x more throughput;
        /// standard wallets keep using bin RPC unchanged.
        pub grpc: GrpcConfig,

        #[child = true]
        /// Optional persistent, block-oriented wallet scan cache.
        pub wallet_scan_cache: WalletScanCacheConfig,
    }
}

config_struct! {
    /// Optional sidecar for prepared wallet-scan blocks.
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields, default)]
    pub struct WalletScanCacheConfig {
        /// Enable serving prepared scan packs when available.
        pub enable: bool,
        /// Directory outside the canonical blockchain database.
        pub directory: PathBuf,
        /// First cached block height, inclusive.
        pub start_height: u64,
        /// Maximum retained cached blocks. `-1` retains all blocks from
        /// `start_height`; a positive value creates a moving recent window.
        pub max_blocks: i64,
        /// Maximum blocks per immutable scan pack.
        pub chunk_blocks: usize,
        /// Build missing packs in the background after startup.
        pub build_on_start: bool,
        /// Seconds between checks for new blocks after the initial build.
        pub build_poll_seconds: u64,
    }
}

impl Default for WalletScanCacheConfig {
    fn default() -> Self {
        Self {
            enable: false,
            directory: PathBuf::from("wallet-scan-cache"),
            start_height: 0,
            max_blocks: -1,
            chunk_blocks: 1_000,
            build_on_start: true,
            build_poll_seconds: 30,
        }
    }
}

config_struct! {
    Shared {
        /// The address the RPC server will listen on.
        ///
        /// Type     | IPv4/IPv6 address
        /// Examples | "", "127.0.0.1", "192.168.1.50"
        pub address: IpAddr,

        /// The port the RPC server will listen on.
        ///
        /// Type         | Number or "Default"
        /// Valid values | 0..65534, "Default"
        /// Examples     | 18081, 18089, 5432
        pub port: DefaultOrCustom<u16>,

        /// Toggle the RPC server.
        ///
        /// If `true` the RPC server will be enabled.
        /// If `false` the RPC server will be disabled.
        ///
        /// Type     | boolean
        /// Examples | true, false
        pub enable: bool,

        #[comment_out = true]
        /// If a request is above this byte limit, it will be rejected.
        ///
        /// Setting this to `0` will disable the limit.
        ///
        /// Type         | Number
        /// Valid values | >= 0
        /// Examples     | 0 (no limit), 5242880 (5MB), 10485760 (10MB)
        pub request_byte_limit: usize,

        // TODO: <https://github.com/Cuprate/cuprate/issues/445>
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields, default)]
    pub struct UnrestrictedRpcConfig {
        /// Allow the unrestricted RPC server to be public.
        ///
        /// ⚠️ WARNING ⚠️
        /// -------------
        /// Unrestricted RPC should almost never be made available
        /// to the wider internet. If the unrestricted address
        /// is a non-local address, `cuprated` will crash,
        /// unless this setting is set to `true`.
        ///
        /// Type         | boolean
        /// Valid values | true, false
        pub i_know_what_im_doing_allow_public_unrestricted_rpc: bool,
    }

    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields, default)]
    pub struct RestrictedRpcConfig {
        /// Advertise the restricted RPC port.
        ///
        /// Setting this to `true` will make `cuprated`
        /// share the restricted RPC server's port
        /// publicly to the P2P network.
        ///
        /// Type         | boolean
        /// Valid values | true, false
        pub advertise: bool,
    }
}

impl Default for UnrestrictedRpcConfig {
    fn default() -> Self {
        Self {
            i_know_what_im_doing_allow_public_unrestricted_rpc: false,
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: DefaultOrCustom::Default,
            enable: true,
            request_byte_limit: 0,
        }
    }
}

impl Default for RestrictedRpcConfig {
    fn default() -> Self {
        Self {
            advertise: false,
            address: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            port: DefaultOrCustom::Default,
            enable: false,
            // 1 megabyte.
            // <https://github.com/monero-project/monero/blob/3b01c490953fe92f3c6628fa31d280a4f0490d28/src/cryptonote_config.h#L134>
            request_byte_limit: 1024 * 1024,
        }
    }
}

config_struct! {
    /// gRPC streaming server config (opt-in, disabled by default).
    #[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
    #[serde(deny_unknown_fields, default)]
    pub struct GrpcConfig {
        /// The address the gRPC server will listen on.
        ///
        /// Type     | IPv4/IPv6 address
        /// Examples | "127.0.0.1", "0.0.0.0", "::"
        pub address: IpAddr,

        /// The port the gRPC server will listen on.
        ///
        /// Type         | Number or "Default"
        /// Valid values | 0..65534, "Default"
        /// Examples     | 18091, 28091, 38091
        pub port: DefaultOrCustom<u16>,

        /// Toggle the gRPC server.
        ///
        /// Default `false` — opt-in.
        ///
        /// Type     | boolean
        /// Examples | true, false
        pub enable: bool,

        /// Allow the gRPC server to bind a non-local address.
        ///
        /// Same safety guard as unrestricted bin RPC: refuses to start on
        /// a public address unless explicitly set to true. The gRPC service
        /// exposes the same blockchain data the unrestricted bin RPC does,
        /// so the same risk profile applies.
        ///
        /// Type     | boolean
        /// Examples | true, false
        pub i_know_what_im_doing_allow_public_grpc: bool,
    }
}

impl Default for GrpcConfig {
    fn default() -> Self {
        Self {
            address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: DefaultOrCustom::Default,
            enable: false,
            i_know_what_im_doing_allow_public_grpc: false,
        }
    }
}

/// Gets the port to listen on for the gRPC streaming server.
pub const fn grpc_rpc_port(config: DefaultOrCustom<u16>, network: Network) -> u16 {
    match config {
        DefaultOrCustom::Default => match network {
            Network::Mainnet => 18091,
            Network::Stagenet => 38091,
            Network::Testnet => 28091,
        },
        DefaultOrCustom::Custom(port) => port,
    }
}

/// Gets the port to listen on for restricted RPC connections.
pub const fn restricted_rpc_port(config: DefaultOrCustom<u16>, network: Network) -> u16 {
    match config {
        DefaultOrCustom::Default => match network {
            Network::Mainnet => 18089,
            Network::Stagenet => 38089,
            Network::Testnet => 28089,
        },
        DefaultOrCustom::Custom(port) => port,
    }
}

/// Gets the port to listen on for unrestricted RPC connections.
pub const fn unrestricted_rpc_port(config: DefaultOrCustom<u16>, network: Network) -> u16 {
    match config {
        DefaultOrCustom::Default => match network {
            Network::Mainnet => 18081,
            Network::Stagenet => 38081,
            Network::Testnet => 28081,
        },
        DefaultOrCustom::Custom(port) => port,
    }
}

impl RestrictedRpcConfig {
    /// Return the restricted RPC port for P2P if available and public.
    pub const fn port_for_p2p(&self, network: Network) -> u16 {
        if self.advertise && self.enable {
            restricted_rpc_port(self.port, network)
        } else {
            0
        }
    }
}
