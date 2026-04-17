<div align="center">
	<img src="misc/logo/wordmark/CuprateWordmark.svg" width="50%"/>

An alternative Monero node implementation.

_(work-in-progress)_

[![Matrix](https://img.shields.io/badge/Matrix-Cuprate-white?logo=matrix&labelColor=grey&logoColor=white)](https://matrix.to/#/#cuprate:monero.social) [![CI](https://github.com/Cuprate/cuprate/actions/workflows/ci.yml/badge.svg)](https://github.com/Cuprate/cuprate/actions/workflows/ci.yml)

</div>

## TEX8 Fork — Wallet Sync Optimizations (`fast-rpc` branch)

**Author:** Roland Kohlhuber  
**Optimized Wallet:** [tex8com/monero-gui](https://github.com/tex8com/monero-gui/tree/fast-crypto) — use both together for gzip compression + larger batches

This fork adds wallet-compatible RPC endpoints and performance optimizations that reduce wallet sync time from **24 minutes to 4 seconds** (360x faster).

### What changed

| Optimization | Impact | Files |
|-------------|--------|-------|
| **`m_block_ids` field name fix** | Enables `fast_refresh` (hash-only sync). Data: 812 MB → 13 MB | `rpc/types/src/bin.rs` |
| **On-the-fly TX pruning** | Strips RCT prunable data via `monero_oxide::Transaction::pruned_with_prunable()`. TX data ~5x smaller | `storage/blockchain/src/ops/block.rs` |
| **Batch output-index lookups** | 1 DB transaction instead of ~6,600 individual calls. Server compute: 30s → 0.66s per batch (46x faster) | `types/types/src/blockchain.rs`, `storage/blockchain/src/service/read.rs`, `binaries/cuprated/src/rpc/service/blockchain.rs` |
| **Optional gzip compression** | Compresses binary RPC responses when client sends `Accept-Encoding: gzip`. Standard wallets get uncompressed responses (fully compatible) | `rpc/interface/src/route/bin.rs`, `rpc/interface/Cargo.toml` |
| **50 MB response cap** | Optimal batch size for pruned block data | `binaries/cuprated/src/rpc/handlers/bin.rs` |
| **Timing logs** | `[TIMING]` diagnostics for block_fetch, index_parse, index_db_batch | `binaries/cuprated/src/rpc/handlers/bin.rs` |

### Benchmark (45,000 blocks, same wallet)

| Setup | Sync Time | Data Transferred |
|-------|-----------|-----------------|
| Standard wallet + monerod (public) | 19s | 22 MB |
| Standard wallet + **this node** | 12s | 13 MB |
| [tex8com/monero-gui](https://github.com/tex8com/monero-gui/tree/fast-crypto) + **this node** | **4s** | gzip compressed |
| This node (localhost, no network) | **4s** | — |

### Compatibility

- Standard Monero wallets (monero-wallet-cli, monero-wallet-gui) work without changes
- gzip compression is **opt-in**: only active when the wallet sends `Accept-Encoding: gzip`
- All existing Monero RPC endpoints are supported

---

## Contents

- [About](#about)
- [Books](#books)
- [Build](#build)
- [Crates](#crates)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## About

Cuprate is an effort to create an alternative [Monero](https://getmonero.org) node implementation
in [Rust](https://rust-lang.org).

It is able to independently validate Monero consensus rules, providing a layer of security and redundancy for the
Monero network.

See <https://user.cuprate.org> for more details.

## Books

_Cuprate is currently a work-in-progress; documentation will be changing/unfinished._

Cuprate maintains various documentation books:

| Book                                                            | Description                                                |
|-----------------------------------------------------------------|------------------------------------------------------------|
| [Monero's protocol book](https://monero-book.cuprate.org)       | Documents the Monero protocol                              |
| [Cuprate's user book](https://user.cuprate.org)                 | Practical user-guide for using `cuprated`                  |

## Build

To build Cuprate from source code, see <https://user.cuprate.org/getting-started/source.html>.

## Crates
For a detailed list of all crates, see: <https://architecture.cuprate.org/appendix/crates.html>.

For crate (library) documentation, see: <https://doc.cuprate.org>. This site holds documentation for Cuprate's crates and all dependencies. All Cuprate crates start with `cuprate_`, for example: [`cuprate_database`](https://doc.cuprate.org/cuprate_database).

## Contributing

See [`CONTRIBUTING.md`](/CONTRIBUTING.md).

## Security

Cuprate has a responsible vulnerability disclosure policy, see [`SECURITY.md`](/SECURITY.md).

## License

The `binaries/` directory is licensed under AGPL-3.0, everything else is licensed under MIT.

See [`LICENSE`](/LICENSE) for more details.
