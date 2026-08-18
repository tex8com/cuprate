<div align="center">
	<img src="misc/logo/wordmark/CuprateWordmark.svg" width="50%"/>

An alternative Monero node implementation.

_(work-in-progress)_

[![Matrix](https://img.shields.io/badge/Matrix-Cuprate-white?logo=matrix&labelColor=grey&logoColor=white)](https://matrix.to/#/#cuprate:monero.social) [![CI](https://github.com/Cuprate/cuprate/actions/workflows/ci.yml/badge.svg)](https://github.com/Cuprate/cuprate/actions/workflows/ci.yml)

</div>

## TEX8 Fork — Wallet Sync Optimizations (`fast-rpc` branch)

**Author:** Roland Kohlhuber  
**Optimized Wallet:** [tex8com/monero-gui](https://github.com/tex8com/monero-gui/tree/fast-crypto) — use both together for gzip compression + larger batches

This fork adds wallet-compatible RPC endpoints and performance optimizations that reduce wallet sync time from **24 minutes to 4 seconds** (360x faster), and enable parallel-client wallet syncs (Ledger initial restore 16 min → 3–4 min when paired with [tex8com/monero-gui](https://github.com/tex8com/monero-gui/tree/fast-crypto)).

### What changed

| Optimization | Impact | Files |
|-------------|--------|-------|
| **`m_block_ids` field name fix** | Enables `fast_refresh` (hash-only sync). Data: 812 MB → 13 MB | `rpc/types/src/bin.rs` |
| **On-the-fly TX pruning** | Strips RCT prunable data via `monero_oxide::Transaction::pruned_with_prunable()`. TX data ~5x smaller | `storage/blockchain/src/ops/block.rs` |
| **Batch output-index lookups** | 1 DB transaction instead of ~6,600 individual calls. Server compute: 30s → 0.66s per batch (46x faster) | `types/types/src/blockchain.rs`, `storage/blockchain/src/service/read.rs`, `binaries/cuprated/src/rpc/service/blockchain.rs` |
| **Optional gzip compression** | Compresses binary RPC responses when client sends `Accept-Encoding: gzip`. Standard wallets get uncompressed responses (fully compatible) | `rpc/interface/src/route/bin.rs`, `rpc/interface/Cargo.toml` |
| **50 MB response cap** | Optimal batch size for pruned block data | `binaries/cuprated/src/rpc/handlers/bin.rs` |
| **DIRECT-BULK `get_hashes` path** | When the client sends an empty `block_ids` + explicit `start_height`, serve up to 100 k hashes in one call via rayon-parallel `BlockHashInRange`. ~100 k hashes in **~12 ms** — enables 16-parallel `fast_refresh` on the wallet side | `binaries/cuprated/src/rpc/handlers/bin.rs`, `types/types/src/blockchain.rs` |
| **Empty-`block_ids` fix in `get_blocks`** | Upstream errored when `block_ids` was empty and `start_height > 0`; now falls back to `top_height` and serves directly from that offset. Required for parallel speculative prefetch from the wallet | `binaries/cuprated/src/rpc/handlers/bin.rs` |
| **LMDB `max_readers` 126 → 512** | 16 parallel wallet clients + P2P sync + txpool readers blew through the default 126-slot table and panicked `cuprated` with `ReadersFull`. Raised cap keeps parallel-client syncs stable | `storage/database/src/backend/heed/env.rs` |
| **Per-request PERF logging + correlation** | Each binary RPC logs `BEGIN id=… active=… req_bytes=… recv_epoch_ms=…` / `END id=… active_remaining=… total_ms=… send_epoch_ms=…`. `id` is taken from the wallet's `X-Perf-Req-Id` header, so wallet and node logs line up one-to-one across machines without a shared clock | `rpc/interface/src/route/bin.rs` |
| **Gzip size/time in log** | `[PERF RPC] … uncompressed=… compressed=… ratio=… gzip_ms=…` — shows when compression helps vs. hurts (random crypto payloads often don't compress) | `rpc/interface/src/route/bin.rs` |
| **Timing logs** | `[TIMING]` diagnostics for block_fetch, index_parse, index_db_batch | `binaries/cuprated/src/rpc/handlers/bin.rs` |

### Benchmark (45,000 blocks, same wallet)

| Setup | Sync Time | Data Transferred |
|-------|-----------|-----------------|
| Standard wallet + monerod (public) | 19s | 22 MB |
| Standard wallet + **this node** | 12s | 13 MB |
| [tex8com/monero-gui](https://github.com/tex8com/monero-gui/tree/fast-crypto) + **this node** | **4s** | gzip compressed |
| This node (localhost, no network) | **4s** | — |

### Ledger initial restore (full chain, ~3.6 M blocks, remote node)

| Phase | Upstream Cuprate + upstream wallet | This node + [tex8com/monero-gui](https://github.com/tex8com/monero-gui/tree/fast-crypto) |
|---|---|---|
| `fast_refresh` (hash phase) | ~6 min (serial, 250 hashes/call) | **~30 s** (16-parallel, 100 k hashes/call via `BlockHashInRange`) |
| Block-scan throughput | ~300 blocks/s | **~738 blocks/s** (speculative prefetch + gzip + tx-pruning) |
| Total restore | ~16 min | **~3–4 min** |

### Compatibility

- Standard Monero wallets (monero-wallet-cli, monero-wallet-gui) work without changes
- gzip compression is **opt-in**: only active when the wallet sends `Accept-Encoding: gzip`
- DIRECT-BULK `get_hashes` only triggers when the client omits `block_ids` and sets `start_height` — standard wallets keep the normal chain-entry path
- All existing Monero RPC endpoints are supported

### Remaining bottleneck

With all of the above enabled, CPU is ~82% idle on the node and the network link is ~50% utilised (12.6 MB/s of a 25 MB/s path). Per-TCP-connection throughput varies 0.69–2.87 MB/s, so each parallel batch waits for its slowest socket — the classic "slowest-wins" TCP-multi-connection ceiling. Further gains require HTTP/2 multiplexing (single congestion window, many streams) or gRPC streaming (server-pushed blocks, no per-batch RTT). Tracked as future work.

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
