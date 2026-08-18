# `cuprated`

This fork optionally publishes the canonical blockchain as signed,
read-optimized `MWSPACK1` packages for the outbound-only Fast Wallet Worker.
Cuprate remains the only Chain-DB and ScanPack writer; the Worker receives a
read-only mount and never a database handle or signing key.

The writer is disabled unless `CUPRATE_SCANPACK_DIRECTORY` is set. A partial or
unsafe configuration fails startup:

```sh
# Create once outside service arguments/environment values:
#   umask 077
#   openssl rand 32 > /etc/cuprate/scanpack-signing.key
export CUPRATE_SCANPACK_DIRECTORY=/var/lib/cuprate/scanpack-v1
export CUPRATE_SCANPACK_SIGNING_KEY_FILE=/etc/cuprate/scanpack-signing.key
export CUPRATE_SCANPACK_START_HEIGHT=0
export CUPRATE_SCANPACK_BLOCKS_PER_PACK=2048
export CUPRATE_SCANPACK_INTERVAL_MS=5000
```

The key file must be a non-symlinked regular file containing exactly 32 raw
bytes (or 64 lowercase hexadecimal characters) with no group/world access.
The writer logs only its public key, holds an exclusive directory lease, reads
pruned blocks and output indices directly from Cuprate's database service, and
publishes immutable content-addressed packages before an atomic signed
manifest commit. It detects append, incomplete-tail growth and reorganization,
publishes a signed freshness/lag status every cycle, and never rewrites bytes
referenced by an older valid manifest.

Run the deterministic crash/reorg/manipulation bench with:

```sh
tools/wallet-testbench/run-scanpack-security-testbench.sh
```
