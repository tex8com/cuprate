# MFW recipient protocol

The public product name for the chain-backed `.mfw` name registry and its
designated payment destination is **Monero Fast Wallet Registry**.

Security-critical Rust protocol core shared by:

- the Cuprate-derived `.mfw` name index;
- mobile and desktop recipient resolution;
- the two independent RFC 9497 VOPRF evaluators; and
- the opaque private-contact directory.

The crate deliberately contains no HTTP client, SMS provider, blockchain
writer, or transaction broadcaster. Those layers consume its canonical
messages and fail closed on errors.

Run locally:

```sh
cargo test --all-targets
```

No GitHub Actions or CI is required or used by this testbench.
