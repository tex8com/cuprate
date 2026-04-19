fn main() {
    generate_fast_sync_hashes();
    compile_grpc_proto();
}

/// Compiles the gRPC streaming proto file into Rust bindings.
///
/// Output is written to `$OUT_DIR/cuprate.stream.v1.rs` and pulled into the
/// crate via `tonic::include_proto!("cuprate.stream.v1")` from `src/rpc/grpc.rs`.
///
/// Requires `protoc` on PATH. macOS: `brew install protobuf`.
/// Linux: `apt install protobuf-compiler`.
fn compile_grpc_proto() {
    println!("cargo::rerun-if-changed=proto/cuprate_stream.proto");
    tonic_build::configure()
        .build_server(true)
        .build_client(false)
        .compile_protos(&["proto/cuprate_stream.proto"], &["proto"])
        .expect("failed to compile gRPC proto — is protoc installed?");
}

/// Generates `fast_sync_hashes.rs` from `fast_sync_hashes.json`.
///
/// This creates a temporary build file with the
/// `Debug` representation of the hashes, i.e.:
/// ```
/// [[0, 1, 2, ...], [0, 1, 2, ...], [0, 1, 2, ...]]
/// ```
///
/// This is then used in `cuprated` with:
/// ```rust
/// let _: &[[u8; 32]] = &include!(...)
/// ```
fn generate_fast_sync_hashes() {
    println!("cargo::rerun-if-changed=src/blockchain/fast_sync/fast_sync_hashes.json");

    let hashes = serde_json::from_str::<Vec<cuprate_hex::Hex<32>>>(include_str!(
        "src/blockchain/fast_sync/fast_sync_hashes.json"
    ))
    .unwrap()
    .into_iter()
    .map(|h| h.0)
    .collect::<Vec<[u8; 32]>>();

    std::fs::write(
        format!("{}/fast_sync_hashes.rs", std::env::var("OUT_DIR").unwrap()),
        format!("{hashes:?}"),
    )
    .unwrap();
}
