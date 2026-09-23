use std::{
    collections::BTreeSet,
    hint::black_box,
    time::{Duration, Instant},
};

use curve25519_dalek::{constants::ED25519_BASEPOINT_POINT, scalar::Scalar};
use mfw_recipient_protocol::{
    combine_phone_token, generate_hpke_keypair, AddressKind, BlockInput, CanonicalName,
    ContactCard, ContactEnvelope, ContactPolicy, ContactSigningKey, IndexedTransaction, NameIndex,
    NameRecord, NameSigningKey, Network, OprfClientSession, OprfServerKey, PhoneToken,
    ProtocolParameters, PublicAddress,
};
use serde_json::json;

const VOPRF_ITERATIONS: u64 = 1_000;
const HPKE_ITERATIONS: u64 = 1_000;
const INDEX_BLOCKS: u64 = 100_000;
const NAME_RESOLVE_ITERATIONS: u64 = 100_000;

fn main() {
    let total_started = Instant::now();
    let (voprf_elapsed, final_token) = benchmark_voprf();
    let (hpke_elapsed, envelope_bytes) = benchmark_hpke();
    let (index_build_elapsed, index_resolve_elapsed, rejected_records) = benchmark_name_index();
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "mfw-recipient-security-bench-v1",
            "voprf": {
                "phone_numbers": VOPRF_ITERATIONS,
                "server_evaluations": VOPRF_ITERATIONS * 2,
                "elapsed_ms": millis(voprf_elapsed),
                "phone_numbers_per_second": rate(VOPRF_ITERATIONS, voprf_elapsed),
                "final_token_prefix": hex::encode(&final_token.0[..4]),
            },
            "hpke_contact_envelopes": {
                "seal_and_open_operations": HPKE_ITERATIONS,
                "elapsed_ms": millis(hpke_elapsed),
                "round_trips_per_second": rate(HPKE_ITERATIONS, hpke_elapsed),
                "fixed_envelope_bytes": envelope_bytes,
            },
            "name_index": {
                "canonical_blocks": INDEX_BLOCKS,
                "build_elapsed_ms": millis(index_build_elapsed),
                "blocks_per_second": rate(INDEX_BLOCKS, index_build_elapsed),
                "cached_resolution_lookups": NAME_RESOLVE_ITERATIONS,
                "cached_resolution_elapsed_ms": millis(index_resolve_elapsed),
                "cached_resolutions_per_second": rate(NAME_RESOLVE_ITERATIONS, index_resolve_elapsed),
                "rejected_records": rejected_records,
            },
            "total_elapsed_ms": millis(total_started.elapsed()),
        }))
        .expect("benchmark JSON serialization")
    );
}

fn benchmark_voprf() -> (Duration, PhoneToken) {
    let first_server = OprfServerKey::from_seed(8, &[1; 32]).expect("first VOPRF key");
    let second_server = OprfServerKey::from_seed(8, &[2; 32]).expect("second VOPRF key");
    let started = Instant::now();
    let mut final_token = PhoneToken([0; 32]);
    for index in 0..VOPRF_ITERATIONS {
        let number = format!("+507{:08}", index + 10_000_000);
        let (first_session, first_request) =
            OprfClientSession::blind(&number, 8).expect("first blind");
        let (second_session, second_request) =
            OprfClientSession::blind(&number, 8).expect("second blind");
        let first_evaluation = first_server
            .evaluate(&first_request)
            .expect("first evaluate");
        let second_evaluation = second_server
            .evaluate(&second_request)
            .expect("second evaluate");
        let first_output = first_session
            .finalize(&first_evaluation, first_server.public_key())
            .expect("first finalize");
        let second_output = second_session
            .finalize(&second_evaluation, second_server.public_key())
            .expect("second finalize");
        final_token = combine_phone_token(
            first_server.public_key(),
            first_output,
            second_server.public_key(),
            second_output,
        )
        .expect("combine token");
        black_box(final_token);
    }
    (started.elapsed(), final_token)
}

fn benchmark_hpke() -> (Duration, usize) {
    let publisher_key = ContactSigningKey::from_bytes([3; 32]);
    let (recipient_private, recipient_public) =
        generate_hpke_keypair().expect("recipient HPKE key");
    let started = Instant::now();
    let mut final_size = 0;
    for index in 0..HPKE_ITERATIONS {
        let mut publisher_token = [4; 32];
        publisher_token[..8].copy_from_slice(&index.to_be_bytes());
        let card = ContactCard {
            policy: ContactPolicy::DirectReceiveAddress,
            network: Network::Mainnet,
            issued_at: 1_000,
            expires_at: 2_000,
            sequence: index,
            publisher_token: PhoneToken(publisher_token),
            recipient_token: PhoneToken([5; 32]),
            address: Some(address(index + 10)),
        };
        let envelope =
            ContactEnvelope::seal(&card, &publisher_key, recipient_public).expect("seal contact");
        final_size = envelope.encode().len();
        let opened = envelope
            .open(
                publisher_key.public_key(),
                &recipient_private,
                recipient_public,
                1_500,
            )
            .expect("open contact");
        assert_eq!(opened, card);
        black_box(opened);
    }
    (started.elapsed(), final_size)
}

fn benchmark_name_index() -> (Duration, Duration, u64) {
    let mut parameters = ProtocolParameters::v1(
        Network::Mainnet,
        0,
        [9; 32],
        BTreeSet::<CanonicalName>::new(),
    );
    parameters.annual_fee_atomic = 10;
    parameters.blocks_per_year = INDEX_BLOCKS + 1;
    parameters.commit_min_confirmations = 15;
    parameters.commit_reveal_window = 720;
    let mut index = NameIndex::new(parameters).expect("name index");
    let owner = NameSigningKey::from_bytes([10; 32]);
    let claim = NameRecord::signed_claim(
        Network::Mainnet,
        CanonicalName::parse("benchmark").expect("name"),
        address(20),
        [11; 16],
        &owner,
    )
    .expect("claim");
    let commit = claim
        .claim_commitment(Network::Mainnet)
        .expect("commit")
        .encode();
    let started = Instant::now();
    for height in 0..INDEX_BLOCKS {
        let transactions = match height {
            0 => vec![IndexedTransaction {
                txid: [1; 32],
                payloads: vec![commit.clone()],
                registry_received_atomic: 0,
            }],
            15 => vec![IndexedTransaction {
                txid: [2; 32],
                payloads: vec![claim.encode().expect("claim encoding")],
                registry_received_atomic: 10,
            }],
            _ => Vec::new(),
        };
        index
            .apply_block(BlockInput {
                height,
                hash: height_hash(height),
                parent_hash: height_hash(height.saturating_sub(1)),
                transactions,
            })
            .expect("canonical block");
    }
    let build_elapsed = started.elapsed();
    let resolve_started = Instant::now();
    for _ in 0..NAME_RESOLVE_ITERATIONS {
        let resolution = index.resolve("benchmark.mfw").expect("resolution");
        assert!(resolution.is_safe_for_payment());
        black_box(resolution);
    }
    let resolve_elapsed = resolve_started.elapsed();
    (
        build_elapsed,
        resolve_elapsed,
        index.rejected_record_count().expect("rejected count"),
    )
}

fn address(seed: u64) -> PublicAddress {
    PublicAddress::new(
        AddressKind::Subaddress,
        (Scalar::from(seed + 1) * ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes(),
        (Scalar::from(seed + 2) * ED25519_BASEPOINT_POINT)
            .compress()
            .to_bytes(),
    )
    .expect("valid address")
}

fn height_hash(height: u64) -> [u8; 32] {
    let mut hash = [0; 32];
    hash[..8].copy_from_slice(&height.to_be_bytes());
    hash
}

fn millis(duration: Duration) -> f64 {
    duration.as_secs_f64() * 1_000.0
}

fn rate(count: u64, duration: Duration) -> f64 {
    count as f64 / duration.as_secs_f64()
}
