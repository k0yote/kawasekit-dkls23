//! End-to-end correctness proof: full 2-of-2 DKG -> sign -> verify under a
//! standard ECDSA verifier, on both curves, plus address derivation.
//! Run: `cargo run -p dkls23-benchmarks --example verify_e2e`
use dkls23_benchmarks::meter::NoMeter;
use dkls23_benchmarks::{run_dkg, run_sign};
use dkls23_core::protocols::signing::verify_ecdsa_signature;
use dkls23_core::protocols::Parameters;
use dkls23_core::utilities::hashes::tagged_hash;

fn main() {
    let params = Parameters::new(2, 2).unwrap();
    let session_id = [7u8; 32];
    let sign_id = [9u8; 32];
    let msg = tagged_hash(b"dkls23-bench/verify-e2e", &[b"hello world"]);

    // secp256k1
    let parties = run_dkg::<k256::Secp256k1, _>(&params, &session_id, &mut NoMeter);
    let sig = run_sign::<k256::Secp256k1, _>(&parties, 2, &sign_id, msg, &mut NoMeter);
    let ok = verify_ecdsa_signature::<k256::Secp256k1>(
        &msg,
        &parties[0].pk,
        &hex::encode(sig.r),
        &hex::encode(sig.s),
    );
    assert!(ok, "secp256k1 signature failed to verify");
    let eth = dkls23_secp256k1::compute_eth_address(&parties[0].pk);
    println!("secp256k1: DKG+sign+verify = PASS | eth address = {eth}");

    // secp256r1
    let parties = run_dkg::<p256::NistP256, _>(&params, &session_id, &mut NoMeter);
    let sig = run_sign::<p256::NistP256, _>(&parties, 2, &sign_id, msg, &mut NoMeter);
    let ok = verify_ecdsa_signature::<p256::NistP256>(
        &msg,
        &parties[0].pk,
        &hex::encode(sig.r),
        &hex::encode(sig.s),
    );
    assert!(ok, "secp256r1 signature failed to verify");
    let sui = dkls23_secp256r1::compute_sui_address(&parties[0].pk);
    println!("secp256r1: DKG+sign+verify = PASS | sui address = {sui}");

    println!("ALL CORRECTNESS CHECKS PASSED");
}
