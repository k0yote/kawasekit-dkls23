//! Reports per-operation message bytes + communication rounds for both curves.
//! Byte figure = total serialized size of point-to-point round messages (the
//! dominant wire term); see docs/BENCHMARKS.md for the exact definition.
//! Run: `cargo run -p dkls23-benchmarks --bin metrics --release`
use dkls23_benchmarks::meter::{NoMeter, WireMeter};
use dkls23_benchmarks::{run_dkg, run_refresh_complete, run_refresh_fast, run_sign};
use dkls23_core::curve::DklsCurve;
use dkls23_core::protocols::Parameters;
use dkls23_core::utilities::hashes::tagged_hash;

struct Row {
    op: &'static str,
    curve: &'static str,
    bytes: u64,
    rounds: u32,
}

fn measure<C: DklsCurve>(curve: &'static str, params: &Parameters) -> Vec<Row>
where
    C::Scalar: serde::Serialize,
    C::AffinePoint: serde::Serialize,
{
    let sid = [7u8; 32];
    let rsid = [5u8; 32];
    let sign_id = [9u8; 32];
    let msg = tagged_hash(b"bench", &[b"m"]);
    let mut rows = Vec::new();

    // DKG
    let mut m = WireMeter::default();
    let _ = run_dkg::<C, _>(params, &sid, &mut m);
    rows.push(Row { op: "dkg", curve, bytes: m.bytes, rounds: m.rounds });

    // Sign (parties via NoMeter; measure only signing)
    let parties = run_dkg::<C, _>(params, &sid, &mut NoMeter);
    let mut m = WireMeter::default();
    let _ = run_sign::<C, _>(&parties, 2, &sign_id, msg, &mut m);
    rows.push(Row { op: "sign", curve, bytes: m.bytes, rounds: m.rounds });

    // Refresh complete
    let mut parties = run_dkg::<C, _>(params, &sid, &mut NoMeter);
    let mut m = WireMeter::default();
    let _ = run_refresh_complete::<C, _>(&mut parties, &rsid, &mut m);
    rows.push(Row { op: "refresh_complete", curve, bytes: m.bytes, rounds: m.rounds });

    // Refresh fast
    let mut parties = run_dkg::<C, _>(params, &sid, &mut NoMeter);
    let mut m = WireMeter::default();
    let _ = run_refresh_fast::<C, _>(&mut parties, &rsid, &mut m);
    rows.push(Row { op: "refresh_fast", curve, bytes: m.bytes, rounds: m.rounds });

    rows
}

fn main() {
    let params = Parameters::new(2, 2).unwrap();
    let mut rows = measure::<k256::Secp256k1>("secp256k1", &params);
    rows.extend(measure::<p256::NistP256>("secp256r1", &params));

    // JSON
    println!("{{\"impl\":\"kawasekit-dkls23\",\"config\":\"2-of-2\",\"rows\":[");
    for (i, r) in rows.iter().enumerate() {
        let comma = if i + 1 < rows.len() { "," } else { "" };
        println!(
            "  {{\"op\":\"{}\",\"curve\":\"{}\",\"bytes\":{},\"rounds\":{}}}{}",
            r.op, r.curve, r.bytes, r.rounds, comma
        );
    }
    println!("]}}");

    // Markdown
    println!("\n| op | curve | bytes | rounds |");
    println!("|----|-------|-------|--------|");
    for r in &rows {
        println!("| {} | {} | {} | {} |", r.op, r.curve, r.bytes, r.rounds);
    }
}
