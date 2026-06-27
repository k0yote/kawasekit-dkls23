# DKLs23 Benchmark & Cross-Implementation Comparison — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a reusable in-process benchmark harness (DKG / sign / refresh, secp256k1 + secp256r1, 2-of-2) that also proves correctness, then compare the fork against `0xCarbon/DKLs23@dev` (controlled) and `silence-laboratories/dkls23@main` (indicative), reported in `docs/BENCHMARKS.md`.

**Architecture:** A new `publish = false` workspace crate `dkls23-benchmarks` drives the protocol entirely through the public API (`DkgSession`, `SignSession`, `Party::refresh_*`, `verify_ecdsa_signature`), so **no audited library `src/` is touched**. Helpers are generic over `C: DklsCurve` and over a `Meter` trait: `NoMeter` (zero-cost) for criterion timing, `WireMeter` for message-byte/round accounting. Timings are compute-only (in-process, no serialization in the hot path); bytes/rounds are measured separately.

**Tech Stack:** Rust 2021, criterion 0.5, bincode 1, k256 0.14.0-rc.7, p256 0.14.0-rc.3, the in-repo `dkls23-core` / `dkls23-secp256k1` / `dkls23-secp256r1` crates.

## Global Constraints

- **Do NOT modify any file under `dkls23-core/src`, `dkls23-secp256k1/src`, or `dkls23-secp256r1/src`.** The harness is a separate crate using only the public API. This keeps the `docs/audit-context.md` citation lock untouched.
- **Branch:** all work on `bench/dkls23-comparison` (already created off `dev`).
- **Edition:** `2021` (match the workspace).
- **Exact dependency pins** (must match core so curve types unify): `k256 = "0.14.0-rc.7"`, `p256 = "0.14.0-rc.3"`. Curve crates already have `default = ["serde"]` (enabling `k256/serde` + `p256/serde`), so transmit messages are `Serialize`.
- **Honesty caveats are a required deliverable** in `docs/BENCHMARKS.md`: perf ≠ correctness ≠ security; fork↔0xCarbon is controlled (identical deps); fork↔silence-laboratories is indicative only; in-process/compute-only timings; UNAUDITED status unchanged.
- **Commits:** end every commit message with `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>`. Merges are user-gated. Push over HTTPS: `git -c credential.helper= -c credential.helper='!gh auth git-credential' push https://github.com/k0yote/kawasekit-dkls23.git HEAD:refs/heads/bench/dkls23-comparison`.
- **Curve type names:** secp256k1 = `k256::Secp256k1`; secp256r1 = `p256::NistP256`. Address fns: `dkls23_secp256k1::compute_eth_address`, `dkls23_secp256r1::compute_sui_address`.
- **Scratchpad** (external clones, never committed): `/private/tmp/claude-501/-Users-jongmin-yu-Documents-workspaces-project-kawasekit-dkls23/5d3519d2-bdf1-4a1e-a136-259e44c958de/scratchpad`.

---

## File Structure

```
dkls23-benchmarks/
  Cargo.toml                 # new workspace member, publish = false
  src/
    lib.rs                   # module wiring + re-exports
    meter.rs                 # Meter trait, NoMeter (zero-cost), WireMeter
    route.rs                 # messages_for() routing helper
    dkg.rs                   # run_dkg<C, M>
    sign.rs                  # run_sign<C, M>
    refresh.rs               # run_refresh_complete<C, M>, run_refresh_fast<C, M>
    bin/
      metrics.rs             # WireMeter-based bytes/rounds reporter (JSON + markdown)
  benches/
    dkls.rs                  # criterion groups: dkg/sign/refresh_complete/refresh_fast × {k1,r1}
  examples/
    verify_e2e.rs            # DKG→sign→verify→address on both curves (correctness artifact)
Cargo.toml                   # MODIFY: add "dkls23-benchmarks" to workspace members
docs/BENCHMARKS.md           # results + methodology + caveats
```

---

## Task 1: Scaffold the `dkls23-benchmarks` crate (meter + routing)

**Files:**
- Modify: `Cargo.toml` (workspace `members`)
- Create: `dkls23-benchmarks/Cargo.toml`
- Create: `dkls23-benchmarks/src/lib.rs`
- Create: `dkls23-benchmarks/src/meter.rs`
- Create: `dkls23-benchmarks/src/route.rs`

**Interfaces:**
- Produces: `meter::Meter` (trait), `meter::NoMeter`, `meter::WireMeter { bytes: u64, rounds: u32 }`; `route::messages_for<M>(receiver, all, recv_of) -> Vec<M>`.

- [ ] **Step 1: Add the crate to the workspace members**

Modify `Cargo.toml` (repo root) — add the new member:

```toml
[workspace]
members = [
    "dkls23-core",
    "dkls23-secp256k1",
    "dkls23-secp256r1",
    "dkls23-benchmarks",
]
resolver = "2"
```

- [ ] **Step 2: Create `dkls23-benchmarks/Cargo.toml`**

```toml
[package]
name = "dkls23-benchmarks"
version = "0.0.0"
edition = "2021"
publish = false

[dependencies]
dkls23-core = { path = "../dkls23-core" }
dkls23-secp256k1 = { path = "../dkls23-secp256k1" }
dkls23-secp256r1 = { path = "../dkls23-secp256r1" }
k256 = "0.14.0-rc.7"
p256 = "0.14.0-rc.3"
bincode = "1"
hex = "0.4"

[dev-dependencies]
criterion = "0.5"

[[bench]]
name = "dkls"
harness = false
```

- [ ] **Step 3: Create `dkls23-benchmarks/src/meter.rs`**

```rust
//! Message-size / round accounting, abstracted so the timed path pays nothing.
use serde::Serialize;

/// Records on-the-wire message sizes and communication rounds.
///
/// The criterion timing path uses [`NoMeter`] (all methods are no-ops the
/// optimizer removes), so serialization never pollutes a timing measurement.
/// The metrics binary uses [`WireMeter`] to accumulate real byte counts.
pub trait Meter {
    fn record<T: Serialize>(&mut self, messages: &[T]);
    fn end_round(&mut self);
}

/// Zero-cost meter used while timing. `record` / `end_round` compile to nothing.
pub struct NoMeter;

impl Meter for NoMeter {
    #[inline(always)]
    fn record<T: Serialize>(&mut self, _messages: &[T]) {}
    #[inline(always)]
    fn end_round(&mut self) {}
}

/// Accumulating meter for the metrics binary.
///
/// `bytes` is the total serialized size of the point-to-point round messages
/// produced (each produced message counted once). `rounds` counts communication
/// rounds via [`Meter::end_round`].
#[derive(Default, Debug, Clone)]
pub struct WireMeter {
    pub bytes: u64,
    pub rounds: u32,
}

impl Meter for WireMeter {
    fn record<T: Serialize>(&mut self, messages: &[T]) {
        for m in messages {
            self.bytes += bincode::serialized_size(m).expect("transmit message must serialize");
        }
    }
    fn end_round(&mut self) {
        self.rounds += 1;
    }
}
```

- [ ] **Step 4: Create `dkls23-benchmarks/src/route.rs`**

```rust
//! Point-to-point message routing shared by every protocol helper.
use dkls23_core::protocols::PartyIndex;

/// Collects, from every party's outbound batch, the messages addressed to `receiver`.
/// `recv_of` extracts a message's destination (always `m.parties.receiver`).
pub fn messages_for<M: Clone>(
    receiver: PartyIndex,
    all: &[Vec<M>],
    recv_of: impl Fn(&M) -> PartyIndex,
) -> Vec<M> {
    all.iter()
        .flatten()
        .filter(|m| recv_of(m) == receiver)
        .cloned()
        .collect()
}
```

- [ ] **Step 5: Create `dkls23-benchmarks/src/lib.rs`**

```rust
//! In-process DKLs23 benchmark + correctness harness.
//!
//! Drives DKG / signing / refresh through the public API only — no library
//! `src/` is touched. Generic over the curve (`C: DklsCurve`) and over a
//! [`meter::Meter`] so the same orchestration serves both criterion timing
//! (`NoMeter`) and message-size accounting (`WireMeter`).
pub mod meter;
pub mod route;

pub mod dkg;
pub mod sign;
pub mod refresh;

pub use dkg::run_dkg;
pub use refresh::{run_refresh_complete, run_refresh_fast};
pub use sign::run_sign;
```

Note: `dkg`/`sign`/`refresh` modules are created in later tasks. To compile Task 1 in isolation, temporarily comment out the three `pub mod` + `pub use` lines for those modules, or create empty stub files. The clean approach: create the three module files as empty (`// filled in Task N`) now so the crate compiles. Add:

```bash
# from repo root
printf '// run_dkg — Task 2\n' > dkls23-benchmarks/src/dkg.rs
printf '// run_sign — Task 3\n' > dkls23-benchmarks/src/sign.rs
printf '// run_refresh_* — Task 5\n' > dkls23-benchmarks/src/refresh.rs
```

…and in `lib.rs` keep only `pub mod meter; pub mod route;` for now; re-enable the others as they are filled. (Simplest: comment the `dkg`/`sign`/`refresh` lines in Task 1 and uncomment per task.)

- [ ] **Step 6: Add a unit test for the meter and router**

Append to `dkls23-benchmarks/src/route.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::meter::{Meter, WireMeter};
    use dkls23_core::protocols::{PartiesMessage, PartyIndex};

    fn pi(n: u8) -> PartyIndex {
        PartyIndex::new(n).unwrap()
    }

    #[test]
    fn messages_for_filters_by_receiver() {
        // Two parties each send one message to the other.
        let p1_out = vec![PartiesMessage { sender: pi(1), receiver: pi(2) }];
        let p2_out = vec![PartiesMessage { sender: pi(2), receiver: pi(1) }];
        let all = vec![p1_out, p2_out];

        let to_1 = messages_for(pi(1), &all, |m| m.receiver);
        assert_eq!(to_1.len(), 1);
        assert_eq!(to_1[0].sender, pi(2));
    }

    #[test]
    fn wiremeter_counts_bytes_and_rounds() {
        let mut m = WireMeter::default();
        let msgs = vec![PartiesMessage { sender: pi(1), receiver: pi(2) }];
        m.record(&msgs);
        m.end_round();
        assert!(m.bytes > 0, "should count serialized bytes");
        assert_eq!(m.rounds, 1);
    }
}
```

(`PartiesMessage` is `pub` with `pub sender` / `pub receiver: PartyIndex` and derives `Serialize` under the default `serde` feature.)

- [ ] **Step 7: Build and test**

Run: `cargo test -p dkls23-benchmarks`
Expected: PASS (2 tests). Also `cargo build -p dkls23-benchmarks` succeeds.

- [ ] **Step 8: Commit**

```bash
git add Cargo.toml dkls23-benchmarks/Cargo.toml dkls23-benchmarks/src/
git commit -m "feat(bench): scaffold dkls23-benchmarks crate (meter + routing)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: `run_dkg<C, M>` — full DKG orchestration

**Files:**
- Create/replace: `dkls23-benchmarks/src/dkg.rs`
- Re-enable `pub mod dkg; pub use dkg::run_dkg;` in `src/lib.rs`

**Interfaces:**
- Consumes: `meter::Meter`, `route::messages_for`.
- Produces: `run_dkg<C: DklsCurve, M: Meter>(parameters: &Parameters, session_id: &[u8], meter: &mut M) -> Vec<Party<C>>`.

Ported from `dkls23-core/src/protocols/dkg_session.rs::test_dkg_session_full_flow`, generalizing `Secp256k1` → `C` and `k256::Scalar` → `C::Scalar`, using the `DkgSession` public API.

- [ ] **Step 1: Write the failing test**

Append to `dkls23-benchmarks/src/dkg.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::meter::NoMeter;
    use dkls23_core::protocols::Parameters;

    #[test]
    fn dkg_2of2_parties_agree_on_pk() {
        let params = Parameters::new(2, 2).unwrap();
        let parties = run_dkg::<k256::Secp256k1, _>(&params, &[7u8; 32], &mut NoMeter);
        assert_eq!(parties.len(), 2);
        // All parties must share the same group public key and chain code.
        assert_eq!(parties[0].pk, parties[1].pk);
        assert_eq!(
            parties[0].derivation_data.chain_code,
            parties[1].derivation_data.chain_code
        );
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p dkls23-benchmarks dkg_2of2_parties_agree_on_pk`
Expected: FAIL to compile — `run_dkg` not found.

- [ ] **Step 3: Write the implementation**

Put this at the TOP of `dkls23-benchmarks/src/dkg.rs` (above the `#[cfg(test)]` module):

```rust
//! Full distributed key generation, driven via the `DkgSession` public API.
use std::collections::BTreeMap;

use dkls23_core::curve::DklsCurve;
use dkls23_core::protocols::dkg::{
    BroadcastDerivationPhase2to4, BroadcastDerivationPhase3to4, ProofCommitment,
    TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
};
use dkls23_core::protocols::dkg_session::DkgSession;
use dkls23_core::protocols::{Parameters, Party, PartyIndex};

use crate::meter::Meter;
use crate::route::messages_for;

/// Runs a full in-process DKG for the given parameters and returns the parties.
/// `meter` records wire bytes/rounds; pass `&mut NoMeter` for timing.
pub fn run_dkg<C: DklsCurve, M: Meter>(
    parameters: &Parameters,
    session_id: &[u8],
    meter: &mut M,
) -> Vec<Party<C>> {
    let n = parameters.share_count as usize;

    let mut sessions: Vec<DkgSession<C>> = (0..parameters.share_count)
        .map(|i| {
            DkgSession::new(
                parameters.clone(),
                PartyIndex::new(i + 1).unwrap(),
                session_id.to_vec(),
            )
        })
        .collect();

    // Phase 1
    let mut dkg_1: Vec<Vec<C::Scalar>> = Vec::with_capacity(n);
    for session in &sessions {
        dkg_1.push(session.phase1());
    }

    // Round 1: transpose poly fragments (party i's row column j -> party j).
    let mut poly_fragments = vec![Vec::<C::Scalar>::with_capacity(n); n];
    for row in dkg_1 {
        for j in 0..parameters.share_count {
            poly_fragments[j as usize].push(row[j as usize]);
        }
    }
    meter.record(&poly_fragments);
    meter.end_round();

    // Phase 2
    let mut proofs_commitments: Vec<ProofCommitment<C>> = Vec::with_capacity(n);
    let mut zero_transmit_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    let mut bip_broadcast_2to4: BTreeMap<PartyIndex, BroadcastDerivationPhase2to4> = BTreeMap::new();
    for (i, session) in sessions.iter_mut().enumerate() {
        let (proof_commitment, zero_transmit, bip_broadcast) =
            session.phase2(&poly_fragments[i]).unwrap();
        proofs_commitments.push(proof_commitment);
        zero_transmit_2to4.push(zero_transmit);
        bip_broadcast_2to4.insert(PartyIndex::new(i as u8 + 1).unwrap(), bip_broadcast);
    }

    // Round 2: route zero-share messages.
    let mut zero_received_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    for i in 1..=parameters.share_count {
        let pi = PartyIndex::new(i).unwrap();
        zero_received_2to4.push(messages_for(pi, &zero_transmit_2to4, |m| m.parties.receiver));
    }
    for v in &zero_transmit_2to4 {
        meter.record(v);
    }
    meter.end_round();

    // Phase 3
    let mut zero_transmit_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4<C>>> = Vec::with_capacity(n);
    let mut bip_broadcast_3to4: BTreeMap<PartyIndex, BroadcastDerivationPhase3to4> = BTreeMap::new();
    for (i, session) in sessions.iter_mut().enumerate() {
        let (zero_transmit, mul_transmit, bip_broadcast) = session.phase3().unwrap();
        zero_transmit_3to4.push(zero_transmit);
        mul_transmit_3to4.push(mul_transmit);
        bip_broadcast_3to4.insert(PartyIndex::new(i as u8 + 1).unwrap(), bip_broadcast);
    }

    // Round 3: route zero-share + mul messages.
    let mut zero_received_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4<C>>> = Vec::with_capacity(n);
    for i in 1..=parameters.share_count {
        let pi = PartyIndex::new(i).unwrap();
        zero_received_3to4.push(messages_for(pi, &zero_transmit_3to4, |m| m.parties.receiver));
        mul_received_3to4.push(messages_for(pi, &mul_transmit_3to4, |m| m.parties.receiver));
    }
    for v in &zero_transmit_3to4 {
        meter.record(v);
    }
    for v in &mul_transmit_3to4 {
        meter.record(v);
    }
    meter.end_round();

    // Phase 4
    let mut parties: Vec<Party<C>> = Vec::with_capacity(n);
    for (i, session) in sessions.into_iter().enumerate() {
        let (party, _pkg) = session
            .phase4(
                &proofs_commitments,
                &zero_received_2to4[i],
                &zero_received_3to4[i],
                &mul_received_3to4[i],
                &bip_broadcast_2to4,
                &bip_broadcast_3to4,
                |_| String::new(),
            )
            .unwrap();
        parties.push(party);
    }
    parties
}
```

Ensure `src/lib.rs` has `pub mod dkg;` and `pub use dkg::run_dkg;` uncommented.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p dkls23-benchmarks dkg_2of2_parties_agree_on_pk`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add dkls23-benchmarks/src/dkg.rs dkls23-benchmarks/src/lib.rs
git commit -m "feat(bench): generic run_dkg<C, M> full-DKG harness

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: `run_sign<C, M>` — signing orchestration (sign correctness gate)

**Files:**
- Create/replace: `dkls23-benchmarks/src/sign.rs`
- Re-enable `pub mod sign; pub use sign::run_sign;` in `src/lib.rs`

**Interfaces:**
- Consumes: `meter::Meter`, `run_dkg` (in the test).
- Produces: `run_sign<C: DklsCurve, M: Meter>(parties: &[Party<C>], threshold: u8, sign_id: &[u8], message_hash: HashOutput, meter: &mut M) -> EcdsaSignature`.

Ported from `dkls23-core/src/protocols/sign_session.rs::test_sign_session_happy_path`, generalizing to `C` and taking externally-produced `parties`.

- [ ] **Step 1: Write the failing test**

Append to `dkls23-benchmarks/src/sign.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::meter::NoMeter;
    use crate::run_dkg;
    use dkls23_core::protocols::signing::verify_ecdsa_signature;
    use dkls23_core::protocols::Parameters;
    use dkls23_core::utilities::hashes::tagged_hash;

    #[test]
    fn sign_2of2_verifies_under_standard_ecdsa() {
        let params = Parameters::new(2, 2).unwrap();
        let parties = run_dkg::<k256::Secp256k1, _>(&params, &[7u8; 32], &mut NoMeter);
        let msg = tagged_hash(b"dkls23-bench", &[b"correctness gate"]);

        let sig = run_sign::<k256::Secp256k1, _>(&parties, 2, &[9u8; 32], msg, &mut NoMeter);

        let r_hex = hex::encode(sig.r);
        let s_hex = hex::encode(sig.s);
        assert!(
            verify_ecdsa_signature::<k256::Secp256k1>(&msg, &parties[0].pk, &r_hex, &s_hex),
            "threshold signature must verify under a standard secp256k1 verifier"
        );
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p dkls23-benchmarks sign_2of2_verifies_under_standard_ecdsa`
Expected: FAIL to compile — `run_sign` not found.

- [ ] **Step 3: Write the implementation**

Put this at the TOP of `dkls23-benchmarks/src/sign.rs`:

```rust
//! Threshold signing, driven via the `SignSession` public API.
use std::collections::BTreeMap;

use dkls23_core::curve::DklsCurve;
use dkls23_core::protocols::sign_session::SignSession;
use dkls23_core::protocols::signature::EcdsaSignature;
use dkls23_core::protocols::signing::{
    Broadcast3to4, SignData, TransmitPhase1to2, TransmitPhase2to3,
};
use dkls23_core::protocols::{Party, PartyIndex};
use dkls23_core::utilities::hashes::HashOutput;

use crate::meter::Meter;

/// Runs a full threshold signing among parties `1..=threshold` and returns the
/// canonical low-S `EcdsaSignature`. `parties` come from [`crate::run_dkg`].
pub fn run_sign<C: DklsCurve, M: Meter>(
    parties: &[Party<C>],
    threshold: u8,
    sign_id: &[u8],
    message_hash: HashOutput,
    meter: &mut M,
) -> EcdsaSignature {
    let executing: Vec<u8> = (1..=threshold).collect();

    // Per-party SignData.
    let mut data: BTreeMap<u8, SignData> = BTreeMap::new();
    for &pidx in &executing {
        let counterparties: Vec<PartyIndex> = executing
            .iter()
            .filter(|&&i| i != pidx)
            .map(|&i| PartyIndex::new(i).unwrap())
            .collect();
        data.insert(
            pidx,
            SignData {
                sign_id: sign_id.to_vec(),
                counterparties,
                message_hash,
            },
        );
    }

    // Phase 1 — create sessions.
    let mut sessions: BTreeMap<u8, SignSession<'_, C>> = BTreeMap::new();
    let mut transmit_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
    for &pidx in &executing {
        let (session, transmit) = SignSession::new(
            &parties[(pidx - 1) as usize],
            data.get(&pidx).unwrap().clone(),
        )
        .unwrap();
        sessions.insert(pidx, session);
        transmit_1to2.insert(pidx, transmit);
    }
    for v in transmit_1to2.values() {
        meter.record(v);
    }
    meter.end_round();

    // Route round 1.
    let mut received_1to2: BTreeMap<u8, Vec<TransmitPhase1to2>> = BTreeMap::new();
    for &pidx in &executing {
        let pi = PartyIndex::new(pidx).unwrap();
        let msgs: Vec<TransmitPhase1to2> = transmit_1to2
            .values()
            .flatten()
            .filter(|m| m.parties.receiver == pi)
            .cloned()
            .collect();
        received_1to2.insert(pidx, msgs);
    }

    // Phase 2.
    let mut transmit_2to3: BTreeMap<u8, Vec<TransmitPhase2to3<C>>> = BTreeMap::new();
    for &pidx in &executing {
        let t = sessions
            .get_mut(&pidx)
            .unwrap()
            .phase2(received_1to2.get(&pidx).unwrap())
            .unwrap();
        transmit_2to3.insert(pidx, t);
    }
    for v in transmit_2to3.values() {
        meter.record(v);
    }
    meter.end_round();

    // Route round 2.
    let mut received_2to3: BTreeMap<u8, Vec<TransmitPhase2to3<C>>> = BTreeMap::new();
    for &pidx in &executing {
        let pi = PartyIndex::new(pidx).unwrap();
        let msgs: Vec<TransmitPhase2to3<C>> = transmit_2to3
            .values()
            .flatten()
            .filter(|m| m.parties.receiver == pi)
            .cloned()
            .collect();
        received_2to3.insert(pidx, msgs);
    }

    // Phase 3.
    let mut broadcasts: Vec<Broadcast3to4<C>> = Vec::with_capacity(threshold as usize);
    for &pidx in &executing {
        let b = sessions
            .get_mut(&pidx)
            .unwrap()
            .phase3(received_2to3.get(&pidx).unwrap())
            .unwrap();
        broadcasts.push(b);
    }
    meter.record(&broadcasts);
    meter.end_round();

    // Phase 4 — first party assembles the signature.
    let first = executing[0];
    let session = sessions.remove(&first).unwrap();
    session.phase4(&broadcasts).unwrap()
}
```

Uncomment `pub mod sign; pub use sign::run_sign;` in `src/lib.rs`.

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test -p dkls23-benchmarks sign_2of2_verifies_under_standard_ecdsa`
Expected: PASS — this is the **signing correctness gate**.

- [ ] **Step 5: Commit**

```bash
git add dkls23-benchmarks/src/sign.rs dkls23-benchmarks/src/lib.rs
git commit -m "feat(bench): generic run_sign<C, M>; signature verifies under standard ECDSA

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: `examples/verify_e2e.rs` — runnable correctness artifact (Phase 0)

**Files:**
- Create: `dkls23-benchmarks/examples/verify_e2e.rs`

**Interfaces:**
- Consumes: `run_dkg`, `run_sign`, `meter::NoMeter`; `verify_ecdsa_signature`; curve address fns.

- [ ] **Step 1: Write the example**

```rust
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
```

- [ ] **Step 2: Run the example**

Run: `cargo run -p dkls23-benchmarks --example verify_e2e`
Expected output (addresses vary per run): three lines ending in `ALL CORRECTNESS CHECKS PASSED`, exit code 0.

- [ ] **Step 3: Commit**

```bash
git add dkls23-benchmarks/examples/verify_e2e.rs
git commit -m "feat(bench): verify_e2e example — DKG+sign+verify+address, both curves

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: `run_refresh_complete<C, M>` and `run_refresh_fast<C, M>`

**Files:**
- Create/replace: `dkls23-benchmarks/src/refresh.rs`
- Re-enable `pub mod refresh; pub use refresh::{run_refresh_complete, run_refresh_fast};` in `src/lib.rs`

**Interfaces:**
- Consumes: `meter::Meter`, `route::messages_for`.
- Produces:
  - `run_refresh_complete<C: DklsCurve, M: Meter>(parties: &mut [Party<C>], refresh_sid: &[u8], meter: &mut M) -> Vec<Party<C>>`
  - `run_refresh_fast<C: DklsCurve, M: Meter>(parties: &mut [Party<C>], refresh_sid: &[u8], meter: &mut M) -> Vec<Party<C>>`

Ported from `refresh.rs::test_refresh_complete` and `refresh.rs::test_refresh`, generalizing to `C`. Note `refresh_*_phase4` takes `&mut self` (zeroizes the old share, self-audit M3), so `parties` is `&mut`.

- [ ] **Step 1: Write the failing test**

Append to `dkls23-benchmarks/src/refresh.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::meter::NoMeter;
    use crate::{run_dkg, run_sign};
    use dkls23_core::protocols::signing::verify_ecdsa_signature;
    use dkls23_core::protocols::Parameters;
    use dkls23_core::utilities::hashes::tagged_hash;

    fn refresh_preserves_pk_and_signing<C: dkls23_core::curve::DklsCurve>(
        fast: bool,
    ) {
        let params = Parameters::new(2, 2).unwrap();
        let mut parties = run_dkg::<C, _>(&params, &[7u8; 32], &mut NoMeter);
        let pk_before = parties[0].pk;

        let refreshed = if fast {
            run_refresh_fast::<C, _>(&mut parties, &[5u8; 32], &mut NoMeter)
        } else {
            run_refresh_complete::<C, _>(&mut parties, &[5u8; 32], &mut NoMeter)
        };

        // Same public key after refresh.
        assert_eq!(pk_before, refreshed[0].pk);
        assert_eq!(refreshed[0].pk, refreshed[1].pk);

        // Refreshed shares still produce a verifying signature.
        let msg = tagged_hash(b"dkls23-bench", &[b"post-refresh"]);
        let sig = run_sign::<C, _>(&refreshed, 2, &[9u8; 32], msg, &mut NoMeter);
        assert!(verify_ecdsa_signature::<C>(
            &msg,
            &refreshed[0].pk,
            &hex::encode(sig.r),
            &hex::encode(sig.s),
        ));
    }

    #[test]
    fn refresh_complete_k256() {
        refresh_preserves_pk_and_signing::<k256::Secp256k1>(false);
    }

    #[test]
    fn refresh_fast_k256() {
        refresh_preserves_pk_and_signing::<k256::Secp256k1>(true);
    }
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test -p dkls23-benchmarks refresh_`
Expected: FAIL to compile — `run_refresh_complete` / `run_refresh_fast` not found.

- [ ] **Step 3: Write the implementation**

Put this at the TOP of `dkls23-benchmarks/src/refresh.rs`:

```rust
//! Proactive refresh (both the complete and fast variants), via `Party::refresh_*`.
use std::collections::BTreeMap;

use dkls23_core::curve::DklsCurve;
use dkls23_core::protocols::dkg::{
    KeepInitMulPhase3to4, KeepInitZeroSharePhase2to3, KeepInitZeroSharePhase3to4, ProofCommitment,
    TransmitInitMulPhase3to4, TransmitInitZeroSharePhase2to4, TransmitInitZeroSharePhase3to4,
};
use dkls23_core::protocols::refresh::{
    KeepRefreshPhase2to3, KeepRefreshPhase3to4, TransmitRefreshPhase2to4, TransmitRefreshPhase3to4,
};
use dkls23_core::protocols::{Party, PartyIndex};

use crate::meter::Meter;
use crate::route::messages_for;

/// Complete refresh: reruns DKG forcing the same public key. Reinitializes the
/// multiplication protocol from scratch (3 communication rounds).
pub fn run_refresh_complete<C: DklsCurve, M: Meter>(
    parties: &mut [Party<C>],
    refresh_sid: &[u8],
    meter: &mut M,
) -> Vec<Party<C>> {
    let n = parties.len();

    // Phase 1
    let mut dkg_1: Vec<Vec<C::Scalar>> = Vec::with_capacity(n);
    for p in parties.iter() {
        dkg_1.push(p.refresh_complete_phase1());
    }
    let mut poly_fragments = vec![Vec::<C::Scalar>::with_capacity(n); n];
    for row in dkg_1 {
        for j in 0..n {
            poly_fragments[j].push(row[j]);
        }
    }
    meter.record(&poly_fragments);
    meter.end_round();

    // Phase 2
    let mut correction_values: Vec<C::Scalar> = Vec::with_capacity(n);
    let mut proofs_commitments: Vec<ProofCommitment<C>> = Vec::with_capacity(n);
    let mut zero_kept_2to3: Vec<BTreeMap<PartyIndex, KeepInitZeroSharePhase2to3>> =
        Vec::with_capacity(n);
    let mut zero_transmit_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    for (i, p) in parties.iter().enumerate() {
        let (cv, pc, zk, zt) = p.refresh_complete_phase2(refresh_sid, &poly_fragments[i]);
        correction_values.push(cv);
        proofs_commitments.push(pc);
        zero_kept_2to3.push(zk);
        zero_transmit_2to4.push(zt);
    }
    let mut zero_received_2to4: Vec<Vec<TransmitInitZeroSharePhase2to4>> = Vec::with_capacity(n);
    for i in 1..=n as u8 {
        let pi = PartyIndex::new(i).unwrap();
        zero_received_2to4.push(messages_for(pi, &zero_transmit_2to4, |m| m.parties.receiver));
    }
    for v in &zero_transmit_2to4 {
        meter.record(v);
    }
    meter.end_round();

    // Phase 3
    let mut zero_kept_3to4: Vec<BTreeMap<PartyIndex, KeepInitZeroSharePhase3to4>> =
        Vec::with_capacity(n);
    let mut zero_transmit_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mul_kept_3to4: Vec<BTreeMap<PartyIndex, KeepInitMulPhase3to4<C>>> = Vec::with_capacity(n);
    let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4<C>>> = Vec::with_capacity(n);
    for (i, p) in parties.iter().enumerate() {
        let (zk, zt, mk, mt) = p.refresh_complete_phase3(refresh_sid, &zero_kept_2to3[i]);
        zero_kept_3to4.push(zk);
        zero_transmit_3to4.push(zt);
        mul_kept_3to4.push(mk);
        mul_transmit_3to4.push(mt);
    }
    let mut zero_received_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mul_received_3to4: Vec<Vec<TransmitInitMulPhase3to4<C>>> = Vec::with_capacity(n);
    for i in 1..=n as u8 {
        let pi = PartyIndex::new(i).unwrap();
        zero_received_3to4.push(messages_for(pi, &zero_transmit_3to4, |m| m.parties.receiver));
        mul_received_3to4.push(messages_for(pi, &mul_transmit_3to4, |m| m.parties.receiver));
    }
    for v in &zero_transmit_3to4 {
        meter.record(v);
    }
    for v in &mul_transmit_3to4 {
        meter.record(v);
    }
    meter.end_round();

    // Phase 4 (&mut self — zeroizes the old share).
    let mut refreshed: Vec<Party<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let party = parties[i]
            .refresh_complete_phase4(
                refresh_sid,
                &correction_values[i],
                &proofs_commitments,
                &zero_kept_3to4[i],
                &zero_received_2to4[i],
                &zero_received_3to4[i],
                &mul_kept_3to4[i],
                &mul_received_3to4[i],
            )
            .unwrap();
        refreshed.push(party);
    }
    refreshed
}

/// Fast refresh: reuses the existing multiplication setup, so phase 3 has no
/// OT/mul round (the speedup). Still preserves the public key.
pub fn run_refresh_fast<C: DklsCurve, M: Meter>(
    parties: &mut [Party<C>],
    refresh_sid: &[u8],
    meter: &mut M,
) -> Vec<Party<C>> {
    let n = parties.len();

    // Phase 1
    let mut dkg_1: Vec<Vec<C::Scalar>> = Vec::with_capacity(n);
    for p in parties.iter() {
        dkg_1.push(p.refresh_phase1());
    }
    let mut poly_fragments = vec![Vec::<C::Scalar>::with_capacity(n); n];
    for row in dkg_1 {
        for j in 0..n {
            poly_fragments[j].push(row[j]);
        }
    }
    meter.record(&poly_fragments);
    meter.end_round();

    // Phase 2
    let mut correction_values: Vec<C::Scalar> = Vec::with_capacity(n);
    let mut proofs_commitments: Vec<ProofCommitment<C>> = Vec::with_capacity(n);
    let mut kept_2to3: Vec<BTreeMap<PartyIndex, KeepRefreshPhase2to3>> = Vec::with_capacity(n);
    let mut transmit_2to4: Vec<Vec<TransmitRefreshPhase2to4>> = Vec::with_capacity(n);
    for (i, p) in parties.iter().enumerate() {
        let (cv, pc, k, t) = p.refresh_phase2(refresh_sid, &poly_fragments[i]);
        correction_values.push(cv);
        proofs_commitments.push(pc);
        kept_2to3.push(k);
        transmit_2to4.push(t);
    }
    let mut received_2to4: Vec<Vec<TransmitRefreshPhase2to4>> = Vec::with_capacity(n);
    for i in 1..=n as u8 {
        let pi = PartyIndex::new(i).unwrap();
        received_2to4.push(messages_for(pi, &transmit_2to4, |m| m.parties.receiver));
    }
    for v in &transmit_2to4 {
        meter.record(v);
    }
    meter.end_round();

    // Phase 3 (no refresh_sid arg, no mul round).
    let mut kept_3to4: Vec<BTreeMap<PartyIndex, KeepRefreshPhase3to4>> = Vec::with_capacity(n);
    let mut transmit_3to4: Vec<Vec<TransmitRefreshPhase3to4>> = Vec::with_capacity(n);
    for (i, p) in parties.iter().enumerate() {
        let (k, t) = p.refresh_phase3(&kept_2to3[i]);
        kept_3to4.push(k);
        transmit_3to4.push(t);
    }
    let mut received_3to4: Vec<Vec<TransmitRefreshPhase3to4>> = Vec::with_capacity(n);
    for i in 1..=n as u8 {
        let pi = PartyIndex::new(i).unwrap();
        received_3to4.push(messages_for(pi, &transmit_3to4, |m| m.parties.receiver));
    }
    for v in &transmit_3to4 {
        meter.record(v);
    }
    meter.end_round();

    // Phase 4 (&mut self).
    let mut refreshed: Vec<Party<C>> = Vec::with_capacity(n);
    for i in 0..n {
        let party = parties[i]
            .refresh_phase4(
                refresh_sid,
                &correction_values[i],
                &proofs_commitments,
                &kept_3to4[i],
                &received_2to4[i],
                &received_3to4[i],
            )
            .unwrap();
        refreshed.push(party);
    }
    refreshed
}
```

Uncomment `pub mod refresh; pub use refresh::{run_refresh_complete, run_refresh_fast};` in `src/lib.rs`.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p dkls23-benchmarks refresh_`
Expected: PASS (`refresh_complete_k256`, `refresh_fast_k256`).

- [ ] **Step 5: Full test sweep + commit**

Run: `cargo test -p dkls23-benchmarks`
Expected: all tests PASS.

```bash
git add dkls23-benchmarks/src/refresh.rs dkls23-benchmarks/src/lib.rs
git commit -m "feat(bench): run_refresh_complete + run_refresh_fast; pk preserved, post-refresh sign verifies

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Metrics binary — message bytes + rounds

**Files:**
- Create: `dkls23-benchmarks/src/bin/metrics.rs`

**Interfaces:**
- Consumes: `run_dkg`, `run_sign`, `run_refresh_complete`, `run_refresh_fast`, `meter::{NoMeter, WireMeter}`.

- [ ] **Step 1: Write the metrics binary**

```rust
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

fn measure<C: DklsCurve>(curve: &'static str, params: &Parameters) -> Vec<Row> {
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
```

- [ ] **Step 2: Run the metrics binary**

Run: `cargo run -p dkls23-benchmarks --bin metrics --release`
Expected: a JSON object followed by a Markdown table; 8 rows (4 ops × 2 curves), all with `bytes > 0` and `rounds == 3`.

- [ ] **Step 3: Commit**

```bash
git add dkls23-benchmarks/src/bin/metrics.rs
git commit -m "feat(bench): metrics binary — message bytes + rounds per op/curve

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 7: Criterion benches

**Files:**
- Create: `dkls23-benchmarks/benches/dkls.rs`

**Interfaces:**
- Consumes: `run_dkg`, `run_sign`, `run_refresh_complete`, `run_refresh_fast`, `meter::NoMeter`.

- [ ] **Step 1: Write the benches**

```rust
//! Criterion timing benches: dkg / sign / refresh_complete / refresh_fast,
//! each on secp256k1 and secp256r1, at 2-of-2. Timings are compute-only
//! (NoMeter — no serialization in the hot path). Sign/refresh use iter_batched
//! so DKG setup is excluded from the measured time.
use std::hint::black_box;

use criterion::{criterion_group, criterion_main, BatchSize, Criterion};
use dkls23_benchmarks::meter::NoMeter;
use dkls23_benchmarks::{run_dkg, run_refresh_complete, run_refresh_fast, run_sign};
use dkls23_core::protocols::Parameters;
use dkls23_core::utilities::hashes::tagged_hash;

const SESSION_ID: [u8; 32] = [7u8; 32];
const REFRESH_SID: [u8; 32] = [5u8; 32];
const SIGN_ID: [u8; 32] = [9u8; 32];

fn params() -> Parameters {
    Parameters::new(2, 2).unwrap()
}

fn bench_dkg(c: &mut Criterion) {
    let p = params();
    let mut g = c.benchmark_group("dkg");
    g.bench_function("secp256k1", |b| {
        b.iter(|| black_box(run_dkg::<k256::Secp256k1, _>(&p, &SESSION_ID, &mut NoMeter)))
    });
    g.bench_function("secp256r1", |b| {
        b.iter(|| black_box(run_dkg::<p256::NistP256, _>(&p, &SESSION_ID, &mut NoMeter)))
    });
    g.finish();
}

fn bench_sign(c: &mut Criterion) {
    let p = params();
    let msg = tagged_hash(b"bench", &[b"m"]);
    let mut g = c.benchmark_group("sign");
    g.bench_function("secp256k1", |b| {
        b.iter_batched(
            || run_dkg::<k256::Secp256k1, _>(&p, &SESSION_ID, &mut NoMeter),
            |parties| {
                black_box(run_sign::<k256::Secp256k1, _>(&parties, 2, &SIGN_ID, msg, &mut NoMeter))
            },
            BatchSize::SmallInput,
        )
    });
    g.bench_function("secp256r1", |b| {
        b.iter_batched(
            || run_dkg::<p256::NistP256, _>(&p, &SESSION_ID, &mut NoMeter),
            |parties| {
                black_box(run_sign::<p256::NistP256, _>(&parties, 2, &SIGN_ID, msg, &mut NoMeter))
            },
            BatchSize::SmallInput,
        )
    });
    g.finish();
}

fn bench_refresh_complete(c: &mut Criterion) {
    let p = params();
    let mut g = c.benchmark_group("refresh_complete");
    g.bench_function("secp256k1", |b| {
        b.iter_batched(
            || run_dkg::<k256::Secp256k1, _>(&p, &SESSION_ID, &mut NoMeter),
            |mut parties| {
                black_box(run_refresh_complete::<k256::Secp256k1, _>(&mut parties, &REFRESH_SID, &mut NoMeter))
            },
            BatchSize::SmallInput,
        )
    });
    g.bench_function("secp256r1", |b| {
        b.iter_batched(
            || run_dkg::<p256::NistP256, _>(&p, &SESSION_ID, &mut NoMeter),
            |mut parties| {
                black_box(run_refresh_complete::<p256::NistP256, _>(&mut parties, &REFRESH_SID, &mut NoMeter))
            },
            BatchSize::SmallInput,
        )
    });
    g.finish();
}

fn bench_refresh_fast(c: &mut Criterion) {
    let p = params();
    let mut g = c.benchmark_group("refresh_fast");
    g.bench_function("secp256k1", |b| {
        b.iter_batched(
            || run_dkg::<k256::Secp256k1, _>(&p, &SESSION_ID, &mut NoMeter),
            |mut parties| {
                black_box(run_refresh_fast::<k256::Secp256k1, _>(&mut parties, &REFRESH_SID, &mut NoMeter))
            },
            BatchSize::SmallInput,
        )
    });
    g.bench_function("secp256r1", |b| {
        b.iter_batched(
            || run_dkg::<p256::NistP256, _>(&p, &SESSION_ID, &mut NoMeter),
            |mut parties| {
                black_box(run_refresh_fast::<p256::NistP256, _>(&mut parties, &REFRESH_SID, &mut NoMeter))
            },
            BatchSize::SmallInput,
        )
    });
    g.finish();
}

criterion_group!(
    benches,
    bench_dkg,
    bench_sign,
    bench_refresh_complete,
    bench_refresh_fast
);
criterion_main!(benches);
```

- [ ] **Step 2: Run the benches (with native codegen)**

Run: `RUSTFLAGS="-C target-cpu=native" cargo bench -p dkls23-benchmarks`
Expected: criterion prints medians for `dkg/{secp256k1,secp256r1}`, `sign/*`, `refresh_complete/*`, `refresh_fast/*`. No panics. (Refresh_fast should be ≤ refresh_complete.)

- [ ] **Step 3: Record the fork's numbers**

Save the run for later aggregation:

```bash
RUSTFLAGS="-C target-cpu=native" cargo bench -p dkls23-benchmarks 2>&1 | tee \
  "/private/tmp/claude-501/-Users-jongmin-yu-Documents-workspaces-project-kawasekit-dkls23/5d3519d2-bdf1-4a1e-a136-259e44c958de/scratchpad/fork-bench.txt"
cargo run -p dkls23-benchmarks --bin metrics --release 2>&1 | tee \
  "/private/tmp/claude-501/-Users-jongmin-yu-Documents-workspaces-project-kawasekit-dkls23/5d3519d2-bdf1-4a1e-a136-259e44c958de/scratchpad/fork-metrics.txt"
```

- [ ] **Step 4: Commit**

```bash
git add dkls23-benchmarks/benches/dkls.rs
git commit -m "feat(bench): criterion benches for dkg/sign/refresh x {k1,r1}

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

**Phase 1 complete.** The fork now has a reusable harness, a correctness artifact, message-size metrics, and timing benches — all without touching audited `src/`.

---

## Task 8: Phase 2a — controlled comparison vs `0xCarbon/DKLs23@dev`

Upstream has the **same** crate layout, the **same** `DkgSession`/`SignSession` public API, and **identical** dependency pins, so the harness ports by copying it into an upstream checkout and pointing the path deps there.

**Files (all in scratchpad — NOT committed to the fork):**
- `…/scratchpad/upstream/DKLs23/` (clone)
- `…/scratchpad/upstream/DKLs23/dkls23-benchmarks/` (copied harness)

- [ ] **Step 1: Clone upstream at `dev`**

```bash
cd "/private/tmp/claude-501/-Users-jongmin-yu-Documents-workspaces-project-kawasekit-dkls23/5d3519d2-bdf1-4a1e-a136-259e44c958de/scratchpad"
mkdir -p upstream && git clone --depth 1 --branch dev https://github.com/0xCarbon/DKLs23.git upstream/DKLs23
```

- [ ] **Step 2: Copy the harness in and register it as a member**

```bash
cp -R dkls23-benchmarks upstream/DKLs23/dkls23-benchmarks
```

Edit `upstream/DKLs23/Cargo.toml` to add `"dkls23-benchmarks"` to `[workspace] members` (same edit as Task 1, Step 1).

- [ ] **Step 3: Parity check — confirm the public API matches**

Run:
```bash
cd upstream/DKLs23
grep -rn "pub fn verify_ecdsa_signature" dkls23-core/src/protocols/signing.rs
grep -rn "pub fn refresh_complete_phase4\|pub fn refresh_phase4\|pub fn refresh_phase3" dkls23-core/src/protocols/refresh.rs
cargo build -p dkls23-benchmarks 2>&1 | tail -30
```
Expected: builds clean. **If it does not build**, the divergence is a known risk (spec §12): the fork added fields the harness never constructs directly, so failures will be in method *signatures*. Apply the minimal shim:
- If `refresh_phase3` upstream takes different args, adjust `run_refresh_fast` in the upstream copy only.
- If `verify_ecdsa_signature` is absent upstream, replace the example/test verification with `k256`'s own verifier in the upstream copy.
Record any shim applied (for the BENCHMARKS.md notes).

- [ ] **Step 4: Run upstream benches + metrics on the same machine**

```bash
cd upstream/DKLs23
RUSTFLAGS="-C target-cpu=native" cargo bench -p dkls23-benchmarks 2>&1 | tee ../upstream-bench.txt
cargo run -p dkls23-benchmarks --bin metrics --release 2>&1 | tee ../upstream-metrics.txt
cargo run -p dkls23-benchmarks --example verify_e2e   # sanity: upstream also produces verifying sigs
```
Expected: comparable medians; correctness example passes.

- [ ] **Step 5: No commit** (scratchpad only). Note the upstream commit SHA: `git -C upstream/DKLs23 rev-parse HEAD` — record it for BENCHMARKS.md.

---

## Task 9: Phase 2b — indicative comparison vs `silence-laboratories/dkls23@main`

Silence-labs is an independent implementation with its own benchmark crate (`crates/dkls-metrics`). Run **their** harness; do not force ours.

- [ ] **Step 1: Clone and inspect their bench harness**

```bash
cd "/private/tmp/claude-501/-Users-jongmin-yu-Documents-workspaces-project-kawasekit-dkls23/5d3519d2-bdf1-4a1e-a136-259e44c958de/scratchpad"
mkdir -p silence && git clone --depth 1 --branch main https://github.com/silence-laboratories/dkls23.git silence/dkls23
sed -n '1,80p' silence/dkls23/crates/dkls-metrics/benches/dkls.rs
sed -n '1,60p' silence/dkls23/crates/dkls-metrics/src/main.rs
```
Read what they measure (operations, threshold config, curve) so the numbers can be mapped to ours (note any 2-of-2 vs t-of-n or curve differences).

- [ ] **Step 2: Build and run their benches/metrics on the same machine**

```bash
cd silence/dkls23
RUSTFLAGS="-C target-cpu=native" cargo bench -p dkls-metrics 2>&1 | tee ../silence-bench.txt || \
  cargo run -p dkls-metrics --release 2>&1 | tee ../silence-metrics.txt
git rev-parse HEAD   # record SHA
```
Expected: their benches produce timing numbers. **If the build fails** (older dep pins), record that and fall back to citing their published numbers, clearly labeled. Do not block on it.

- [ ] **Step 3: No commit** (scratchpad only).

---

## Task 10: `docs/BENCHMARKS.md` — aggregate report

**Files:**
- Create: `docs/BENCHMARKS.md`

- [ ] **Step 1: Assemble the report from the captured outputs**

Use the four scratchpad capture files (`fork-bench.txt`, `fork-metrics.txt`, `upstream-bench.txt`, `upstream-metrics.txt`, `silence-bench.txt`/`silence-metrics.txt`). Fill the medians/bytes into this skeleton:

```markdown
# DKLs23 Benchmarks

> **perf ≠ correctness ≠ security.** These numbers measure speed only. They say
> nothing about cryptographic correctness or safety. This fork remains
> **UNAUDITED**; a third-party cryptographic audit is mandatory before real value.

## Methodology
- Machine: <CPU model, cores>, <OS version>. rustc `<rustc --version>`.
- Build: `RUSTFLAGS="-C target-cpu=native" cargo bench`. criterion default sampling.
- Config: 2-of-2. In-process, **no network** — timings are compute-only.
- Message bytes = total serialized (bincode) size of point-to-point round messages,
  each produced message counted once. Rounds = communication rounds.
- Implementations:
  - `kawasekit-dkls23` @ `<git rev-parse HEAD>` (this repo)
  - `0xCarbon/DKLs23` @ `<upstream SHA>` (controlled: identical crate layout + deps)
  - `silence-laboratories/dkls23` @ `<silence SHA>` (indicative: independent impl/API)

## Honesty caveats
- **fork ↔ 0xCarbon = controlled.** Identical deps (`k256 0.14.0-rc.7`, `elliptic-curve
  0.14.0-rc.4`); any delta is attributable to the fork's hardening (H1/M1/M2/L*).
- **fork ↔ silence-laboratories = indicative only.** Different implementation, API,
  validation strictness, and proof parameters; ran their own harness, mapped the
  workload as closely as possible. Not a controlled experiment.
- Any upstream shim applied for API parity is noted under the relevant table.

## Timing (median)
### DKG (2-of-2)
| impl | secp256k1 | secp256r1 |
|------|-----------|-----------|
| kawasekit-dkls23 | <ms> | <ms> |
| 0xCarbon/DKLs23 | <ms> | <ms> |
| silence-laboratories | <ms / n.a.> | <ms / n.a.> |

### Signing (2-of-2)
(same table shape)

### Refresh — complete / fast (2-of-2)
(same table shape; two sub-rows or two tables)

## Message size & rounds (fork)
| op | curve | bytes | rounds |
|----|-------|-------|--------|
| … from `cargo run --bin metrics` … |

## Interpretation
- 2-3 sentences: cost of the fork's hardening vs upstream (should be small);
  k1 vs r1; refresh_fast vs refresh_complete; where silence-labs differs and why
  the comparison is indicative.
```

Replace every `<…>` placeholder with real captured values. Leave no angle-bracket placeholder behind.

- [ ] **Step 2: Sanity-check the file**

Run: `grep -n "<" docs/BENCHMARKS.md || echo "no placeholders left"`
Expected: `no placeholders left` (or only legitimate `<` in prose — verify none are unfilled template slots).

- [ ] **Step 3: Commit**

```bash
git add docs/BENCHMARKS.md
git commit -m "docs(bench): BENCHMARKS.md — fork vs 0xCarbon (controlled) + silence-labs (indicative)

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 4: Push the branch (do not merge — user-gated)**

```bash
git -c credential.helper= -c credential.helper='!gh auth git-credential' \
  push https://github.com/k0yote/kawasekit-dkls23.git HEAD:refs/heads/bench/dkls23-comparison
```
Then open a PR for the user to review; **do not merge** (merges are user-gated).

---

## Self-Review (completed by plan author)

**Spec coverage:**
- Goals: harness ✓ (T1–T7), time+bytes+rounds ✓ (T6–T7), controlled 0xCarbon ✓ (T8), indicative silence-labs ✓ (T9), correctness artifact ✓ (T4), BENCHMARKS.md ✓ (T10).
- Non-goals respected: no interop; no network (compute-only + bytes/rounds); 2-of-2 only.
- Honesty constraints: encoded in Global Constraints + T10 skeleton.
- "No audited src touched": enforced in Global Constraints + separate crate; verified by construction (public API only).

**Placeholder scan:** Code blocks are complete. The only intentional fill-ins are the measured numbers in `docs/BENCHMARKS.md` (Task 10), which cannot exist before the runs; Step 2 guards against leftover template slots.

**Type consistency:** `run_dkg(&Parameters, &[u8], &mut M) -> Vec<Party<C>>`, `run_sign(&[Party<C>], u8, &[u8], HashOutput, &mut M) -> EcdsaSignature`, `run_refresh_{complete,fast}(&mut [Party<C>], &[u8], &mut M) -> Vec<Party<C>>`, `Meter::{record,end_round}`, `messages_for(PartyIndex, &[Vec<M>], impl Fn(&M)->PartyIndex) -> Vec<M>` are used identically across tasks, benches, metrics, and the example.

**Known adaptive point:** Tasks 8–9 may need a small shim if an external repo's API/build diverges; the spec's risk section anticipates this and the steps make the probe explicit before adapting.
