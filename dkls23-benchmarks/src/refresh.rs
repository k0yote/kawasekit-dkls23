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
) -> Vec<Party<C>>
where
    C::Scalar: serde::Serialize,
    C::AffinePoint: serde::Serialize,
{
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
) -> Vec<Party<C>>
where
    C::Scalar: serde::Serialize,
    C::AffinePoint: serde::Serialize,
{
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
    ) where
        C::Scalar: serde::Serialize,
        C::AffinePoint: serde::Serialize,
    {
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
