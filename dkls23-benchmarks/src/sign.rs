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
) -> EcdsaSignature
where
    C::Scalar: serde::Serialize,
    C::AffinePoint: serde::Serialize,
{
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

    #[test]
    fn sign_2of2_verifies_under_standard_ecdsa_p256() {
        let params = Parameters::new(2, 2).unwrap();
        let parties = run_dkg::<p256::NistP256, _>(&params, &[7u8; 32], &mut NoMeter);
        let msg = tagged_hash(b"dkls23-bench", &[b"correctness gate p256"]);

        let sig = run_sign::<p256::NistP256, _>(&parties, 2, &[9u8; 32], msg, &mut NoMeter);

        let r_hex = hex::encode(sig.r);
        let s_hex = hex::encode(sig.s);
        assert!(
            verify_ecdsa_signature::<p256::NistP256>(&msg, &parties[0].pk, &r_hex, &s_hex),
            "threshold signature must verify under a standard secp256r1 verifier"
        );
    }
}
