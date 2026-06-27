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
) -> Vec<Party<C>>
where
    C::Scalar: serde::Serialize,
    C::AffinePoint: serde::Serialize,
{
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
    let mut bip_broadcast_2to4: BTreeMap<PartyIndex, BroadcastDerivationPhase2to4> =
        BTreeMap::new();
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
        zero_received_2to4.push(messages_for(pi, &zero_transmit_2to4, |m| {
            m.parties.receiver
        }));
    }
    for v in &zero_transmit_2to4 {
        meter.record(v);
    }
    meter.end_round();

    // Phase 3
    let mut zero_transmit_3to4: Vec<Vec<TransmitInitZeroSharePhase3to4>> = Vec::with_capacity(n);
    let mut mul_transmit_3to4: Vec<Vec<TransmitInitMulPhase3to4<C>>> = Vec::with_capacity(n);
    let mut bip_broadcast_3to4: BTreeMap<PartyIndex, BroadcastDerivationPhase3to4> =
        BTreeMap::new();
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
        zero_received_3to4.push(messages_for(pi, &zero_transmit_3to4, |m| {
            m.parties.receiver
        }));
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
