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

#[cfg(test)]
mod tests {
    use super::*;
    use dkls23_core::protocols::{PartiesMessage, PartyIndex};

    fn pi(n: u8) -> PartyIndex {
        PartyIndex::new(n).unwrap()
    }

    #[test]
    fn messages_for_filters_by_receiver() {
        // Two parties each send one message to the other.
        let p1_out = vec![PartiesMessage {
            sender: pi(1),
            receiver: pi(2),
        }];
        let p2_out = vec![PartiesMessage {
            sender: pi(2),
            receiver: pi(1),
        }];
        let all = vec![p1_out, p2_out];

        let to_1 = messages_for(pi(1), &all, |m| m.receiver);
        assert_eq!(to_1.len(), 1);
        assert_eq!(to_1[0].sender, pi(2));
    }
}
