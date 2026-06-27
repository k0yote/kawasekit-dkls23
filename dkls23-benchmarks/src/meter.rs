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
