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
