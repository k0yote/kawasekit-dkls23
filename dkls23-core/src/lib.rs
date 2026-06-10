//! A library for dealing with the `DKLs23` protocol (see <https://eprint.iacr.org/2023/765.pdf>)
//! and related protocols.
//!
//! Written and used by Alore.
#![recursion_limit = "512"]
#![forbid(unsafe_code)]

// A4 (kawasekit hardening) — lock the dangerous features out of the release / wasm builds, so a
// future refactor cannot silently re-enable them where it matters. These guards are belt-and-
// suspenders on top of the existing `#[cfg(...)]` gating; tests reach the gated code via `cfg(test)`,
// so they are unaffected. A CI job asserts the bad combos below fail to build.
//
// `insecure-rng` weakens the CSPRNG and is TEST-ONLY — it must never be in a non-test build.
#[cfg(all(not(test), feature = "insecure-rng"))]
compile_error!(
    "`insecure-rng` is a test-only RNG weakening; it must NOT be enabled in a non-test build"
);
// `trusted-dealer-import` exposes single-custody `re_key` (one host briefly holds the whole key).
// The wasm32 agent is a distributed 2-of-2 party and must NEVER single-custody-import a key — that
// would be a custody violation. (A deliberate native import flow may still enable it; this guard
// targets the agent/wasm build, the real risk.)
#[cfg(all(target_arch = "wasm32", feature = "trusted-dealer-import"))]
compile_error!(
    "`trusted-dealer-import` (single-custody re_key) must NOT be enabled on the wasm32 agent"
);

pub mod curve;
pub mod protocols;
pub mod utilities;

pub use protocols::dkg_session::DkgSession;
pub use protocols::sign_session::SignSession;
pub use protocols::signature::EcdsaSignature;

// The following constants should not be changed!
// They are the same as the reference implementation of DKLs19:
// https://gitlab.com/neucrypt/mpecdsa/-/blob/release/src/lib.rs

/// Computational security parameter `lambda_c` from `DKLs23`.
/// We take it to be the same as the parameter `kappa`.
pub const RAW_SECURITY: u16 = 256;
/// `RAW_SECURITY` divided by 8 (used for arrays of bytes)
pub const SECURITY: u16 = 32;

/// Statistical security parameter `lambda_s` from `DKLs23`.
pub const STAT_SECURITY: u16 = 80;
