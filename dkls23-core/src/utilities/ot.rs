//! Oblivious Transfer.
//!
//! The main protocol is given by the file [`extension`], but it needs
//! a base OT implemented in [`base`].

pub mod base;
pub mod extension;

/// Classifies an OT error so callers can decide ban vs. recoverable.
///
/// Only the COTe consistency check over the reused OT correlations is leak-bearing and
/// must ban the counterparty; dimension/bounds/base-OT-proof errors are recoverable. See
/// `docs/audit-findings.md` finding H1. NOTE (issue #48): there is deliberately **no**
/// defaulting constructor — every OT error must name its severity explicitly via
/// [`ErrorOT::malformed`] (recoverable) or [`ErrorOT::consistency`] (ban), so a *new*
/// leak-bearing OT error cannot silently default to recoverable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtErrorKind {
    /// A leak-bearing consistency-check failure. The counterparty MUST be permanently banned.
    ConsistencyFailure,
    /// A malformed / ill-dimensioned message or other non-leak-bearing fault. Recoverable.
    MalformedMessage,
}

/// Represents an error during any of the OT protocols.
#[derive(Debug, Clone)]
pub struct ErrorOT {
    pub description: String,
    pub kind: OtErrorKind,
}

impl ErrorOT {
    /// Creates a malformed-message (recoverable-class) error — for OT's overwhelmingly
    /// dimension/bounds/base-OT-proof faults. Severity is explicit: a leak-bearing OT
    /// failure must use [`ErrorOT::consistency`] instead (issue #48).
    #[must_use]
    pub fn malformed(description: &str) -> ErrorOT {
        ErrorOT {
            description: String::from(description),
            kind: OtErrorKind::MalformedMessage,
        }
    }

    /// Creates a consistency-failure (ban-class) error — the leak-bearing COTe check.
    #[must_use]
    pub fn consistency(description: &str) -> ErrorOT {
        ErrorOT {
            description: String::from(description),
            kind: OtErrorKind::ConsistencyFailure,
        }
    }
}
