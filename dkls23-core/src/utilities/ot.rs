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
/// `docs/audit-findings.md` finding H1. NOTE: the default ([`ErrorOT::new`]) is
/// `MalformedMessage` because OTE errors are overwhelmingly dimensional — any *new*
/// leak-bearing OT error MUST be constructed with [`ErrorOT::consistency`].
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
    /// Creates a malformed-message (recoverable-class) error — the default for OT, whose
    /// errors are overwhelmingly dimension/bounds/base-OT-proof faults.
    #[must_use]
    pub fn new(description: &str) -> ErrorOT {
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
