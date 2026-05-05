//! Shared logic for Beam clients and relay.
//!
//! Local transfer scaffolding lives in [`local_transfer`] and [`manifest`]; Phase 2 adds [`session_crypto`] for application-layer envelopes.

#![forbid(unsafe_code)]

pub mod chunking;
mod error;
pub mod local_transfer;
pub mod manifest;
pub mod session_crypto;

pub use error::TransferError;
pub use manifest::manifest_from_plaintext_file;
pub use manifest::ChunkHashCommitment;
pub use manifest::OneFileManifest;

/// Placeholder surface for framing and message semantics to be layered later.
pub mod protocol {
    /// Marker until wire types land.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
    pub struct ProtocolSurface;
}

/// Returns a short build identity string for `--version` style output.
#[must_use]
pub fn build_identity() -> &'static str {
    concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stubs_are_present() {
        let _ = protocol::ProtocolSurface;
    }

    #[test]
    fn build_identity_is_non_empty() {
        assert!(!build_identity().is_empty());
    }
}
