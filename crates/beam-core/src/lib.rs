//! Shared logic for Beam clients and relay.
//!
//! Local transfer scaffolding lives in [`local_transfer`], [`manifest`], and [`folder_snapshot`];
//! session crypto and pairing live in [`session_crypto`] and [`pairing`].

#![forbid(unsafe_code)]

pub mod chunking;
pub mod direct_quic;
mod error;
pub mod folder_snapshot;
pub mod local_transfer;
pub mod manifest;
pub mod pairing;
pub mod paths;
pub mod relay_default;
pub mod retry;
pub mod session_crypto;
pub mod session_file;

pub use error::TransferError;
pub use manifest::manifest_from_plaintext_file;
pub use manifest::ChunkHashCommitment;
pub use manifest::OneFileManifest;
pub use paths::{beam_cache_dir, beam_data_dir, beam_sessions_dir};
pub use relay_default::{resolved_public_relay_base_url, DEFAULT_PUBLIC_RELAY_BASE_URL};
pub use retry::{
    pairing_error_is_transient_transport, transfer_error_is_transient_transport, RetryPolicy,
};

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
