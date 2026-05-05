//! Default hosted relay URL for zero-config pairing (public alpha).

use crate::pairing::normalize_http_relay_base;

/// HTTPS relay base URL when neither `--relay-dir` nor `--relay-url` is passed and for invites whose relay kind is [`crate::pairing::RendezvousRelay::Default`].
///
/// Set **`BEAM_RELAY_URL`** to the same base URL your CLI binary expects (trimmed; trailing slashes stripped).
pub const DEFAULT_PUBLIC_RELAY_BASE_URL: &str = "https://relay.beam.dev";

#[must_use]
pub fn resolved_public_relay_base_url() -> String {
    normalize_http_relay_base(
        &std::env::var("BEAM_RELAY_URL")
            .unwrap_or_else(|_| DEFAULT_PUBLIC_RELAY_BASE_URL.to_string()),
    )
}

#[cfg(test)]
mod tests {
    use crate::pairing::{ParsedInvite, RelayTransport, RendezvousRelay};

    use super::*;

    #[test]
    fn default_constant_has_no_trailing_slash() {
        assert!(!DEFAULT_PUBLIC_RELAY_BASE_URL.ends_with('/'));
    }

    #[test]
    fn default_invite_receiver_uses_resolved_public_http_relay() {
        let invite = ParsedInvite {
            relay: RendezvousRelay::Default,
            room_id: [0u8; 16],
            expires_unix: u64::MAX,
            seed: [0u8; 10],
        };
        let transport = RelayTransport::for_receiver(&invite, None).expect("transport");
        match transport {
            RelayTransport::Http(h) => assert_eq!(h.base_url(), resolved_public_relay_base_url()),
            _ => panic!("expected HTTP relay"),
        }
    }
}
