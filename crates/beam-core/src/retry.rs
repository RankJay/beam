//! Bounded retries for transient transport failures (Phase 9, ADR 0089).
//!
//! Deterministic failures (auth, manifest, hashes, wire semantics) must not be retried as
//! ordinary network glitches.

use std::io::ErrorKind;
use std::thread;
use std::time::Duration;

use crate::error::TransferError;

#[must_use]
pub fn transfer_error_is_transient_transport(e: &TransferError) -> bool {
    match e {
        TransferError::Io(io) => io_error_kind_is_transient(io.kind()),
        TransferError::RelayHttpTransient { .. } => true,
        TransferError::RelayPipe(msg) => matches!(
            *msg,
            "pipe PUT transport failed"
                | "pipe GET transport failed"
                | "pipe GET body failed"
        ),
        _ => false,
    }
}

/// Pairing rendezvous I/O or relay 5xx-style failures may be worth retrying; deterministic invite
/// or crypto errors are not.
#[must_use]
pub fn pairing_error_is_transient_transport(e: &crate::pairing::PairingError) -> bool {
    match e {
        crate::pairing::PairingError::Io(io) => io_error_kind_is_transient(io.kind()),
        crate::pairing::PairingError::Relay(msg) => {
            matches!(
                *msg,
                "http relay body read failed"
                    | "http relay request timed out"
                    | "http relay I/O error"
                    | "http relay transport error"
                    | "http relay unreachable (connection refused — is beam-relay listening on this URL?)"
            )
        }
        _ => false,
    }
}

fn io_error_kind_is_transient(k: ErrorKind) -> bool {
    matches!(
        k,
        ErrorKind::Interrupted
            | ErrorKind::TimedOut
            | ErrorKind::WouldBlock
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::UnexpectedEof
    )
}

/// Default policy for HTTP relay frames (conservative caps for scripts).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetryPolicy {
    pub max_attempts: u32,
    pub initial_backoff: Duration,
    pub max_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::relay_http_default()
    }
}

impl RetryPolicy {
    #[must_use]
    pub fn relay_http_default() -> Self {
        Self {
            max_attempts: 5,
            initial_backoff: Duration::from_millis(200),
            max_backoff: Duration::from_secs(8),
        }
    }

    /// Run `attempt` until success, a non-transient error, or attempts exhausted.
    pub fn retry_transfer_blocking<T, F>(&self, mut attempt: F) -> Result<T, TransferError>
    where
        F: FnMut() -> Result<T, TransferError>,
    {
        let mut delay = self.initial_backoff;
        let mut n = 0u32;
        loop {
            match attempt() {
                Ok(v) => return Ok(v),
                Err(e) => {
                    n += 1;
                    if n >= self.max_attempts || !transfer_error_is_transient_transport(&e) {
                        return Err(e);
                    }
                    thread::sleep(delay);
                    delay = (delay * 2).min(self.max_backoff);
                }
            }
        }
    }

    /// Same semantics as [`Self::retry_transfer_blocking`] for pairing / rendezvous HTTP.
    pub fn retry_pairing_blocking<T, F>(&self, mut attempt: F) -> Result<T, crate::pairing::PairingError>
    where
        F: FnMut() -> Result<T, crate::pairing::PairingError>,
    {
        let mut delay = self.initial_backoff;
        let mut n = 0u32;
        loop {
            match attempt() {
                Ok(v) => return Ok(v),
                Err(e) => {
                    n += 1;
                    if n >= self.max_attempts || !pairing_error_is_transient_transport(&e) {
                        return Err(e);
                    }
                    thread::sleep(delay);
                    delay = (delay * 2).min(self.max_backoff);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn auth_and_hash_errors_are_not_transient() {
        assert!(!transfer_error_is_transient_transport(
            &TransferError::ManifestEnvelopeAuthFailed
        ));
        assert!(!transfer_error_is_transient_transport(
            &TransferError::ChunkVerificationFailed { index: 0 }
        ));
        assert!(!transfer_error_is_transient_transport(
            &TransferError::FileDigestMismatch
        ));
        assert!(!transfer_error_is_transient_transport(
            &TransferError::InvalidManifest("bad")
        ));
    }

    #[test]
    fn transient_io_and_relay_status() {
        assert!(transfer_error_is_transient_transport(&TransferError::Io(
            io::Error::new(ErrorKind::TimedOut, "x")
        )));
        assert!(transfer_error_is_transient_transport(
            &TransferError::RelayHttpTransient { status: 503 }
        ));
        assert!(!transfer_error_is_transient_transport(
            &TransferError::RelayPipe("pipe expired (gone)")
        ));
    }

    #[test]
    fn retry_stops_on_deterministic_error() {
        let policy = RetryPolicy {
            max_attempts: 10,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        };
        let mut calls = 0u32;
        let err = policy
            .retry_transfer_blocking(|| -> Result<(), TransferError> {
                calls += 1;
                Err(TransferError::ChunkVerificationFailed { index: 1 })
            })
            .expect_err("should fail");
        assert!(matches!(
            err,
            TransferError::ChunkVerificationFailed { index: 1 }
        ));
        assert_eq!(calls, 1);
    }

    #[test]
    fn retry_exhausts_on_persistent_transient() {
        let policy = RetryPolicy {
            max_attempts: 3,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::ZERO,
        };
        let mut calls = 0u32;
        let _: Result<(), TransferError> = policy.retry_transfer_blocking(|| {
            calls += 1;
            Err(TransferError::RelayHttpTransient { status: 503 })
        });
        assert_eq!(calls, 3);
    }
}
