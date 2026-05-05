//! Transfer-time errors for the local pipeline.

use std::fmt;
use std::io;
use std::path::PathBuf;

/// Errors from manifest construction, chunk receipt, verification, or finalization.
#[derive(Debug)]
pub enum TransferError {
    Io(io::Error),
    InvalidChunkSize {
        chunk_size: u64,
    },
    InvalidManifest(&'static str),
    ChunkIndexOutOfBounds {
        index: u32,
        count: u32,
    },
    HashNotCommitted {
        index: u32,
    },
    ChunkPayloadSize {
        index: u32,
        expected: usize,
        actual: usize,
    },
    ChunkVerificationFailed {
        index: u32,
    },
    IncompleteTransfer {
        missing_chunk: u32,
    },
    FileDigestMismatch,
    DestinationExists(PathBuf),
    /// Symmetric crypto / key schedule failure (AEAD seal, HKDF, etc.).
    SessionCrypto(&'static str),
    /// Manifest or metadata envelope failed AEAD or used the wrong session material.
    ManifestEnvelopeAuthFailed,
    /// Chunk ciphertext failed AEAD or used the wrong purpose key.
    ChunkEnvelopeAuthFailed,
    /// Control-plane envelope failed AEAD or used the wrong purpose key.
    ControlEnvelopeAuthFailed,
}

impl fmt::Display for TransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransferError::Io(e) => write!(f, "I/O error: {e}"),
            TransferError::InvalidChunkSize { chunk_size } => {
                write!(f, "chunk size must be positive (got {chunk_size})")
            }
            TransferError::InvalidManifest(msg) => write!(f, "invalid manifest: {msg}"),
            TransferError::ChunkIndexOutOfBounds { index, count } => {
                write!(f, "chunk index {index} out of bounds (count {count})")
            }
            TransferError::HashNotCommitted { index } => {
                write!(f, "chunk {index} hash is not committed")
            }
            TransferError::ChunkPayloadSize {
                index,
                expected,
                actual,
            } => write!(
                f,
                "chunk {index} payload size mismatch (expected {expected}, got {actual})"
            ),
            TransferError::ChunkVerificationFailed { index } => {
                write!(f, "chunk {index} failed Blake3 verification")
            }
            TransferError::IncompleteTransfer { missing_chunk } => {
                write!(
                    f,
                    "cannot finalize with missing chunk indices (first missing {missing_chunk})"
                )
            }
            TransferError::FileDigestMismatch => {
                write!(
                    f,
                    "staged file digest does not match manifest file commitment"
                )
            }
            TransferError::DestinationExists(p) => {
                write!(
                    f,
                    "destination exists and overwrite is not permitted: {}",
                    p.display()
                )
            }
            TransferError::SessionCrypto(msg) => {
                write!(f, "session crypto error: {msg}")
            }
            TransferError::ManifestEnvelopeAuthFailed => {
                write!(f, "manifest envelope authentication failed")
            }
            TransferError::ChunkEnvelopeAuthFailed => {
                write!(f, "chunk envelope authentication failed")
            }
            TransferError::ControlEnvelopeAuthFailed => {
                write!(f, "control envelope authentication failed")
            }
        }
    }
}

impl std::error::Error for TransferError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            TransferError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for TransferError {
    fn from(value: io::Error) -> Self {
        TransferError::Io(value)
    }
}
