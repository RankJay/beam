//! One-file manifest: path, size, chunk plan, plaintext Blake3 identity (ADR 0013, 0039, 0040, 0077, 0082).

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use blake3::Hasher;

use crate::chunking::chunk_count_for_size;
use crate::chunking::chunk_span;
use crate::error::TransferError;

/// 32-byte Blake3 digest identifying plaintext bytes.
pub type Blake3Digest = [u8; 32];

/// Chunk hash maturity: only [`ChunkHashCommitment::Committed`] is a content commitment for verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkHashCommitment {
    Pending,
    Committed(Blake3Digest),
}

/// Describes a single file's transfer shape and commitments before/during plaintext transfer (ADR 0040).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneFileManifest {
    /// Logical relative path used for naming at the receiver (posix-style or plain name for this slice).
    pub relative_path: String,
    /// Total plaintext size in bytes.
    pub size: u64,
    /// Negotiated fixed chunk size in bytes for this manifest (ADR 0062).
    pub chunk_size: u64,
    /// Number of chunks (derived from size and chunk_size).
    pub chunk_count: u32,
    /// Blake3 digest over entire plaintext file.
    pub file_blake3: Blake3Digest,
    /// Ordered per-chunk commitments (hybrid hashing: pending allowed until commit).
    pub chunk_hashes: Vec<ChunkHashCommitment>,
}

impl OneFileManifest {
    /// Validates internal consistency derived fields.
    pub fn validate(&self) -> Result<(), TransferError> {
        if self.chunk_size == 0 {
            return Err(TransferError::InvalidChunkSize {
                chunk_size: self.chunk_size,
            });
        }
        let expected = chunk_count_for_size(self.size, self.chunk_size);
        if self.chunk_count != expected {
            return Err(TransferError::InvalidManifest(
                "chunk_count does not match size and chunk_size",
            ));
        }
        if usize::try_from(self.chunk_count).unwrap() != self.chunk_hashes.len() {
            return Err(TransferError::InvalidManifest(
                "chunk_hashes length does not match chunk_count",
            ));
        }
        Ok(())
    }
}

/// Builds a manifest with every chunk commitment precomputed from the plaintext at `source`.
pub fn manifest_from_plaintext_file(
    source: &Path,
    relative_path: &str,
    chunk_size: u64,
) -> Result<OneFileManifest, TransferError> {
    if chunk_size == 0 {
        return Err(TransferError::InvalidChunkSize { chunk_size });
    }

    let size = fs_metadata_len(source)?;

    let mut file = File::open(source)?;
    let mut whole = Hasher::new();
    let mut buf = vec![0u8; chunk_size.min(1024 * 1024) as usize];

    let chunk_count = chunk_count_for_size(size, chunk_size);
    let mut chunk_hashes = Vec::with_capacity(chunk_count as usize);

    let mut offset: u64 = 0;
    for index in 0..chunk_count {
        let Some((expected_off, len)) = chunk_span(size, chunk_size, index) else {
            return Err(TransferError::InvalidManifest("chunk index out of range"));
        };
        debug_assert_eq!(expected_off, offset);

        let mut chunk_hasher = Hasher::new();
        let mut remaining = len;
        while remaining > 0 {
            let take = (buf.len() as u64).min(remaining) as usize;
            let n = read_exact_up_to(&mut file, &mut buf[..take])?;
            if n == 0 {
                return Err(TransferError::InvalidManifest(
                    "unexpected EOF hashing file",
                ));
            }
            whole.update(&buf[..n]);
            chunk_hasher.update(&buf[..n]);
            let n64 = n as u64;
            offset = offset.saturating_add(n64);
            remaining = remaining.saturating_sub(n64);
        }
        let digest: Blake3Digest = *chunk_hasher.finalize().as_bytes();
        chunk_hashes.push(ChunkHashCommitment::Committed(digest));
    }

    if offset != size {
        return Err(TransferError::InvalidManifest("hashed size mismatch"));
    }

    let file_blake3: Blake3Digest = *whole.finalize().as_bytes();

    let m = OneFileManifest {
        relative_path: relative_path.to_owned(),
        size,
        chunk_size,
        chunk_count,
        file_blake3,
        chunk_hashes,
    };
    m.validate()?;
    Ok(m)
}

fn fs_metadata_len(path: &Path) -> Result<u64, TransferError> {
    let meta = std::fs::metadata(path)?;
    Ok(meta.len())
}

/// Reads up to `buf.len()` bytes; returns how many were read (short read only at EOF).
fn read_exact_up_to(r: &mut File, buf: &mut [u8]) -> io::Result<usize> {
    if buf.is_empty() {
        return Ok(0);
    }
    let mut read_total = 0usize;
    while read_total < buf.len() {
        match r.read(&mut buf[read_total..])? {
            0 => break,
            n => read_total += n,
        }
    }
    Ok(read_total)
}
