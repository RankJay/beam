//! In-process provider/receiver pipeline: staging, per-chunk verification, atomic finalize (ADR 0015, 0016, 0083).

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use blake3::Hasher;

use crate::chunking::chunk_span;
use crate::error::TransferError;
use crate::manifest::manifest_from_plaintext_file;
use crate::manifest::ChunkHashCommitment;
use crate::manifest::OneFileManifest;
use crate::session_crypto::{
    decode_manifest_plaintext, decrypt_chunk_payload, decrypt_control_payload,
    decrypt_manifest_blob, encode_manifest_plaintext, encrypt_chunk_payload,
    encrypt_control_payload, encrypt_manifest_blob, receiver_approve_payload, HandshakeBinding,
    InviteContext, SessionSecrets,
};

/// What to do if the final path already exists when finalizing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationConflictPolicy {
    /// Refuse finalize when [`Path::exists`] would prevent a safe overwrite.
    FailIfExists,
}

/// Sender side: computes manifest and exposes plaintext chunks.
#[derive(Debug, Clone)]
pub struct LocalProvider {
    source: PathBuf,
    manifest: OneFileManifest,
}

impl LocalProvider {
    /// Hash plaintext and build commitments for every chunk (`Pending` hashes are preserved if added later elsewhere).
    pub fn from_file(
        source: impl Into<PathBuf>,
        relative_path: &str,
        chunk_size: u64,
    ) -> Result<Self, TransferError> {
        let source = source.into();
        let manifest = manifest_from_plaintext_file(&source, relative_path, chunk_size)?;
        Ok(Self { source, manifest })
    }

    /// Use a frozen manifest from [`crate::folder_snapshot::build_folder_snapshot_manifest`]; rejects source size drift (ADR 0079).
    pub fn with_frozen_file_manifest(
        source: impl Into<PathBuf>,
        manifest: OneFileManifest,
    ) -> Result<Self, TransferError> {
        let source = source.into();
        let meta = fs::metadata(&source)?;
        if !meta.is_file() {
            return Err(TransferError::InvalidManifest(
                "snapshot source is not a regular file",
            ));
        }
        if meta.len() != manifest.size {
            return Err(TransferError::SnapshotSourceSizeMismatch {
                rel_path: manifest.relative_path.clone(),
                expected: manifest.size,
                actual: meta.len(),
            });
        }
        manifest.validate()?;
        Ok(Self { source, manifest })
    }

    #[must_use]
    pub fn manifest(&self) -> &OneFileManifest {
        &self.manifest
    }

    /// Read plaintext chunk bytes (`index` in `[0, chunk_count)`).
    pub fn read_chunk(&self, index: u32) -> Result<Vec<u8>, TransferError> {
        read_file_chunk(&self.source, self.manifest(), index)
    }
}

/// Receiver side: write plaintext chunks to staging and finalize atomically onto the destination.
#[derive(Debug)]
pub struct LocalReceiver {
    manifest: OneFileManifest,
    staging_path: PathBuf,
    destination: PathBuf,
    conflict: DestinationConflictPolicy,
    file: File,
    chunk_received: Vec<bool>,
}

impl LocalReceiver {
    /// Create an empty staged file sized to [`OneFileManifest::size`] under `staging_path`.
    pub fn new(
        manifest: OneFileManifest,
        staging_path: PathBuf,
        destination: PathBuf,
        conflict: DestinationConflictPolicy,
    ) -> Result<Self, TransferError> {
        manifest.validate()?;
        let staging_parent = staging_path.parent().ok_or(TransferError::InvalidManifest(
            "staging path must have a parent directory",
        ))?;
        fs::create_dir_all(staging_parent)?;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&staging_path)?;

        if manifest.size > 0 {
            file.set_len(manifest.size)?;
        }

        Ok(Self {
            chunk_received: vec![false; manifest.chunk_count as usize],
            manifest,
            staging_path,
            destination,
            conflict,
            file,
        })
    }

    /// Continue assembly on existing staged bytes (no truncate). Caller supplies chunk completion flags from persisted session state.
    pub fn resume(
        manifest: OneFileManifest,
        staging_path: PathBuf,
        destination: PathBuf,
        conflict: DestinationConflictPolicy,
        chunk_received: Vec<bool>,
    ) -> Result<Self, TransferError> {
        manifest.validate()?;
        if chunk_received.len() != manifest.chunk_count as usize {
            return Err(TransferError::ResumeRejected(
                "chunk_received length does not match manifest chunk_count",
            ));
        }

        let staging_parent = staging_path.parent().ok_or(TransferError::InvalidManifest(
            "staging path must have a parent directory",
        ))?;
        fs::create_dir_all(staging_parent)?;

        let meta = fs::metadata(&staging_path)?;
        if meta.len() != manifest.size {
            return Err(TransferError::ResumeRejected(
                "staging file size does not match manifest",
            ));
        }

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(false)
            .truncate(false)
            .open(&staging_path)?;

        Ok(Self {
            chunk_received,
            manifest,
            staging_path,
            destination,
            conflict,
            file,
        })
    }

    #[must_use]
    pub fn chunk_received_flags(&self) -> &[bool] {
        &self.chunk_received
    }

    #[must_use]
    pub fn manifest(&self) -> &OneFileManifest {
        &self.manifest
    }

    /// [`PathBuf`] staged assembly file (plaintext).
    #[must_use]
    pub fn staging_path(&self) -> &Path {
        &self.staging_path
    }

    /// Intended final path after successful [`Self::finalize`].
    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    #[must_use]
    pub fn all_chunks_received(&self) -> bool {
        self.chunk_received.iter().all(|b| *b)
    }

    /// Verify a plaintext chunk against its committed Blake3 digest and write it at the staged offset (ADR 0077, 0082).
    pub fn receive_chunk(&mut self, index: u32, payload: &[u8]) -> Result<(), TransferError> {
        let count = self.manifest.chunk_count;
        let Some((offset, expected_len_u64)) =
            chunk_span(self.manifest.size, self.manifest.chunk_size, index)
        else {
            return Err(TransferError::ChunkIndexOutOfBounds { index, count });
        };

        let expected_len = usize::try_from(expected_len_u64).map_err(|_| {
            TransferError::InvalidManifest("chunk length does not fit usize on this platform")
        })?;

        if payload.len() != expected_len {
            return Err(TransferError::ChunkPayloadSize {
                index,
                expected: expected_len,
                actual: payload.len(),
            });
        }

        let idx = usize::try_from(index).map_err(|_| {
            TransferError::InvalidManifest("chunk index does not fit usize on this platform")
        })?;

        let commitment = self
            .manifest
            .chunk_hashes
            .get(idx)
            .ok_or(TransferError::ChunkIndexOutOfBounds { index, count })?;

        let expected_digest = match commitment {
            ChunkHashCommitment::Pending => {
                return Err(TransferError::HashNotCommitted { index });
            }
            ChunkHashCommitment::Committed(d) => *d,
        };

        let actual: [u8; 32] = *blake3::hash(payload).as_bytes();
        if actual != expected_digest {
            return Err(TransferError::ChunkVerificationFailed { index });
        }

        self.file.seek(SeekFrom::Start(offset))?;
        self.file.write_all(payload)?;

        self.chunk_received[idx] = true;

        Ok(())
    }

    /// Flush staging, verify whole-file digest, enforce conflict policy, then rename into place.
    pub fn finalize(self) -> Result<(), TransferError> {
        for (i, done) in self.chunk_received.iter().enumerate() {
            if !done {
                return Err(TransferError::IncompleteTransfer {
                    missing_chunk: i as u32,
                });
            }
        }

        self.file.sync_all()?;
        drop(self.file);

        let digest = hash_file_plaintext(&self.staging_path)?;
        if digest != self.manifest.file_blake3 {
            return Err(TransferError::FileDigestMismatch);
        }

        if matches!(self.conflict, DestinationConflictPolicy::FailIfExists)
            && self.destination.exists()
        {
            return Err(TransferError::DestinationExists(self.destination.clone()));
        }

        fs::rename(&self.staging_path, &self.destination)?;

        Ok(())
    }
}

/// Local end-to-end copy: provider reads `source`; receiver fills `staging` and finalizes onto `destination`.
pub fn transfer_one_file_local(
    source: &Path,
    staging: &Path,
    destination: &Path,
    relative_path: &str,
    chunk_size: u64,
    conflict: DestinationConflictPolicy,
) -> Result<(), TransferError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }

    let provider = LocalProvider::from_file(source.to_path_buf(), relative_path, chunk_size)?;
    let manifest = provider.manifest().clone();

    let mut receiver = LocalReceiver::new(
        manifest,
        staging.to_path_buf(),
        destination.to_path_buf(),
        conflict,
    )?;

    for chunk_index in 0..provider.manifest().chunk_count {
        let data = provider.read_chunk(chunk_index)?;
        receiver.receive_chunk(chunk_index, &data)?;
    }

    receiver.finalize()
}

/// Phase 2 local path: same as [`transfer_one_file_local`], but manifest + control + chunk bytes use session crypto (compress is a no-op until wired).
pub fn transfer_one_file_local_encrypted(
    secrets: &SessionSecrets,
    invite: InviteContext,
    source: &Path,
    staging: &Path,
    destination: &Path,
    relative_path: &str,
    chunk_size: u64,
    conflict: DestinationConflictPolicy,
) -> Result<(), TransferError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }

    let binding = HandshakeBinding {
        invite,
        chunk_size,
        framing_version: 1,
    };
    let keys = secrets.derive_keys(&binding)?;

    let provider = LocalProvider::from_file(source.to_path_buf(), relative_path, chunk_size)?;
    let sealed_manifest =
        encrypt_manifest_blob(&keys, &encode_manifest_plaintext(provider.manifest()))?;

    let opened_plain = decrypt_manifest_blob(&keys, &sealed_manifest)?;
    let recv_manifest = decode_manifest_plaintext(&opened_plain)?;

    let approve = encrypt_control_payload(
        keys.control_key(),
        keys.session_id(),
        receiver_approve_payload(),
    )?;
    decrypt_control_payload(keys.control_key(), keys.session_id(), &approve)?;

    let mut receiver = LocalReceiver::new(
        recv_manifest,
        staging.to_path_buf(),
        destination.to_path_buf(),
        conflict,
    )?;

    for chunk_index in 0..provider.manifest().chunk_count {
        let pt = provider.read_chunk(chunk_index)?;
        let wire = encrypt_chunk_payload(&keys, chunk_index, &pt)?;
        let plaintext = decrypt_chunk_payload(&keys, chunk_index, &wire)?;
        receiver.receive_chunk(chunk_index, &plaintext)?;
    }

    receiver.finalize()
}

pub(crate) fn read_file_chunk(
    source: &Path,
    manifest: &OneFileManifest,
    index: u32,
) -> Result<Vec<u8>, TransferError> {
    let count = manifest.chunk_count;
    let Some((off, len)) = chunk_span(manifest.size, manifest.chunk_size, index) else {
        return Err(TransferError::ChunkIndexOutOfBounds { index, count });
    };

    let mut f = File::open(source)?;
    f.seek(SeekFrom::Start(off))?;
    let mut buf = vec![0u8; len as usize];
    f.read_exact(&mut buf)?;
    Ok(buf)
}

fn hash_file_plaintext(path: &Path) -> Result<[u8; 32], TransferError> {
    let mut file = File::open(path)?;
    let mut hasher = Hasher::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}
