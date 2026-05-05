//! Structured local session files for pause / resume (Phase 7, ADR 0088).
//!
//! Session secrets are stored in plaintext JSON suitable for tests and trusted single-user hosts;
//! callers should set restrictive file permissions.

use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::TransferError;
use crate::local_transfer::DestinationConflictPolicy;
use crate::manifest::OneFileManifest;
use crate::session_crypto::{
    decode_manifest_plaintext, encode_manifest_plaintext, HandshakeBinding, InviteContext,
    SessionSecrets,
};

const FILE_FORMAT_V1: u32 = 1;

/// Explicit transfer progress persisted for UX and validation (ADR 0085 subset).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersistedTransferState {
    Transferring,
    Paused,
    Reconnecting,
    Finalizing,
    Complete,
    Partial,
    Failed,
}

/// On-disk layout for [`LocalSessionFileV1::save`] / [`LocalSessionFileV1::load`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LocalSessionFileV1 {
    pub format: u32,
    /// Hex-encoded 16-byte machine fingerprint (ADR 0059).
    pub machine_id_hex: String,
    pub session_id_hex: String,
    pub ikm_hex: String,
    pub invite_context_hex: String,
    pub chunk_size: u64,
    pub framing_version: u8,
    /// Original relative path filter (ADR 0043).
    pub relative_path: String,
    /// Hex-encoded [`encode_manifest_plaintext`] blob.
    pub manifest_plaintext_hex: String,
    pub staging_path: String,
    pub destination_path: String,
    pub conflict: DestinationConflictPolicy,
    /// Next QUIC leg serial for [`SessionSecrets::derive_keys_for_connection_serial`].
    pub next_connection_serial: u64,
    pub transfer_state: PersistedTransferState,
    pub chunk_received: Vec<bool>,
}

impl LocalSessionFileV1 {
    /// Stable fingerprint for the current host (hash of hostname material).
    #[must_use]
    pub fn current_machine_id_hex() -> String {
        let host = hostname_for_machine_id();
        let mut h = Sha256::new();
        h.update(b"beam.v1.machine_id.v1");
        h.update(host.as_bytes());
        let full: [u8; 32] = h.finalize().into();
        hex_lower_16(&full[..16])
    }

    pub fn save(&self, path: impl AsRef<Path>) -> Result<(), TransferError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_vec_pretty(self)
            .map_err(|_| TransferError::SessionState("serialize session json failed"))?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn load(path: impl AsRef<Path>) -> Result<Self, TransferError> {
        let bytes = fs::read(path.as_ref()).map_err(|_| {
            TransferError::SessionState("cannot read session file (missing or unreadable)")
        })?;
        let s: Self = serde_json::from_slice(&bytes)
            .map_err(|_| TransferError::SessionState("session file is not valid v1 json"))?;
        if s.format != FILE_FORMAT_V1 {
            return Err(TransferError::SessionState("unsupported session format version"));
        }
        Ok(s)
    }

    pub fn validate_machine(&self) -> Result<(), TransferError> {
        if self.machine_id_hex != Self::current_machine_id_hex() {
            return Err(TransferError::ResumeMachineMismatch);
        }
        Ok(())
    }

    pub fn session_secrets(&self) -> Result<SessionSecrets, TransferError> {
        let sid = parse_16_hex(&self.session_id_hex).map_err(|_| {
            TransferError::SessionState("session_id_hex must be 32 hex chars (16 bytes)")
        })?;
        let ikm = parse_32_hex(&self.ikm_hex).map_err(|_| {
            TransferError::SessionState("ikm_hex must be 64 hex chars (32 bytes)")
        })?;
        Ok(SessionSecrets::from_persisted_parts(sid, ikm))
    }

    pub fn handshake_binding(&self) -> Result<HandshakeBinding, TransferError> {
        let invite_bytes = parse_32_hex(&self.invite_context_hex).map_err(|_| {
            TransferError::SessionState("invite_context_hex must be 64 hex chars")
        })?;
        Ok(HandshakeBinding {
            invite: InviteContext(invite_bytes),
            chunk_size: self.chunk_size,
            framing_version: self.framing_version,
        })
    }

    pub fn staging_path_buf(&self) -> PathBuf {
        PathBuf::from(&self.staging_path)
    }

    pub fn destination_path_buf(&self) -> PathBuf {
        PathBuf::from(&self.destination_path)
    }

    #[must_use]
    pub fn conflict_policy(&self) -> DestinationConflictPolicy {
        self.conflict
    }

    pub fn manifest_from_session(&self) -> Result<OneFileManifest, TransferError> {
        let bytes = decode_hex(&self.manifest_plaintext_hex).map_err(|_| {
            TransferError::SessionState("manifest_plaintext_hex is invalid hex")
        })?;
        decode_manifest_plaintext(&bytes)
    }

    /// Build a new file after the first leg paused mid-transfer.
    pub fn new_receiver_paused(
        secrets: &SessionSecrets,
        binding: &HandshakeBinding,
        manifest: &OneFileManifest,
        relative_path: impl Into<String>,
        staging: PathBuf,
        destination: PathBuf,
        conflict: DestinationConflictPolicy,
        chunk_received: Vec<bool>,
    ) -> Self {
        let (sid, ikm) = secrets.persist_parts();
        let mp = encode_manifest_plaintext(manifest);
        Self {
            format: FILE_FORMAT_V1,
            machine_id_hex: Self::current_machine_id_hex(),
            session_id_hex: hex_encode(&sid),
            ikm_hex: hex_encode(&ikm),
            invite_context_hex: hex_encode(&binding.invite.0),
            chunk_size: binding.chunk_size,
            framing_version: binding.framing_version,
            relative_path: relative_path.into(),
            manifest_plaintext_hex: hex_encode(&mp),
            staging_path: staging.to_string_lossy().into_owned(),
            destination_path: destination.to_string_lossy().into_owned(),
            conflict,
            next_connection_serial: 1,
            transfer_state: PersistedTransferState::Paused,
            chunk_received,
        }
    }
}

fn hostname_for_machine_id() -> String {
    if let Ok(h) = std::env::var("BEAM_MACHINE_ID") {
        return h;
    }
    #[cfg(windows)]
    {
        std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
    }
    #[cfg(not(windows))]
    {
        std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "unknown".to_string())
    }
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_lower_16(b: &[u8]) -> String {
    hex_encode(b)
}

fn parse_16_hex(s: &str) -> Result<[u8; 16], ()> {
    let v = decode_hex(s)?;
    if v.len() != 16 {
        return Err(());
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&v);
    Ok(out)
}

fn parse_32_hex(s: &str) -> Result<[u8; 32], ()> {
    let v = decode_hex(s)?;
    if v.len() != 32 {
        return Err(());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn decode_hex(s: &str) -> Result<Vec<u8>, ()> {
    if s.len() % 2 != 0 {
        return Err(());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

/// Enforce relative path filter on resume (ADR 0043).
pub fn assert_resume_relative_path(session: &LocalSessionFileV1, relative_path: &str) -> Result<(), TransferError> {
    if session.relative_path != relative_path {
        return Err(TransferError::ResumeRejected(
            "relative_path does not match persisted session",
        ));
    }
    Ok(())
}
