//! Application-layer session material, transcript-bound HKDF derivation, and XChaCha20-Poly1305 envelopes for local transfer.
//!
//! Pairing establishes [`SessionSecrets`] via SPAKE2 (see [`crate::pairing`]); [`SessionSecrets::pairing_shim_local`] remains for offline tests without an invite.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand::{rngs::OsRng, TryRngCore};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::error::TransferError;
use crate::manifest::{ChunkHashCommitment, OneFileManifest};

const LABEL_META: &[u8] = b"beam.v1.key.meta";
const LABEL_CTRL: &[u8] = b"beam.v1.key.ctrl";
const LABEL_CHUNK: &[u8] = b"beam.v1.key.chunk";
const LABEL_RECONNECT: &[u8] = b"beam.v1.key.reconnect";

const AAD_MANIFEST_ENVELOPE: &[u8] = b"beam.v1.env.manifest.v1";
const AAD_CONTROL_ENVELOPE: &[u8] = b"beam.v1.env.control.v1";
const AAD_CHUNK_ENVELOPE: &[u8] = b"beam.v1.env.chunk.v1";

const CONTROL_APPROVE_PAYLOAD: &[u8] = b"beam.v1.ctrl.receiver_approve_one_file.v1";

/// Invite / rendezvous context bound into every derived key (`[0;32]` acceptable for temporary local pairing).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InviteContext(pub [u8; 32]);

impl Default for InviteContext {
    fn default() -> Self {
        InviteContext([0u8; 32])
    }
}

/// Negotiated handshake fields both sides serialize identically before key derivation (ADR transcript binding).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HandshakeBinding {
    pub invite: InviteContext,
    pub chunk_size: u64,
    /// Protocol-framing discriminator for downstream wire formats.
    pub framing_version: u8,
}

/// Symmetric pairing output until PAKE fills this hole: random session id plus root IKM authenticated out-of-band later.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionSecrets {
    pub session_id: [u8; 16],
    ikm: [u8; 32],
}

impl Zeroize for SessionSecrets {
    fn zeroize(&mut self) {
        self.session_id.zeroize();
        self.ikm.zeroize();
    }
}

impl Drop for SessionSecrets {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SessionSecrets {
    /// Builds session root material from a 32-byte SPAKE2 shared secret and the pairing room id (salt).
    ///
    /// Resume contexts must not depend on the human-facing invite code after pairing; they hang off these secrets.
    pub fn from_pake_shared_secret(
        pake_shared_key: &[u8],
        room_id: &[u8; 16],
    ) -> Result<Self, TransferError> {
        if pake_shared_key.len() != 32 {
            return Err(TransferError::SessionCrypto(
                "PAKE shared secret must be 32 bytes",
            ));
        }
        let hk = Hkdf::<Sha256>::new(Some(room_id), pake_shared_key);
        let mut session_id = [0u8; 16];
        let mut ikm = [0u8; 32];
        hk.expand(b"beam.session.id.v1", &mut session_id)
            .map_err(|_| TransferError::SessionCrypto("hkdf expand session id"))?;
        hk.expand(b"beam.session.ikm.v1", &mut ikm)
            .map_err(|_| TransferError::SessionCrypto("hkdf expand session ikm"))?;
        Ok(Self { session_id, ikm })
    }

    /// Temporary shim: emits fresh authenticated session secret material for same-process tests and local tooling.
    pub fn pairing_shim_local() -> Self {
        let mut session_id = [0u8; 16];
        let mut ikm = [0u8; 32];
        let mut rng = OsRng;
        rng.try_fill_bytes(&mut session_id)
            .expect("session id entropy from OsRng must succeed");
        rng.try_fill_bytes(&mut ikm)
            .expect("pairing root key entropy from OsRng must succeed");
        Self { session_id, ikm }
    }

    #[must_use]
    pub fn transcript_digest(&self, binding: &HandshakeBinding) -> [u8; 32] {
        handshake_transcript_sha256(&self.session_id, binding)
    }

    /// Purpose-separated keys bound to the handshake transcript and root IKM.
    pub fn derive_keys(&self, binding: &HandshakeBinding) -> Result<SessionKeys, TransferError> {
        let transcript = self.transcript_digest(binding);
        let hk = Hkdf::<Sha256>::new(Some(&transcript), &self.ikm);
        let mut metadata_key = [0u8; 32];
        let mut control_key = [0u8; 32];
        let mut chunk_key = [0u8; 32];
        let mut reconnect_key = [0u8; 32];
        hk.expand(LABEL_META, &mut metadata_key)
            .map_err(|_| TransferError::SessionCrypto("hkdf expand meta"))?;
        hk.expand(LABEL_CTRL, &mut control_key)
            .map_err(|_| TransferError::SessionCrypto("hkdf expand ctrl"))?;
        hk.expand(LABEL_CHUNK, &mut chunk_key)
            .map_err(|_| TransferError::SessionCrypto("hkdf expand chunk"))?;
        hk.expand(LABEL_RECONNECT, &mut reconnect_key)
            .map_err(|_| TransferError::SessionCrypto("hkdf expand reconnect"))?;
        Ok(SessionKeys {
            session_id: self.session_id,
            metadata_key,
            control_key,
            chunk_key,
            reconnect_key,
        })
    }
}

/// Canonical invite/rendezvous fingerprint bound into HKDF (distinct from the PAKE password material).
#[must_use]
pub fn invite_context_from_pairing(
    room_id: &[u8; 16],
    expires_unix: u64,
    relay_tag: &[u8],
) -> InviteContext {
    let mut h = Sha256::new();
    h.update(b"beam.invite.ctx.v1");
    h.update(room_id);
    h.update(expires_unix.to_le_bytes());
    h.update(relay_tag);
    InviteContext(h.finalize().into())
}

fn handshake_transcript_sha256(session_id: &[u8; 16], binding: &HandshakeBinding) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"beam.handshake.transcript.v1");
    h.update(session_id);
    h.update(b"beam.role.provider.v1");
    h.update(b"beam.role.receiver.v1");
    h.update(binding.invite.0);
    h.update(binding.chunk_size.to_le_bytes());
    h.update([binding.framing_version]);
    h.finalize().into()
}

/// Derived symmetric keys for metadata, control plane, chunk payloads, and reconnect contexts.
#[derive(Clone, Eq, PartialEq)]
pub struct SessionKeys {
    session_id: [u8; 16],
    metadata_key: [u8; 32],
    control_key: [u8; 32],
    chunk_key: [u8; 32],
    reconnect_key: [u8; 32],
}

impl Zeroize for SessionKeys {
    fn zeroize(&mut self) {
        self.session_id.zeroize();
        self.metadata_key.zeroize();
        self.control_key.zeroize();
        self.chunk_key.zeroize();
        self.reconnect_key.zeroize();
    }
}

impl Drop for SessionKeys {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl SessionKeys {
    #[must_use]
    pub fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    #[must_use]
    pub fn metadata_key(&self) -> &[u8; 32] {
        &self.metadata_key
    }

    #[must_use]
    pub fn control_key(&self) -> &[u8; 32] {
        &self.control_key
    }

    #[must_use]
    pub fn chunk_key(&self) -> &[u8; 32] {
        &self.chunk_key
    }

    #[must_use]
    pub fn reconnect_key(&self) -> &[u8; 32] {
        &self.reconnect_key
    }
}

fn build_manifest_aad(session_id: &[u8; 16]) -> [u8; 16 + AAD_MANIFEST_ENVELOPE.len()] {
    let mut aad = [0u8; 16 + AAD_MANIFEST_ENVELOPE.len()];
    let n = AAD_MANIFEST_ENVELOPE.len();
    aad[..n].copy_from_slice(AAD_MANIFEST_ENVELOPE);
    aad[n..].copy_from_slice(session_id);
    aad
}

fn build_control_aad(session_id: &[u8; 16]) -> [u8; 16 + AAD_CONTROL_ENVELOPE.len()] {
    let mut aad = [0u8; 16 + AAD_CONTROL_ENVELOPE.len()];
    let n = AAD_CONTROL_ENVELOPE.len();
    aad[..n].copy_from_slice(AAD_CONTROL_ENVELOPE);
    aad[n..].copy_from_slice(session_id);
    aad
}

fn build_chunk_aad(session_id: &[u8; 16], index: u32) -> [u8; AAD_CHUNK_ENVELOPE.len() + 16 + 4] {
    let mut aad = [0u8; AAD_CHUNK_ENVELOPE.len() + 16 + 4];
    let mut o = 0usize;
    aad[o..o + AAD_CHUNK_ENVELOPE.len()].copy_from_slice(AAD_CHUNK_ENVELOPE);
    o += AAD_CHUNK_ENVELOPE.len();
    aad[o..o + 16].copy_from_slice(session_id);
    o += 16;
    aad[o..o + 4].copy_from_slice(&index.to_le_bytes());
    aad
}

fn xchacha_seal(
    key: &[u8; 32],
    aad_slice: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, TransferError> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 24];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut nonce)
        .map_err(|_| TransferError::SessionCrypto("rng nonce"))?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: aad_slice,
            },
        )
        .map_err(|_| TransferError::SessionCrypto("aead encrypt"))?;

    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn xchacha_open_into(
    key: &[u8; 32],
    aad_slice: &[u8],
    blob: &[u8],
    fail: TransferError,
) -> Result<Vec<u8>, TransferError> {
    if blob.len() < 24 + 16 {
        return Err(fail);
    }
    let (nonce, ciphertext) = blob.split_at(24);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: aad_slice,
            },
        )
        .map_err(|_| fail)
}

/// Encode plaintext manifest commitments for sealing (plaintext stays under Blake3 hashing pre-seal upstream).
#[must_use]
pub fn encode_manifest_plaintext(m: &OneFileManifest) -> Vec<u8> {
    let path_bytes = m.relative_path.as_bytes();
    let mut out =
        Vec::with_capacity(path_bytes.len() + 128 + usize::try_from(m.chunk_count).unwrap() * 33);
    out.extend_from_slice(&(path_bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(path_bytes);
    out.extend_from_slice(&m.size.to_le_bytes());
    out.extend_from_slice(&m.chunk_size.to_le_bytes());
    out.extend_from_slice(&m.chunk_count.to_le_bytes());
    out.extend_from_slice(&m.file_blake3);
    for c in &m.chunk_hashes {
        match c {
            ChunkHashCommitment::Pending => out.push(0),
            ChunkHashCommitment::Committed(d) => {
                out.push(1);
                out.extend_from_slice(d);
            }
        }
    }
    out
}

/// Decode plaintext manifest commitments after successful AEAD decryption.
pub fn decode_manifest_plaintext(data: &[u8]) -> Result<OneFileManifest, TransferError> {
    fn read_u32(data: &mut &[u8]) -> Result<u32, TransferError> {
        if data.len() < 4 {
            return Err(TransferError::InvalidManifest("truncated manifest"));
        }
        let (head, tail) = data.split_at(4);
        *data = tail;
        Ok(u32::from_le_bytes(head.try_into().unwrap()))
    }
    fn read_u64(data: &mut &[u8]) -> Result<u64, TransferError> {
        if data.len() < 8 {
            return Err(TransferError::InvalidManifest("truncated manifest"));
        }
        let (head, tail) = data.split_at(8);
        *data = tail;
        Ok(u64::from_le_bytes(head.try_into().unwrap()))
    }
    fn take<'a>(data: &mut &'a [u8], n: usize) -> Result<&'a [u8], TransferError> {
        if data.len() < n {
            return Err(TransferError::InvalidManifest("truncated manifest"));
        }
        let (head, tail) = data.split_at(n);
        *data = tail;
        Ok(head)
    }

    let mut cur = data;
    let len = read_u32(&mut cur)? as usize;
    let path_bytes = take(&mut cur, len)?;
    let relative_path = std::str::from_utf8(path_bytes)
        .map_err(|_| TransferError::InvalidManifest("manifest path is not utf-8"))?
        .to_owned();
    let size = read_u64(&mut cur)?;
    let chunk_size = read_u64(&mut cur)?;
    let chunk_count = read_u32(&mut cur)?;
    let file_digest = take(&mut cur, 32)?;
    let mut file_blake3 = [0u8; 32];
    file_blake3.copy_from_slice(file_digest);

    let mut chunk_hashes = Vec::with_capacity(chunk_count as usize);
    for _ in 0..chunk_count {
        let tag = *take(&mut cur, 1)?
            .first()
            .ok_or(TransferError::InvalidManifest(
                "missing chunk commitment tag",
            ))?;
        match tag {
            0 => chunk_hashes.push(ChunkHashCommitment::Pending),
            1 => {
                let d = take(&mut cur, 32)?;
                let mut digest = [0u8; 32];
                digest.copy_from_slice(d);
                chunk_hashes.push(ChunkHashCommitment::Committed(digest));
            }
            _ => {
                return Err(TransferError::InvalidManifest(
                    "unknown chunk commitment tag",
                ));
            }
        }
    }
    if !cur.is_empty() {
        return Err(TransferError::InvalidManifest("trailing manifest bytes"));
    }

    let m = OneFileManifest {
        relative_path,
        size,
        chunk_size,
        chunk_count,
        file_blake3,
        chunk_hashes,
    };
    m.validate()?;
    Ok(m)
}

/// Encrypt+authenticate manifest bytes (receiver must validate after open, before staging).
pub fn encrypt_manifest_blob(
    keys: &SessionKeys,
    plaintext: &[u8],
) -> Result<Vec<u8>, TransferError> {
    let aad = build_manifest_aad(keys.session_id());
    xchacha_seal(keys.metadata_key(), &aad, plaintext)
}

/// Recover manifest plaintext; wrong material or tampering yields [`TransferError::ManifestEnvelopeAuthFailed`].
pub fn decrypt_manifest_blob(keys: &SessionKeys, blob: &[u8]) -> Result<Vec<u8>, TransferError> {
    let aad = build_manifest_aad(keys.session_id());
    xchacha_open_into(
        keys.metadata_key(),
        &aad,
        blob,
        TransferError::ManifestEnvelopeAuthFailed,
    )
}

pub fn encrypt_control_payload(
    key: &[u8; 32],
    session_id: &[u8; 16],
    body: &[u8],
) -> Result<Vec<u8>, TransferError> {
    let aad = build_control_aad(session_id);
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let mut nonce = [0u8; 24];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut nonce)
        .map_err(|_| TransferError::SessionCrypto("rng nonce"))?;
    let ct = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: body,
                aad: &aad,
            },
        )
        .map_err(|_| TransferError::SessionCrypto("control encrypt"))?;
    let mut out = Vec::with_capacity(24 + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(out)
}

pub fn decrypt_control_payload(
    key: &[u8; 32],
    session_id: &[u8; 16],
    blob: &[u8],
) -> Result<Vec<u8>, TransferError> {
    let aad = build_control_aad(session_id);
    xchacha_open_into(key, &aad, blob, TransferError::ControlEnvelopeAuthFailed)
}

#[must_use]
pub fn receiver_approve_payload() -> &'static [u8] {
    CONTROL_APPROVE_PAYLOAD
}

pub fn encrypt_chunk_payload(
    keys: &SessionKeys,
    index: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>, TransferError> {
    let aad = build_chunk_aad(keys.session_id(), index);
    xchacha_seal(keys.chunk_key(), &aad, plaintext)
}

pub fn decrypt_chunk_payload(
    keys: &SessionKeys,
    index: u32,
    blob: &[u8],
) -> Result<Vec<u8>, TransferError> {
    let aad = build_chunk_aad(keys.session_id(), index);
    xchacha_open_into(
        keys.chunk_key(),
        &aad,
        blob,
        TransferError::ChunkEnvelopeAuthFailed,
    )
}
