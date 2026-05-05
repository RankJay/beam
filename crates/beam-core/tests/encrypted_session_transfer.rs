//! Phase 2 proof tests: session crypto on the local pipeline.

use std::fs;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use beam_core::local_transfer::{
    transfer_one_file_local_encrypted, DestinationConflictPolicy, LocalProvider,
};
use beam_core::session_crypto::{
    decrypt_chunk_payload, decrypt_control_payload, decrypt_manifest_blob,
    encode_manifest_plaintext, encrypt_chunk_payload, encrypt_control_payload,
    encrypt_manifest_blob, receiver_approve_payload, HandshakeBinding, InviteContext,
    SessionSecrets,
};
use beam_core::TransferError;

fn binding_for(chunk_size: u64) -> HandshakeBinding {
    HandshakeBinding {
        invite: InviteContext::default(),
        chunk_size,
        framing_version: 1,
    }
}

#[test]
fn encrypted_roundtrip_matches_plaintext_pipeline() {
    let dir = TempDir::new().expect("temp");
    let staging_dir = TempDir::new().expect("staging");
    let secrets = SessionSecrets::pairing_shim_local();
    let src = dir.path().join("e.bin");
    let body: Vec<u8> = (0_u8..=211).collect();
    fs::write(&src, &body).expect("write");

    let dest = dir.path().join("out-e.bin");
    let staging = staging_dir.path().join("st-e.bin");
    transfer_one_file_local_encrypted(
        &secrets,
        InviteContext::default(),
        &src,
        &staging,
        &dest,
        "e.bin",
        64,
        DestinationConflictPolicy::FailIfExists,
    )
    .expect("encrypted transfer");

    assert_eq!(fs::read(&dest).expect("read"), body);
}

#[test]
fn mismatched_handshake_binding_rejects_manifest_open() {
    let dir = TempDir::new().expect("temp");
    let src = dir.path().join("hb.bin");
    fs::write(&src, b"z").expect("write");

    let secrets = SessionSecrets::pairing_shim_local();
    let keys_encrypt = secrets
        .derive_keys(&HandshakeBinding {
            invite: InviteContext::default(),
            chunk_size: 4096,
            framing_version: 1,
        })
        .expect("keys seal");
    let provider = LocalProvider::from_file(&src, "hb.bin", 4096).expect("prov");
    let sealed = encrypt_manifest_blob(
        &keys_encrypt,
        &encode_manifest_plaintext(provider.manifest()),
    )
    .expect("seal");

    let keys_other_binding = secrets
        .derive_keys(&HandshakeBinding {
            invite: InviteContext([1u8; 32]),
            chunk_size: 4096,
            framing_version: 1,
        })
        .expect("keys open");
    assert!(matches!(
        decrypt_manifest_blob(&keys_other_binding, &sealed),
        Err(TransferError::ManifestEnvelopeAuthFailed)
    ));
}

#[test]
fn wrong_session_ikm_rejects_manifest_open() {
    let dir = TempDir::new().expect("temp");
    let src = dir.path().join("w.bin");
    fs::write(&src, b"x").expect("write");

    let good = SessionSecrets::pairing_shim_local();
    let keys = good.derive_keys(&binding_for(4096)).expect("keys");
    let provider = LocalProvider::from_file(&src, "w.bin", 4096).expect("prov");
    let sealed = encrypt_manifest_blob(&keys, &encode_manifest_plaintext(provider.manifest()))
        .expect("seal");

    let bad = SessionSecrets::pairing_shim_local();
    let bad_keys = bad.derive_keys(&binding_for(4096)).expect("keys2");
    assert!(matches!(
        decrypt_manifest_blob(&bad_keys, &sealed),
        Err(TransferError::ManifestEnvelopeAuthFailed)
    ));
}

#[test]
fn tampered_manifest_ciphertext_fails_before_receiver() {
    let dir = TempDir::new().expect("temp");
    let src = dir.path().join("t.bin");
    fs::write(&src, b"y").expect("write");

    let secrets = SessionSecrets::pairing_shim_local();
    let keys = secrets.derive_keys(&binding_for(4096)).expect("keys");
    let provider = LocalProvider::from_file(&src, "t.bin", 4096).expect("prov");
    let mut sealed = encrypt_manifest_blob(&keys, &encode_manifest_plaintext(provider.manifest()))
        .expect("seal");
    if let Some(last) = sealed.last_mut() {
        *last ^= 0x01;
    }
    assert!(matches!(
        decrypt_manifest_blob(&keys, &sealed),
        Err(TransferError::ManifestEnvelopeAuthFailed)
    ));
}

#[test]
fn tampered_chunk_wire_fails_before_staging_verification() {
    let dir = TempDir::new().expect("temp");
    let staging_dir = TempDir::new().expect("staging");
    let secrets = SessionSecrets::pairing_shim_local();
    let src = dir.path().join("c.bin");
    fs::write(&src, [9, 9, 9, 9]).expect("write");

    let keys = secrets.derive_keys(&binding_for(2)).expect("keys");
    let provider = LocalProvider::from_file(&src, "c.bin", 2).expect("prov");
    let mut wire = encrypt_chunk_payload(&keys, 0, &provider.read_chunk(0).unwrap()).expect("wire");
    wire[30] ^= 0xff;
    assert!(matches!(
        decrypt_chunk_payload(&keys, 0, &wire),
        Err(TransferError::ChunkEnvelopeAuthFailed)
    ));

    let dest = dir.path().join("out-c.bin");
    let staging = staging_dir.path().join("st-c.bin");
    let _ = fs::remove_file(&dest);
    let r = transfer_one_file_local_encrypted(
        &secrets,
        InviteContext::default(),
        &src,
        &staging,
        &dest,
        "c.bin",
        2,
        DestinationConflictPolicy::FailIfExists,
    );
    assert!(r.is_ok());
}

#[test]
fn control_envelope_cannot_be_opened_with_chunk_keys() {
    let secrets = SessionSecrets::pairing_shim_local();
    let keys = secrets.derive_keys(&binding_for(128)).expect("keys");
    let sealed = encrypt_control_payload(
        keys.control_key(),
        keys.session_id(),
        receiver_approve_payload(),
    )
    .expect("seal ctrl");

    assert!(matches!(
        decrypt_control_payload(keys.chunk_key(), keys.session_id(), &sealed),
        Err(TransferError::ControlEnvelopeAuthFailed)
    ));
}

#[test]
fn metadata_path_not_embedded_in_ciphertext_plaintext_leak_harness() {
    let dir = TempDir::new().expect("temp");
    let src = dir.path().join("secret-name.bin");
    fs::write(&src, b"payload").expect("write");
    let secrets = SessionSecrets::pairing_shim_local();
    let keys = secrets.derive_keys(&binding_for(4096)).expect("keys");
    let provider =
        LocalProvider::from_file(&src, "deep/hidden/secret-name.bin", 4096).expect("prov");
    let ct =
        encrypt_manifest_blob(&keys, &encode_manifest_plaintext(provider.manifest())).expect("ct");

    let needle = b"deep/hidden/secret-name.bin";
    assert!(
        !ct.windows(needle.len()).any(|w| w == needle),
        "AEAD ciphertext should not literally contain the UTF-8 logical path"
    );
}

#[test]
fn crypto_overhead_smoke_stays_within_loose_budget() {
    let secrets = SessionSecrets::pairing_shim_local();
    let chunk_size = 256 * 1024u64;
    let binding = binding_for(chunk_size);
    let keys = secrets.derive_keys(&binding).expect("keys");
    let plaintext: Vec<u8> = vec![0xabu8; chunk_size as usize];

    let iterations = 48u32;
    let start = Instant::now();
    for i in 0..iterations {
        let wire = encrypt_chunk_payload(&keys, i, &plaintext).expect("seal chunk");
        let out = decrypt_chunk_payload(&keys, i, &wire).expect("open chunk");
        assert_eq!(out, plaintext);
    }
    let elapsed = start.elapsed();
    let per_round = elapsed / iterations;
    let budget = if cfg!(debug_assertions) {
        Duration::from_millis(3000)
    } else {
        Duration::from_millis(750)
    };
    assert!(
        per_round < budget,
        "expected ~256KiB chunk AEAD round trip within {budget:?}/item, got {per_round:?} (total {elapsed:?})"
    );
}
