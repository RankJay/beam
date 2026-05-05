//! Phase 3 validation: invite parsing, SPAKE2 pairing, expiry, and single-use mailbox semantics.

use std::thread;
use std::time::Duration;

use tempfile::TempDir;

use beam_core::chunking::DEFAULT_CHUNK_SIZE;
use beam_core::pairing::{
    parse_invite_line, prepare_invite_default_word_stub, prepare_invite_human_words,
    prepare_invite_long_token, receiver_derive_session_secrets, sender_derive_session_secrets,
    FsRelay, MemoryRelay, PairingError, ParsedInvite, RendezvousRelay, RELAY_BEAM_FS_PREFIX,
};
use beam_core::session_crypto::{decrypt_manifest_blob, encrypt_manifest_blob, HandshakeBinding};

#[test]
fn correct_invite_pairs_and_derives_matching_session_material() {
    let relay = MemoryRelay::default();
    let prepared = prepare_invite_default_word_stub(3600).expect("prepare");
    let invite_ctx = prepared.invite_context();
    let (tx, rx) = beam_core::pairing::pair_in_memory_for_test(&relay, prepared).expect("pair");
    assert_eq!(tx.session_id, rx.session_id);
    let binding = HandshakeBinding {
        invite: invite_ctx,
        chunk_size: DEFAULT_CHUNK_SIZE,
        framing_version: 1,
    };
    assert_eq!(
        tx.transcript_digest(&binding),
        rx.transcript_digest(&binding)
    );
}

#[test]
fn human_word_invite_pairs_through_fs_mailbox() {
    let dir = TempDir::new().expect("temp");
    let mailbox = dir.path().join("mb");
    std::fs::create_dir_all(&mailbox).expect("mkdir");
    let prepared = prepare_invite_human_words(3600, &mailbox).expect("prep");
    let line = prepared.invite_line.clone();

    let send_mailbox = mailbox.clone();
    let prep_clone = prepared.clone();
    let th = thread::spawn(move || {
        let mut r = FsRelay::new(send_mailbox);
        sender_derive_session_secrets(&mut r, &prep_clone, Duration::from_secs(10))
    });

    thread::sleep(Duration::from_millis(50));
    let invite = parse_invite_line(&line).expect("parse");
    let mut relay = FsRelay::new(mailbox.clone());
    let rx = receiver_derive_session_secrets(&mut relay, &invite, Duration::from_secs(10))
        .expect("recv pair");
    let tx = th.join().expect("join").expect("sender pair");

    assert_eq!(tx.session_id, rx.session_id);
}

#[test]
fn long_token_carries_custom_relay_without_extra_cli_config() {
    let dir = TempDir::new().expect("temp");
    let mailbox = dir.path().join("custom-mb");
    std::fs::create_dir_all(&mailbox).expect("mkdir");
    let url = format!("{}{}", RELAY_BEAM_FS_PREFIX, mailbox.display());
    let prepared = prepare_invite_long_token(600, &url).expect("prep");
    let parsed = parse_invite_line(&prepared.invite_line).expect("parse");
    assert!(matches!(
        parsed.relay,
        RendezvousRelay::BeamFs(ref p) if p == &mailbox
    ));
}

#[test]
fn wrong_seed_fails_to_align_session_material() {
    let relay = MemoryRelay::default();
    let prepared = prepare_invite_default_word_stub(120).expect("prep");
    let mut invite = parse_invite_line(&prepared.invite_line).expect("parse");
    invite.seed[3] ^= 0xff;

    let relay_a = relay.clone();
    let prepared_a = prepared.clone();
    let sender = thread::spawn(move || {
        let mut r = relay_a.clone();
        sender_derive_session_secrets(&mut r, &prepared_a, Duration::from_secs(5))
    });
    thread::sleep(Duration::from_millis(20));
    let mut relay_b = relay.clone();
    let recv_sec = receiver_derive_session_secrets(&mut relay_b, &invite, Duration::from_secs(5))
        .expect("recv finishes handshake");
    let send_sec = sender
        .join()
        .expect("join")
        .expect("sender finishes handshake");
    assert_ne!(send_sec.session_id, recv_sec.session_id);
}

#[test]
fn expired_invite_is_rejected_before_handshake() {
    let invite = ParsedInvite {
        relay: RendezvousRelay::Default,
        room_id: [9u8; 16],
        expires_unix: 1,
        seed: [1u8; 10],
    };
    assert!(matches!(
        invite.assert_not_expired(),
        Err(PairingError::Expired)
    ));
}

#[test]
fn consumed_mailbox_rejects_a_second_receiver() {
    let relay = MemoryRelay::default();
    let prepared = prepare_invite_default_word_stub(600).expect("prep");
    let line = prepared.invite_line.clone();
    beam_core::pairing::pair_in_memory_for_test(&relay, prepared).expect("first pair");

    let invite = parse_invite_line(&line).expect("parse");
    let mut relay2 = relay.clone();
    let second = receiver_derive_session_secrets(&mut relay2, &invite, Duration::from_millis(200));
    assert!(second.is_err());
}

#[test]
fn pairing_derived_keys_decrypt_manifest_across_participants() {
    let relay = MemoryRelay::default();
    let prepared = prepare_invite_default_word_stub(600).expect("prep");
    let invite_ctx = prepared.invite_context();
    let line = prepared.invite_line.clone();
    let (tx_sec, rx_sec) =
        beam_core::pairing::pair_in_memory_for_test(&relay, prepared).expect("pair");

    let invite_parsed = parse_invite_line(&line).expect("parse");
    assert_eq!(invite_ctx, invite_parsed.invite_context());

    let binding = HandshakeBinding {
        invite: invite_ctx,
        chunk_size: DEFAULT_CHUNK_SIZE,
        framing_version: 1,
    };
    let tx_keys = tx_sec.derive_keys(&binding).expect("tx keys");
    let rx_keys = rx_sec.derive_keys(&binding).expect("rx keys");
    let pt = b"beam-manifest-cross-check";
    let sealed = encrypt_manifest_blob(&tx_keys, pt).expect("seal");
    let opened = decrypt_manifest_blob(&rx_keys, &sealed).expect("open");
    assert_eq!(opened.as_slice(), pt);
}
