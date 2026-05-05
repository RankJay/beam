//! Phase 7: clean pause / resume across process-style legs (persisted session + connection serial).

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};

use beam_core::direct_quic::{
    development_localhost_quinn, framed_transfer_provider_quic_leg, framed_transfer_receiver_quic_leg,
    ReceiverSessionOutcome,
};
use beam_core::TransferError;
use beam_core::local_transfer::{DestinationConflictPolicy, LocalProvider, LocalReceiver};
use beam_core::session_crypto::{HandshakeBinding, InviteContext, SessionSecrets};
use beam_core::session_file::{assert_resume_relative_path, LocalSessionFileV1};
use tokio::sync::oneshot;

#[tokio::test]
async fn pause_mid_transfer_resume_with_fresh_keys_same_machine() {
    std::env::set_var("BEAM_MACHINE_ID", "phase7-proof-machine");

    let dir = tempfile::TempDir::new().expect("temp");
    let staging_path = dir.path().join("st.bin");
    let dest_path = dir.path().join("out.bin");
    let src_path = dir.path().join("src.bin");

    let body: Vec<u8> = (0_u8..=255).collect();
    std::fs::write(&src_path, &body).expect("write source");

    let chunk_size = 64_u64;
    let secrets = SessionSecrets::pairing_shim_local();
    let binding = HandshakeBinding {
        invite: InviteContext::default(),
        chunk_size,
        framing_version: 1,
    };

    let manifest = LocalProvider::from_file(&src_path, "f.bin", chunk_size)
        .expect("provider")
        .manifest()
        .clone();
    assert_eq!(manifest.chunk_count, 4);

    let (server_cfg, client_cfg) = development_localhost_quinn().expect("quic dev creds");
    let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let log = Arc::new(Mutex::new(Vec::new()));

    let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
    let secrets_p0 = secrets.clone();
    let binding_p0 = binding.clone();
    let src_clone = src_path.clone();
    let log0 = Arc::clone(&log);
    let prov0 = tokio::spawn(async move {
        framed_transfer_provider_quic_leg(
            server_cfg,
            listen,
            secrets_p0,
            binding_p0,
            0,
            src_clone,
            "f.bin".into(),
            ready_tx,
            log0,
        )
        .await
    });

    let connect_to = ready_rx.await.expect("provider addr");
    let receiver0 = LocalReceiver::new(
        manifest.clone(),
        staging_path.clone(),
        dest_path.clone(),
        DestinationConflictPolicy::FailIfExists,
    )
    .expect("receiver0");

    let out0 = framed_transfer_receiver_quic_leg(
        &client_cfg,
        connect_to,
        &secrets,
        &binding,
        0,
        receiver0,
        &[0, 1],
    )
    .await
    .expect("leg0");

    let ReceiverSessionOutcome::Paused { receiver: paused } = out0 else {
        panic!("expected paused first leg");
    };

    let session = LocalSessionFileV1::new_receiver_paused(
        &secrets,
        &binding,
        paused.manifest(),
        "f.bin",
        staging_path.clone(),
        dest_path.clone(),
        DestinationConflictPolicy::FailIfExists,
        paused.chunk_received_flags().to_vec(),
    );
    let session_path = dir.path().join("session.json");
    session.save(&session_path).expect("save session");

    prov0.await.expect("join prov0").expect("prov0 ok");

    assert!(!dest_path.exists(), "destination must not exist until finalize");

    let (server_cfg1, client_cfg1) = development_localhost_quinn().expect("quic dev creds");
    let (ready_tx1, ready_rx1) = oneshot::channel::<SocketAddr>();
    let secrets_p1 = secrets.clone();
    let binding_p1 = binding.clone();
    let log1 = Arc::clone(&log);
    let prov1 = tokio::spawn(async move {
        framed_transfer_provider_quic_leg(
            server_cfg1,
            listen,
            secrets_p1,
            binding_p1,
            1,
            src_path,
            "f.bin".into(),
            ready_tx1,
            log1,
        )
        .await
    });

    let connect_to1 = ready_rx1.await.expect("provider addr 1");

    let loaded = LocalSessionFileV1::load(&session_path).expect("load session");
    loaded.validate_machine().expect("same machine");
    assert_resume_relative_path(&loaded, "f.bin").expect("filter ok");

    let resume_receiver = LocalReceiver::resume(
        loaded.manifest_from_session().expect("manifest"),
        loaded.staging_path_buf(),
        loaded.destination_path_buf(),
        loaded.conflict_policy(),
        loaded.chunk_received.clone(),
    )
    .expect("resume open");

    let missing: Vec<u32> = (0..manifest.chunk_count)
        .filter(|&i| !resume_receiver.chunk_received_flags()[i as usize])
        .collect();
    assert_eq!(missing, vec![2, 3]);

    let secrets_load = loaded.session_secrets().expect("secrets");
    let binding_load = loaded.handshake_binding().expect("binding");
    assert_eq!(secrets_load.persist_parts(), secrets.persist_parts());

    let out1 = framed_transfer_receiver_quic_leg(
        &client_cfg1,
        connect_to1,
        &secrets_load,
        &binding_load,
        loaded.next_connection_serial,
        resume_receiver,
        &missing,
    )
    .await
    .expect("leg1");

    assert!(matches!(out1, ReceiverSessionOutcome::Completed));
    prov1.await.expect("join prov1").expect("prov1 ok");

    assert_eq!(std::fs::read(&dest_path).expect("read dest"), body);
}

#[tokio::test]
async fn resume_leg_fails_with_stale_connection_serial() {
    std::env::set_var("BEAM_MACHINE_ID", "phase7-stale-serial");

    let dir = tempfile::TempDir::new().expect("temp");
    let staging_path = dir.path().join("st.bin");
    let dest_path = dir.path().join("out.bin");
    let src_path = dir.path().join("src.bin");
    std::fs::write(&src_path, vec![1_u8; 128]).expect("write source");

    let secrets = SessionSecrets::pairing_shim_local();
    let binding = HandshakeBinding {
        invite: InviteContext::default(),
        chunk_size: 64,
        framing_version: 1,
    };
    let manifest = LocalProvider::from_file(&src_path, "g.bin", 64)
        .expect("provider")
        .manifest()
        .clone();

    let (server_cfg, client_cfg) = development_localhost_quinn().expect("quic");
    let listen = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
    let log = Arc::new(Mutex::new(Vec::new()));

    let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();
    let prov = tokio::spawn(framed_transfer_provider_quic_leg(
        server_cfg,
        listen,
        secrets.clone(),
        binding.clone(),
        1,
        src_path,
        "g.bin".into(),
        ready_tx,
        log,
    ));
    let connect_to = ready_rx.await.expect("addr");
    let recv = LocalReceiver::new(
        manifest,
        staging_path,
        dest_path,
        DestinationConflictPolicy::FailIfExists,
    )
    .expect("recv");
    let err = framed_transfer_receiver_quic_leg(
        &client_cfg,
        connect_to,
        &secrets,
        &binding,
        0,
        recv,
        &[0],
    )
    .await
    .expect_err("serial mismatch");
    assert!(
        matches!(err, TransferError::ManifestEnvelopeAuthFailed | TransferError::ChunkEnvelopeAuthFailed),
        "wrong keys should fail open/decrypt, got {err:?}"
    );
    prov.abort();
}

#[test]
fn deleted_session_file_cannot_resume() {
    let err = LocalSessionFileV1::load("definitely-missing-beam-session.json")
        .expect_err("missing file");
    assert!(matches!(err, TransferError::SessionState(_)));
}

#[test]
fn resume_rejects_different_machine_fingerprint() {
    std::env::set_var("BEAM_MACHINE_ID", "machine-a");
    let secrets = SessionSecrets::pairing_shim_local();
    let binding = HandshakeBinding {
        invite: InviteContext::default(),
        chunk_size: 64,
        framing_version: 1,
    };
    let dir = tempfile::TempDir::new().unwrap();
    let p = dir.path().join("one.bin");
    std::fs::write(&p, b"x").unwrap();
    let m = LocalProvider::from_file(&p, "m.bin", 64)
        .unwrap()
        .manifest()
        .clone();
    let mut s = LocalSessionFileV1::new_receiver_paused(
        &secrets,
        &binding,
        &m,
        "m.bin",
        dir.path().join("st"),
        dir.path().join("dst"),
        DestinationConflictPolicy::FailIfExists,
        vec![false],
    );
    std::env::set_var("BEAM_MACHINE_ID", "machine-b");
    s.machine_id_hex = LocalSessionFileV1::current_machine_id_hex();
    std::env::set_var("BEAM_MACHINE_ID", "machine-a");
    let err = s.validate_machine().expect_err("machine mismatch");
    assert!(matches!(err, TransferError::ResumeMachineMismatch));
}

#[test]
fn resume_relative_path_mismatch_is_rejected() {
    std::env::set_var("BEAM_MACHINE_ID", "rp-check");
    let secrets = SessionSecrets::pairing_shim_local();
    let binding = HandshakeBinding {
        invite: InviteContext::default(),
        chunk_size: 64,
        framing_version: 1,
    };
    let dir = tempfile::TempDir::new().unwrap();
    let p = dir.path().join("one.bin");
    std::fs::write(&p, b"hello").unwrap();
    let m = LocalProvider::from_file(&p, "keep.bin", 64)
        .unwrap()
        .manifest()
        .clone();
    let s = LocalSessionFileV1::new_receiver_paused(
        &secrets,
        &binding,
        &m,
        "keep.bin",
        dir.path().join("st"),
        dir.path().join("dst"),
        DestinationConflictPolicy::FailIfExists,
        vec![false],
    );
    let e = assert_resume_relative_path(&s, "other.bin").expect_err("filter");
    assert!(matches!(e, TransferError::ResumeRejected(_)));
}
