//! Phase 6: when direct QUIC cannot complete in time, encrypted transfer falls back to the relay blind pipe.

#![forbid(unsafe_code)]

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use beam_core::direct_quic::{
    transfer_one_file_with_relay_fallback_blocking, DirectQuicEvent, DirectQuicTransferReceipt,
    RelayPipeConfig, TransferPathSurface,
};
use beam_core::local_transfer::DestinationConflictPolicy;
use beam_core::session_crypto::{HandshakeBinding, InviteContext, SessionSecrets};
use beam_relay::{router, AppState};
use tempfile::TempDir;
use tokio::net::TcpListener;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[test]
fn encrypted_one_file_transfer_relay_fallback_when_direct_skipped() {
    let dir = TempDir::new().expect("temp");
    let staging_dir = TempDir::new().expect("staging");
    let secrets = SessionSecrets::pairing_shim_local();
    let room_id = [0xabu8; 16];
    let gate = secrets.relay_pipe_gate_token(&room_id).expect("pipe gate");

    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let listener = rt
        .block_on(async { TcpListener::bind("127.0.0.1:0").await })
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let base = format!("http://{}", addr);
    rt.spawn(async move {
        axum::serve(listener, router(AppState::default()))
            .await
            .expect("serve");
    });
    std::thread::sleep(Duration::from_millis(60));

    let src = dir.path().join("r.bin");
    let body: Vec<u8> = (0_u8..=211).cycle().take(900).collect();
    fs::write(&src, &body).expect("write");

    let dest = dir.path().join("out-r.bin");
    let staging = staging_dir.path().join("st-r.bin");
    let binding = HandshakeBinding {
        invite: InviteContext::default(),
        chunk_size: 64,
        framing_version: 1,
    };

    let relay = RelayPipeConfig {
        base_url: base,
        room_id,
        expires_unix: unix_now() + 3600,
        gate,
    };

    let receipt: DirectQuicTransferReceipt = transfer_one_file_with_relay_fallback_blocking(
        &secrets,
        InviteContext::default(),
        binding,
        &src,
        &staging,
        &dest,
        "r.bin",
        DestinationConflictPolicy::FailIfExists,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        relay,
        Duration::from_millis(0),
    )
    .expect("relay fallback transfer");

    assert_eq!(receipt.path, TransferPathSurface::Relayed);
    assert_eq!(fs::read(&dest).expect("read dest"), body);
    assert!(
        receipt.relay_phase_ms.is_some(),
        "expected relay phase timing on receipt: {:?}",
        receipt.relay_phase_ms
    );
    assert!(
        receipt
            .events
            .iter()
            .any(|e| matches!(e, DirectQuicEvent::DirectPathAbandoned { .. })),
        "expected DirectPathAbandoned in {:?}",
        receipt.events
    );
}
