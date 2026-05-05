//! Split provider vs receiver processes share the same path decision as the combined helper.

#![forbid(unsafe_code)]

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use beam_core::direct_quic::{
    provide_one_file_with_relay_fallback_blocking, receive_one_file_with_relay_fallback_blocking,
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
fn network_file_transfer_split_sender_receiver_threads() {
    let dir = TempDir::new().expect("temp");
    let staging_recv_dir = TempDir::new().expect("st recv");

    let secrets = SessionSecrets::pairing_shim_local();
    let room_id = [0x11u8; 16];
    let gate = secrets.relay_pipe_gate_token(&room_id).expect("gate");

    let rt = tokio::runtime::Runtime::new().expect("rt");
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
    thread::sleep(Duration::from_millis(80));

    let src = dir.path().join("s.bin");
    let body: Vec<u8> = (0_u8..=200).cycle().take(4_000).collect();
    std::fs::write(&src, &body).expect("write");

    let dest = dir.path().join("got.bin");
    let staging_recv = staging_recv_dir.path().join("st.bin");

    let binding = HandshakeBinding {
        invite: InviteContext::default(),
        chunk_size: 1024,
        framing_version: 1,
    };

    let relay = RelayPipeConfig {
        base_url: base,
        room_id,
        expires_unix: unix_now() + 3600,
        gate,
    };

    let (addr_tx, addr_rx) = mpsc::channel::<SocketAddr>();
    let secrets_p = secrets.clone();
    let relay_p = relay.clone();
    let binding_p = binding;
    let src_pb = src.clone();
    let serve = thread::spawn(move || {
        provide_one_file_with_relay_fallback_blocking(
            &secrets_p,
            binding_p,
            &src_pb,
            "s.bin",
            SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
            relay_p,
            Duration::from_millis(0),
            |c| addr_tx.send(c).expect("addr"),
        )
        .expect("provide")
    });

    let connect_to = addr_rx.recv_timeout(Duration::from_secs(10)).expect("connect addr");

    let receipt = receive_one_file_with_relay_fallback_blocking(
        &secrets,
        binding,
        connect_to,
        &staging_recv,
        &dest,
        DestinationConflictPolicy::FailIfExists,
        relay,
        Duration::from_millis(0),
    )
    .expect("recv");

    let prov_path = serve.join().expect("join serve");
    assert_eq!(prov_path, receipt.path);
    assert_eq!(receipt.path, TransferPathSurface::Relayed);
    assert_eq!(std::fs::read(&dest).expect("read"), body);

    drop(rt);
}
