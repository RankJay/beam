//! Print timing for one encrypted file over [`beam_core::direct_quic::transfer_one_file_with_relay_fallback_blocking`]
//! (same stack as `tests/relay_fallback_one_file.rs`).
//!
//! Run: `cargo run -p beam-core --example benchmark_network --locked`

#![forbid(unsafe_code)]

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use beam_core::direct_quic::{
    transfer_one_file_with_relay_fallback_blocking, DirectQuicTransferReceipt, RelayPipeConfig,
    TransferPathSurface,
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

fn main() {
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
    std::thread::sleep(Duration::from_millis(80));

    let src = dir.path().join("bench.bin");
    let body: Vec<u8> = (0_u8..=211).cycle().take(900_000).collect();
    fs::write(&src, &body).expect("write");

    let dest = dir.path().join("out-bench.bin");
    let staging = staging_dir.path().join("st-bench.bin");
    let binding = HandshakeBinding {
        invite: InviteContext::default(),
        chunk_size: 64 * 1024,
        framing_version: 1,
    };

    let relay = RelayPipeConfig {
        base_url: base,
        room_id,
        expires_unix: unix_now() + 3600,
        gate,
    };

    let t0 = Instant::now();
    let receipt: DirectQuicTransferReceipt = transfer_one_file_with_relay_fallback_blocking(
        &secrets,
        binding,
        &src,
        &staging,
        &dest,
        "bench.bin",
        DestinationConflictPolicy::FailIfExists,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        relay,
        Duration::from_millis(0),
    )
    .expect("transfer");
    let ms = t0.elapsed().as_secs_f64() * 1000.0;

    assert_eq!(receipt.path, TransferPathSurface::Relayed);
    assert_eq!(fs::read(&dest).expect("read dest").len(), body.len());

    println!(
        "benchmark_network: relay-only, {} bytes, chunk_size={}, total_ms={:.2}, path={:?}",
        body.len(),
        binding.chunk_size,
        ms,
        receipt.path
    );
}
