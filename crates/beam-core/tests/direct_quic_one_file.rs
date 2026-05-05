//! Phase 5 proof: one-file transfer across two async tasks over QUIC (localhost).

#![forbid(unsafe_code)]

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Instant;

use beam_core::chunking::DEFAULT_CHUNK_SIZE;
use beam_core::direct_quic::{
    transfer_one_file_direct_quic_blocking, DirectQuicEvent, TransferPathSurface,
};
use beam_core::local_transfer::DestinationConflictPolicy;
use beam_core::session_crypto::{HandshakeBinding, InviteContext, SessionSecrets};
use tempfile::TempDir;

#[test]
fn encrypted_one_file_transfer_over_direct_quic_localhost() {
    let dir = TempDir::new().expect("temp");
    let staging_dir = TempDir::new().expect("staging");
    let secrets = SessionSecrets::pairing_shim_local();

    let src = dir.path().join("q.bin");
    let body: Vec<u8> = (0_u8..=211).collect();
    fs::write(&src, &body).expect("write");

    let dest = dir.path().join("out-q.bin");
    let staging = staging_dir.path().join("st-q.bin");
    let binding = HandshakeBinding {
        invite: InviteContext::default(),
        chunk_size: 64,
        framing_version: 1,
    };

    let receipt = transfer_one_file_direct_quic_blocking(
        &secrets,
        InviteContext::default(),
        binding,
        &src,
        &staging,
        &dest,
        "q.bin",
        DestinationConflictPolicy::FailIfExists,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .expect("direct quic transfer");

    assert_eq!(receipt.path, TransferPathSurface::Direct);
    assert_eq!(fs::read(&dest).expect("read dest"), body);
    assert!(
        receipt.events.iter().any(|e| matches!(e, DirectQuicEvent::ConnectOk { .. })),
        "expected ConnectOk in {:?}",
        receipt.events
    );
    assert!(
        receipt
            .events
            .iter()
            .any(|e| matches!(e, DirectQuicEvent::ListenerBound { .. })),
        "expected ListenerBound in {:?}",
        receipt.events
    );
}

#[test]
fn direct_quic_throughput_smoke_large_chunk() {
    let dir = TempDir::new().expect("temp");
    let staging_dir = TempDir::new().expect("staging");
    let secrets = SessionSecrets::pairing_shim_local();

    let chunk_size = DEFAULT_CHUNK_SIZE.min(256 * 1024);
    let total = chunk_size * 32;
    let src = dir.path().join("big.bin");
    fs::write(&src, vec![0xabu8; total as usize]).expect("write");

    let dest = dir.path().join("out-big.bin");
    let staging = staging_dir.path().join("st-big.bin");
    let binding = HandshakeBinding {
        invite: InviteContext::default(),
        chunk_size,
        framing_version: 1,
    };

    let t0 = Instant::now();
    let receipt = transfer_one_file_direct_quic_blocking(
        &secrets,
        InviteContext::default(),
        binding,
        &src,
        &staging,
        &dest,
        "big.bin",
        DestinationConflictPolicy::FailIfExists,
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
    )
    .expect("direct quic large transfer");
    let elapsed = t0.elapsed();

    assert_eq!(receipt.path, TransferPathSurface::Direct);
    assert_eq!(fs::metadata(&dest).expect("meta").len(), total);
    let mb = total as f64 / 1_000_000.0;
    let secs = elapsed.as_secs_f64().max(0.001);
    eprintln!(
        "direct QUIC throughput smoke: {:.2} MB in {:.3}s ({:.2} MB/s)",
        mb,
        secs,
        mb / secs
    );
}
