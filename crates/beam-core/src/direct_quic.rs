//! Direct QUIC transport for Beam v1: provider listens, receiver connects after pairing (ADR 0006).
//!
//! QUIC/TLS authenticates transport; manifests, chunk ciphertext, and control envelopes remain under
//! [`crate::session_crypto`] with distinct AEAD keys (ADR 0084). Chunk Blake3 commitments stay independent of QUIC crypto (ADR 0080).

use std::fs;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Once};
use std::time::Duration;

use crate::pairing::room_id_hex;

use quinn::{Connecting, Endpoint, RecvStream, SendStream};
use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::pki_types::PrivateKeyDer;
use rustls::RootCertStore;
use tokio::sync::oneshot;

use crate::error::TransferError;
use crate::local_transfer::{DestinationConflictPolicy, LocalProvider, LocalReceiver};
use crate::session_crypto::{
    decode_manifest_plaintext, decrypt_chunk_payload, decrypt_control_payload,
    decrypt_manifest_blob, encode_manifest_plaintext, encrypt_chunk_payload,
    encrypt_control_payload, encrypt_manifest_blob, receiver_approve_payload, HandshakeBinding,
    InviteContext, SessionKeys, SessionSecrets,
};

/// Wire magic for application-layer QUIC frames (`BMQ1`).
pub const QUIC_FRAME_MAGIC: [u8; 4] = *b"BMQ1";

const CONTROL_REQ_MANIFEST: u8 = 1;
const CONTROL_MANIFEST_BODY: u8 = 2;
const CONTROL_RECEIVER_APPROVE: u8 = 3;
const CHUNK_REQ: u8 = 0x20;
const CHUNK_RESP: u8 = 0x21;

const MAX_CONTROL_PAYLOAD: usize = 4 * 1024 * 1024;
const MAX_CHUNK_WIRE_PAYLOAD: usize = 32 * 1024 * 1024;

static CRYPTO_PROVIDER: Once = Once::new();

fn install_ring_crypto_provider() -> Result<(), TransferError> {
    let mut install_res = Ok(());
    CRYPTO_PROVIDER.call_once(|| {
        if rustls::crypto::ring::default_provider()
            .install_default()
            .is_err()
        {
            install_res = Err(TransferError::DirectQuicTransport(
                "failed to install rustls ring crypto provider",
            ));
        }
    });
    install_res
}

/// Path surface for telemetry (ADR 0035 style).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransferPathSurface {
    /// App-encrypted payloads flow over direct QUIC (`transport = QUIC`).
    Direct,
    /// Same app-layer frames tunneled through the relay blind pipe (`transport = relay`).
    Relayed,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DirectQuicEvent {
    ListenerBound {
        addr: String,
    },
    PunchAttempt {
        peer: String,
        packet_len: usize,
    },
    ConnectCandidates {
        attempted: Vec<String>,
    },
    ConnectOk {
        peer: String,
        elapsed_ms: u64,
    },
    ConnectFailed {
        target: String,
        reason: &'static str,
    },
    /// Direct path did not complete in time or failed before handshake; continuing via relay.
    DirectPathAbandoned {
        reason: &'static str,
    },
}

#[derive(Clone, Debug)]
pub struct DirectQuicTransferReceipt {
    pub path: TransferPathSurface,
    pub events: Vec<DirectQuicEvent>,
    /// Remote peer when direct QUIC succeeded; loopback placeholder for pure relay tests.
    pub peer: SocketAddrOwned,
    /// Wall time spent attempting direct QUIC (connect or accept), if that phase ran.
    pub direct_attempt_ms: Option<u64>,
    /// Wall time for the relay pipe phase (provider and receiver overlap); `None` when path is direct-only.
    pub relay_phase_ms: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SocketAddrOwned {
    pub repr: String,
}

impl SocketAddrOwned {
    #[must_use]
    pub fn from_std(addr: SocketAddr) -> Self {
        Self {
            repr: addr.to_string(),
        }
    }
}

/// Development-only self-signed credential for `localhost` (not for production).
pub fn development_localhost_quinn(
) -> Result<(quinn::ServerConfig, quinn::ClientConfig), TransferError> {
    install_ring_crypto_provider()?;

    let CertifiedKey { cert, signing_key } =
        generate_simple_self_signed(vec!["localhost".to_string()]).map_err(|_| {
            TransferError::DirectQuicTransport("self-signed credential generation failed")
        })?;

    let cert_der = cert.der().clone();
    let key_der_vec = signing_key.serialize_der();
    let key_der = PrivateKeyDer::Pkcs8(key_der_vec.into());

    let server_cfg = quinn::ServerConfig::with_single_cert(vec![cert_der.clone()], key_der)
        .map_err(|_| TransferError::DirectQuicTransport(" QUIC server tls config rejected"))?;

    let mut roots = RootCertStore::empty();
    roots
        .add(cert_der.clone())
        .map_err(|_| TransferError::DirectQuicTransport("root store rejected server cert"))?;
    let client_cfg = quinn::ClientConfig::with_root_certificates(Arc::new(roots))
        .map_err(|_| TransferError::DirectQuicTransport(" QUIC client tls config rejected"))?;

    Ok((server_cfg, client_cfg))
}

/// Best-effort unsolicited UDP toward the QUIC port (NAT pinhole warmup; symmetric punch needs coordination).
pub async fn best_effort_udp_punch(remote: SocketAddr, log: &mut impl FnMut(DirectQuicEvent)) {
    const PAYLOAD: &[u8] = b"beam-punch-v1";
    if let Ok(s) = tokio::net::UdpSocket::bind((IpAddr::from(Ipv4Addr::UNSPECIFIED), 0)).await {
        for _ in 0..3 {
            let _ = s.send_to(PAYLOAD, remote).await;
            log(DirectQuicEvent::PunchAttempt {
                peer: remote.to_string(),
                packet_len: PAYLOAD.len(),
            });
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FrameHeader {
    kind: u8,
    #[allow(dead_code)]
    reserved: [u8; 3],
    payload_len: u32,
}

pub(crate) fn parse_header(buf: &[u8; 12]) -> Result<FrameHeader, TransferError> {
    if buf[0..4] != QUIC_FRAME_MAGIC {
        return Err(TransferError::WireProtocol("quic app frame magic mismatch"));
    }
    if buf[5] != 0 || buf[6] != 0 || buf[7] != 0 {
        return Err(TransferError::WireProtocol(
            "reserved quic framing bytes must be zero",
        ));
    }
    Ok(FrameHeader {
        kind: buf[4],
        reserved: [buf[5], buf[6], buf[7]],
        payload_len: u32::from_le_bytes(buf[8..12].try_into().unwrap()),
    })
}

fn build_header(kind: u8, payload_len: u32) -> [u8; 12] {
    let mut h = [0u8; 12];
    h[0..4].copy_from_slice(&QUIC_FRAME_MAGIC);
    h[4] = kind;
    h[8..12].copy_from_slice(&payload_len.to_le_bytes());
    h
}

async fn write_frame(send: &mut SendStream, kind: u8, payload: &[u8]) -> Result<(), TransferError> {
    let len_u32 =
        u32::try_from(payload.len()).map_err(|_| TransferError::WireProtocol("payload length"))?;
    let hdr = build_header(kind, len_u32);
    send.write_all(&hdr)
        .await
        .map_err(|_| TransferError::WireProtocol("send frame header incomplete"))?;
    send.write_all(payload)
        .await
        .map_err(|_| TransferError::WireProtocol("send frame body incomplete"))?;
    Ok(())
}

pub(crate) fn encode_wire_frame(kind: u8, payload: &[u8]) -> Result<Vec<u8>, TransferError> {
    let len_u32 =
        u32::try_from(payload.len()).map_err(|_| TransferError::WireProtocol("payload length"))?;
    let hdr = build_header(kind, len_u32);
    let mut out = Vec::with_capacity(12 + payload.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(payload);
    Ok(out)
}

pub(crate) fn decode_wire_frame(
    buf: &[u8],
    max_payload: usize,
) -> Result<(u8, Vec<u8>), TransferError> {
    if buf.len() < 12 {
        return Err(TransferError::WireProtocol("truncated frame header"));
    }
    let hdr: [u8; 12] = buf[0..12]
        .try_into()
        .map_err(|_| TransferError::WireProtocol("frame header"))?;
    let parsed = parse_header(&hdr)?;
    let len_usize = usize::try_from(parsed.payload_len)
        .map_err(|_| TransferError::WireProtocol("payload length does not fit usize"))?;
    if len_usize > max_payload {
        return Err(TransferError::WireProtocol(
            "frame exceeds max payload budget",
        ));
    }
    if buf.len() != 12 + len_usize {
        return Err(TransferError::WireProtocol("frame length mismatch"));
    }
    Ok((parsed.kind, buf[12..].to_vec()))
}

async fn read_framed(
    recv: &mut RecvStream,
    max_payload: usize,
) -> Result<(u8, Vec<u8>), TransferError> {
    let mut hdr = [0u8; 12];
    recv.read_exact(&mut hdr)
        .await
        .map_err(|_| TransferError::WireProtocol("truncated frame header"))?;
    let parsed = parse_header(&hdr)?;
    let len_usize = usize::try_from(parsed.payload_len)
        .map_err(|_| TransferError::WireProtocol("payload length does not fit usize"))?;
    if len_usize > max_payload {
        return Err(TransferError::WireProtocol(
            "frame exceeds max payload budget",
        ));
    }
    let mut body = vec![0u8; len_usize];
    recv.read_exact(&mut body)
        .await
        .map_err(|_| TransferError::WireProtocol("truncated frame body"))?;
    Ok((parsed.kind, body))
}

#[must_use]
pub fn loopback_connect_addr(advertised: SocketAddr) -> SocketAddr {
    match advertised {
        SocketAddr::V4(v4) if v4.ip().is_unspecified() => {
            SocketAddr::from((Ipv4Addr::LOCALHOST, v4.port()))
        }
        other => other,
    }
}

async fn provider_framed_session(
    send: &mut SendStream,
    recv: &mut RecvStream,
    keys: &SessionKeys,
    provider: &LocalProvider,
    sealed_manifest: &[u8],
) -> Result<(), TransferError> {
    let (kind, body) = read_framed(recv, 64).await?;
    if kind != CONTROL_REQ_MANIFEST || !body.is_empty() {
        return Err(TransferError::WireProtocol("unexpected manifest request"));
    }

    write_frame(send, CONTROL_MANIFEST_BODY, sealed_manifest).await?;

    let (kind2, approve_blob) = read_framed(recv, MAX_CONTROL_PAYLOAD).await?;
    if kind2 != CONTROL_RECEIVER_APPROVE {
        return Err(TransferError::WireProtocol(
            "expected receiver approve control frame",
        ));
    }
    decrypt_control_payload(keys.control_key(), keys.session_id(), &approve_blob)
        .map_err(|_| TransferError::ControlEnvelopeAuthFailed)?;

    for chunk_idx in 0..provider.manifest().chunk_count {
        let (ck, req) = read_framed(recv, 64).await?;
        if ck != CHUNK_REQ || req.len() != 4 {
            return Err(TransferError::WireProtocol("chunk request malformed"));
        }
        let requested = u32::from_le_bytes(req.try_into().unwrap());
        if requested != chunk_idx {
            return Err(TransferError::WireProtocol(
                "chunk requests arrived out of expected order",
            ));
        }

        let pt = provider.read_chunk(chunk_idx)?;
        let sealed = encrypt_chunk_payload(keys, chunk_idx, &pt)?;
        write_frame(send, CHUNK_RESP, &sealed).await?;
    }

    Ok(())
}

async fn receiver_framed_session(
    send: &mut SendStream,
    recv: &mut RecvStream,
    keys: &SessionKeys,
    staging: PathBuf,
    destination: PathBuf,
    conflict: DestinationConflictPolicy,
) -> Result<(), TransferError> {
    write_frame(send, CONTROL_REQ_MANIFEST, &[]).await?;
    let (mk, sealed_manifest) = read_framed(recv, MAX_CONTROL_PAYLOAD).await?;
    if mk != CONTROL_MANIFEST_BODY {
        return Err(TransferError::WireProtocol("expected manifest frame"));
    }

    let opened_plain = decrypt_manifest_blob(keys, &sealed_manifest)
        .map_err(|_| TransferError::ManifestEnvelopeAuthFailed)?;
    let recv_manifest = decode_manifest_plaintext(&opened_plain)?;

    let approve_wire = encrypt_control_payload(
        keys.control_key(),
        keys.session_id(),
        receiver_approve_payload(),
    )?;
    write_frame(send, CONTROL_RECEIVER_APPROVE, &approve_wire).await?;

    let mut receiver = LocalReceiver::new(recv_manifest, staging, destination, conflict)?;

    let chunk_count = receiver.manifest().chunk_count;
    for chunk_idx in 0..chunk_count {
        write_frame(send, CHUNK_REQ, &chunk_idx.to_le_bytes()).await?;
        let (rk, wired) = read_framed(recv, MAX_CHUNK_WIRE_PAYLOAD).await?;
        if rk != CHUNK_RESP {
            return Err(TransferError::WireProtocol("expected chunk response"));
        }
        let plain = decrypt_chunk_payload(keys, chunk_idx, &wired)
            .map_err(|_| TransferError::ChunkEnvelopeAuthFailed)?;
        receiver.receive_chunk(chunk_idx, &plain)?;
    }

    receiver.finalize()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn run_direct_quic_provider(
    server_cfg: quinn::ServerConfig,
    listen: SocketAddr,
    secrets: SessionSecrets,
    binding: HandshakeBinding,
    source: PathBuf,
    relative_path: String,
    ready_tx: oneshot::Sender<SocketAddr>,
    log: Arc<std::sync::Mutex<Vec<DirectQuicEvent>>>,
) -> Result<(), TransferError> {
    let keys = secrets.derive_keys(&binding)?;

    install_ring_crypto_provider()?;
    let endpoint = Endpoint::server(server_cfg, listen)
        .map_err(|_| TransferError::DirectQuicTransport(" QUIC server endpoint bind failed"))?;

    let bound = endpoint
        .local_addr()
        .map_err(|_| TransferError::DirectQuicTransport("missing server local_addr"))?;
    let connect_target = loopback_connect_addr(bound);
    let _ = ready_tx.send(connect_target);

    log.lock()
        .expect("diagnostics mutex poisoned")
        .push(DirectQuicEvent::ListenerBound {
            addr: bound.to_string(),
        });

    let incoming_opt = endpoint
        .accept()
        .await
        .ok_or(TransferError::DirectQuicTransport(
            "endpoint accept returned None",
        ))?;
    let connection = incoming_opt
        .await
        .map_err(|_| TransferError::DirectQuicTransport("incoming QUIC handshake failed"))?;

    let provider = LocalProvider::from_file(&source, &relative_path, binding.chunk_size)?;
    let sealed_manifest =
        encrypt_manifest_blob(&keys, &encode_manifest_plaintext(provider.manifest()))?;

    let (mut send, mut recv) = connection
        .accept_bi()
        .await
        .map_err(|_| TransferError::DirectQuicTransport("accept session stream failed"))?;

    provider_framed_session(&mut send, &mut recv, &keys, &provider, &sealed_manifest).await?;

    let _ = send.finish();
    let _ = recv.read_to_end(usize::MAX).await;

    endpoint.wait_idle().await;
    Ok(())
}

async fn receiver_session(
    connection: &quinn::Connection,
    secrets: &SessionSecrets,
    binding: &HandshakeBinding,
    staging: &Path,
    destination: &Path,
    conflict: DestinationConflictPolicy,
) -> Result<(), TransferError> {
    let keys = secrets.derive_keys(binding)?;

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(|_| TransferError::DirectQuicTransport(" open session stream failed"))?;

    receiver_framed_session(
        &mut send,
        &mut recv,
        &keys,
        staging.to_path_buf(),
        destination.to_path_buf(),
        conflict,
    )
    .await?;

    let _ = send.finish();
    let _ = recv.read_to_end(usize::MAX).await;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub fn transfer_one_file_direct_quic_blocking(
    secrets: &SessionSecrets,
    _invite: InviteContext,
    binding: HandshakeBinding,
    source: &Path,
    staging: &Path,
    destination: &Path,
    relative_path: &str,
    conflict: DestinationConflictPolicy,
    provider_listen: SocketAddr,
) -> Result<DirectQuicTransferReceipt, TransferError> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|_| TransferError::DirectQuicTransport("tokio runtime init failed"))?;
    rt.block_on(transfer_one_file_direct_quic(
        secrets,
        binding,
        source,
        staging,
        destination,
        relative_path,
        conflict,
        provider_listen,
    ))
}

#[allow(clippy::too_many_arguments)]
pub async fn transfer_one_file_direct_quic(
    secrets: &SessionSecrets,
    binding: HandshakeBinding,
    source: &Path,
    staging: &Path,
    destination: &Path,
    relative_path: &str,
    conflict: DestinationConflictPolicy,
    provider_listen: SocketAddr,
) -> Result<DirectQuicTransferReceipt, TransferError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }

    install_ring_crypto_provider()?;
    let (server_cfg, client_cfg) = development_localhost_quinn()?;

    let events: Arc<std::sync::Mutex<Vec<DirectQuicEvent>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();

    let source = source.to_path_buf();
    let rel = relative_path.to_owned();
    let secrets_clone = secrets.clone();
    let log = Arc::clone(&events);

    let provider_task = tokio::spawn(async move {
        run_direct_quic_provider(
            server_cfg,
            provider_listen,
            secrets_clone,
            binding,
            source,
            rel,
            ready_tx,
            log,
        )
        .await
    });

    let connect_target = ready_rx.await.map_err(|_| {
        TransferError::DirectQuicTransport("provider never reported listen address")
    })?;

    events
        .lock()
        .expect("diag")
        .push(DirectQuicEvent::ConnectCandidates {
            attempted: vec![connect_target.to_string()],
        });

    best_effort_udp_punch(connect_target, &mut |e| {
        events.lock().expect("diag").push(e);
    })
    .await;

    let mut client_ep = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .map_err(|_| TransferError::DirectQuicTransport(" QUIC client endpoint bind failed"))?;
    client_ep.set_default_client_config(client_cfg);

    let t0 = std::time::Instant::now();
    let connecting: Connecting = client_ep
        .connect(connect_target, "localhost")
        .map_err(|_| TransferError::DirectQuicTransport(" QUIC connect initiation failed"))?;
    let connection = connecting
        .await
        .map_err(|_| TransferError::DirectQuicTransport(" QUIC connect handshake failed"))?;

    let direct_ms = t0.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
    events
        .lock()
        .expect("diag")
        .push(DirectQuicEvent::ConnectOk {
            peer: connect_target.to_string(),
            elapsed_ms: direct_ms,
        });

    receiver_session(
        &connection,
        secrets,
        &binding,
        staging,
        destination,
        conflict,
    )
    .await?;

    client_ep.wait_idle().await;

    provider_task
        .await
        .map_err(|_| TransferError::DirectQuicTransport("provider task join failed"))??;

    let diagnostics = events.lock().expect("diag").clone();

    Ok(DirectQuicTransferReceipt {
        path: TransferPathSurface::Direct,
        events: diagnostics,
        peer: SocketAddrOwned::from_std(connect_target),
        direct_attempt_ms: Some(direct_ms),
        relay_phase_ms: None,
    })
}

const RELAY_PIPE_GATE_HEADER: &str = "x-beam-pipe-gate";

/// Configuration for the HTTP blind pipe (`/v1/pipe/...`) on the same relay host as pairing.
#[derive(Clone, Debug)]
pub struct RelayPipeConfig {
    pub base_url: String,
    pub room_id: [u8; 16],
    pub expires_unix: u64,
    pub gate: [u8; 32],
}

fn gate_hex_bytes(gate: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(64);
    for &b in gate {
        s.push(char::from(HEX[(b >> 4) as usize]));
        s.push(char::from(HEX[(b & 0xf) as usize]));
    }
    s
}

fn relay_pipe_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into()
}

fn relay_put_frame(
    agent: &ureq::Agent,
    url: &str,
    gate_hex: &str,
    expires_unix: u64,
    wire: &[u8],
) -> Result<(), TransferError> {
    let resp = agent
        .put(url)
        .header("x-beam-expires", &expires_unix.to_string())
        .header(RELAY_PIPE_GATE_HEADER, gate_hex)
        .send(wire)
        .map_err(|_| TransferError::RelayPipe("pipe PUT transport failed"))?;
    match resp.status().as_u16() {
        204 => Ok(()),
        410 => Err(TransferError::RelayPipe("pipe expired (gone)")),
        _ => Err(TransferError::RelayPipe("pipe PUT rejected")),
    }
}

fn relay_get_frame_poll(
    agent: &ureq::Agent,
    url: &str,
    gate_hex: &str,
    expires_unix: u64,
) -> Result<Option<Vec<u8>>, TransferError> {
    let mut resp = agent
        .get(url)
        .header("x-beam-expires", &expires_unix.to_string())
        .header(RELAY_PIPE_GATE_HEADER, gate_hex)
        .call()
        .map_err(|_| TransferError::RelayPipe("pipe GET transport failed"))?;
    match resp.status().as_u16() {
        200 => {
            let body = resp
                .body_mut()
                .read_to_vec()
                .map_err(|_| TransferError::RelayPipe("pipe GET body failed"))?;
            Ok(Some(body))
        }
        404 => Ok(None),
        410 => Err(TransferError::RelayPipe("pipe expired (gone)")),
        _ => Err(TransferError::RelayPipe("pipe GET rejected")),
    }
}

fn relay_get_frame_loop(
    agent: &ureq::Agent,
    url: &str,
    gate_hex: &str,
    expires_unix: u64,
) -> Result<Vec<u8>, TransferError> {
    let start = std::time::Instant::now();
    loop {
        if let Some(f) = relay_get_frame_poll(agent, url, gate_hex, expires_unix)? {
            return Ok(f);
        }
        if start.elapsed() > Duration::from_secs(120) {
            return Err(TransferError::RelayPipe(
                "pipe GET timed out waiting for frame",
            ));
        }
        std::thread::sleep(Duration::from_millis(15));
    }
}

fn relay_provider_blocking(
    cfg: &RelayPipeConfig,
    keys: &SessionKeys,
    provider: &LocalProvider,
    sealed_manifest: &[u8],
) -> Result<(), TransferError> {
    let agent = relay_pipe_agent();
    let gate_hex = gate_hex_bytes(&cfg.gate);
    let base = cfg.base_url.trim_end_matches('/');
    let room = room_id_hex(&cfg.room_id);
    let url_up = format!("{base}/v1/pipe/{room}/up");
    let url_down = format!("{base}/v1/pipe/{room}/down");

    let first = relay_get_frame_loop(&agent, &url_up, &gate_hex, cfg.expires_unix)?;
    let (kind, body) = decode_wire_frame(&first, 64)?;
    if kind != CONTROL_REQ_MANIFEST || !body.is_empty() {
        return Err(TransferError::WireProtocol("unexpected manifest request"));
    }

    relay_put_frame(
        &agent,
        &url_down,
        &gate_hex,
        cfg.expires_unix,
        &encode_wire_frame(CONTROL_MANIFEST_BODY, sealed_manifest)?,
    )?;

    let approve_raw = relay_get_frame_loop(&agent, &url_up, &gate_hex, cfg.expires_unix)?;
    let (kind2, approve_blob) = decode_wire_frame(&approve_raw, MAX_CONTROL_PAYLOAD)?;
    if kind2 != CONTROL_RECEIVER_APPROVE {
        return Err(TransferError::WireProtocol(
            "expected receiver approve control frame",
        ));
    }
    decrypt_control_payload(keys.control_key(), keys.session_id(), &approve_blob)
        .map_err(|_| TransferError::ControlEnvelopeAuthFailed)?;

    for chunk_idx in 0..provider.manifest().chunk_count {
        let raw = relay_get_frame_loop(&agent, &url_up, &gate_hex, cfg.expires_unix)?;
        let (ck, req) = decode_wire_frame(&raw, 64)?;
        if ck != CHUNK_REQ || req.len() != 4 {
            return Err(TransferError::WireProtocol("chunk request malformed"));
        }
        let requested = u32::from_le_bytes(req.try_into().unwrap());
        if requested != chunk_idx {
            return Err(TransferError::WireProtocol(
                "chunk requests arrived out of expected order",
            ));
        }

        let pt = provider.read_chunk(chunk_idx)?;
        let sealed = encrypt_chunk_payload(keys, chunk_idx, &pt)?;
        relay_put_frame(
            &agent,
            &url_down,
            &gate_hex,
            cfg.expires_unix,
            &encode_wire_frame(CHUNK_RESP, &sealed)?,
        )?;
    }

    Ok(())
}

fn relay_receiver_blocking(
    cfg: &RelayPipeConfig,
    keys: &SessionKeys,
    staging: PathBuf,
    destination: PathBuf,
    conflict: DestinationConflictPolicy,
) -> Result<(), TransferError> {
    let agent = relay_pipe_agent();
    let gate_hex = gate_hex_bytes(&cfg.gate);
    let base = cfg.base_url.trim_end_matches('/');
    let room = room_id_hex(&cfg.room_id);
    let url_up = format!("{base}/v1/pipe/{room}/up");
    let url_down = format!("{base}/v1/pipe/{room}/down");

    relay_put_frame(
        &agent,
        &url_up,
        &gate_hex,
        cfg.expires_unix,
        &encode_wire_frame(CONTROL_REQ_MANIFEST, &[])?,
    )?;

    let man_raw = relay_get_frame_loop(&agent, &url_down, &gate_hex, cfg.expires_unix)?;
    let (mk, sealed_manifest) = decode_wire_frame(&man_raw, MAX_CONTROL_PAYLOAD)?;
    if mk != CONTROL_MANIFEST_BODY {
        return Err(TransferError::WireProtocol("expected manifest frame"));
    }

    let opened_plain = decrypt_manifest_blob(keys, &sealed_manifest)
        .map_err(|_| TransferError::ManifestEnvelopeAuthFailed)?;
    let recv_manifest = decode_manifest_plaintext(&opened_plain)?;

    let approve_wire = encrypt_control_payload(
        keys.control_key(),
        keys.session_id(),
        receiver_approve_payload(),
    )?;
    relay_put_frame(
        &agent,
        &url_up,
        &gate_hex,
        cfg.expires_unix,
        &encode_wire_frame(CONTROL_RECEIVER_APPROVE, &approve_wire)?,
    )?;

    let mut receiver = LocalReceiver::new(recv_manifest, staging, destination, conflict)?;

    let chunk_count = receiver.manifest().chunk_count;
    for chunk_idx in 0..chunk_count {
        relay_put_frame(
            &agent,
            &url_up,
            &gate_hex,
            cfg.expires_unix,
            &encode_wire_frame(CHUNK_REQ, &chunk_idx.to_le_bytes())?,
        )?;

        let chunk_raw = relay_get_frame_loop(&agent, &url_down, &gate_hex, cfg.expires_unix)?;
        let (rk, wired) = decode_wire_frame(&chunk_raw, MAX_CHUNK_WIRE_PAYLOAD)?;
        if rk != CHUNK_RESP {
            return Err(TransferError::WireProtocol("expected chunk response"));
        }
        let plain = decrypt_chunk_payload(keys, chunk_idx, &wired)
            .map_err(|_| TransferError::ChunkEnvelopeAuthFailed)?;
        receiver.receive_chunk(chunk_idx, &plain)?;
    }

    receiver.finalize()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn provider_either_quic_or_relay(
    server_cfg: quinn::ServerConfig,
    listen: SocketAddr,
    secrets: SessionSecrets,
    binding: HandshakeBinding,
    source: PathBuf,
    relative_path: String,
    ready_tx: oneshot::Sender<SocketAddr>,
    log: Arc<std::sync::Mutex<Vec<DirectQuicEvent>>>,
    relay: RelayPipeConfig,
    direct_wait: Duration,
) -> Result<TransferPathSurface, TransferError> {
    let keys = secrets.derive_keys(&binding)?;
    let provider = LocalProvider::from_file(&source, &relative_path, binding.chunk_size)?;
    let sealed_manifest =
        encrypt_manifest_blob(&keys, &encode_manifest_plaintext(provider.manifest()))?;

    install_ring_crypto_provider()?;
    let endpoint = Endpoint::server(server_cfg, listen)
        .map_err(|_| TransferError::DirectQuicTransport(" QUIC server endpoint bind failed"))?;
    let bound = endpoint
        .local_addr()
        .map_err(|_| TransferError::DirectQuicTransport("missing server local_addr"))?;
    let connect_target = loopback_connect_addr(bound);
    let _ = ready_tx.send(connect_target);

    log.lock()
        .expect("diagnostics mutex poisoned")
        .push(DirectQuicEvent::ListenerBound {
            addr: bound.to_string(),
        });

    tokio::select! {
        incoming_res = async {
            let incoming = endpoint.accept().await.ok_or(TransferError::DirectQuicTransport(
                "endpoint accept returned None",
            ))?;
            let connection = incoming
                .await
                .map_err(|_| TransferError::DirectQuicTransport("incoming QUIC handshake failed"))?;
            Ok::<quinn::Connection, TransferError>(connection)
        } => {
            let connection = incoming_res?;
            let (mut send, mut recv) = connection
                .accept_bi()
                .await
                .map_err(|_| TransferError::DirectQuicTransport("accept session stream failed"))?;
            provider_framed_session(&mut send, &mut recv, &keys, &provider, &sealed_manifest).await?;
            let _ = send.finish();
            let _ = recv.read_to_end(usize::MAX).await;
            endpoint.wait_idle().await;
            Ok(TransferPathSurface::Direct)
        }
        _ = tokio::time::sleep(direct_wait) => {
            log.lock().expect("diag").push(DirectQuicEvent::DirectPathAbandoned {
                reason: "direct QUIC accept timed out; using relay pipe",
            });
            endpoint.close(quinn::VarInt::from_u32(0), &[]);
            drop(endpoint);

            let secrets_b = secrets.clone();
            let binding_b = binding;
            let relay_b = relay;
            let sealed = sealed_manifest;
            let rel = relative_path;
            let src = source;

            tokio::task::spawn_blocking(move || {
                let keys = secrets_b.derive_keys(&binding_b)?;
                let provider = LocalProvider::from_file(&src, &rel, binding_b.chunk_size)?;
                relay_provider_blocking(&relay_b, &keys, &provider, &sealed)
            })
            .await
            .map_err(|_| TransferError::RelayPipe("provider relay task join failed"))??;

            Ok(TransferPathSurface::Relayed)
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub fn transfer_one_file_with_relay_fallback_blocking(
    secrets: &SessionSecrets,
    _invite: InviteContext,
    binding: HandshakeBinding,
    source: &Path,
    staging: &Path,
    destination: &Path,
    relative_path: &str,
    conflict: DestinationConflictPolicy,
    provider_listen: SocketAddr,
    relay: RelayPipeConfig,
    direct_timeout: Duration,
) -> Result<DirectQuicTransferReceipt, TransferError> {
    let rt = tokio::runtime::Runtime::new()
        .map_err(|_| TransferError::DirectQuicTransport("tokio runtime init failed"))?;
    rt.block_on(transfer_one_file_with_relay_fallback(
        secrets,
        binding,
        source,
        staging,
        destination,
        relative_path,
        conflict,
        provider_listen,
        relay,
        direct_timeout,
    ))
}

#[allow(clippy::too_many_arguments)]
pub async fn transfer_one_file_with_relay_fallback(
    secrets: &SessionSecrets,
    binding: HandshakeBinding,
    source: &Path,
    staging: &Path,
    destination: &Path,
    relative_path: &str,
    conflict: DestinationConflictPolicy,
    provider_listen: SocketAddr,
    relay: RelayPipeConfig,
    direct_timeout: Duration,
) -> Result<DirectQuicTransferReceipt, TransferError> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }

    install_ring_crypto_provider()?;
    let (server_cfg, client_cfg) = development_localhost_quinn()?;

    let events: Arc<std::sync::Mutex<Vec<DirectQuicEvent>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let (ready_tx, ready_rx) = oneshot::channel::<SocketAddr>();

    let source_pb = source.to_path_buf();
    let rel = relative_path.to_owned();
    let secrets_clone = secrets.clone();
    let log_prov = Arc::clone(&events);
    let relay_clone = relay.clone();

    let provider_task = tokio::spawn(async move {
        provider_either_quic_or_relay(
            server_cfg,
            provider_listen,
            secrets_clone,
            binding,
            source_pb,
            rel,
            ready_tx,
            log_prov,
            relay_clone,
            direct_timeout,
        )
        .await
    });

    let connect_target = ready_rx.await.map_err(|_| {
        TransferError::DirectQuicTransport("provider never reported listen address")
    })?;

    events
        .lock()
        .expect("diag")
        .push(DirectQuicEvent::ConnectCandidates {
            attempted: vec![connect_target.to_string()],
        });

    best_effort_udp_punch(connect_target, &mut |e| {
        events.lock().expect("diag").push(e);
    })
    .await;

    let mut client_ep = Endpoint::client(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)))
        .map_err(|_| TransferError::DirectQuicTransport(" QUIC client endpoint bind failed"))?;
    client_ep.set_default_client_config(client_cfg);

    let t0 = std::time::Instant::now();
    let conn_attempt = async {
        let connecting: Connecting = client_ep
            .connect(connect_target, "localhost")
            .map_err(|_| TransferError::DirectQuicTransport(" QUIC connect initiation failed"))?;
        connecting
            .await
            .map_err(|_| TransferError::DirectQuicTransport(" QUIC connect handshake failed"))
    };

    let keys = secrets.derive_keys(&binding)?;
    let path: TransferPathSurface;
    let direct_ms: Option<u64>;
    let relay_ms: Option<u64>;

    match tokio::time::timeout(direct_timeout, conn_attempt).await {
        Ok(Ok(connection)) => {
            direct_ms = Some(t0.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
            relay_ms = None;
            events
                .lock()
                .expect("diag")
                .push(DirectQuicEvent::ConnectOk {
                    peer: connect_target.to_string(),
                    elapsed_ms: direct_ms.unwrap_or(0),
                });
            let (mut send, mut recv) = connection
                .open_bi()
                .await
                .map_err(|_| TransferError::DirectQuicTransport(" open session stream failed"))?;
            receiver_framed_session(
                &mut send,
                &mut recv,
                &keys,
                staging.to_path_buf(),
                destination.to_path_buf(),
                conflict,
            )
            .await?;
            let _ = send.finish();
            let _ = recv.read_to_end(usize::MAX).await;
            path = TransferPathSurface::Direct;
            client_ep.wait_idle().await;
        }
        Ok(Err(_)) => {
            direct_ms = Some(t0.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
            events
                .lock()
                .expect("diag")
                .push(DirectQuicEvent::ConnectFailed {
                    target: connect_target.to_string(),
                    reason: "quic handshake failed",
                });
            events
                .lock()
                .expect("diag")
                .push(DirectQuicEvent::DirectPathAbandoned {
                    reason: "direct QUIC connect failed; using relay pipe",
                });
            client_ep.close(quinn::VarInt::from_u32(0), &[]);
            drop(client_ep);
            let t1 = std::time::Instant::now();
            let relay_cfg = relay.clone();
            let staging_b = staging.to_path_buf();
            let dest_b = destination.to_path_buf();
            let secrets_b = secrets.clone();
            let binding_b = binding;
            tokio::task::spawn_blocking(move || {
                let keys = secrets_b.derive_keys(&binding_b)?;
                relay_receiver_blocking(&relay_cfg, &keys, staging_b, dest_b, conflict)
            })
            .await
            .map_err(|_| TransferError::RelayPipe("receiver relay join failed"))??;
            relay_ms = Some(t1.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
            path = TransferPathSurface::Relayed;
        }
        Err(_) => {
            direct_ms = Some(t0.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
            events
                .lock()
                .expect("diag")
                .push(DirectQuicEvent::DirectPathAbandoned {
                    reason: "direct QUIC connect timed out; using relay pipe",
                });
            client_ep.close(quinn::VarInt::from_u32(0), &[]);
            drop(client_ep);
            let t1 = std::time::Instant::now();
            let relay_cfg = relay.clone();
            let staging_b = staging.to_path_buf();
            let dest_b = destination.to_path_buf();
            let secrets_b = secrets.clone();
            let binding_b = binding;
            tokio::task::spawn_blocking(move || {
                let keys = secrets_b.derive_keys(&binding_b)?;
                relay_receiver_blocking(&relay_cfg, &keys, staging_b, dest_b, conflict)
            })
            .await
            .map_err(|_| TransferError::RelayPipe("receiver relay join failed"))??;
            relay_ms = Some(t1.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
            path = TransferPathSurface::Relayed;
        }
    }

    let provider_path = provider_task
        .await
        .map_err(|_| TransferError::DirectQuicTransport("provider task join failed"))??;

    if provider_path != path {
        return Err(TransferError::WireProtocol(
            "provider and receiver disagreed on transfer path (direct vs relay)",
        ));
    }

    let diagnostics = events.lock().expect("diag").clone();

    Ok(DirectQuicTransferReceipt {
        path,
        events: diagnostics,
        peer: SocketAddrOwned::from_std(connect_target),
        direct_attempt_ms: direct_ms,
        relay_phase_ms: relay_ms,
    })
}

#[cfg(test)]
mod wire_tests {
    use super::{parse_header, QUIC_FRAME_MAGIC};

    #[test]
    fn framing_rejects_wrong_magic() {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(b"XXXX");
        assert!(parse_header(&buf).is_err());
    }

    #[test]
    fn framing_rejects_nonzero_reserved() {
        let mut buf = [0u8; 12];
        buf[0..4].copy_from_slice(&QUIC_FRAME_MAGIC);
        buf[4] = 1;
        buf[5] = 1;
        assert!(parse_header(&buf).is_err());
    }
}
