//! Minimal HTTP rendezvous for Beam pairing (Phase 4).
//!
//! Stores only ephemeral SPAKE exchange blobs keyed by room id until pairing completes or TTL passes.
//! Does not accept manifests, filenames, hashes, or transfer progress.

#![forbid(unsafe_code)]

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, put};
use axum::Router;
use tokio::sync::Mutex as AsyncMutex;

pub mod api {
    pub const EXPIRES_HEADER: &str = "x-beam-expires";
    pub const PIPE_GATE_HEADER: &str = "x-beam-pipe-gate";
}

/// Max single-frame payload on the blind pipe (12-byte BMQ1 header + app chunk envelope budget).
const MAX_PIPE_FRAME: usize = 12 + 32 * 1024 * 1024;

#[derive(Clone)]
struct Room {
    expires_unix: u64,
    sender: Option<Vec<u8>>,
    receiver: Option<Vec<u8>>,
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn decode_room_hex(room_hex: &str) -> Option<[u8; 16]> {
    let b = room_hex.as_bytes();
    if b.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for i in 0..16 {
        let hi = hex_val(b[2 * i])?;
        let lo = hex_val(b[2 * i + 1])?;
        out[i] = hi << 4 | lo;
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(10 + (c - b'a')),
        b'A'..=b'F' => Some(10 + (c - b'A')),
        _ => None,
    }
}

struct PipeRoom {
    expires_unix: u64,
    gate: [u8; 32],
    /// Provider → receiver framed messages (`BMQ1`).
    down: VecDeque<Vec<u8>>,
    /// Receiver → provider framed messages.
    up: VecDeque<Vec<u8>>,
}

#[derive(Clone)]
pub struct AppState {
    rooms: Arc<Mutex<HashMap<[u8; 16], Room>>>,
    pipes: Arc<AsyncMutex<HashMap<[u8; 16], PipeRoom>>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            rooms: Arc::new(Mutex::new(HashMap::new())),
            pipes: Arc::new(AsyncMutex::new(HashMap::new())),
        }
    }
}

impl AppState {
    fn purge_expired_locked(map: &mut HashMap<[u8; 16], Room>, room_id: &[u8; 16], now: u64) {
        if let Some(r) = map.get(room_id) {
            if now > r.expires_unix {
                map.remove(room_id);
            }
        }
    }
}

async fn put_sender(
    State(state): State<AppState>,
    Path(room_hex): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let Some(room_id) = decode_room_hex(&room_hex) else {
        return StatusCode::BAD_REQUEST;
    };
    let expires_raw = headers
        .get(api::EXPIRES_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let Some(expires_unix) = expires_raw else {
        return StatusCode::BAD_REQUEST;
    };
    let now = unix_now_secs();
    if now > expires_unix {
        return StatusCode::GONE;
    }

    let mut map = match state.rooms.lock() {
        Ok(g) => g,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };

    AppState::purge_expired_locked(&mut map, &room_id, now);

    if map.contains_key(&room_id) {
        return StatusCode::CONFLICT;
    }

    map.insert(
        room_id,
        Room {
            expires_unix,
            sender: Some(body.to_vec()),
            receiver: None,
        },
    );
    StatusCode::CREATED
}

async fn get_sender(
    State(state): State<AppState>,
    Path(room_hex): Path<String>,
) -> Result<Bytes, StatusCode> {
    let Some(room_id) = decode_room_hex(&room_hex) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let now = unix_now_secs();
    let mut map = state
        .rooms
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    AppState::purge_expired_locked(&mut map, &room_id, now);

    let expires_unix = match map.get(&room_id) {
        None => return Err(StatusCode::NOT_FOUND),
        Some(r) => r.expires_unix,
    };
    if now > expires_unix {
        map.remove(&room_id);
        return Err(StatusCode::GONE);
    }
    let sender = match map.get(&room_id).and_then(|r| r.sender.as_ref()) {
        Some(s) => s,
        None => return Err(StatusCode::NOT_FOUND),
    };
    Ok(Bytes::copy_from_slice(sender))
}

async fn put_receiver(
    State(state): State<AppState>,
    Path(room_hex): Path<String>,
    body: Bytes,
) -> StatusCode {
    let Some(room_id) = decode_room_hex(&room_hex) else {
        return StatusCode::BAD_REQUEST;
    };
    let now = unix_now_secs();
    let mut map = match state.rooms.lock() {
        Ok(g) => g,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };
    AppState::purge_expired_locked(&mut map, &room_id, now);

    let expires_unix = match map.get(&room_id) {
        None => return StatusCode::NOT_FOUND,
        Some(r) => r.expires_unix,
    };
    if now > expires_unix {
        map.remove(&room_id);
        return StatusCode::GONE;
    }

    let Some(room) = map.get_mut(&room_id) else {
        return StatusCode::NOT_FOUND;
    };
    if room.sender.is_none() {
        return StatusCode::NOT_FOUND;
    }
    if room.receiver.is_some() {
        return StatusCode::CONFLICT;
    }
    room.receiver = Some(body.to_vec());
    StatusCode::NO_CONTENT
}

async fn get_receiver(
    State(state): State<AppState>,
    Path(room_hex): Path<String>,
) -> Result<Bytes, StatusCode> {
    let Some(room_id) = decode_room_hex(&room_hex) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let now = unix_now_secs();
    let mut map = state
        .rooms
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    AppState::purge_expired_locked(&mut map, &room_id, now);

    let expires_unix = match map.get(&room_id) {
        None => return Err(StatusCode::NOT_FOUND),
        Some(r) => r.expires_unix,
    };
    if now > expires_unix {
        map.remove(&room_id);
        return Err(StatusCode::GONE);
    }
    let rx = match map.get(&room_id).and_then(|r| r.receiver.as_ref()) {
        Some(msg) => msg,
        None => return Err(StatusCode::NOT_FOUND),
    };
    Ok(Bytes::copy_from_slice(rx))
}

async fn delete_room(State(state): State<AppState>, Path(room_hex): Path<String>) -> StatusCode {
    let Some(room_id) = decode_room_hex(&room_hex) else {
        return StatusCode::BAD_REQUEST;
    };
    let mut map = match state.rooms.lock() {
        Ok(g) => g,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };
    map.remove(&room_id);
    StatusCode::NO_CONTENT
}

fn decode_gate_hex(s: &str) -> Result<[u8; 32], StatusCode> {
    if s.len() != 64 {
        return Err(StatusCode::BAD_REQUEST);
    }
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = hex_val(b[2 * i]).ok_or(StatusCode::BAD_REQUEST)?;
        let lo = hex_val(b[2 * i + 1]).ok_or(StatusCode::BAD_REQUEST)?;
        out[i] = hi << 4 | lo;
    }
    Ok(out)
}

fn pipe_expires_gate_headers(headers: &HeaderMap) -> Result<(u64, [u8; 32]), StatusCode> {
    let expires_raw = headers
        .get(api::EXPIRES_HEADER)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok());
    let Some(expires_unix) = expires_raw else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let gate_raw = headers
        .get(api::PIPE_GATE_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let gate = decode_gate_hex(gate_raw)?;
    Ok((expires_unix, gate))
}

fn prepare_pipe_put(
    map: &mut HashMap<[u8; 16], PipeRoom>,
    room_id: &[u8; 16],
    expires_unix: u64,
    gate: [u8; 32],
    now: u64,
) -> Result<(), StatusCode> {
    if let Some(r) = map.get(room_id) {
        if now > r.expires_unix {
            map.remove(room_id);
        }
    }
    if !map.contains_key(room_id) {
        if now > expires_unix {
            return Err(StatusCode::GONE);
        }
        map.insert(
            *room_id,
            PipeRoom {
                expires_unix,
                gate,
                down: VecDeque::new(),
                up: VecDeque::new(),
            },
        );
        return Ok(());
    }
    let room = map.get(room_id).ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    if now > room.expires_unix {
        map.remove(room_id);
        return Err(StatusCode::GONE);
    }
    if room.gate != gate {
        return Err(StatusCode::FORBIDDEN);
    }
    if room.expires_unix != expires_unix {
        return Err(StatusCode::CONFLICT);
    }
    Ok(())
}

fn validate_pipe_get(
    map: &mut HashMap<[u8; 16], PipeRoom>,
    room_id: &[u8; 16],
    expires_unix: u64,
    gate: [u8; 32],
    now: u64,
) -> Result<(), StatusCode> {
    let Some(room) = map.get(room_id) else {
        return Err(StatusCode::NOT_FOUND);
    };
    if now > room.expires_unix {
        map.remove(room_id);
        return Err(StatusCode::GONE);
    }
    if room.gate != gate {
        return Err(StatusCode::FORBIDDEN);
    }
    if room.expires_unix != expires_unix {
        return Err(StatusCode::CONFLICT);
    }
    Ok(())
}

async fn put_pipe_down(
    State(state): State<AppState>,
    Path(room_hex): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let Some(room_id) = decode_room_hex(&room_hex) else {
        return StatusCode::BAD_REQUEST;
    };
    if body.len() < 12 || body.len() > MAX_PIPE_FRAME {
        return StatusCode::BAD_REQUEST;
    }
    let Ok((expires_unix, gate)) = pipe_expires_gate_headers(&headers) else {
        return StatusCode::BAD_REQUEST;
    };
    let now = unix_now_secs();
    let mut map = state.pipes.lock().await;
    if let Err(s) = prepare_pipe_put(&mut map, &room_id, expires_unix, gate, now) {
        return s;
    }
    let Some(room) = map.get_mut(&room_id) else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };
    room.down.push_back(body.to_vec());
    StatusCode::NO_CONTENT
}

async fn get_pipe_down(
    State(state): State<AppState>,
    Path(room_hex): Path<String>,
    headers: HeaderMap,
) -> Result<Bytes, StatusCode> {
    let Some(room_id) = decode_room_hex(&room_hex) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let Ok((expires_unix, gate)) = pipe_expires_gate_headers(&headers) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let now = unix_now_secs();
    let mut map = state.pipes.lock().await;
    validate_pipe_get(&mut map, &room_id, expires_unix, gate, now)?;
    let room = map
        .get_mut(&room_id)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    match room.down.pop_front() {
        Some(b) => Ok(Bytes::from(b)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

async fn put_pipe_up(
    State(state): State<AppState>,
    Path(room_hex): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let Some(room_id) = decode_room_hex(&room_hex) else {
        return StatusCode::BAD_REQUEST;
    };
    if body.len() < 12 || body.len() > MAX_PIPE_FRAME {
        return StatusCode::BAD_REQUEST;
    }
    let Ok((expires_unix, gate)) = pipe_expires_gate_headers(&headers) else {
        return StatusCode::BAD_REQUEST;
    };
    let now = unix_now_secs();
    let mut map = state.pipes.lock().await;
    if let Err(s) = prepare_pipe_put(&mut map, &room_id, expires_unix, gate, now) {
        return s;
    }
    let Some(room) = map.get_mut(&room_id) else {
        return StatusCode::INTERNAL_SERVER_ERROR;
    };
    room.up.push_back(body.to_vec());
    StatusCode::NO_CONTENT
}

async fn get_pipe_up(
    State(state): State<AppState>,
    Path(room_hex): Path<String>,
    headers: HeaderMap,
) -> Result<Bytes, StatusCode> {
    let Some(room_id) = decode_room_hex(&room_hex) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let Ok((expires_unix, gate)) = pipe_expires_gate_headers(&headers) else {
        return Err(StatusCode::BAD_REQUEST);
    };
    let now = unix_now_secs();
    let mut map = state.pipes.lock().await;
    validate_pipe_get(&mut map, &room_id, expires_unix, gate, now)?;
    let room = map
        .get_mut(&room_id)
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;
    match room.up.pop_front() {
        Some(b) => Ok(Bytes::from(b)),
        None => Err(StatusCode::NOT_FOUND),
    }
}

/// Builds the rendezvous router (shared state is per-process).
#[must_use]
pub fn router(state: AppState) -> Router {
    Router::new()
        .route(
            "/v1/rooms/{room_hex}/sender",
            put(put_sender).get(get_sender),
        )
        .route(
            "/v1/rooms/{room_hex}/receiver",
            put(put_receiver).get(get_receiver),
        )
        .route("/v1/rooms/{room_hex}", delete(delete_room))
        .route(
            "/v1/pipe/{room_hex}/down",
            put(put_pipe_down).get(get_pipe_down),
        )
        .route("/v1/pipe/{room_hex}/up", put(put_pipe_up).get(get_pipe_up))
        .with_state(state)
}
