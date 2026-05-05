//! Minimal HTTP rendezvous for Beam pairing (Phase 4).
//!
//! Stores only ephemeral SPAKE exchange blobs keyed by room id until pairing completes or TTL passes.
//! Does not accept manifests, filenames, hashes, or transfer progress.

#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{delete, put};
use axum::Router;

pub mod api {
    pub const EXPIRES_HEADER: &str = "x-beam-expires";
}

#[derive(Clone, Default)]
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

#[derive(Clone)]
pub struct AppState {
    rooms: Arc<Mutex<HashMap<[u8; 16], Room>>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            rooms: Arc::new(Mutex::new(HashMap::new())),
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
        .with_state(state)
}
