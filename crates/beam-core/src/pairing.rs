//! Real invite formats, filesystem rendezvous, and SPAKE2 pairing (Phase 3).
//!
//! Short human invites use a 256-word list plus a default/planned relay tag; copy-paste tokens embed a relay URL string (for example a `beam-fs:` mailbox root).
//! The PAKE password is always derived from invite-only material with HKDF; it is never used directly as an AEAD key.

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hkdf::Hkdf;
use rand::{rngs::OsRng, TryRngCore};
use sha2::Sha256;
use spake2::{Ed25519Group, Identity, Password, Spake2};

use crate::session_crypto::{invite_context_from_pairing, InviteContext, SessionSecrets};

const INVITE_LINE_PREFIX: &str = "beam-invite-v1";

/// Root URL/path marker for the placeholder mailbox transport used by the CLI (`beam-fs:<utf8 path>`).
pub const RELAY_BEAM_FS_PREFIX: &str = "beam-fs:";

/// Errors specific to invite parsing or rendezvous pairing.
#[derive(Debug)]
pub enum PairingError {
    InvalidInvite(&'static str),
    Expired,
    Relay(&'static str),
    Io(std::io::Error),
    Spake,
    Crypto(&'static str),
}

impl fmt::Display for PairingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PairingError::InvalidInvite(msg) => write!(f, "invalid invite: {msg}"),
            PairingError::Expired => write!(f, "invite expired"),
            PairingError::Relay(msg) => write!(f, "rendezvous relay error: {msg}"),
            PairingError::Io(e) => write!(f, "I/O error during pairing: {e}"),
            PairingError::Spake => write!(f, "PAKE handshake failed"),
            PairingError::Crypto(msg) => write!(f, "pairing crypto error: {msg}"),
        }
    }
}

impl std::error::Error for PairingError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PairingError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for PairingError {
    fn from(value: std::io::Error) -> Self {
        PairingError::Io(value)
    }
}

/// Rendezvous target encoded into an invite.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RendezvousRelay {
    /// Hosted/default relay (URL negotiated out-of-band until cloud relay ships).
    Default,
    /// Local mailbox directory used by [`FsRelay`].
    BeamFs(PathBuf),
    /// HTTP(S) rendezvous base URL (no trailing slash), served by `beam-relay`.
    Http(String),
    /// Parsed relay string without a built-in transport implementation yet.
    Unsupported(String),
}

/// Parsed invite payload shared by every surface form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedInvite {
    pub relay: RendezvousRelay,
    pub room_id: [u8; 16],
    pub expires_unix: u64,
    /// Ten-byte seed encoded by human words or embedded in a binary token.
    pub seed: [u8; 10],
}

/// Invite material generated locally by the sender before rendezvous registration.
#[derive(Clone, Debug)]
pub struct PreparedInvite {
    pub invite_line: String,
    pub room_id: [u8; 16],
    pub expires_unix: u64,
    pub seed: [u8; 10],
    pub relay: RendezvousRelay,
}

impl PreparedInvite {
    #[must_use]
    pub fn invite_context(&self) -> InviteContext {
        invite_context_for(&self.relay, &self.room_id, self.expires_unix)
    }
}

impl ParsedInvite {
    #[must_use]
    pub fn invite_context(&self) -> InviteContext {
        invite_context_for(&self.relay, &self.room_id, self.expires_unix)
    }

    pub fn assert_not_expired(&self) -> Result<(), PairingError> {
        let now = unix_now_secs();
        if now > self.expires_unix {
            return Err(PairingError::Expired);
        }
        Ok(())
    }
}

fn invite_context_for(
    relay: &RendezvousRelay,
    room_id: &[u8; 16],
    expires_unix: u64,
) -> InviteContext {
    let tag = relay_tag_bytes(relay);
    invite_context_from_pairing(room_id, expires_unix, &tag)
}

fn relay_tag_bytes(relay: &RendezvousRelay) -> Vec<u8> {
    match relay {
        RendezvousRelay::Default => b"default".to_vec(),
        RendezvousRelay::BeamFs(p) => {
            let mut v = RELAY_BEAM_FS_PREFIX.as_bytes().to_vec();
            v.extend_from_slice(p.as_os_str().as_encoded_bytes());
            v
        }
        RendezvousRelay::Http(url) => url.as_bytes().to_vec(),
        RendezvousRelay::Unsupported(s) => s.as_bytes().to_vec(),
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn words256() -> &'static [&'static str] {
    static WORDS: std::sync::OnceLock<Vec<&'static str>> = std::sync::OnceLock::new();
    WORDS.get_or_init(|| {
        include_str!("../data/wordlist_256.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect()
    })
}

fn validate_word_list() -> Result<(), PairingError> {
    let w = words256();
    if w.len() != 256 {
        return Err(PairingError::Crypto("word list must contain 256 entries"));
    }
    Ok(())
}

fn words_from_seed(seed: &[u8; 10]) -> Result<String, PairingError> {
    validate_word_list()?;
    let list = words256();
    let mut out = Vec::with_capacity(10);
    for b in seed {
        let word = list
            .get(usize::from(*b))
            .ok_or(PairingError::InvalidInvite("word index out of range"))?;
        out.push(*word);
    }
    Ok(out.join(" "))
}

fn seed_from_words_blob(words_blob: &str) -> Result<[u8; 10], PairingError> {
    validate_word_list()?;
    let list = words256();
    let mut map: HashMap<&str, u8> = HashMap::with_capacity(list.len());
    for (i, w) in list.iter().enumerate() {
        map.insert(*w, i as u8);
    }
    let tokens: Vec<&str> = words_blob.split_whitespace().collect();
    if tokens.len() != 10 {
        return Err(PairingError::InvalidInvite(
            "invite words must be exactly 10",
        ));
    }
    let mut seed = [0u8; 10];
    for (i, tok) in tokens.iter().enumerate() {
        let idx = map
            .get(*tok)
            .ok_or(PairingError::InvalidInvite("unknown invite word"))?;
        seed[i] = *idx;
    }
    Ok(seed)
}

fn pake_password_bytes(room_id: &[u8; 16], seed: &[u8; 10]) -> Result<Vec<u8>, PairingError> {
    let hk = Hkdf::<Sha256>::new(Some(room_id), seed);
    let mut out = vec![0u8; 64];
    hk.expand(b"beam.pair.pake_pw.v1", &mut out)
        .map_err(|_| PairingError::Crypto("hkdf pake password"))?;
    Ok(out)
}

fn spake_identity(room_id: &[u8; 16]) -> Identity {
    let mut buf = Vec::with_capacity(b"beam.pair.sym.v1".len() + 16);
    buf.extend_from_slice(b"beam.pair.sym.v1");
    buf.extend_from_slice(room_id);
    Identity::new(&buf)
}

/// Binary layout for [`prepare_invite_long_token`].
fn encode_token_v1(
    expires: u64,
    room_id: &[u8; 16],
    relay_url: &str,
    seed: &[u8; 10],
) -> Result<Vec<u8>, PairingError> {
    let url_bytes = relay_url.as_bytes();
    let url_len = u16::try_from(url_bytes.len())
        .map_err(|_| PairingError::InvalidInvite("relay URL is too long"))?;
    let mut out = Vec::with_capacity(1 + 8 + 16 + 2 + url_bytes.len() + seed.len());
    out.push(1u8);
    out.extend_from_slice(&expires.to_le_bytes());
    out.extend_from_slice(room_id);
    out.extend_from_slice(&url_len.to_le_bytes());
    out.extend_from_slice(url_bytes);
    out.extend_from_slice(seed);
    Ok(out)
}

fn decode_token_v1(payload: &[u8]) -> Result<(u64, [u8; 16], String, [u8; 10]), PairingError> {
    if payload.first().copied() != Some(1u8) || payload.len() < 1 + 8 + 16 + 2 {
        return Err(PairingError::InvalidInvite("unknown token version"));
    }
    let mut cur = &payload[1..];
    let expires = read_u64(&mut cur)?;
    let mut room_id = [0u8; 16];
    room_id.copy_from_slice(take(&mut cur, 16)?);
    let url_len = read_u16(&mut cur)? as usize;
    let url_bytes = take(&mut cur, url_len)?;
    let seed_slice = take(&mut cur, 10)?;
    let mut seed = [0u8; 10];
    seed.copy_from_slice(seed_slice);
    if !cur.is_empty() {
        return Err(PairingError::InvalidInvite("trailing token bytes"));
    }
    let relay_url = std::str::from_utf8(url_bytes)
        .map_err(|_| PairingError::InvalidInvite("relay URL is not utf-8"))?
        .to_owned();
    Ok((expires, room_id, relay_url, seed))
}

fn read_u64(cur: &mut &[u8]) -> Result<u64, PairingError> {
    if cur.len() < 8 {
        return Err(PairingError::InvalidInvite("truncated token"));
    }
    let (head, tail) = cur.split_at(8);
    *cur = tail;
    Ok(u64::from_le_bytes(head.try_into().unwrap()))
}

fn read_u16(cur: &mut &[u8]) -> Result<u16, PairingError> {
    if cur.len() < 2 {
        return Err(PairingError::InvalidInvite("truncated token"));
    }
    let (head, tail) = cur.split_at(2);
    *cur = tail;
    Ok(u16::from_le_bytes(head.try_into().unwrap()))
}

fn take<'a>(cur: &mut &'a [u8], n: usize) -> Result<&'a [u8], PairingError> {
    if cur.len() < n {
        return Err(PairingError::InvalidInvite("truncated token"));
    }
    let (head, tail) = cur.split_at(n);
    *cur = tail;
    Ok(head)
}

pub(crate) fn normalize_http_relay_base(url: &str) -> String {
    url.trim().trim_end_matches('/').to_owned()
}

fn relay_from_url(url: &str) -> RendezvousRelay {
    if url == "default" {
        RendezvousRelay::Default
    } else if let Some(rest) = url.strip_prefix(RELAY_BEAM_FS_PREFIX) {
        RendezvousRelay::BeamFs(PathBuf::from(rest))
    } else if url.starts_with("http://") || url.starts_with("https://") {
        RendezvousRelay::Http(normalize_http_relay_base(url))
    } else {
        RendezvousRelay::Unsupported(url.to_owned())
    }
}

/// Prepare a human-word invite that still carries a local mailbox path (`beam-fs:`) for rendezvous.
pub fn prepare_invite_human_words(
    ttl_seconds: u64,
    mailbox_root: &Path,
) -> Result<PreparedInvite, PairingError> {
    validate_word_list()?;
    let mut room_id = [0u8; 16];
    let mut seed = [0u8; 10];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut room_id)
        .map_err(|_| PairingError::Crypto("rng room id"))?;
    rng.try_fill_bytes(&mut seed)
        .map_err(|_| PairingError::Crypto("rng seed"))?;
    let expires_unix = unix_now_secs().saturating_add(ttl_seconds);
    let relay_url = format!("{}{}", RELAY_BEAM_FS_PREFIX, mailbox_root.display());
    let relay = RendezvousRelay::BeamFs(mailbox_root.to_path_buf());
    let room_b64 = URL_SAFE_NO_PAD.encode(room_id);
    let path_b64 = URL_SAFE_NO_PAD.encode(relay_url.as_bytes());
    let words = words_from_seed(&seed)?;
    let line = format!(
        "{INVITE_LINE_PREFIX}\tword\tbeam-fs\t{expires_unix}\t{room_b64}\t{path_b64}\t{words}"
    );
    Ok(PreparedInvite {
        invite_line: line,
        room_id,
        expires_unix,
        seed,
        relay,
    })
}

/// Human-word invite embedding an HTTP(S) relay base URL (receiver reaches the same host as in the invite).
pub fn prepare_invite_human_words_http(
    ttl_seconds: u64,
    relay_base_url: &str,
) -> Result<PreparedInvite, PairingError> {
    validate_word_list()?;
    let mut room_id = [0u8; 16];
    let mut seed = [0u8; 10];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut room_id)
        .map_err(|_| PairingError::Crypto("rng room id"))?;
    rng.try_fill_bytes(&mut seed)
        .map_err(|_| PairingError::Crypto("rng seed"))?;
    let expires_unix = unix_now_secs().saturating_add(ttl_seconds);
    let relay_url = normalize_http_relay_base(relay_base_url);
    let relay = RendezvousRelay::Http(relay_url.clone());
    let room_b64 = URL_SAFE_NO_PAD.encode(room_id);
    let url_b64 = URL_SAFE_NO_PAD.encode(relay_url.as_bytes());
    let words = words_from_seed(&seed)?;
    let line =
        format!("{INVITE_LINE_PREFIX}\tword\thttp\t{expires_unix}\t{room_b64}\t{url_b64}\t{words}");
    Ok(PreparedInvite {
        invite_line: line,
        room_id,
        expires_unix,
        seed,
        relay,
    })
}

/// Compact base64url token for copy/paste; embeds relay URL and cryptographic seed material.
pub fn prepare_invite_long_token(
    ttl_seconds: u64,
    relay_url: &str,
) -> Result<PreparedInvite, PairingError> {
    let mut room_id = [0u8; 16];
    let mut seed = [0u8; 10];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut room_id)
        .map_err(|_| PairingError::Crypto("rng room id"))?;
    rng.try_fill_bytes(&mut seed)
        .map_err(|_| PairingError::Crypto("rng seed"))?;
    let expires_unix = unix_now_secs().saturating_add(ttl_seconds);
    let relay_url_stored = if relay_url.starts_with("http://") || relay_url.starts_with("https://")
    {
        normalize_http_relay_base(relay_url)
    } else {
        relay_url.to_owned()
    };
    let payload = encode_token_v1(expires_unix, &room_id, &relay_url_stored, &seed)?;
    let token = URL_SAFE_NO_PAD.encode(&payload);
    let line = format!("{INVITE_LINE_PREFIX}\ttoken\t{token}");
    let relay = relay_from_url(&relay_url_stored);
    Ok(PreparedInvite {
        invite_line: line,
        room_id,
        expires_unix,
        seed,
        relay,
    })
}

/// Sender-side helper for tests that target the planned default relay without embedding filesystem paths.
pub fn prepare_invite_default_word_stub(ttl_seconds: u64) -> Result<PreparedInvite, PairingError> {
    validate_word_list()?;
    let mut room_id = [0u8; 16];
    let mut seed = [0u8; 10];
    let mut rng = OsRng;
    rng.try_fill_bytes(&mut room_id)
        .map_err(|_| PairingError::Crypto("rng room id"))?;
    rng.try_fill_bytes(&mut seed)
        .map_err(|_| PairingError::Crypto("rng seed"))?;
    let expires_unix = unix_now_secs().saturating_add(ttl_seconds);
    let room_b64 = URL_SAFE_NO_PAD.encode(room_id);
    let words = words_from_seed(&seed)?;
    let line = format!("{INVITE_LINE_PREFIX}\tword\tdefault\t{expires_unix}\t{room_b64}\t{words}");
    Ok(PreparedInvite {
        invite_line: line,
        room_id,
        expires_unix,
        seed,
        relay: RendezvousRelay::Default,
    })
}

/// Parse every supported invite line into [`ParsedInvite`].
pub fn parse_invite_line(line: &str) -> Result<ParsedInvite, PairingError> {
    let line = line.trim();
    let parts: Vec<&str> = line.split('\t').collect();
    if parts.len() >= 3 && parts[0] == INVITE_LINE_PREFIX {
        return match parts[1] {
            "word" => parse_word_invite(&parts),
            "token" => parse_token_invite(parts[2]),
            _ => Err(PairingError::InvalidInvite("unknown invite kind")),
        };
    }
    parse_invite_line_whitespace_token_fallback(line)
}

/// Token invites may be pasted with spaces instead of tabs (Windows consoles).
fn parse_invite_line_whitespace_token_fallback(line: &str) -> Result<ParsedInvite, PairingError> {
    let line = line.trim();
    if !line.starts_with(INVITE_LINE_PREFIX) {
        return Err(PairingError::InvalidInvite("unknown magic"));
    }
    let rest = line[INVITE_LINE_PREFIX.len()..].trim_start();
    let mut iter = rest.split_whitespace();
    match (iter.next(), iter.next()) {
        (Some("token"), Some(tok)) => {
            if iter.next().is_some() {
                return Err(PairingError::InvalidInvite(
                    "token invite must be exactly three fields",
                ));
            }
            parse_token_invite(tok)
        }
        _ => Err(PairingError::InvalidInvite("line too short")),
    }
}

fn parse_word_invite(parts: &[&str]) -> Result<ParsedInvite, PairingError> {
    let relay_kind = parts
        .get(2)
        .copied()
        .ok_or(PairingError::InvalidInvite("missing relay kind"))?;
    let expires_raw = parts
        .get(3)
        .copied()
        .ok_or(PairingError::InvalidInvite("missing expiry"))?;
    let expires_unix = expires_raw
        .parse::<u64>()
        .map_err(|_| PairingError::InvalidInvite("invalid expiry"))?;
    let room_b64 = parts
        .get(4)
        .copied()
        .ok_or(PairingError::InvalidInvite("missing room id"))?;
    let room_bytes = URL_SAFE_NO_PAD
        .decode(room_b64.as_bytes())
        .map_err(|_| PairingError::InvalidInvite("room id is not valid base64"))?;
    let room_vec = room_bytes.as_slice();
    if room_vec.len() != 16 {
        return Err(PairingError::InvalidInvite("room id must be 16 bytes"));
    }
    let mut room_id = [0u8; 16];
    room_id.copy_from_slice(room_vec);

    match relay_kind {
        "default" => {
            let words_blob = parts
                .get(5)
                .copied()
                .ok_or(PairingError::InvalidInvite("missing words"))?;
            let seed = seed_from_words_blob(words_blob)?;
            Ok(ParsedInvite {
                relay: RendezvousRelay::Default,
                room_id,
                expires_unix,
                seed,
            })
        }
        "http" => {
            let url_b64 = parts
                .get(5)
                .copied()
                .ok_or(PairingError::InvalidInvite("missing relay URL"))?;
            let url_bytes = URL_SAFE_NO_PAD
                .decode(url_b64.as_bytes())
                .map_err(|_| PairingError::InvalidInvite("relay URL is not valid base64"))?;
            let relay_url = std::str::from_utf8(&url_bytes)
                .map_err(|_| PairingError::InvalidInvite("relay URL is not utf-8"))?;
            let relay = relay_from_url(relay_url);
            let words_blob = parts
                .get(6)
                .copied()
                .ok_or(PairingError::InvalidInvite("missing words"))?;
            let seed = seed_from_words_blob(words_blob)?;
            Ok(ParsedInvite {
                relay,
                room_id,
                expires_unix,
                seed,
            })
        }
        "beam-fs" => {
            let path_b64 = parts
                .get(5)
                .copied()
                .ok_or(PairingError::InvalidInvite("missing mailbox path"))?;
            let path_bytes = URL_SAFE_NO_PAD
                .decode(path_b64.as_bytes())
                .map_err(|_| PairingError::InvalidInvite("mailbox path is not valid base64"))?;
            let relay_url = std::str::from_utf8(&path_bytes)
                .map_err(|_| PairingError::InvalidInvite("mailbox path is not utf-8"))?;
            let relay = relay_from_url(relay_url);
            let words_blob = parts
                .get(6)
                .copied()
                .ok_or(PairingError::InvalidInvite("missing words"))?;
            let seed = seed_from_words_blob(words_blob)?;
            Ok(ParsedInvite {
                relay,
                room_id,
                expires_unix,
                seed,
            })
        }
        _ => Err(PairingError::InvalidInvite("unknown relay kind")),
    }
}

fn parse_token_invite(token: &str) -> Result<ParsedInvite, PairingError> {
    let payload = URL_SAFE_NO_PAD
        .decode(token.as_bytes())
        .map_err(|_| PairingError::InvalidInvite("token is not valid base64"))?;
    let (expires_unix, room_id, relay_url, seed) = decode_token_v1(&payload)?;
    let relay = relay_from_url(&relay_url);
    Ok(ParsedInvite {
        relay,
        room_id,
        expires_unix,
        seed,
    })
}

/// Mailbox relay surface used by pairing endpoints.
pub trait PairingRelay {
    fn put_sender_message(
        &mut self,
        room_id: &[u8; 16],
        expires_unix: u64,
        msg: &[u8],
    ) -> Result<(), PairingError>;

    fn wait_receiver_message(
        &mut self,
        room_id: &[u8; 16],
        timeout: Duration,
    ) -> Result<Vec<u8>, PairingError>;

    fn wait_sender_message(
        &mut self,
        room_id: &[u8; 16],
        timeout: Duration,
    ) -> Result<Vec<u8>, PairingError>;

    fn put_receiver_message(&mut self, room_id: &[u8; 16], msg: &[u8]) -> Result<(), PairingError>;

    fn consume_room(&mut self, room_id: &[u8; 16]) -> Result<(), PairingError>;
}

#[must_use]
pub fn room_id_hex(room_id: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in room_id {
        use core::fmt::Write;
        let _ = write!(&mut s, "{b:02x}");
    }
    s
}

/// Filesystem-backed mailbox (`<root>/<room_hex>/...`) for local demos and tests.
#[derive(Debug)]
pub struct FsRelay {
    root: PathBuf,
}

impl FsRelay {
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn room_dir(&self, room_id: &[u8; 16]) -> PathBuf {
        self.root.join(room_id_hex(room_id))
    }

    fn write_meta_expiry(&self, room_dir: &Path, expires_unix: u64) -> Result<(), PairingError> {
        fs::create_dir_all(room_dir)?;
        let path = room_dir.join("expires.txt");
        let mut f = fs::File::create(path)?;
        write!(f, "{expires_unix}")?;
        Ok(())
    }

    fn read_meta_expiry(&self, room_dir: &Path) -> Result<Option<u64>, PairingError> {
        let path = room_dir.join("expires.txt");
        if !path.exists() {
            return Ok(None);
        }
        let data = fs::read_to_string(path)?;
        let exp = data
            .trim()
            .parse::<u64>()
            .map_err(|_| PairingError::Relay("expires metadata is corrupt"))?;
        Ok(Some(exp))
    }

    fn ensure_room_active(&self, room_dir: &Path) -> Result<(), PairingError> {
        let exp = self.read_meta_expiry(room_dir)?;
        let Some(expires_unix) = exp else {
            return Err(PairingError::Relay("missing pairing mailbox metadata"));
        };
        let now = unix_now_secs();
        if now > expires_unix {
            return Err(PairingError::Expired);
        }
        Ok(())
    }
}

impl PairingRelay for FsRelay {
    fn put_sender_message(
        &mut self,
        room_id: &[u8; 16],
        expires_unix: u64,
        msg: &[u8],
    ) -> Result<(), PairingError> {
        let dir = self.room_dir(room_id);
        fs::create_dir_all(&dir)?;
        self.write_meta_expiry(&dir, expires_unix)?;
        let tmp = dir.join("sender.msg.tmp");
        let final_path = dir.join("sender.msg");
        fs::write(&tmp, msg)?;
        fs::rename(tmp, final_path)?;
        Ok(())
    }

    fn wait_receiver_message(
        &mut self,
        room_id: &[u8; 16],
        timeout: Duration,
    ) -> Result<Vec<u8>, PairingError> {
        let dir = self.room_dir(room_id);
        let path = dir.join("receiver.msg");
        let start = Instant::now();
        loop {
            self.ensure_room_active(&dir)?;
            if path.exists() {
                return Ok(fs::read(&path)?);
            }
            if start.elapsed() > timeout {
                return Err(PairingError::Relay(
                    "timed out waiting for receiver PAKE message",
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_sender_message(
        &mut self,
        room_id: &[u8; 16],
        timeout: Duration,
    ) -> Result<Vec<u8>, PairingError> {
        let dir = self.room_dir(room_id);
        let path = dir.join("sender.msg");
        let start = Instant::now();
        loop {
            if dir.exists() {
                self.ensure_room_active(&dir)?;
            }
            if path.exists() {
                return Ok(fs::read(&path)?);
            }
            if start.elapsed() > timeout {
                return Err(PairingError::Relay(
                    "timed out waiting for sender PAKE message",
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn put_receiver_message(&mut self, room_id: &[u8; 16], msg: &[u8]) -> Result<(), PairingError> {
        let dir = self.room_dir(room_id);
        self.ensure_room_active(&dir)?;
        let path = dir.join("receiver.msg");
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)?;
        f.write_all(msg)?;
        f.sync_all()?;
        Ok(())
    }

    fn consume_room(&mut self, room_id: &[u8; 16]) -> Result<(), PairingError> {
        let dir = self.room_dir(room_id);
        if dir.exists() {
            fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }
}

#[derive(Default, Debug)]
struct MemoryRoom {
    expires_unix: u64,
    sender_msg: Option<Vec<u8>>,
    receiver_msg: Option<Vec<u8>>,
}

/// In-process mailbox for deterministic tests (no relay can inspect PAKE payloads offline beyond guessing).
#[derive(Clone, Debug, Default)]
pub struct MemoryRelay {
    inner: Arc<Mutex<HashMap<[u8; 16], MemoryRoom>>>,
}

impl MemoryRelay {
    fn ensure_expiry(room: &MemoryRoom) -> Result<(), PairingError> {
        let now = unix_now_secs();
        if now > room.expires_unix {
            return Err(PairingError::Expired);
        }
        Ok(())
    }
}

impl PairingRelay for MemoryRelay {
    fn put_sender_message(
        &mut self,
        room_id: &[u8; 16],
        expires_unix: u64,
        msg: &[u8],
    ) -> Result<(), PairingError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PairingError::Relay("relay mutex poisoned"))?;
        let entry = guard.entry(*room_id).or_default();
        if entry.sender_msg.is_some() {
            return Err(PairingError::Relay("sender message already registered"));
        }
        entry.expires_unix = expires_unix;
        entry.sender_msg = Some(msg.to_vec());
        Ok(())
    }

    fn wait_receiver_message(
        &mut self,
        room_id: &[u8; 16],
        timeout: Duration,
    ) -> Result<Vec<u8>, PairingError> {
        let start = Instant::now();
        loop {
            {
                let guard = self
                    .inner
                    .lock()
                    .map_err(|_| PairingError::Relay("relay mutex poisoned"))?;
                if let Some(room) = guard.get(room_id) {
                    Self::ensure_expiry(room)?;
                    if let Some(msg) = room.receiver_msg.clone() {
                        return Ok(msg);
                    }
                }
            }
            if start.elapsed() > timeout {
                return Err(PairingError::Relay(
                    "timed out waiting for receiver PAKE message",
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_sender_message(
        &mut self,
        room_id: &[u8; 16],
        timeout: Duration,
    ) -> Result<Vec<u8>, PairingError> {
        let start = Instant::now();
        loop {
            {
                let guard = self
                    .inner
                    .lock()
                    .map_err(|_| PairingError::Relay("relay mutex poisoned"))?;
                if let Some(room) = guard.get(room_id) {
                    Self::ensure_expiry(room)?;
                    if let Some(msg) = room.sender_msg.clone() {
                        return Ok(msg);
                    }
                }
            }
            if start.elapsed() > timeout {
                return Err(PairingError::Relay(
                    "timed out waiting for sender PAKE message",
                ));
            }
            thread::sleep(Duration::from_millis(5));
        }
    }

    fn put_receiver_message(&mut self, room_id: &[u8; 16], msg: &[u8]) -> Result<(), PairingError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PairingError::Relay("relay mutex poisoned"))?;
        let Some(room) = guard.get_mut(room_id) else {
            return Err(PairingError::Relay("unknown pairing room"));
        };
        Self::ensure_expiry(room)?;
        if room.receiver_msg.is_some() {
            return Err(PairingError::Relay("receiver message already present"));
        }
        room.receiver_msg = Some(msg.to_vec());
        Ok(())
    }

    fn consume_room(&mut self, room_id: &[u8; 16]) -> Result<(), PairingError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| PairingError::Relay("relay mutex poisoned"))?;
        guard.remove(room_id);
        Ok(())
    }
}

const HTTP_RELAY_EXPIRES_HEADER: &str = "x-beam-expires";

fn http_read_body(mut resp: ureq::http::Response<ureq::Body>) -> Result<Vec<u8>, PairingError> {
    resp.body_mut()
        .read_to_vec()
        .map_err(|_| PairingError::Relay("http relay body read failed"))
}

fn http_transport(err: ureq::Error) -> PairingError {
    match err {
        ureq::Error::StatusCode(410) => PairingError::Expired,
        ureq::Error::StatusCode(409) => PairingError::Relay("http relay conflict"),
        ureq::Error::Io(ref e) => PairingError::Relay(match e.kind() {
            std::io::ErrorKind::ConnectionRefused => {
                "http relay unreachable (connection refused — is beam-relay listening on this URL?)"
            }
            std::io::ErrorKind::TimedOut => "http relay request timed out",
            _ => "http relay I/O error",
        }),
        _ => PairingError::Relay("http relay transport error"),
    }
}

/// HTTP rendezvous client matching `beam-relay`'s `/v1/rooms/...` API.
#[derive(Clone)]
pub struct HttpRelay {
    base: String,
    agent: ureq::Agent,
}

impl fmt::Debug for HttpRelay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HttpRelay")
            .field("base", &self.base)
            .finish()
    }
}

impl HttpRelay {
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();
        Self {
            base: normalize_http_relay_base(&base_url.into()),
            agent,
        }
    }

    fn url_sender(&self, room_id: &[u8; 16]) -> String {
        format!("{}/v1/rooms/{}/sender", self.base, room_id_hex(room_id))
    }

    fn url_receiver(&self, room_id: &[u8; 16]) -> String {
        format!("{}/v1/rooms/{}/receiver", self.base, room_id_hex(room_id))
    }

    fn url_room(&self, room_id: &[u8; 16]) -> String {
        format!("{}/v1/rooms/{}", self.base, room_id_hex(room_id))
    }
}

impl PairingRelay for HttpRelay {
    fn put_sender_message(
        &mut self,
        room_id: &[u8; 16],
        expires_unix: u64,
        msg: &[u8],
    ) -> Result<(), PairingError> {
        let resp = self
            .agent
            .put(&self.url_sender(room_id))
            .header(HTTP_RELAY_EXPIRES_HEADER, &expires_unix.to_string())
            .send(msg)
            .map_err(http_transport)?;
        match resp.status().as_u16() {
            201 | 204 => Ok(()),
            409 => Err(PairingError::Relay("sender message already registered")),
            410 => Err(PairingError::Expired),
            _ => Err(PairingError::Relay(
                "http relay rejected sender registration",
            )),
        }
    }

    fn wait_receiver_message(
        &mut self,
        room_id: &[u8; 16],
        timeout: Duration,
    ) -> Result<Vec<u8>, PairingError> {
        let url = self.url_receiver(room_id);
        let start = Instant::now();
        loop {
            let resp = self.agent.get(&url).call().map_err(http_transport)?;
            match resp.status().as_u16() {
                200 => return http_read_body(resp),
                404 => {}
                410 => return Err(PairingError::Expired),
                _ => return Err(PairingError::Relay("http relay GET receiver failed")),
            }
            if start.elapsed() > timeout {
                return Err(PairingError::Relay(
                    "timed out waiting for receiver PAKE message",
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn wait_sender_message(
        &mut self,
        room_id: &[u8; 16],
        timeout: Duration,
    ) -> Result<Vec<u8>, PairingError> {
        let url = self.url_sender(room_id);
        let start = Instant::now();
        loop {
            let resp = self.agent.get(&url).call().map_err(http_transport)?;
            match resp.status().as_u16() {
                200 => return http_read_body(resp),
                404 => {}
                410 => return Err(PairingError::Expired),
                _ => return Err(PairingError::Relay("http relay GET sender failed")),
            }
            if start.elapsed() > timeout {
                return Err(PairingError::Relay(
                    "timed out waiting for sender PAKE message",
                ));
            }
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn put_receiver_message(&mut self, room_id: &[u8; 16], msg: &[u8]) -> Result<(), PairingError> {
        let resp = self
            .agent
            .put(&self.url_receiver(room_id))
            .send(msg)
            .map_err(http_transport)?;
        match resp.status().as_u16() {
            204 => Ok(()),
            409 => Err(PairingError::Relay("receiver message already present")),
            410 => Err(PairingError::Expired),
            _ => Err(PairingError::Relay("http relay rejected receiver message")),
        }
    }

    fn consume_room(&mut self, room_id: &[u8; 16]) -> Result<(), PairingError> {
        let resp = self
            .agent
            .delete(&self.url_room(room_id))
            .call()
            .map_err(http_transport)?;
        match resp.status().as_u16() {
            204 => Ok(()),
            _ => Err(PairingError::Relay("http relay delete room failed")),
        }
    }
}

/// Chooses filesystem vs HTTP transport for [`PairingRelay`] operations.
#[derive(Debug)]
pub enum RelayTransport {
    Fs(FsRelay),
    Http(HttpRelay),
}

impl RelayTransport {
    /// Opens the transport implied by a locally prepared invite (`send` side).
    #[must_use]
    pub fn for_sender_prepare(prepared: &PreparedInvite) -> Result<Self, String> {
        match &prepared.relay {
            RendezvousRelay::BeamFs(path) => Ok(Self::Fs(FsRelay::new(path))),
            RendezvousRelay::Http(url) => Ok(Self::Http(HttpRelay::new(url))),
            RendezvousRelay::Default => Err(
                "invite relay kind \"default\" cannot drive sender_prepare transport selection"
                    .into(),
            ),
            RendezvousRelay::Unsupported(url) => Err(format!(
                "relay URL {url:?} is not supported for pairing transport"
            )),
        }
    }

    /// Opens the transport implied by a parsed invite (`recv` side).
    #[must_use]
    pub fn for_receiver(
        invite: &ParsedInvite,
        relay_dir_override: Option<PathBuf>,
    ) -> Result<Self, String> {
        match (&invite.relay, relay_dir_override) {
            (RendezvousRelay::BeamFs(path), _) => Ok(Self::Fs(FsRelay::new(path))),
            (RendezvousRelay::Http(url), _) => Ok(Self::Http(HttpRelay::new(url))),
            (RendezvousRelay::Default, Some(path)) => Ok(Self::Fs(FsRelay::new(path))),
            (RendezvousRelay::Default, None) => Err(
                "invite uses relay kind \"default\"; pass --relay-dir with the sender mailbox directory path"
                    .into(),
            ),
            (RendezvousRelay::Unsupported(url), _) => Err(format!(
                "relay URL {url:?} is not supported for pairing transport"
            )),
        }
    }
}

impl PairingRelay for RelayTransport {
    fn put_sender_message(
        &mut self,
        room_id: &[u8; 16],
        expires_unix: u64,
        msg: &[u8],
    ) -> Result<(), PairingError> {
        match self {
            RelayTransport::Fs(r) => r.put_sender_message(room_id, expires_unix, msg),
            RelayTransport::Http(r) => r.put_sender_message(room_id, expires_unix, msg),
        }
    }

    fn wait_receiver_message(
        &mut self,
        room_id: &[u8; 16],
        timeout: Duration,
    ) -> Result<Vec<u8>, PairingError> {
        match self {
            RelayTransport::Fs(r) => r.wait_receiver_message(room_id, timeout),
            RelayTransport::Http(r) => r.wait_receiver_message(room_id, timeout),
        }
    }

    fn wait_sender_message(
        &mut self,
        room_id: &[u8; 16],
        timeout: Duration,
    ) -> Result<Vec<u8>, PairingError> {
        match self {
            RelayTransport::Fs(r) => r.wait_sender_message(room_id, timeout),
            RelayTransport::Http(r) => r.wait_sender_message(room_id, timeout),
        }
    }

    fn put_receiver_message(&mut self, room_id: &[u8; 16], msg: &[u8]) -> Result<(), PairingError> {
        match self {
            RelayTransport::Fs(r) => r.put_receiver_message(room_id, msg),
            RelayTransport::Http(r) => r.put_receiver_message(room_id, msg),
        }
    }

    fn consume_room(&mut self, room_id: &[u8; 16]) -> Result<(), PairingError> {
        match self {
            RelayTransport::Fs(r) => r.consume_room(room_id),
            RelayTransport::Http(r) => r.consume_room(room_id),
        }
    }
}

/// Runs the sender side of SPAKE2 + mailbox exchange.
pub fn sender_derive_session_secrets(
    relay: &mut impl PairingRelay,
    prepared: &PreparedInvite,
    timeout: Duration,
) -> Result<SessionSecrets, PairingError> {
    let pwd_bytes = pake_password_bytes(&prepared.room_id, &prepared.seed)?;
    let pwd = Password::new(pwd_bytes);
    let identity = spake_identity(&prepared.room_id);
    let (spake, outbound) = Spake2::<Ed25519Group>::start_symmetric(&pwd, &identity);
    relay.put_sender_message(&prepared.room_id, prepared.expires_unix, &outbound)?;
    let inbound = relay.wait_receiver_message(&prepared.room_id, timeout)?;
    let shared = spake.finish(&inbound).map_err(|_| PairingError::Spake)?;
    let secrets = SessionSecrets::from_pake_shared_secret(&shared, &prepared.room_id)
        .map_err(|_| PairingError::Crypto("session secrets derivation failed"))?;
    relay.consume_room(&prepared.room_id)?;
    Ok(secrets)
}

/// Runs the receiver side using a parsed invite string plus mailbox access.
pub fn receiver_derive_session_secrets(
    relay: &mut impl PairingRelay,
    invite: &ParsedInvite,
    timeout: Duration,
) -> Result<SessionSecrets, PairingError> {
    invite.assert_not_expired()?;
    let outbound_sender = relay.wait_sender_message(&invite.room_id, timeout)?;
    let pwd_bytes = pake_password_bytes(&invite.room_id, &invite.seed)?;
    let pwd = Password::new(pwd_bytes);
    let identity = spake_identity(&invite.room_id);
    let (spake, outbound_recv) = Spake2::<Ed25519Group>::start_symmetric(&pwd, &identity);
    relay.put_receiver_message(&invite.room_id, &outbound_recv)?;
    let shared = spake
        .finish(&outbound_sender)
        .map_err(|_| PairingError::Spake)?;
    let secrets = SessionSecrets::from_pake_shared_secret(&shared, &invite.room_id)
        .map_err(|_| PairingError::Crypto("session secrets derivation failed"))?;
    Ok(secrets)
}

/// Runs sender and receiver concurrently against a shared [`MemoryRelay`] (unit-test helper).
pub fn pair_in_memory_for_test(
    relay: &MemoryRelay,
    prepared: PreparedInvite,
) -> Result<(SessionSecrets, SessionSecrets), PairingError> {
    let relay_clone = relay.clone();
    let line = prepared.invite_line.clone();
    let prepared_sender = prepared.clone();
    let sender_handle = thread::spawn(move || {
        let mut relay = relay_clone.clone();
        sender_derive_session_secrets(&mut relay, &prepared_sender, Duration::from_secs(5))
    });

    let invite = parse_invite_line(&line)?;
    let mut relay_rx = relay.clone();
    // Receiver runs after sender posts — small yield for ordering.
    thread::sleep(Duration::from_millis(10));
    let rx_sec = receiver_derive_session_secrets(&mut relay_rx, &invite, Duration::from_secs(5))?;
    let tx_sec = sender_handle
        .join()
        .map_err(|_| PairingError::Relay("sender thread panicked"))??;
    Ok((tx_sec, rx_sec))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn word_invite_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fs_root = dir.path().join("mailbox");
        let prepared = prepare_invite_human_words(3600, &fs_root).expect("prepare");
        let parsed = parse_invite_line(&prepared.invite_line).expect("parse");
        assert_eq!(parsed.room_id, prepared.room_id);
        assert_eq!(parsed.seed, prepared.seed);
        assert_eq!(parsed.expires_unix, prepared.expires_unix);
        assert!(matches!(
            parsed.relay,
            RendezvousRelay::BeamFs(ref p) if p == &fs_root
        ));
    }

    #[test]
    fn long_token_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("mailbox");
        let relay_url = format!("{}{}", RELAY_BEAM_FS_PREFIX, path.display());
        let prepared = prepare_invite_long_token(120, &relay_url).expect("prep");
        let parsed = parse_invite_line(&prepared.invite_line).expect("parse");
        assert_eq!(parsed.seed, prepared.seed);
        assert_eq!(parsed.room_id, prepared.room_id);
        assert!(matches!(
            parsed.relay,
            RendezvousRelay::BeamFs(ref p) if p == &path
        ));
    }

    #[test]
    fn token_invite_accepts_whitespace_field_separators() {
        let prepared = prepare_invite_long_token(120, "http://127.0.0.1:9/").expect("prep");
        let tab_line = prepared.invite_line.clone();
        let parsed_tab = parse_invite_line(&tab_line).expect("tab parse");
        let spaced = tab_line.replace('\t', "   ");
        let parsed_spaced = parse_invite_line(&spaced).expect("whitespace parse");
        assert_eq!(parsed_tab, parsed_spaced);
    }

    #[test]
    fn word_http_invite_round_trips() {
        let prepared =
            prepare_invite_human_words_http(3600, "http://127.0.0.1:8787/").expect("prepare");
        let parsed = parse_invite_line(&prepared.invite_line).expect("parse");
        assert_eq!(parsed.room_id, prepared.room_id);
        assert!(matches!(
            parsed.relay,
            RendezvousRelay::Http(ref u) if u == "http://127.0.0.1:8787"
        ));
    }

    #[test]
    fn wrong_seed_produces_different_pake_secret_material() {
        let mut a = [0u8; 10];
        let mut b = [0u8; 10];
        a.fill(3);
        b.fill(9);
        let room = [7u8; 16];
        let pa = pake_password_bytes(&room, &a).expect("hkdf");
        let pb = pake_password_bytes(&room, &b).expect("hkdf");
        assert_ne!(pa, pb);
    }
}
