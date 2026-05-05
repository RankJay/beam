# Beam protocol v0 (alpha)

This document describes **implemented behavior** in this repository at alpha — wire surfaces the binaries rely on — not a frozen standard.

## Roles

- **Sender**: prepares an invite, publishes SPAKE2 material to rendezvous, derives session secrets.
- **Receiver**: consumes invite, completes SPAKE2, derives matching secrets.
- **Relay (`beam-relay`)**: HTTP pairing mailbox + blind framed pipe only; no filename or hash semantics in stored payloads.

## Invite formats (`beam-invite-v1`)

Parsed by `beam_core::pairing::parse_invite_line`:

1. **Token** — tab-separated `beam-invite-v1\ttoken\t<base64url(payload)>`. Payload carries expiry (unix seconds), 16-byte room id, relay URL string, and 10-byte seed. Relay URL encodes transport:
   - `http://` / `https://` → HTTP relay (`beam-relay`).
   - `beam-fs:<utf8 path>` → filesystem mailbox directory.
   - literal `default` → hosted relay placeholder resolved via `beam_core::relay_default::resolved_public_relay_base_url()` on receive.

2. **Human words** — `beam-invite-v1\tword\t<relay-kind>\t…`:
   - `default` — seed + room id + expiry; relay resolved like token `default`.
   - `http` — base64url-encoded relay base URL + words blob.
   - `beam-fs` — base64url-encoded `beam-fs:` path + words blob.

PAKE password is derived from invite-only material (never sent raw as an AEAD key).

## HTTP relay API (`beam-relay`)

Base URL must have **no trailing slash**. Headers:

- **`x-beam-expires`**: unix expiry seconds on pairing writes and pipe registration.
- **`x-beam-pipe-gate`**: 64 hex chars (32-byte gate token for blind pipe).

### Pairing (`/v1/rooms`)

| Method | Path | Body | Meaning |
|--------|------|------|---------|
| PUT | `/v1/rooms/{room_hex}/sender` | SPAKE outbound | Register sender leg (`201`; `409` if taken). |
| GET | `/v1/rooms/{room_hex}/sender` | — | Poll sender blob (`404` until present). |
| PUT | `/v1/rooms/{room_hex}/receiver` | SPAKE outbound | Receiver reply (`204`). |
| GET | `/v1/rooms/{room_hex}/receiver` | — | Sender polls receiver blob. |
| DELETE | `/v1/rooms/{room_hex}` | — | Consume room after pairing (`204`). |

Expired rooms → **`410 Gone`** where enforced.

### Blind pipe (`/v1/pipe`)

Framed **`BMQ1`** records with small header; relay stores queues per room (`down` provider→receiver, `up` receiver→provider). Gate header must match room registration; oversize frames rejected.

Used when direct QUIC cannot complete within implementation timeouts (relay fallback).

## Direct transport

QUIC (`rustls`) carries the same application framing as the relay pipe when both peers reach each other on the LAN/WAN path.

## Manifest & chunks (local / encrypted pipelines)

v1 manifests bind chunk hashes; transfer applies AEAD over control + chunk envelopes with keys derived from pairing secrets + handshake binding (invite context, chunk size, framing version). Details live in `beam_core::session_crypto` and ADRs referenced from `.ai/phases/10-public-alpha.md`.

## CLI ↔ protocol mapping

| User action | Implementation anchor |
|-------------|------------------------|
| Default send | `beam send` → `resolved_public_relay_base_url()` embedded in invite |
| Custom relay | `--relay-url` or token/`http` human-word URL |
| FS mailbox | `--relay-dir` / `beam-fs:` in invite |
| Resume | Structured JSON session files under data dir (`beam paths`) |

## Troubleshooting matrix

1. **Pairing timeout** — relay logs / HTTP reachability; invite expiry; retry after sync clocks.
2. **Relay fallback only** — expected on restrictive NAT; verify relay pipe not blocked by proxy (HTTPS).
3. **Resume failures** — session JSON machine fingerprint, `connection_serial`, and provider address must align with paused leg.
