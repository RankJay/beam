# Beam (alpha)

Encrypted file transfer CLI and minimal HTTP relay (`beam-relay`). Uses a **default hosted relay** for pairing and the blind pipe, optional self-hosted `beam-relay`, direct QUIC when it completes in time, and structured session files for pause/resume.

## Install (from source)

```bash
cargo install --path crates/beam-cli --locked
cargo install --path crates/beam-relay --locked   # optional; self-hosted pairing + pipe
```

GitHub Actions builds **two artifacts per target** on tag pushes (`v*`): `beam-*` (CLI) and `beam-*-relay` (`beam-relay`). Download from the workflow run, or build locally:

```bash
cargo build --release -p beam-cli -p beam-relay --locked
# target/release/beam and target/release/beam-relay (plus .exe on Windows)
```

## Default relay (zero-config send)

If you run **`beam send`** without `--relay-dir` or `--relay-url`, the CLI uses `beam_core::DEFAULT_PUBLIC_RELAY_BASE_URL` (currently `https://relay.beam.dev`) in the invite.

Set **`BEAM_RELAY_URL`** to your own `beam-relay` base when self-hosting or when the default host is wrong. If that URL is **down**, pairing and relay fallback **fail** until you point at a live relay or use a filesystem mailbox (`--relay-dir`) for pairing only (file transfer over the network still needs an HTTP relay for the blind pipe—see below).

Receivers:

- Token / HTTP human-word invites embed the relay URL (no extra flags).
- Invites with relay kind **`default`** resolve like the sender unless **`beam recv --relay-dir`** selects a shared filesystem mailbox for pairing.

## Send and receive a file (network)

Typical flow (two terminals), using the **default HTTP relay** for pairing and relay fallback:

1. **Sender:** `beam send /path/to/file.bin` — prints an invite line, waits for the receiver to pair, then prints `quic_connect=HOST:PORT`. Use **`--advertise <ip-or-host>`** on the sender if the receiver should dial a LAN address instead of `127.0.0.1` (same machine: omit `--advertise`).
2. **Receiver:** `beam recv '<paste-invite>' /path/to/out.bin --provider HOST:PORT` — if you omit `--provider` in interactive use, the CLI prompts for the `quic_connect=` line.

The CLI tries **direct QUIC first** (`--direct-timeout-ms`, default 8000), then the **relay blind pipe**. Human stderr / JSON includes whether the transfer used **`direct`** or **`relayed`**.

Omit the file path on **`beam send`** or the destination on **`beam recv`** for **pairing-only** smoke tests.

**Filesystem relay (`--relay-dir`):** supports PAKE pairing only. **One-file network transfer** after pairing requires the HTTP blind pipe—use the default relay or **`--relay-url`**.

**Folders over the network** are not implemented; use **`beam local-transfer-folder`** on one machine. Trying to **`beam send`** a directory prints an error.

Structured session files for pause/resume live under **`beam paths`** → `sessions_dir` (see **`beam resume`**). Use **`beam session-cleanup --clean-staging`** to drop terminal session JSON and best-effort remove their staging paths.

## Commands (overview)

| Flow | Command |
|------|---------|
| Pairing + send one file | `beam send [opts] FILE` — optional `--relay-dir`, `--relay-url`, `--human-words`, `--advertise`, `--listen`, `--direct-timeout-ms` |
| Pairing + recv one file | `beam recv '<invite>' DEST` — `--provider`, `--staging`, `--direct-timeout-ms`; pairing-only if `DEST` omitted |
| Resume paused receiver | `beam resume SESSION.json --provider ADDR` |
| Local smoke / staging | `beam local-transfer`, `beam local-transfer-folder` |
| Data dirs | `beam paths` |
| Shell completions | `beam completions bash` \| `zsh` \| `fish` \| `elvish` \| `powershell` |

Machine-readable output: **`--json`** / **`--json-stream`** on supported subcommands (send/recv include `path`, `file_blake3_hex` on recv, no raw filenames beyond paths you passed).

## Benchmarks

- Local pipeline: **`beam benchmark-local`**
- Network stack (local `beam-relay`, relay-only timing): **`cargo run -p beam-core --example benchmark_network --locked`**
- Full matrix: **`cargo test --workspace --locked`** (pairing, QUIC, relay fallback, split send/recv, resume, folders local)

## Privacy (alpha)

- **Relay sees ciphertext-sized blobs** for pairing and for the blind pipe. It does **not** receive filenames or manifest plaintext from this relay API.
- **Direct QUIC** avoids relay payload hops when both peers complete the handshake in time; otherwise the relay pipe is used (still E2E encrypted at the app layer).

See [docs/protocol-v0.md](docs/protocol-v0.md) for endpoints, invites, and troubleshooting.

## Troubleshooting

| Symptom | Check |
|---------|--------|
| `connection refused` / TLS errors to default relay | `BEAM_RELAY_URL`, firewall, TLS interception; host `DEFAULT_PUBLIC_RELAY_BASE_URL` must serve a compatible `beam-relay` |
| Receiver hangs on pairing | Clock skew (expiry), invite typo, relay unreachable |
| `default` relay + FS mailbox | Same mailbox path on sender (`--relay-dir`) and **`beam recv --relay-dir`** |

Run **`cargo test --workspace --locked`** before releasing.
