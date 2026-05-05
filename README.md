# Beam (alpha)

Encrypted file transfer CLI and minimal HTTP relay (`beam-relay`). Phase 10 focuses on installable binaries, a **default hosted relay URL**, custom relay paths, shell completions, and a written **v0 protocol** overview.

## Install (from source)

```bash
cargo install --path crates/beam-cli --locked
cargo install --path crates/beam-relay --locked   # optional; self-hosted pairing
```

GitHub Actions builds release binaries on tag pushes (`v*`). Download artifacts from the workflow run, or build locally:

```bash
cargo build --release -p beam-cli --locked
# binary: target/release/beam (or beam.exe on Windows)
```

## Default relay (zero-config send)

If you run **`beam send`** without `--relay-dir` or `--relay-url`, the CLI uses the built-in alpha relay base URL (`beam_core::DEFAULT_PUBLIC_RELAY_BASE_URL`, currently `https://relay.beam.dev`) and embeds it in the invite.

Point **`BEAM_RELAY_URL`** at your own `beam-relay` base when self-hosting or when the packaged default hostname is wrong for your network.

Receivers:

- Token / HTTP human-word invites embed the relay URL — no extra flags.
- Legacy human-word invites with relay kind **`default`** hit the same resolved URL unless **`beam recv --relay-dir`** selects a shared filesystem mailbox instead.

## Commands (overview)

| Flow | Command |
|------|---------|
| Pairing + invite (sender) | `beam send` … optional `--relay-dir`, `--relay-url`, `--human-words` |
| Pairing (receiver) | `beam recv '<invite>'` … optional `--relay-dir` for `default` + FS mailbox |
| Resume paused receiver | `beam resume SESSION.json --provider ADDR` |
| Local smoke / staging | `beam local-transfer`, `beam local-transfer-folder` |
| Data dirs | `beam paths` |
| Shell completions | `beam completions bash` \| `zsh` \| `fish` \| `elvish` \| `powershell` → redirect to your shell’s completion path |

Machine-readable output: **`--json`** / **`--json-stream`** on supported subcommands.

## Privacy (alpha)

- **Relay sees ciphertext-sized blobs** for pairing frames and for the blind pipe (ADR intent: minimal relay knowledge). It does **not** receive filenames or manifest plaintext from this relay API.
- **Direct QUIC** avoids relay payload hops when both peers can complete the handshake in time; otherwise traffic may use the relay pipe (still encrypted end-to-end at the app layer).

See [docs/protocol-v0.md](docs/protocol-v0.md) for endpoints, invite layouts, and troubleshooting hints.

## Troubleshooting

| Symptom | Check |
|---------|--------|
| `connection refused` to relay | Relay URL / `BEAM_RELAY_URL`, firewall, TLS interception |
| Receiver hangs on pairing | Clock skew (expiry), invite typo / truncation, relay unreachable |
| `default` relay + FS mailbox | Sender and receiver must agree: `--relay-dir` on **`beam recv`** points at the same directory tree the sender used |

Run **`cargo test --workspace --locked`** before releasing; integration tests cover pairing, QUIC, relay fallback, resume, and folder snapshots.
