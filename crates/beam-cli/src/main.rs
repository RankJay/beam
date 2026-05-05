//! Beam CLI — thin front-end over `beam-core`.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use beam_core::chunking::DEFAULT_CHUNK_SIZE;
use beam_core::direct_quic::{framed_transfer_receiver_quic_leg_blocking, ReceiverSessionOutcome};
use beam_core::folder_snapshot::{
    build_folder_snapshot_manifest, transfer_folder_snapshot_local, SnapshotFilters,
};
use beam_core::local_transfer::{
    transfer_one_file_local, transfer_one_file_local_encrypted, DestinationConflictPolicy,
    LocalReceiver,
};
use beam_core::pairing::{
    parse_invite_line, prepare_invite_human_words, prepare_invite_human_words_http,
    prepare_invite_long_token, receiver_derive_session_secrets, sender_derive_session_secrets,
    RelayTransport, RELAY_BEAM_FS_PREFIX,
};
use beam_core::session_crypto::{InviteContext, SessionSecrets};
use beam_core::session_file::{LocalSessionFileV1, PersistedTransferState};
use beam_core::{beam_cache_dir, beam_data_dir, beam_sessions_dir};
use clap::{CommandFactory, Parser, Subcommand};
use clap_complete::{generate, Shell};

#[derive(Debug, Parser)]
#[command(name = "beam", version, about = "Beam file transfer")]
struct Cli {
    /// Emit a single JSON object on stdout (for scripts).
    #[arg(long, global = true)]
    json: bool,
    /// Emit newline-delimited JSON records (sessions list, benchmarks).
    #[arg(long, global = true, conflicts_with = "json")]
    json_stream: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Prepare pairing, print an invite, then wait for a receiver (filesystem or HTTP relay).
    Send {
        /// When both this and `--relay-url` are omitted, uses the built-in alpha relay URL (`DEFAULT_PUBLIC_RELAY_BASE_URL`), overridable with `BEAM_RELAY_URL`.
        #[arg(long, value_name = "DIR")]
        relay_dir: Option<PathBuf>,
        /// Base URL of `beam-relay` (`http://...`); mutually exclusive with `--relay-dir`.
        ///
        /// When both this and `--relay-dir` are omitted, uses the same default as above.
        #[arg(long, value_name = "URL")]
        relay_url: Option<String>,
        /// Invite lifetime in seconds (rendezvous expiry metadata).
        #[arg(long, default_value_t = 3600)]
        ttl_secs: u64,
        /// Emit a human-word invite with the same `beam-fs:` mailbox embedded (otherwise use a compact token).
        #[arg(long)]
        human_words: bool,
        /// Abort if pairing does not finish within this many seconds.
        #[arg(long, default_value_t = 600)]
        timeout_secs: u64,
    },
    /// Accept an invite string and complete PAKE pairing (filesystem or HTTP relay per invite).
    Recv {
        /// Full single-line invite (TAB-separated fields from `beam send`; quote as one argument).
        #[arg(value_name = "INVITE")]
        invite: String,
        /// Use this mailbox directory instead of the default HTTP relay when the invite relay kind is `default`.
        #[arg(long, value_name = "DIR")]
        relay_dir: Option<PathBuf>,
        #[arg(long, default_value_t = 600)]
        timeout_secs: u64,
    },
    /// Copy one file through the manifest, staging, and atomic finalize path (no network).
    LocalTransfer {
        #[arg(value_name = "SOURCE")]
        from: PathBuf,
        #[arg(value_name = "DEST")]
        to: PathBuf,
        #[arg(long, value_name = "BYTES")]
        chunk_size: Option<u64>,
        #[arg(long, value_name = "PATH")]
        staging: Option<PathBuf>,
        #[arg(long)]
        relative_path: Option<String>,
        #[arg(long)]
        encrypted: bool,
    },
    /// Copy a folder snapshot: full manifest before transfer, filters, staged per file (Phase 8).
    LocalTransferFolder {
        #[arg(value_name = "SOURCE_DIR")]
        from: PathBuf,
        /// Destination root directory (created; tree mirrors source).
        #[arg(value_name = "DEST_DIR")]
        to: PathBuf,
        #[arg(long, value_name = "BYTES")]
        chunk_size: Option<u64>,
        #[arg(long, value_name = "DIR")]
        staging_dir: Option<PathBuf>,
        /// Label embedded in per-file manifest paths (receiver summary / approval).
        #[arg(long, default_value = "snap")]
        root_label: String,
        #[arg(long = "exclude", value_name = "GLOB")]
        excludes: Vec<String>,
        #[arg(long = "include", value_name = "GLOB")]
        includes: Vec<String>,
    },
    Version,
    /// Continue a paused receiver transfer using a structured session file (Phase 7).
    ///
    /// The provider must listen with matching session material and the correct connection leg
    /// (same `next_connection_serial` as stored in the session file).
    Resume {
        #[arg(value_name = "SESSION_JSON")]
        session: PathBuf,
        /// Address of the running provider (`host:port`).
        #[arg(long)]
        provider: std::net::SocketAddr,
    },
    /// Show default local storage directories (data, sessions, cache).
    Paths,
    /// List structured session files under the default or given directory.
    Sessions {
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
    },
    /// Print a structured session file (JSON body; metadata only in stream mode).
    SessionInspect {
        #[arg(value_name = "SESSION_JSON")]
        path: PathBuf,
    },
    /// Delete a session file (`--force` required; does not remove staging/payload files).
    SessionCancel {
        #[arg(value_name = "SESSION_JSON")]
        path: PathBuf,
        #[arg(long)]
        force: bool,
    },
    /// Remove session files in terminal states only (complete / failed). Never deletes paused/partial.
    SessionCleanup {
        #[arg(long, value_name = "DIR")]
        dir: Option<PathBuf>,
        #[arg(long)]
        dry_run: bool,
    },
    /// Benchmark local plaintext transfer latency (same pipeline as `local-transfer`).
    BenchmarkLocal {
        #[arg(value_name = "SOURCE")]
        from: PathBuf,
        #[arg(long, default_value_t = 3)]
        iterations: u32,
        #[arg(long, value_name = "BYTES")]
        chunk_size: Option<u64>,
    },
    /// Emit shell completions for `beam` (stdout).
    Completions {
        #[arg(value_enum)]
        shell: Shell,
    },
}

fn default_staging_path(dest: &Path) -> PathBuf {
    let file_name = dest
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    let mut staged = file_name;
    staged.push(".beam-staging");
    dest.parent().unwrap_or_else(|| Path::new(".")).join(staged)
}

fn hex_session_id(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

fn print_json_value(v: serde_json::Value) {
    println!("{}", serde_json::to_string(&v).expect("serialize json"));
}

fn exit_cli(json: bool, command: &'static str, msg: impl std::fmt::Display) -> ! {
    if json {
        print_json_value(serde_json::json!({
            "ok": false,
            "command": command,
            "error": msg.to_string(),
        }));
    } else {
        eprintln!("beam {command}: {msg}");
    }
    std::process::exit(1);
}

fn main() {
    let cli = Cli::parse();
    let json = cli.json;
    let json_stream = cli.json_stream;
    match cli.command {
        Command::Completions { shell } => {
            let mut cmd = Cli::command();
            generate(shell, &mut cmd, "beam", &mut std::io::stdout());
        }
        Command::Send {
            relay_dir,
            relay_url,
            ttl_secs,
            human_words,
            timeout_secs,
        } => {
            let prepared = match (relay_dir.as_ref(), relay_url.as_ref()) {
                (Some(_), Some(_)) => {
                    eprintln!("beam send: specify at most one of --relay-dir or --relay-url");
                    std::process::exit(1);
                }
                (Some(dir), None) => {
                    std::fs::create_dir_all(dir).unwrap_or_else(|e| {
                        eprintln!("beam send: cannot create relay dir: {e}");
                        std::process::exit(1);
                    });
                    if human_words {
                        prepare_invite_human_words(ttl_secs, dir)
                    } else {
                        let url = format!("{}{}", RELAY_BEAM_FS_PREFIX, dir.display());
                        prepare_invite_long_token(ttl_secs, &url)
                    }
                }
                (None, Some(url)) => {
                    if human_words {
                        prepare_invite_human_words_http(ttl_secs, url)
                    } else {
                        prepare_invite_long_token(ttl_secs, url)
                    }
                }
                (None, None) => {
                    let url = beam_core::resolved_public_relay_base_url();
                    if human_words {
                        prepare_invite_human_words_http(ttl_secs, &url)
                    } else {
                        prepare_invite_long_token(ttl_secs, &url)
                    }
                }
            };
            let prepared = prepared.unwrap_or_else(|e| {
                eprintln!("beam send: {e}");
                std::process::exit(1);
            });
            println!("{}", prepared.invite_line);
            std::io::stdout().flush().unwrap_or(());
            let mut relay = RelayTransport::for_sender_prepare(&prepared).unwrap_or_else(|e| {
                eprintln!("beam send: {e}");
                std::process::exit(1);
            });
            let secrets = sender_derive_session_secrets(
                &mut relay,
                &prepared,
                Duration::from_secs(timeout_secs),
            )
            .unwrap_or_else(|e| {
                eprintln!("beam send: pairing failed: {e}");
                std::process::exit(1);
            });
            eprintln!(
                "paired: resume lives in session material (session_id={})",
                hex_session_id(&secrets.session_id)
            );
        }
        Command::Recv {
            invite,
            relay_dir,
            timeout_secs,
        } => {
            let parsed = parse_invite_line(&invite).unwrap_or_else(|e| {
                eprintln!("beam recv: {e}");
                std::process::exit(1);
            });
            parsed.assert_not_expired().unwrap_or_else(|e| {
                eprintln!("beam recv: {e}");
                std::process::exit(1);
            });
            let mut relay = RelayTransport::for_receiver(&parsed, relay_dir).unwrap_or_else(|e| {
                eprintln!("beam recv: {e}");
                std::process::exit(1);
            });
            let secrets = receiver_derive_session_secrets(
                &mut relay,
                &parsed,
                Duration::from_secs(timeout_secs),
            )
            .unwrap_or_else(|e| {
                eprintln!("beam recv: pairing failed: {e}");
                std::process::exit(1);
            });
            println!("paired session_id={}", hex_session_id(&secrets.session_id));
        }
        Command::LocalTransfer {
            from,
            to,
            chunk_size,
            staging,
            relative_path,
            encrypted,
        } => {
            let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
            let staging = staging.unwrap_or_else(|| default_staging_path(&to));
            let relative = relative_path.unwrap_or_else(|| {
                from.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("file")
                    .to_owned()
            });
            let xfer = if encrypted {
                let secrets = SessionSecrets::pairing_shim_local();
                transfer_one_file_local_encrypted(
                    &secrets,
                    InviteContext::default(),
                    &from,
                    &staging,
                    &to,
                    &relative,
                    chunk_size,
                    DestinationConflictPolicy::FailIfExists,
                )
            } else {
                transfer_one_file_local(
                    &from,
                    &staging,
                    &to,
                    &relative,
                    chunk_size,
                    DestinationConflictPolicy::FailIfExists,
                )
            };
            if let Err(e) = xfer {
                exit_cli(json, "local-transfer", e);
            }
            if json {
                print_json_value(serde_json::json!({
                    "ok": true,
                    "command": "local-transfer",
                    "source": from,
                    "destination": to,
                    "encrypted": encrypted,
                }));
            }
        }
        Command::LocalTransferFolder {
            from,
            to,
            chunk_size,
            staging_dir,
            root_label,
            excludes,
            includes,
        } => {
            let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
            let filters = SnapshotFilters {
                include_globs: includes.clone(),
                exclude_globs: excludes.clone(),
            };
            let snap = build_folder_snapshot_manifest(&from, &root_label, filters, chunk_size)
                .unwrap_or_else(|e| {
                    eprintln!("beam local-transfer-folder: {e}");
                    std::process::exit(1);
                });
            for line in snap.approval_summary_lines() {
                eprintln!("{line}");
            }
            let staging = staging_dir.unwrap_or_else(|| {
                to.parent()
                    .map(|p| {
                        p.join(format!(
                            "{}.beam-folder-staging",
                            to.file_name().and_then(|n| n.to_str()).unwrap_or("dest")
                        ))
                    })
                    .unwrap_or_else(|| PathBuf::from(".beam-folder-staging"))
            });
            let report = transfer_folder_snapshot_local(
                &from,
                &to,
                &snap,
                &staging,
                DestinationConflictPolicy::FailIfExists,
            )
            .unwrap_or_else(|e| {
                eprintln!("beam local-transfer-folder: {e}");
                std::process::exit(1);
            });
            for (path, outcome) in &report.by_rel_path {
                eprintln!("{path}: {outcome:?}");
            }
            if report
                .by_rel_path
                .values()
                .any(|o| matches!(o, beam_core::folder_snapshot::FolderEntryOutcome::Failed(_)))
            {
                std::process::exit(1);
            }
        }
        Command::Resume { session, provider } => {
            let loaded = LocalSessionFileV1::load(&session).unwrap_or_else(|e| {
                eprintln!("beam resume: {e}");
                std::process::exit(1);
            });
            if let Err(e) = loaded.validate_machine() {
                eprintln!("beam resume: {e}");
                std::process::exit(1);
            }
            let secrets = loaded.session_secrets().unwrap_or_else(|e| {
                eprintln!("beam resume: {e}");
                std::process::exit(1);
            });
            let binding = loaded.handshake_binding().unwrap_or_else(|e| {
                eprintln!("beam resume: {e}");
                std::process::exit(1);
            });
            let manifest = loaded.manifest_from_session().unwrap_or_else(|e| {
                eprintln!("beam resume: {e}");
                std::process::exit(1);
            });
            let receiver = LocalReceiver::resume(
                manifest,
                loaded.staging_path_buf(),
                loaded.destination_path_buf(),
                loaded.conflict_policy(),
                loaded.chunk_received.clone(),
            )
            .unwrap_or_else(|e| {
                eprintln!("beam resume: {e}");
                std::process::exit(1);
            });
            let flags = receiver.chunk_received_flags();
            let missing: Vec<u32> = (0..flags.len())
                .filter(|&i| !flags[i])
                .map(|i| i as u32)
                .collect();
            let outcome = framed_transfer_receiver_quic_leg_blocking(
                provider,
                &secrets,
                &binding,
                loaded.next_connection_serial,
                receiver,
                &missing,
            )
            .unwrap_or_else(|e| {
                eprintln!("beam resume: {e}");
                std::process::exit(1);
            });
            match outcome {
                ReceiverSessionOutcome::Completed => {
                    if json {
                        print_json_value(serde_json::json!({
                            "ok": true,
                            "command": "resume",
                            "outcome": "completed",
                        }));
                    } else {
                        eprintln!("beam resume: transfer completed.");
                    }
                }
                ReceiverSessionOutcome::Paused { .. } => {
                    if json {
                        print_json_value(serde_json::json!({
                            "ok": true,
                            "command": "resume",
                            "outcome": "paused",
                        }));
                    } else {
                        eprintln!("beam resume: paused again; update session file support is manual for now.");
                    }
                }
            }
        }
        Command::Paths => {
            let data = beam_data_dir();
            let sessions = beam_sessions_dir();
            let cache = beam_cache_dir();
            if json {
                print_json_value(serde_json::json!({
                    "ok": true,
                    "command": "paths",
                    "data_dir": data,
                    "sessions_dir": sessions,
                    "cache_dir": cache,
                }));
            } else {
                println!("data_dir     {}", data.display());
                println!("sessions_dir {}", sessions.display());
                println!("cache_dir    {}", cache.display());
            }
        }
        Command::Sessions { dir } => {
            let root = dir.unwrap_or_else(beam_sessions_dir);
            if let Err(e) = std::fs::create_dir_all(&root) {
                exit_cli(json, "sessions", format!("cannot create sessions dir: {e}"));
            }
            let Ok(read) = std::fs::read_dir(&root) else {
                exit_cli(json, "sessions", "cannot read sessions directory");
            };
            let mut paths: Vec<PathBuf> = read
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("json"))
                .collect();
            paths.sort();
            if json_stream {
                for p in &paths {
                    match LocalSessionFileV1::load(p) {
                        Ok(s) => {
                            print_json_value(serde_json::json!({
                                "event": "session.list_entry",
                                "path": p,
                                "transfer_state": s.transfer_state,
                                "session_id_hex": s.session_id_hex,
                                "relative_path": s.relative_path,
                            }));
                        }
                        Err(e) => {
                            print_json_value(serde_json::json!({
                                "event": "session.list_entry",
                                "path": p,
                                "error": e.to_string(),
                            }));
                        }
                    }
                }
                print_json_value(serde_json::json!({
                    "event": "session.list_done",
                    "count": paths.len(),
                }));
            } else if json {
                let mut entries = Vec::new();
                for p in &paths {
                    match LocalSessionFileV1::load(p) {
                        Ok(s) => entries.push(serde_json::json!({
                            "path": p,
                            "transfer_state": s.transfer_state,
                            "session_id_hex": s.session_id_hex,
                        })),
                        Err(e) => entries.push(serde_json::json!({
                            "path": p,
                            "error": e.to_string(),
                        })),
                    }
                }
                print_json_value(serde_json::json!({
                    "ok": true,
                    "command": "sessions",
                    "sessions_dir": root,
                    "entries": entries,
                }));
            } else {
                if paths.is_empty() {
                    eprintln!("(no .json sessions under {})", root.display());
                }
                for p in paths {
                    match LocalSessionFileV1::load(&p) {
                        Ok(s) => println!(
                            "{}  state={:?}  session_id={}",
                            p.display(),
                            s.transfer_state,
                            s.session_id_hex
                        ),
                        Err(e) => println!("{}  (unreadable: {e})", p.display()),
                    }
                }
            }
        }
        Command::SessionInspect { path } => {
            let loaded = LocalSessionFileV1::load(&path).unwrap_or_else(|e| {
                exit_cli(json, "session-inspect", e);
            });
            if json_stream {
                print_json_value(serde_json::json!({
                    "event": "session.inspect",
                    "path": path,
                    "session": loaded,
                }));
            } else if json {
                print_json_value(serde_json::json!({
                    "ok": true,
                    "command": "session-inspect",
                    "path": path,
                    "session": loaded,
                }));
            } else {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&loaded).expect("session json")
                );
            }
        }
        Command::SessionCancel { path, force } => {
            if !force {
                exit_cli(json, "session-cancel", "refusing to delete without --force");
            }
            if let Err(e) = std::fs::remove_file(&path) {
                exit_cli(json, "session-cancel", e);
            }
            if json {
                print_json_value(serde_json::json!({
                    "ok": true,
                    "command": "session-cancel",
                    "removed": path,
                }));
            } else {
                eprintln!("removed {}", path.display());
            }
        }
        Command::SessionCleanup { dir, dry_run } => {
            let root = dir.unwrap_or_else(beam_sessions_dir);
            let Ok(read) = std::fs::read_dir(&root) else {
                exit_cli(json, "session-cleanup", "cannot read sessions directory");
            };
            let mut removed = 0u32;
            let mut dry_candidates = Vec::new();
            let mut stream_would_remove = 0u32;
            for e in read.flatten() {
                let p = e.path();
                if p.extension().and_then(|s| s.to_str()) != Some("json") {
                    continue;
                }
                let Ok(s) = LocalSessionFileV1::load(&p) else {
                    continue;
                };
                let terminal = matches!(
                    s.transfer_state,
                    PersistedTransferState::Complete | PersistedTransferState::Failed
                );
                if !terminal {
                    continue;
                }
                if dry_run {
                    if json_stream {
                        stream_would_remove = stream_would_remove.saturating_add(1);
                        print_json_value(serde_json::json!({
                            "event": "session.cleanup_candidate",
                            "path": p,
                            "transfer_state": s.transfer_state,
                        }));
                    } else if json {
                        dry_candidates.push(serde_json::json!({
                            "path": p,
                            "transfer_state": s.transfer_state,
                        }));
                    } else {
                        println!("would remove {}", p.display());
                    }
                    continue;
                }
                if let Err(e) = std::fs::remove_file(&p) {
                    exit_cli(json, "session-cleanup", format!("{}: {e}", p.display()));
                }
                removed = removed.saturating_add(1);
                if json_stream {
                    print_json_value(serde_json::json!({
                        "event": "session.cleanup_removed",
                        "path": p,
                    }));
                }
            }
            if json_stream {
                print_json_value(serde_json::json!({
                    "event": "session.cleanup_done",
                    "dry_run": dry_run,
                    "removed_count": removed,
                    "would_remove_count": stream_would_remove,
                }));
            } else if json {
                if dry_run {
                    print_json_value(serde_json::json!({
                        "ok": true,
                        "command": "session-cleanup",
                        "dry_run": true,
                        "would_remove": dry_candidates,
                    }));
                } else {
                    print_json_value(serde_json::json!({
                        "ok": true,
                        "command": "session-cleanup",
                        "dry_run": false,
                        "removed_count": removed,
                    }));
                }
            } else if !dry_run {
                eprintln!(
                    "removed {removed} terminal session file(s) under {}",
                    root.display()
                );
            }
        }
        Command::BenchmarkLocal {
            from,
            iterations,
            chunk_size,
        } => {
            let chunk_size = chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE);
            let relative = from
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
                .to_owned();
            let base = std::env::temp_dir().join(format!("beam-bench-{}", std::process::id()));
            if let Err(e) = std::fs::create_dir_all(&base) {
                exit_cli(json, "benchmark-local", e);
            }
            let mut total = Duration::ZERO;
            let mut per_ms = Vec::new();
            for i in 0..iterations {
                let to = base.join(format!("out-{i}.bin"));
                let staging = base.join(format!("st-{i}.bin.staging"));
                let t0 = Instant::now();
                if let Err(e) = transfer_one_file_local(
                    &from,
                    &staging,
                    &to,
                    &relative,
                    chunk_size,
                    DestinationConflictPolicy::FailIfExists,
                ) {
                    let _ = std::fs::remove_dir_all(&base);
                    exit_cli(json, "benchmark-local", e);
                }
                let elapsed = t0.elapsed();
                total += elapsed;
                let ms = elapsed.as_secs_f64() * 1000.0;
                per_ms.push(ms);
                if json_stream {
                    print_json_value(serde_json::json!({
                        "event": "benchmark.local.iteration",
                        "i": i,
                        "elapsed_ms": ms,
                        "chunk_size": chunk_size,
                    }));
                }
            }
            let _ = std::fs::remove_dir_all(&base);
            let avg = if iterations > 0 {
                total.as_secs_f64() * 1000.0 / f64::from(iterations)
            } else {
                0.0
            };
            if json_stream {
                print_json_value(serde_json::json!({
                    "event": "benchmark.local.summary",
                    "iterations": iterations,
                    "total_ms": total.as_secs_f64() * 1000.0,
                    "avg_ms": avg,
                    "chunk_size": chunk_size,
                    "source": from,
                }));
            } else if json {
                print_json_value(serde_json::json!({
                    "ok": true,
                    "command": "benchmark-local",
                    "iterations": iterations,
                    "total_ms": total.as_secs_f64() * 1000.0,
                    "avg_ms": avg,
                    "per_iteration_ms": per_ms,
                    "chunk_size": chunk_size,
                    "source": from,
                }));
            } else {
                eprintln!(
                    "benchmark-local: {} iterations, total {:.2} ms, avg {:.2} ms (chunk_size={})",
                    iterations,
                    total.as_secs_f64() * 1000.0,
                    avg,
                    chunk_size
                );
            }
        }
        Command::Version => {
            if json {
                print_json_value(serde_json::json!({
                    "ok": true,
                    "command": "version",
                    "identity": beam_core::build_identity(),
                }));
            } else {
                println!("{}", beam_core::build_identity());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_parses_local_transfer() {
        let cli =
            Cli::try_parse_from(["beam", "local-transfer", "C:\\a\\in.txt", "C:\\b\\out.txt"])
                .expect("parse");
        assert!(matches!(
            cli.command,
            Command::LocalTransfer {
                ref from,
                ref to,
                chunk_size: None,
                staging: None,
                relative_path: None,
                encrypted: false,
            }
            if from == Path::new("C:\\a\\in.txt") && to == Path::new("C:\\b\\out.txt")
        ));
    }

    #[test]
    fn cli_parses_send() {
        let cli =
            Cli::try_parse_from(["beam", "send", "--relay-dir", "C:\\beam\\mb"]).expect("parse");
        assert!(matches!(
            cli.command,
            Command::Send {
                relay_dir: Some(dir),
                relay_url: None,
                ttl_secs: 3600,
                human_words: false,
                timeout_secs: 600,
            } if dir == Path::new("C:\\beam\\mb")
        ));
    }

    #[test]
    fn cli_parses_send_with_relay_url() {
        let cli = Cli::try_parse_from(["beam", "send", "--relay-url", "http://127.0.0.1:8787/"])
            .expect("parse");
        assert!(matches!(
            cli.command,
            Command::Send {
                relay_dir: None,
                relay_url: Some(ref url),
                ttl_secs: 3600,
                human_words: false,
                timeout_secs: 600,
            } if url == "http://127.0.0.1:8787/"
        ));
    }

    #[test]
    fn cli_parses_send_with_default_relay() {
        let cli = Cli::try_parse_from(["beam", "send"]).expect("parse");
        assert!(matches!(
            cli.command,
            Command::Send {
                relay_dir: None,
                relay_url: None,
                ttl_secs: 3600,
                human_words: false,
                timeout_secs: 600,
            }
        ));
    }

    #[test]
    fn cli_parses_completions() {
        let cli = Cli::try_parse_from(["beam", "completions", "bash"]).expect("parse");
        assert!(matches!(cli.command, Command::Completions { shell } if shell == Shell::Bash));
    }

    #[test]
    fn cli_parses_local_transfer_folder() {
        let cli = Cli::try_parse_from([
            "beam",
            "local-transfer-folder",
            "C:\\src",
            "C:\\dst\\out",
            "--exclude",
            "*.tmp",
            "--include",
            "*.rs",
        ])
        .expect("parse");
        assert!(matches!(
            cli.command,
            Command::LocalTransferFolder {
                ref from,
                ref to,
                chunk_size: None,
                staging_dir: None,
                ref root_label,
                ref excludes,
                ref includes,
            } if from == Path::new("C:\\src")
                && to == Path::new("C:\\dst\\out")
                && root_label == "snap"
                && excludes == &["*.tmp".to_string()]
                && includes == &["*.rs".to_string()]
        ));
    }

    #[test]
    fn cli_parses_resume() {
        let cli = Cli::try_parse_from([
            "beam",
            "resume",
            "C:\\beam\\sess.json",
            "--provider",
            "127.0.0.1:4433",
        ])
        .expect("parse");
        assert!(matches!(
            cli.command,
            Command::Resume {
                ref session,
                provider,
            } if session == Path::new("C:\\beam\\sess.json")
                && provider == std::net::SocketAddr::from(([127, 0, 0, 1], 4433))
        ));
    }

    #[test]
    fn cli_parses_paths_and_global_json() {
        let cli = Cli::try_parse_from(["beam", "--json", "paths"]).expect("parse");
        assert!(cli.json);
        assert!(matches!(cli.command, Command::Paths));
    }

    #[test]
    fn cli_parses_benchmark_local() {
        let cli = Cli::try_parse_from([
            "beam",
            "benchmark-local",
            "C:\\x\\f.bin",
            "--iterations",
            "2",
        ])
        .expect("parse");
        assert!(matches!(
            cli.command,
            Command::BenchmarkLocal {
                ref from,
                iterations: 2,
                chunk_size: None,
            } if from == Path::new("C:\\x\\f.bin")
        ));
    }

    #[test]
    fn cli_json_stream_conflicts_with_json() {
        assert!(Cli::try_parse_from(["beam", "--json", "--json-stream", "paths"]).is_err());
    }

    #[test]
    fn cli_parses_version() {
        let cli = Cli::try_parse_from(["beam", "version"]).expect("parse");
        assert!(matches!(cli.command, Command::Version));
    }
}
