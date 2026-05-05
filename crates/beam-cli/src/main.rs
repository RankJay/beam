//! Beam CLI — thin front-end over `beam-core`.

#![forbid(unsafe_code)]

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::Duration;

use beam_core::chunking::DEFAULT_CHUNK_SIZE;
use beam_core::direct_quic::{framed_transfer_receiver_quic_leg_blocking, ReceiverSessionOutcome};
use beam_core::local_transfer::{
    transfer_one_file_local, transfer_one_file_local_encrypted, DestinationConflictPolicy, LocalReceiver,
};
use beam_core::pairing::{
    parse_invite_line, prepare_invite_human_words, prepare_invite_human_words_http,
    prepare_invite_long_token, receiver_derive_session_secrets, sender_derive_session_secrets,
    RelayTransport, RELAY_BEAM_FS_PREFIX,
};
use beam_core::session_crypto::{InviteContext, SessionSecrets};
use beam_core::session_file::LocalSessionFileV1;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "beam", version, about = "Beam file transfer")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Prepare pairing, print an invite, then wait for a receiver (filesystem mailbox).
    Send {
        /// Shared mailbox directory (`beam-fs:` rendezvous); mutually exclusive with `--relay-url`.
        #[arg(long, value_name = "DIR")]
        relay_dir: Option<PathBuf>,
        /// Base URL of `beam-relay` (`http://...`); mutually exclusive with `--relay-dir`.
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
        /// Override mailbox directory when the invite uses relay kind `default`.
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

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Send {
            relay_dir,
            relay_url,
            ttl_secs,
            human_words,
            timeout_secs,
        } => {
            let prepared = match (relay_dir.as_ref(), relay_url.as_ref()) {
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
                _ => {
                    eprintln!("beam send: specify exactly one of --relay-dir or --relay-url");
                    std::process::exit(1);
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
                eprintln!("beam local-transfer: {e}");
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
                    eprintln!("beam resume: transfer completed.");
                }
                ReceiverSessionOutcome::Paused { .. } => {
                    eprintln!("beam resume: paused again; update session file support is manual for now.");
                }
            }
        }
        Command::Version => println!("{}", beam_core::build_identity()),
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
    fn cli_parses_version() {
        let cli = Cli::try_parse_from(["beam", "version"]).expect("parse");
        assert!(matches!(cli.command, Command::Version));
    }
}
