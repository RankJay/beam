//! Beam CLI — thin front-end over `beam-core` (stubs until later phases).

#![forbid(unsafe_code)]

use std::path::{Path, PathBuf};

use beam_core::chunking::DEFAULT_CHUNK_SIZE;
use beam_core::local_transfer::{
    transfer_one_file_local, transfer_one_file_local_encrypted, DestinationConflictPolicy,
};
use beam_core::session_crypto::{InviteContext, SessionSecrets};
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "beam", version, about = "Beam file transfer (scaffold build)")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Prepare a transfer session (stub).
    Send,
    /// Accept an incoming transfer (stub).
    Recv,
    /// Copy one file through the Phase 1 manifest, staging, and atomic finalize path (no network).
    LocalTransfer {
        /// File to read (plaintext).
        #[arg(value_name = "SOURCE")]
        from: PathBuf,
        /// Final path after transfer (must not exist unless you change policy later).
        #[arg(value_name = "DEST")]
        to: PathBuf,
        /// Fixed chunk size in bytes (default from core, ~4 MiB).
        #[arg(long, value_name = "BYTES")]
        chunk_size: Option<u64>,
        /// Staging file path (default: `<DEST filename>.beam-staging` next to `DEST`).
        #[arg(long, value_name = "PATH")]
        staging: Option<PathBuf>,
        /// Logical name stored in the manifest (defaults to `SOURCE` file name).
        #[arg(long)]
        relative_path: Option<String>,
        /// Run through Phase 2 application-layer session crypto (shared secret is generated in-process; PAKE replaces this later).
        #[arg(long)]
        encrypted: bool,
    },
    /// Show core build identity (uses `beam-core`).
    Version,
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

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Command::Send => eprintln!("beam send: not implemented (phase 0 scaffold)"),
        Command::Recv => eprintln!("beam recv: not implemented (phase 0 scaffold)"),
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
    fn cli_parses_version() {
        let cli = Cli::try_parse_from(["beam", "version"]).expect("parse");
        assert!(matches!(cli.command, Command::Version));
    }
}
