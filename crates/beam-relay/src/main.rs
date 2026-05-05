//! Beam relay binary — minimal HTTP rendezvous for pairing.

#![forbid(unsafe_code)]

use beam_relay::{router, AppState};
use clap::Parser;
use tokio::net::TcpListener;

#[derive(Debug, Parser)]
#[command(name = "beam-relay", version, about = "Beam rendezvous relay (HTTP)")]
struct Args {
    /// Socket address to bind (e.g. 127.0.0.1:8787).
    #[arg(long, default_value = "127.0.0.1:8787")]
    listen: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let listener = TcpListener::bind(&args.listen).await.unwrap_or_else(|e| {
        eprintln!("beam-relay: bind {} failed: {e}", args.listen);
        std::process::exit(1);
    });
    eprintln!("beam-relay: listening on {}", args.listen);
    let state = AppState::default();
    let app = router(state);
    if let Err(e) = axum::serve(listener, app).await {
        eprintln!("beam-relay: server error: {e}");
        std::process::exit(1);
    }
}
