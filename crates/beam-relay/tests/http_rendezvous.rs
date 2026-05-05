//! Phase 4: provider registers PAKE sender blob on relay; receiver claims and completes pairing.

use std::thread;
use std::time::Duration;

use beam_core::pairing::{
    parse_invite_line, prepare_invite_long_token, receiver_derive_session_secrets,
    sender_derive_session_secrets, HttpRelay,
};
use beam_relay::{router, AppState};
use tokio::net::TcpListener;
use tokio::runtime::Runtime;

#[test]
fn http_relay_pairs_sender_and_receiver() {
    let rt = Runtime::new().expect("tokio runtime");
    let listener = rt
        .block_on(async { TcpListener::bind("127.0.0.1:0").await })
        .expect("bind random port");
    let addr = listener.local_addr().expect("addr");
    let base = format!("http://{}", addr);
    let _serve = rt.spawn(async move {
        axum::serve(listener, router(AppState::default()))
            .await
            .expect("serve");
    });
    thread::sleep(Duration::from_millis(80));

    let prepared = prepare_invite_long_token(600, &base).expect("prepare invite");
    let line = prepared.invite_line.clone();

    let base_tx = base.clone();
    let prep_sender = prepared.clone();
    let sender = thread::spawn(move || {
        let mut relay = HttpRelay::new(base_tx);
        sender_derive_session_secrets(&mut relay, &prep_sender, Duration::from_secs(10))
    });

    thread::sleep(Duration::from_millis(50));

    let base_rx = base.clone();
    let receiver = thread::spawn(move || {
        let invite = parse_invite_line(&line).expect("parse");
        let mut relay = HttpRelay::new(base_rx);
        receiver_derive_session_secrets(&mut relay, &invite, Duration::from_secs(10))
    });

    let tx_sec = sender.join().expect("join sender").expect("sender pairs");
    let rx_sec = receiver
        .join()
        .expect("join receiver")
        .expect("receiver pairs");

    assert_eq!(tx_sec.session_id, rx_sec.session_id);
}
