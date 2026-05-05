//! Beam relay binary — deployable separately from the CLI (stubs until later phases).

#![forbid(unsafe_code)]

fn main() {
    eprintln!(
        "beam-relay: scaffold (core = {})",
        beam_core::build_identity()
    );
}
