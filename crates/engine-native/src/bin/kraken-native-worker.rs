//! `kraken-native-worker`: the native engine's confined worker process (ADR 0014, phase 3).
//!
//! Started by `engine-native` through the sidecar spawner with the protocol socketpair as stdin;
//! not meant to be run by hand.

#[cfg(unix)]
fn main() {
    std::process::exit(engine_native::worker::serve::main());
}

#[cfg(not(unix))]
fn main() {
    eprintln!("kraken-native-worker runs on Unix only");
    std::process::exit(2);
}
