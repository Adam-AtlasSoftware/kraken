//! `kraken-native-worker`: the native engine's confined worker process (ADR 0014, phase 3).
//!
//! Started by `engine-native` through the sidecar spawner with the protocol socketpair as stdin
//! (the stdin and stdout pipes on Windows); not meant to be run by hand.

#[cfg(any(unix, windows))]
fn main() {
    std::process::exit(engine_native::worker::serve::main());
}

#[cfg(not(any(unix, windows)))]
fn main() {
    eprintln!("kraken-native-worker runs on Unix and Windows only");
    std::process::exit(2);
}
