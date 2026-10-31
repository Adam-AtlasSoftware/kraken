//! Compiles the build channel and the target triple in, for the updater (ADR 0015).

fn main() {
    println!("cargo:rerun-if-env-changed=KRAKEN_BUILD_CHANNEL");
    let channel = match std::env::var("KRAKEN_BUILD_CHANNEL").as_deref() {
        Ok("release") => "release",
        _ => "source",
    };
    println!("cargo:rustc-env=KRAKEN_BUILD_CHANNEL={channel}");
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());
    println!("cargo:rustc-env=KRAKEN_BUILD_TARGET={target}");
}
