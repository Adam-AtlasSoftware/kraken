//! Helpers for tests.

/// A temporary directory whose path has no dot-prefixed element (Ghidra rejects those, and the
/// GUI refuses to place projects there).
pub fn tempdir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("kraken-gui")
        .tempdir()
        .expect("temp dir")
}
