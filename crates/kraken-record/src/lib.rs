//! Records [`engine_fake::FixtureFile`]s from corpus binaries with a real Ghidra, and compares a
//! fresh recording with a committed fixture (the nightly drift check).

mod check;
mod record;
mod render;

pub use check::{Drift, compare};
pub use record::{
    DEFAULT_FUNCTION_CAP, DEFAULT_TYPE_CAP, RecordError, RecordOptions, record_binary,
    render_fixture,
};
