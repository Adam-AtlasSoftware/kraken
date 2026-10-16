//! Where real projects get their analysis engine.

use std::sync::Arc;

use kraken_registry::EngineFactory;

/// The engine factory for real (non-demo) projects.
///
/// TODO(kraken-host): `kraken-host` is being built in parallel and will provide the Ghidra
/// sidecar factory. When it lands, return `Some(Arc::new(kraken_host::ghidra_factory(..)))` here
/// and nothing else in the GUI has to change: `main` passes this value into
/// [`crate::app::KrakenApp`], which wraps it in an in-process backend for Open / New project.
/// Until then real projects show an explanation and the demo project is the way to explore.
pub fn real_engine_factory() -> Option<Arc<dyn EngineFactory>> {
    None
}
