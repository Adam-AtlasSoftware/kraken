//! A FakeEngine-backed in-process connection, for the Python test-suite and CI (feature
//! `testing`). Not part of the public Python API: it is reached as `kraken._testing`.

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use engine_fake::{FakeEngine, FixtureFile};
use kraken_engine::SharedEngine;
use kraken_host::{KrakenConfig, ManagedFactory};
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::EngineFactory;

use crate::conn::Connection;

struct FakeFactory(FixtureFile);

#[async_trait]
impl EngineFactory for FakeFactory {
    async fn create(&self, _engine_dir: &Path) -> Result<SharedEngine, ProtoError> {
        Ok(Arc::new(FakeEngine::new(self.0.clone())))
    }
}

#[async_trait]
impl ManagedFactory for FakeFactory {
    async fn shutdown(&self) {}
}

/// An in-process connection whose engine replays the recorded fixture at `fixture`.
pub fn fake_connection(fixture: &Path) -> Result<Connection, ProtoError> {
    let fx = FixtureFile::from_path(fixture).map_err(|e| {
        ProtoError::new(
            ErrorCode::InvalidArgument,
            format!("cannot read fixture {}: {e}", fixture.display()),
        )
    })?;
    Ok(Connection::with_factory(
        Arc::new(FakeFactory(fx)),
        KrakenConfig::default(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::conn::{Author, Mode};

    #[test]
    fn a_missing_fixture_is_an_invalid_argument() {
        let e = fake_connection(Path::new("/nonexistent/fixture.json"))
            .err()
            .expect("error");
        assert_eq!(e.code, ErrorCode::InvalidArgument);
    }

    #[tokio::test]
    async fn the_fake_connection_serves_the_fixture_and_honours_cancel() {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("../engine-fake/fixtures/tiny.json");
        let conn = fake_connection(&p).expect("conn");
        assert_eq!(conn.mode(), Mode::Local);
        let tmp = tempfile::tempdir().expect("tmp");
        let bin = tmp.path().join("p.bin");
        std::fs::write(&bin, b"\x7fELF").expect("bin");
        let h = conn.handle(None, Author::User("t".into()));
        let cancel = kraken_engine::CancellationToken::new();
        h.call(
            "project_create",
            serde_json::json!({"binary": bin, "project_dir": tmp.path().join("p")}),
            cancel.clone(),
            false,
        )
        .await
        .expect("create");
        cancel.cancel();
        let e = h
            .call("project_info", serde_json::json!({}), cancel, false)
            .await
            .unwrap_err();
        assert_eq!(e.code, ErrorCode::Cancelled);
    }
}
