//! [`InferApi`] over the GUI's daemon backend. It asks the backend for its current connection
//! on every call, so a reconnect (daemon restarted) is picked up without rebuilding the panel.

use std::sync::Arc;

use async_trait::async_trait;
use kraken_host::infer::{
    InferApi, InferListReply, LogsParams, LogsReply, StartReply, StatusReply, StopReply,
};
use kraken_proto::ProtoError;
use serde_json::Value;

use crate::daemon::DaemonClientBackend;

/// The daemon's local-model methods, through a [`DaemonClientBackend`].
pub struct DaemonInfer(pub Arc<DaemonClientBackend>);

#[async_trait]
impl InferApi for DaemonInfer {
    async fn list(&self) -> Result<InferListReply, ProtoError> {
        InferApi::list(&self.0.daemon_client()?).await
    }

    async fn start(&self, backend: &str, settings: Value) -> Result<StartReply, ProtoError> {
        InferApi::start(&self.0.daemon_client()?, backend, settings).await
    }

    async fn status(&self) -> Result<StatusReply, ProtoError> {
        InferApi::status(&self.0.daemon_client()?).await
    }

    async fn stop(&self) -> Result<StopReply, ProtoError> {
        InferApi::stop(&self.0.daemon_client()?).await
    }

    async fn logs(&self, params: LogsParams) -> Result<LogsReply, ProtoError> {
        InferApi::logs(&self.0.daemon_client()?, params).await
    }
}
