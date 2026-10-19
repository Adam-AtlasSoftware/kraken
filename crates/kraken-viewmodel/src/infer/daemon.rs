//! [`InferApi`] over the GUI's daemon backend. It asks the backend for its current connection
//! on every call, so a reconnect (daemon restarted) is picked up without rebuilding the panel.

use std::sync::Arc;

use async_trait::async_trait;
use kraken_host::infer::{
    AutostartReport, DevicesReply, InferApi, InferListReply, LogsParams, LogsReply,
    ModelLogsParams, ModelStatus, ModelsReply, ReleaseReply, ServingApi, StartOptions, StartReply,
    StatusReply, StopReply,
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

/// The daemon's local-model methods for this window: the holds it takes belong to the window's
/// own connection, so they end when the window does. It asks the backend for the current
/// connection on every call.
pub struct BackendServing(pub Arc<DaemonClientBackend>);

#[async_trait]
impl ServingApi for BackendServing {
    async fn models(&self) -> Result<ModelsReply, ProtoError> {
        ServingApi::models(&self.0.daemon_client()?).await
    }

    async fn devices(&self) -> Result<DevicesReply, ProtoError> {
        ServingApi::devices(&self.0.daemon_client()?).await
    }

    async fn hold(&self, model: &str, opts: StartOptions) -> Result<ModelStatus, ProtoError> {
        ServingApi::hold(&self.0.daemon_client()?, model, opts).await
    }

    async fn release(&self, model: &str) -> Result<ReleaseReply, ProtoError> {
        ServingApi::release(&self.0.daemon_client()?, model).await
    }

    async fn start_model(
        &self,
        model: &str,
        opts: StartOptions,
    ) -> Result<ModelStatus, ProtoError> {
        ServingApi::start_model(&self.0.daemon_client()?, model, opts).await
    }

    async fn stop_model(&self, model: &str) -> Result<StopReply, ProtoError> {
        ServingApi::stop_model(&self.0.daemon_client()?, model).await
    }

    async fn autostart(&self) -> Result<AutostartReport, ProtoError> {
        ServingApi::autostart(&self.0.daemon_client()?).await
    }

    async fn model_logs(&self, params: ModelLogsParams) -> Result<LogsReply, ProtoError> {
        ServingApi::model_logs(&self.0.daemon_client()?, params).await
    }
}
