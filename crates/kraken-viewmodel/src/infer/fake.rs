//! A scripted [`ServingApi`] for tests of the cards and the GUI: models that start and stop
//! without any process, and a start that can be made to run out of memory.

use std::sync::{Mutex, PoisonError};

use async_trait::async_trait;
use kraken_host::infer::{
    AutostartReport, DevicesReply, LogsReply, ModelLogsParams, ModelStatus, ModelsReply,
    ReleaseReply, ServingApi, StartOptions, StopReply,
};
use kraken_proto::infer::{DeviceInfo, LocalEngine, ModelState};
use kraken_proto::{ErrorCode, ProtoError};
use serde_json::json;

/// What a [`FakeServing`] did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FakeCall {
    /// `autostart`.
    Autostart,
    /// `start_model` with the options.
    Start(String, StartOptions),
    /// `stop_model`.
    Stop(String),
}

struct Inner {
    models: Vec<ModelStatus>,
    devices: Vec<DeviceInfo>,
    calls: Vec<FakeCall>,
    /// Starts of this model fail with "does not fit" unless stopped others, forced or on the cpu.
    no_fit: Option<String>,
}

/// The fake service.
pub struct FakeServing(Mutex<Inner>);

/// A stopped model for tests.
pub fn stopped_status(id: &str, name: &str) -> ModelStatus {
    ModelStatus {
        id: id.into(),
        name: name.into(),
        engine: Some(LocalEngine::Llama),
        state: ModelState::Stopped,
        base_url: None,
        served_model: None,
        api_key: None,
        port: None,
        pid: None,
        load_fraction: None,
        restarts: 0,
        uptime_secs: None,
        holders: 0,
        pinned: false,
        stops_in_secs: None,
        notice: None,
        warnings: Vec::new(),
        devices: Vec::new(),
        stats: None,
        role_assigned: false,
        autostart: true,
    }
}

impl FakeServing {
    /// A service with `models` and the cards `devices`.
    pub fn new(models: Vec<ModelStatus>, devices: Vec<DeviceInfo>) -> Self {
        FakeServing(Mutex::new(Inner {
            models,
            devices,
            calls: Vec::new(),
            no_fit: None,
        }))
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starting `id` is refused for lack of memory until it is forced or run on the processor.
    pub fn refuse_start(&self, id: &str) {
        self.inner().no_fit = Some(id.to_string());
    }

    /// Changes a model's status.
    pub fn edit(&self, id: &str, f: impl FnOnce(&mut ModelStatus)) {
        if let Some(m) = self.inner().models.iter_mut().find(|m| m.id == id) {
            f(m);
        }
    }

    /// Everything asked of the service so far.
    pub fn calls(&self) -> Vec<FakeCall> {
        self.inner().calls.clone()
    }
}

fn not_found(id: &str) -> ProtoError {
    ProtoError::new(ErrorCode::NotFound, format!("no local model `{id}`"))
}

#[async_trait]
impl ServingApi for FakeServing {
    async fn models(&self) -> Result<ModelsReply, ProtoError> {
        Ok(ModelsReply {
            models: self.inner().models.clone(),
            grace_secs: 120,
        })
    }

    async fn devices(&self) -> Result<DevicesReply, ProtoError> {
        Ok(DevicesReply {
            devices: self.inner().devices.clone(),
        })
    }

    async fn hold(&self, model: &str, opts: StartOptions) -> Result<ModelStatus, ProtoError> {
        self.start_model(model, opts).await
    }

    async fn release(&self, _model: &str) -> Result<ReleaseReply, ProtoError> {
        Ok(ReleaseReply { released: true })
    }

    async fn start_model(
        &self,
        model: &str,
        opts: StartOptions,
    ) -> Result<ModelStatus, ProtoError> {
        let mut s = self.inner();
        s.calls.push(FakeCall::Start(model.to_string(), opts));
        if s.no_fit.as_deref() == Some(model) && !opts.force && !opts.cpu {
            let mut choices: Vec<_> = s
                .models
                .iter()
                .filter(|m| m.is_running() && m.id != model)
                .map(|m| json!({"kind": "stop_model", "model": m.id, "name": m.name}))
                .collect();
            choices.push(json!({"kind": "cpu"}));
            choices.push(json!({"kind": "start_anyway"}));
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                "It needs about 7.4 GB but only 2.1 GB is free in the memory on RTX 3070 Ti (VRAM).",
            )
            .with_details(json!({
                "reason": "no_fit", "model": model,
                "need_bytes": 7_400_000_000u64, "free_bytes": 2_100_000_000u64,
                "choices": choices,
            })));
        }
        if s.no_fit.as_deref() == Some(model) {
            s.no_fit = None;
        }
        let m = s
            .models
            .iter_mut()
            .find(|m| m.id == model)
            .ok_or_else(|| not_found(model))?;
        m.state = ModelState::Ready;
        m.pinned = true;
        Ok(m.clone())
    }

    async fn stop_model(&self, model: &str) -> Result<StopReply, ProtoError> {
        let mut s = self.inner();
        s.calls.push(FakeCall::Stop(model.to_string()));
        s.no_fit = None; // the memory is free now
        let m = s
            .models
            .iter_mut()
            .find(|m| m.id == model)
            .ok_or_else(|| not_found(model))?;
        let was = m.is_running();
        m.state = ModelState::Stopped;
        m.pinned = false;
        Ok(StopReply { stopped: was })
    }

    async fn autostart(&self) -> Result<AutostartReport, ProtoError> {
        let mut s = self.inner();
        s.calls.push(FakeCall::Autostart);
        let mut report = AutostartReport::default();
        for m in s.models.iter_mut().filter(|m| m.autostart) {
            m.state = ModelState::Ready;
            m.holders += 1;
            report.started.push(m.id.clone());
        }
        Ok(report)
    }

    async fn model_logs(&self, _params: ModelLogsParams) -> Result<LogsReply, ProtoError> {
        Err(ProtoError::new(
            ErrorCode::Unsupported,
            "no logs in the fake",
        ))
    }
}
