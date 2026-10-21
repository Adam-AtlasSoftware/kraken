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

    /// Adds a model the service knows from now on (setup registers one).
    pub fn add_model(&self, status: ModelStatus) {
        self.inner().models.push(status);
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

pub use setup_fake::{FakeSetupProbe, sample_survey};

mod setup_fake {
    //! A scripted [`SetupProbe`]: a survey made of numbers, an install that writes the real
    //! configuration entries into a scratch file and registers the model with a
    //! [`FakeServing`], and a test question that answers.

    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Arc, Mutex, PoisonError};
    use std::time::Duration;

    use async_trait::async_trait;
    use kraken_proto::infer::{DeviceInfo, LocalEngine};
    use kraken_proto::{ErrorCode, ProtoError};
    use kraken_registry::commands::{
        DownloadView, GpuView, LocalFeature, LocalModelRecommendOut, ModelView,
        StrataCandidateView, StrataView,
    };

    use super::{FakeServing, stopped_status};
    use crate::assist::TestReport;
    use crate::infer::setup::{InstallRequest, RawSurvey, SetupProbe};

    const GIB: u64 = 1 << 30;

    /// A computer with the given cards, RAM and free disk, and the first catalog model that
    /// fits suggested; with an NVIDIA card Strata is offered too.
    pub fn sample_survey(devices: Vec<DeviceInfo>, ram_gib: f64, disk_gib: f64) -> RawSurvey {
        let catalog = kraken_infer::model_catalog();
        let suggested = catalog.iter().find(|m| m.id == "qwen3-8b-q4_k_m");
        let llama = LocalModelRecommendOut {
            gpus: devices
                .iter()
                .map(|d| GpuView {
                    vendor: format!("{:?}", d.vendor).to_lowercase(),
                    name: d.name.clone(),
                    vram_gib: Some(d.vram_total as f64 / GIB as f64),
                })
                .collect(),
            ram_gib,
            free_disk_gib: disk_gib,
            cpu_cores: 16,
            engine: "llama-server".into(),
            engine_label: "llama-server (CUDA)".into(),
            gpu_api: "cuda".into(),
            model: suggested.map(ModelView::from),
            download_bytes: suggested.map_or(0, |m| m.size),
            disk_bytes: suggested.map_or(0, |m| m.size),
            reasons: vec!["A card was found.".into()],
            strata: None,
        };
        let strata = LocalModelRecommendOut {
            engine: "strata".into(),
            engine_label: "Strata".into(),
            strata: Some(StrataView {
                candidates: vec![StrataCandidateView {
                    id: "strata-iq1-m".into(),
                    name: "Big mixture-of-experts model".into(),
                    quant: "IQ1_M".into(),
                    min_ram_gib: 32,
                    fit: if ram_gib >= 32.0 {
                        "fits"
                    } else {
                        "below_minimum"
                    }
                    .into(),
                    warnings: vec!["Needs 32 GB of RAM to run well.".into()],
                    speed: "Roughly 3 to 8 words a second on a card with 12 GB.".into(),
                    download_bytes: 60 * GIB,
                    disk_bytes: 90 * GIB,
                    downloads: vec![DownloadView {
                        name: "model".into(),
                        url: "https://example.invalid/m".into(),
                        size_bytes: 60 * GIB,
                        sha256: "00".into(),
                    }],
                }],
                recommended: None,
                missing: Vec::new(),
                notes: Vec::new(),
                revision: "v1".into(),
            }),
            ..llama.clone()
        };
        RawSurvey {
            devices,
            llama,
            strata: Some(strata),
        }
    }

    /// The scripted probe.
    pub struct FakeSetupProbe {
        survey: Mutex<Result<RawSurvey, ProtoError>>,
        serving: Arc<FakeServing>,
        config: PathBuf,
        installs: Mutex<Vec<(String, LocalEngine)>>,
        requests: Mutex<Vec<InstallRequest>>,
        fail_install: Mutex<Option<ProtoError>>,
        fail_test: Mutex<Option<String>>,
        delay: Duration,
        disk: AtomicU64,
    }

    impl FakeSetupProbe {
        /// A probe whose installs write to `config` and register with `serving`.
        pub fn new(survey: RawSurvey, serving: Arc<FakeServing>, config: &Path) -> Self {
            FakeSetupProbe {
                survey: Mutex::new(Ok(survey)),
                serving,
                config: config.to_path_buf(),
                installs: Mutex::default(),
                requests: Mutex::default(),
                fail_install: Mutex::default(),
                fail_test: Mutex::default(),
                delay: Duration::ZERO,
                disk: AtomicU64::new(0),
            }
        }

        /// The download takes this long (and the disk grows meanwhile).
        pub fn slow(mut self, delay: Duration) -> Self {
            self.delay = delay;
            self
        }

        /// The look at the computer fails.
        pub fn fail_survey(&self, message: &str) {
            *self.survey.lock().unwrap_or_else(PoisonError::into_inner) =
                Err(ProtoError::new(ErrorCode::Internal, message));
        }

        /// The next install fails with `e`.
        pub fn fail_install(&self, e: ProtoError) {
            *self
                .fail_install
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(e);
        }

        /// The next test question fails.
        pub fn fail_test(&self, message: &str) {
            *self
                .fail_test
                .lock()
                .unwrap_or_else(PoisonError::into_inner) = Some(message.to_string());
        }

        /// What each install was asked, in order.
        pub fn requests(&self) -> Vec<InstallRequest> {
            self.requests
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        /// Models installed so far.
        pub fn installs(&self) -> Vec<(String, LocalEngine)> {
            self.installs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }
    }

    #[async_trait]
    impl SetupProbe for FakeSetupProbe {
        async fn survey(&self) -> Result<RawSurvey, ProtoError> {
            self.survey
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone()
        }

        async fn install(
            &self,
            id: &str,
            engine: LocalEngine,
            request: &InstallRequest,
        ) -> Result<(), ProtoError> {
            self.requests
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(request.clone());
            if !self.delay.is_zero() {
                for _ in 0..4 {
                    tokio::time::sleep(self.delay / 4).await;
                    self.disk.fetch_add(GIB, Ordering::SeqCst);
                }
            }
            if let Some(e) = self
                .fail_install
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            {
                return Err(e);
            }
            kraken_host::local_models::write_local_provider(
                &self.config,
                id,
                engine,
                Path::new(&format!("/models/{id}.gguf")),
                &[LocalFeature::Assistant],
            )?;
            let mut status = stopped_status(id, id);
            status.engine = Some(engine);
            self.serving.add_model(status);
            self.installs
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push((id.to_string(), engine));
            Ok(())
        }

        fn bytes_on_disk(&self) -> u64 {
            self.disk.load(Ordering::SeqCst)
        }

        async fn test(&self, model: &str) -> Result<TestReport, String> {
            if let Some(e) = self
                .fail_test
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .take()
            {
                return Err(e);
            }
            Ok(TestReport {
                model: model.to_string(),
                reply: "ready".into(),
                millis: 420,
            })
        }
    }
}
