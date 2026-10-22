//! Finding the server of a `local` model (`[provider] kind = "local"`).
//!
//! The assistant and the rewrite pipeline name a model KRAKEN serves; the address and the
//! per-run key change with every start, so each request asks the serving service (the daemon, or
//! the manager of this process when the program registered one with [`set_serving`]). A model
//! that a role uses is held for this process and started on first use if it fits; any other
//! model that is not running gives a plain message that says how to start it.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use kraken_agent::{AgentError, LocalEndpoint, LocalResolver};
use kraken_host::daemon::{DaemonClient, StartOptions as DaemonStart};
use kraken_host::infer::{ModelStatus, ServingApi, StartOptions};
use kraken_ipc::{ClientKind, RuntimeDir};
use kraken_proto::{ErrorCode, ProtoError, infer::ModelState};

const BUILD: &str = env!("CARGO_PKG_VERSION");
const POLL: Duration = Duration::from_millis(500);
/// How long a request waits for a model to finish loading.
const LOAD_TIMEOUT: Duration = Duration::from_secs(15 * 60);

/// A serving service and the number of the connection it is: holds belong to a connection, so
/// a new number means the holds made before are gone.
type Conn = (Arc<dyn ServingApi>, u64);

static SERVING: RwLock<Option<Conn>> = RwLock::new(None);
static DAEMON: tokio::sync::Mutex<Option<(Arc<DaemonClient>, u64)>> =
    tokio::sync::Mutex::const_new(None);
static CONNECTIONS: AtomicU64 = AtomicU64::new(1);

fn next_connection() -> u64 {
    CONNECTIONS.fetch_add(1, Ordering::Relaxed)
}

/// Makes `api` the serving service of this process (the CLI without a daemon, the GUI, tests);
/// `None` goes back to the daemon.
pub fn set_serving(api: Option<Arc<dyn ServingApi>>) {
    *SERVING.write().unwrap_or_else(PoisonError::into_inner) = api.map(|a| (a, next_connection()));
}

fn registered() -> Option<Conn> {
    SERVING
        .read()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
}

/// The shared connection of this process to `krakend`, started when none runs. A model held on
/// it stays held while the process lives.
async fn daemon_api(fresh: bool) -> Result<Conn, AgentError> {
    let mut slot = DAEMON.lock().await;
    if fresh {
        *slot = None;
    }
    if let Some((c, n)) = slot.as_ref() {
        return Ok((c.clone() as Arc<dyn ServingApi>, *n));
    }
    let dir = RuntimeDir::resolve().map_err(|e| {
        AgentError::Config(format!("cannot find the krakend runtime directory: {e}"))
    })?;
    let client =
        DaemonClient::connect_or_start(&dir, ClientKind::Cli, BUILD, &DaemonStart::default())
            .await
            .map_err(|e| {
                AgentError::Config(format!(
                    "cannot reach krakend, which serves the local models: {e}"
                ))
            })?;
    let client = Arc::new(client);
    let n = next_connection();
    *slot = Some((client.clone(), n));
    Ok((client as Arc<dyn ServingApi>, n))
}

/// The models this resolver holds, and the connection the holds were made on.
#[derive(Default)]
struct Held {
    connection: u64,
    models: HashSet<String>,
}

/// Resolves `local` models through the serving service.
#[derive(Default)]
pub struct ServingResolver {
    api: RwLock<Option<Conn>>,
    held: Mutex<Held>,
    /// Context length per model id, from `[[local_models]]`.
    contexts: HashMap<String, u32>,
}

impl ServingResolver {
    /// A resolver for the standard service of this process.
    pub fn new() -> Self {
        let models = kraken_host::KrakenConfig::load()
            .map(|c| c.local_models)
            .unwrap_or_default();
        Self::default().with_contexts(models.iter().map(|m| {
            (
                m.id.clone(),
                m.context_size
                    .unwrap_or(kraken_host::infer::serving::DEFAULT_CONTEXT),
            )
        }))
    }

    /// Sets the context length each model is served with.
    pub fn with_contexts(mut self, contexts: impl IntoIterator<Item = (String, u32)>) -> Self {
        self.contexts = contexts.into_iter().collect();
        self
    }

    /// A resolver that always asks `api`.
    pub fn with_api(api: Arc<dyn ServingApi>) -> Self {
        Self {
            api: RwLock::new(Some((api, next_connection()))),
            held: Mutex::default(),
            contexts: HashMap::new(),
        }
    }

    /// The service to ask. When it is another connection than the one the holds were made on
    /// (the daemon connection was replaced after it died, or the program registered another
    /// service), those holds ended with the old connection: they are forgotten, so the role
    /// models are held again on this one.
    async fn api(&self, fresh: bool) -> Result<Arc<dyn ServingApi>, AgentError> {
        let fixed = self
            .api
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let (api, connection) = match fixed {
            Some(c) => c,
            None => match registered() {
                Some(c) => c,
                None => daemon_api(fresh).await?,
            },
        };
        let mut held = self.held.lock().unwrap_or_else(PoisonError::into_inner);
        if held.connection != connection {
            held.models.clear();
            held.connection = connection;
        }
        Ok(api)
    }

    async fn status(&self, model: &str) -> Result<ModelStatus, AgentError> {
        let reply = match self.api(false).await?.models().await {
            Ok(r) => r,
            Err(first) if first.code == ErrorCode::Internal || first.code == ErrorCode::Timeout => {
                // The connection may have died: one fresh try.
                self.api(true)
                    .await?
                    .models()
                    .await
                    .map_err(|e| AgentError::Transport(e.message))?
            }
            Err(e) => return Err(AgentError::Config(e.message)),
        };
        reply
            .models
            .into_iter()
            .find(|m| m.id == model)
            .ok_or_else(|| AgentError::ModelNotRunning {
                model: model.to_string(),
                message: format!(
                    "There is no local model called `{model}`. See the ones you have with \
                     `kraken local-model-list`, or set one up in Settings."
                ),
            })
    }

    fn is_held(&self, model: &str) -> bool {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .models
            .contains(model)
    }

    fn mark_held(&self, model: &str) -> bool {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .models
            .insert(model.to_string())
    }

    fn forget_hold(&self, model: &str) {
        self.held
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .models
            .remove(model);
    }

    async fn start(&self, model: &str) -> Result<(), AgentError> {
        let api = self.api(false).await?;
        match api.hold(model, StartOptions::default()).await {
            Ok(_) => {
                self.mark_held(model);
                Ok(())
            }
            Err(e) => Err(AgentError::ModelNotRunning {
                model: model.to_string(),
                message: start_refusal(model, &e),
            }),
        }
    }
}

/// A refused start in words, with what to do next.
fn start_refusal(model: &str, e: &ProtoError) -> String {
    let reason = e.details.as_ref().and_then(|d| d["reason"].as_str());
    if reason == Some("no_fit") {
        return format!(
            "`{model}` is not running and does not fit in memory right now: {} Stop another \
             model (`kraken local-model-stop <id>`), run it on the processor \
             (`kraken local-model-start {model} --cpu`), or start it anyway \
             (`kraken local-model-start {model} --force`).",
            e.message
        );
    }
    format!("`{model}` could not be started: {}", e.message)
}

fn not_running(model: &str, why: &str) -> AgentError {
    AgentError::ModelNotRunning {
        model: model.to_string(),
        message: format!(
            "The local model `{model}` {why}. Start it with `kraken local-model-start {model}` \
             (or `kraken infer start {model}`), or press Start serving in Settings."
        ),
    }
}

#[async_trait]
impl LocalResolver for ServingResolver {
    fn context_window(&self, model: &str) -> Option<u32> {
        self.contexts.get(model).copied()
    }

    async fn resolve(&self, model: &str) -> Result<LocalEndpoint, AgentError> {
        let deadline = Instant::now() + LOAD_TIMEOUT;
        let mut tried_start = false;
        loop {
            let st = self.status(model).await?;
            match &st.state {
                ModelState::Ready => {
                    if let (Some(base_url), Some(served)) = (&st.base_url, &st.served_model) {
                        if st.role_assigned && !self.is_held(model) {
                            self.start(model).await?;
                        }
                        return Ok(LocalEndpoint {
                            base_url: base_url.clone(),
                            served_model: served.clone(),
                            api_key: st.api_key.clone(),
                        });
                    }
                }
                ModelState::Loading | ModelState::Stopping => {}
                ModelState::Stopped | ModelState::Failed { .. } => {
                    self.forget_hold(model);
                    if !st.role_assigned {
                        let why = match &st.state {
                            ModelState::Failed { message } => format!("stopped: {message}"),
                            _ => "is not running".to_string(),
                        };
                        return Err(not_running(model, &why));
                    }
                    if tried_start {
                        let why = match &st.state {
                            ModelState::Failed { message } => message.clone(),
                            _ => "stopped again right after it was started".to_string(),
                        };
                        return Err(AgentError::ModelNotRunning {
                            model: model.to_string(),
                            message: format!("`{model}` could not be started: {why}"),
                        });
                    }
                    tried_start = true;
                    self.start(model).await?;
                }
            }
            if Instant::now() >= deadline {
                return Err(not_running(model, "is still loading after 15 minutes"));
            }
            tokio::time::sleep(POLL).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_host::infer::{
        AutostartReport, DevicesReply, ModelLogsParams, ModelsReply, ReleaseReply,
    };
    use kraken_host::infer::{LogsReply, StopReply};

    struct Fake {
        models: Mutex<Vec<ModelStatus>>,
        holds: Mutex<Vec<String>>,
        refuse: Option<ProtoError>,
    }

    fn status(id: &str, state: ModelState, role: bool) -> ModelStatus {
        ModelStatus {
            id: id.into(),
            name: id.into(),
            engine: None,
            state,
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
            role_assigned: role,
            autostart: true,
        }
    }

    impl Fake {
        fn new(models: Vec<ModelStatus>, refuse: Option<ProtoError>) -> Arc<Self> {
            Arc::new(Fake {
                models: Mutex::new(models),
                holds: Mutex::default(),
                refuse,
            })
        }
    }

    #[async_trait]
    impl ServingApi for Fake {
        async fn models(&self) -> Result<ModelsReply, ProtoError> {
            Ok(ModelsReply {
                models: self.models.lock().unwrap().clone(),
                grace_secs: 120,
            })
        }
        async fn devices(&self) -> Result<DevicesReply, ProtoError> {
            Ok(DevicesReply { devices: vec![] })
        }
        async fn hold(&self, model: &str, _: StartOptions) -> Result<ModelStatus, ProtoError> {
            if let Some(e) = &self.refuse {
                return Err(e.clone());
            }
            self.holds.lock().unwrap().push(model.into());
            let mut all = self.models.lock().unwrap();
            let m = all.iter_mut().find(|m| m.id == model).unwrap();
            m.state = ModelState::Ready;
            m.base_url = Some("http://127.0.0.1:5000/v1".into());
            m.served_model = Some("served.gguf".into());
            m.api_key = Some("run-key".into());
            Ok(m.clone())
        }
        async fn release(&self, _: &str) -> Result<ReleaseReply, ProtoError> {
            Ok(ReleaseReply { released: true })
        }
        async fn start_model(&self, m: &str, o: StartOptions) -> Result<ModelStatus, ProtoError> {
            self.hold(m, o).await
        }
        async fn stop_model(&self, _: &str) -> Result<StopReply, ProtoError> {
            Ok(StopReply { stopped: true })
        }
        async fn autostart(&self) -> Result<AutostartReport, ProtoError> {
            Ok(AutostartReport::default())
        }
        async fn model_logs(&self, _: ModelLogsParams) -> Result<LogsReply, ProtoError> {
            Ok(LogsReply {
                lines: vec![],
                last_seq: 0,
            })
        }
    }

    #[tokio::test]
    async fn a_role_model_that_is_stopped_is_started_on_first_use() {
        let fake = Fake::new(vec![status("qwen", ModelState::Stopped, true)], None);
        let r = ServingResolver::with_api(fake.clone());
        let ep = r.resolve("qwen").await.expect("started and resolved");
        assert_eq!(ep.base_url, "http://127.0.0.1:5000/v1");
        assert_eq!(ep.served_model, "served.gguf");
        assert_eq!(ep.api_key.as_deref(), Some("run-key"));
        assert_eq!(*fake.holds.lock().unwrap(), vec!["qwen".to_string()]);
        // A second request does not hold again.
        r.resolve("qwen").await.expect("still ready");
        assert_eq!(fake.holds.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn role_models_are_held_again_on_a_new_connection() {
        let mut ready = status("qwen", ModelState::Ready, true);
        ready.base_url = Some("http://127.0.0.1:5000/v1".into());
        ready.served_model = Some("served.gguf".into());
        let first = Fake::new(vec![ready.clone()], None);
        let r = ServingResolver::with_api(first.clone());
        r.resolve("qwen").await.expect("ready");
        r.resolve("qwen").await.expect("ready");
        assert_eq!(first.holds.lock().unwrap().len(), 1, "held once");
        // The connection died and was replaced: its holds went with it.
        let second = Fake::new(vec![ready], None);
        *r.api.write().unwrap() = Some((second.clone(), next_connection()));
        r.resolve("qwen").await.expect("ready");
        assert_eq!(
            *second.holds.lock().unwrap(),
            vec!["qwen".to_string()],
            "held again on the new connection"
        );
        r.resolve("qwen").await.expect("ready");
        assert_eq!(second.holds.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn a_model_no_role_uses_is_not_started() {
        let fake = Fake::new(vec![status("side", ModelState::Stopped, false)], None);
        let r = ServingResolver::with_api(fake.clone());
        let e = r.resolve("side").await.expect_err("not running");
        match e {
            AgentError::ModelNotRunning { model, message } => {
                assert_eq!(model, "side");
                assert!(
                    message.contains("kraken local-model-start side"),
                    "{message}"
                );
            }
            other => panic!("{other:?}"),
        }
        assert!(fake.holds.lock().unwrap().is_empty());
        let e = r.resolve("nope").await.expect_err("unknown");
        assert!(matches!(e, AgentError::ModelNotRunning { .. }));
    }

    #[tokio::test]
    async fn a_start_that_does_not_fit_says_what_to_do() {
        let no_fit = ProtoError::new(ErrorCode::Unsupported, "Qwen needs about 9 GiB")
            .with_details(serde_json::json!({"reason": "no_fit"}));
        let fake = Fake::new(
            vec![status("qwen", ModelState::Stopped, true)],
            Some(no_fit),
        );
        let e = ServingResolver::with_api(fake)
            .resolve("qwen")
            .await
            .expect_err("does not fit");
        let AgentError::ModelNotRunning { message, .. } = e else {
            panic!("wrong error");
        };
        assert!(
            message.contains("--cpu") && message.contains("--force"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn a_running_model_is_used_as_it_is() {
        let mut running = status("side", ModelState::Ready, false);
        running.base_url = Some("http://127.0.0.1:7/v1".into());
        running.served_model = Some("m".into());
        let fake = Fake::new(vec![running], None);
        let ep = ServingResolver::with_api(fake.clone())
            .resolve("side")
            .await
            .expect("ready");
        assert_eq!(ep.base_url, "http://127.0.0.1:7/v1");
        assert!(fake.holds.lock().unwrap().is_empty());
    }

    #[test]
    fn context_window_comes_from_the_model_card() {
        let r = ServingResolver::with_api(Fake::new(vec![], None))
            .with_contexts([("qwen".to_string(), 32_768)]);
        assert_eq!(r.context_window("qwen"), Some(32_768));
        assert_eq!(r.context_window("other"), None);
    }
}
