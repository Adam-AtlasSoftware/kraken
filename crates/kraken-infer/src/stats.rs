//! Live figures of served models: words per second from the engine's own metrics, card memory
//! per process, RAM over the process tree, all sampled by one shared timer.
//!
//! The parsers ([`StrataStats`], [`LlamaStats`]) and the `/proc`, `nvidia-smi` and `rocm-smi`
//! readers are plain functions over text so they can be tested on recorded payloads;
//! [`StatsSampler`] ties them together through a [`SamplerEnv`].

use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use kraken_proto::infer::{DeviceRef, DeviceVram, GpuVendor, ModelState, ModelStats, TokSource};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

use crate::port::LOOPBACK;

#[derive(Debug, thiserror::Error)]
pub enum StatsError {
    #[error("metrics are not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("metrics text has no figures: {0}")]
    Empty(&'static str),
}

/// Memory in use on one card as the engine sees it (the whole card, not only this model).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CardMemory {
    /// The card's number; `None` when the engine reports a single total.
    pub index: Option<u32>,
    pub used: u64,
    pub total: Option<u64>,
}

/// What one scrape of an engine's metrics says.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EngineReading {
    /// Words per second right now; `None` while nothing is being generated.
    pub tok_s: Option<f32>,
    pub cards: Vec<CardMemory>,
}

/// A parser of one engine's metrics endpoint. It may keep the previous scrape (counters).
pub trait EngineStats: Send {
    /// The path to GET on the engine's port.
    fn path(&self) -> &'static str;
    fn ingest(&mut self, body: &str) -> Result<EngineReading, StatsError>;
}

/// Strata's `GET /metrics` JSON: `live.tok_s` while generating, the `hardware` block for cards.
#[derive(Debug, Default)]
pub struct StrataStats;

impl EngineStats for StrataStats {
    fn path(&self) -> &'static str {
        "/metrics"
    }

    fn ingest(&mut self, body: &str) -> Result<EngineReading, StatsError> {
        let v: Value = serde_json::from_str(body)?;
        let tok_s = v["live"]["tok_s"].as_f64().map(|t| t as f32);
        let hw = &v["hardware"];
        let mut cards = Vec::new();
        if let Some(list) = hw["gpus"].as_array() {
            for g in list {
                if let Some(used) = g["mem_used"].as_u64() {
                    cards.push(CardMemory {
                        index: g["index"].as_u64().map(|i| i as u32),
                        used,
                        total: g["mem_total"].as_u64(),
                    });
                }
            }
        } else if let Some(used) = hw["gpu_mem_used"].as_u64() {
            cards.push(CardMemory {
                index: None,
                used,
                total: hw["gpu_mem_total"].as_u64(),
            });
        }
        Ok(EngineReading { tok_s, cards })
    }
}

/// llama-server's Prometheus text (`--metrics`). Words per second are the change of
/// `tokens_predicted_total` over the change of `tokens_predicted_seconds_total` between two
/// scrapes: the engine's own gauge is averaged over a window it resets on every scrape.
#[derive(Debug, Default)]
pub struct LlamaStats {
    prev: Option<(f64, f64)>,
}

impl EngineStats for LlamaStats {
    fn path(&self) -> &'static str {
        "/metrics"
    }

    fn ingest(&mut self, body: &str) -> Result<EngineReading, StatsError> {
        let m = parse_prometheus(body);
        let (Some(&n), Some(&s)) = (
            m.get("llamacpp:tokens_predicted_total"),
            m.get("llamacpp:tokens_predicted_seconds_total"),
        ) else {
            return Err(StatsError::Empty("llamacpp:tokens_predicted_total"));
        };
        let tok_s = match self.prev {
            Some((pn, ps)) if n >= pn && s >= ps && s > ps && n > pn => {
                Some(((n - pn) / (s - ps)) as f32)
            }
            _ => None,
        };
        self.prev = Some((n, s));
        Ok(EngineReading {
            tok_s,
            cards: Vec::new(),
        })
    }
}

/// Samples of a Prometheus text exposition, by metric name (labels dropped, last one wins).
pub fn parse_prometheus(text: &str) -> HashMap<String, f64> {
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((name, rest)) = line.split_once([' ', '{']) else {
            continue;
        };
        let value = rest.rsplit(' ').next().unwrap_or("");
        if let Ok(v) = value.parse::<f64>() {
            out.insert(name.to_string(), v);
        }
    }
    out
}

/// Words per second measured by KRAKEN from the replies it saw, over the last few of them.
#[derive(Debug, Default)]
pub struct ApproxMeter {
    replies: VecDeque<(u64, f64)>,
}

impl ApproxMeter {
    const KEEP: usize = 8;

    pub fn record(&mut self, tokens: u64, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        if tokens == 0 || secs <= 0.0 {
            return;
        }
        if self.replies.len() == Self::KEEP {
            self.replies.pop_front();
        }
        self.replies.push_back((tokens, secs));
    }

    pub fn tok_s(&self) -> Option<f32> {
        let (n, s) = self
            .replies
            .iter()
            .fold((0u64, 0f64), |(n, s), (t, d)| (n + t, s + d));
        (s > 0.0).then(|| (n as f64 / s) as f32)
    }
}

/// A process using card memory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuProcUse {
    pub pid: u32,
    /// The card's UUID; `None` when the tool does not say which card.
    pub uuid: Option<String>,
    pub vendor: GpuVendor,
    pub bytes: u64,
}

/// The output of `nvidia-smi --query-compute-apps=pid,gpu_uuid,used_memory --format=csv,noheader,nounits`
/// (memory in MiB).
pub fn parse_nvidia_compute_apps(csv: &str) -> Vec<GpuProcUse> {
    csv.lines()
        .filter_map(|l| {
            let mut f = l.split(',').map(str::trim);
            let pid = f.next()?.parse().ok()?;
            let uuid = f.next()?.to_string();
            let mib: u64 = f.next()?.parse().ok()?;
            Some(GpuProcUse {
                pid,
                uuid: Some(uuid),
                vendor: GpuVendor::Nvidia,
                bytes: mib * 1024 * 1024,
            })
        })
        .collect()
}

/// The output of `rocm-smi --showpids --json`: `"PID<n>": "name, processes, vram bytes, ..."`.
/// It does not say which card.
pub fn parse_rocm_pids(json: &str) -> Vec<GpuProcUse> {
    let Ok(v) = serde_json::from_str::<Value>(json) else {
        return Vec::new();
    };
    let Some(map) = v["system"].as_object() else {
        return Vec::new();
    };
    map.iter()
        .filter_map(|(k, val)| {
            let pid = k.strip_prefix("PID")?.parse().ok()?;
            let bytes = val.as_str()?.split(',').nth(2)?.trim().parse().ok()?;
            Some(GpuProcUse {
                pid,
                uuid: None,
                vendor: GpuVendor::Amd,
                bytes,
            })
        })
        .collect()
}

fn ppid_of_stat(stat: &str) -> Option<u32> {
    let after = &stat[stat.rfind(')')? + 1..];
    after.split_whitespace().nth(1)?.parse().ok()
}

fn rss_of_status(status: &str) -> u64 {
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|r| r.split_whitespace().next()?.parse::<u64>().ok())
        .map_or(0, |kb| kb * 1024)
}

/// `pid` and all its descendants, read from a `/proc`-shaped directory.
pub fn process_tree(proc_root: &Path, pid: u32) -> Vec<u32> {
    let mut children: HashMap<u32, Vec<u32>> = HashMap::new();
    if let Ok(rd) = std::fs::read_dir(proc_root) {
        for e in rd.flatten() {
            let Some(p) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else {
                continue;
            };
            if let Some(pp) = std::fs::read_to_string(e.path().join("stat"))
                .ok()
                .and_then(|s| ppid_of_stat(&s))
            {
                children.entry(pp).or_default().push(p);
            }
        }
    }
    let mut out = vec![pid];
    let mut i = 0;
    while i < out.len() {
        if let Some(kids) = children.get(&out[i]) {
            let fresh: Vec<u32> = kids.iter().copied().filter(|k| !out.contains(k)).collect();
            out.extend(fresh);
        }
        i += 1;
    }
    out
}

/// Resident memory summed over `pids`, in bytes.
pub fn rss_sum(proc_root: &Path, pids: &[u32]) -> u64 {
    pids.iter()
        .filter_map(|p| std::fs::read_to_string(proc_root.join(p.to_string()).join("status")).ok())
        .map(|s| rss_of_status(&s))
        .sum()
}

/// What the sampler needs from the outside, replaceable in tests.
#[async_trait]
pub trait SamplerEnv: Send + Sync {
    /// Body of `GET path` on the engine's port, sent with `Authorization: Bearer <bearer>` when
    /// the engine needs its per-run key; `None` when it does not answer 200.
    async fn http_get(&self, port: u16, path: &str, bearer: Option<&str>) -> Option<String>;
    /// Card memory per process, all vendors.
    async fn gpu_apps(&self) -> Vec<GpuProcUse>;
    /// The process and its descendants, and their summed RAM.
    fn tree(&self, pid: u32) -> (Vec<u32>, u64);
}

/// The real thing: loopback HTTP, `nvidia-smi` and `rocm-smi`, `/proc`.
#[derive(Debug, Default)]
pub struct SystemEnv;

#[async_trait]
impl SamplerEnv for SystemEnv {
    async fn http_get(&self, port: u16, path: &str, bearer: Option<&str>) -> Option<String> {
        let fut = async {
            let mut s = TcpStream::connect((LOOPBACK, port)).await.ok()?;
            let auth = bearer.map_or(String::new(), |k| format!("Authorization: Bearer {k}\r\n"));
            let req = format!(
                "GET {path} HTTP/1.1\r\nHost: {LOOPBACK}\r\n{auth}Connection: close\r\n\r\n"
            );
            s.write_all(req.as_bytes()).await.ok()?;
            let mut raw = Vec::new();
            s.take(4 << 20).read_to_end(&mut raw).await.ok()?;
            let text = String::from_utf8_lossy(&raw).into_owned();
            let (head, body) = text.split_once("\r\n\r\n")?;
            let status: u16 = head.split(' ').nth(1)?.parse().ok()?;
            (status == 200).then(|| body.to_string())
        };
        tokio::time::timeout(Duration::from_secs(2), fut)
            .await
            .ok()
            .flatten()
    }

    async fn gpu_apps(&self) -> Vec<GpuProcUse> {
        tokio::task::spawn_blocking(|| {
            let mut out = Vec::new();
            if let Some(t) = run_capture(
                "nvidia-smi",
                &[
                    "--query-compute-apps=pid,gpu_uuid,used_memory",
                    "--format=csv,noheader,nounits",
                ],
            ) {
                out.extend(parse_nvidia_compute_apps(&t));
            }
            if let Some(t) = run_capture("rocm-smi", &["--showpids", "--json"]) {
                out.extend(parse_rocm_pids(&t));
            }
            out
        })
        .await
        .unwrap_or_default()
    }

    fn tree(&self, pid: u32) -> (Vec<u32>, u64) {
        let root = Path::new("/proc");
        let pids = process_tree(root, pid);
        let rss = rss_sum(root, &pids);
        (pids, rss)
    }
}

/// Runs a tool and returns its stdout, giving up (and killing it) after 5 seconds; a broken
/// driver can make `nvidia-smi` hang.
fn run_capture(program: &str, args: &[&str]) -> Option<String> {
    use std::io::Read;
    use std::process::{Command, Stdio};
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let mut stdout = child.stdout.take()?;
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut s = String::new();
        let _ = stdout.read_to_string(&mut s);
        let _ = tx.send(s);
    });
    match rx.recv_timeout(Duration::from_secs(5)) {
        Ok(s) => {
            let ok = child.wait().is_ok_and(|st| st.success());
            ok.then_some(s)
        }
        Err(_) => {
            let _ = child.kill();
            let _ = child.wait();
            None
        }
    }
}

/// Which parser reads a model's engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatsKind {
    Strata,
    Llama,
}

/// A running (or starting) model to watch.
#[derive(Clone)]
pub struct Target {
    pub model: String,
    pub kind: StatsKind,
    pub port: u16,
    pub pid: Option<u32>,
    /// The cards it runs on; used to name the rows of card memory.
    pub devices: Vec<DeviceRef>,
    /// The per-run key the engine requires (llama-server started with `LLAMA_API_KEY` answers
    /// `/metrics` with 401 without it). Never logged: `Debug` hides it.
    pub api_key: Option<String>,
}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Target")
            .field("model", &self.model)
            .field("kind", &self.kind)
            .field("port", &self.port)
            .field("pid", &self.pid)
            .field("devices", &self.devices)
            .field("api_key", &self.api_key.as_ref().map(|_| "<hidden>"))
            .finish()
    }
}

struct Entry {
    target: Target,
    parser: SharedParser,
    approx: ApproxMeter,
    stats: ModelStats,
    engine_tok_s: Option<f32>,
    /// The latest scrape of the engine's metrics answered: its figure (or its silence while
    /// idle) wins over the one KRAKEN measured.
    engine_reports: bool,
}

type SharedParser = Arc<Mutex<Box<dyn EngineStats>>>;
type Table = Arc<Mutex<HashMap<String, Entry>>>;

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// One sampler for all models: a single timer, one `nvidia-smi` call per tick.
pub struct StatsSampler {
    env: Arc<dyn SamplerEnv>,
    table: Table,
    task: Mutex<Option<JoinHandle<()>>>,
}

impl StatsSampler {
    /// A sampler that is only ticked by hand ([`tick`](Self::tick)).
    pub fn new(env: Arc<dyn SamplerEnv>) -> Arc<Self> {
        Arc::new(Self {
            env,
            table: Arc::default(),
            task: Mutex::new(None),
        })
    }

    /// A sampler that ticks every `interval` on the current tokio runtime until dropped.
    pub fn spawn(env: Arc<dyn SamplerEnv>, interval: Duration) -> Arc<Self> {
        let s = Self::new(env);
        let weak = Arc::downgrade(&s);
        let handle = tokio::spawn(async move {
            let mut t = tokio::time::interval(interval);
            t.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                t.tick().await;
                let Some(s) = weak.upgrade() else { break };
                s.tick().await;
            }
        });
        *lock(&s.task) = Some(handle);
        s
    }

    pub fn register(&self, target: Target) {
        let parser: Box<dyn EngineStats> = match target.kind {
            StatsKind::Strata => Box::new(StrataStats),
            StatsKind::Llama => Box::<LlamaStats>::default(),
        };
        let stats = ModelStats {
            model: target.model.clone(),
            phase: ModelState::Loading,
            load_fraction: None,
            vram_per_device: Vec::new(),
            ram_bytes: 0,
            tok_s: None,
            tok_s_source: None,
            devices: target.devices.clone(),
        };
        lock(&self.table).insert(
            target.model.clone(),
            Entry {
                target,
                parser: Arc::new(Mutex::new(parser)),
                approx: ApproxMeter::default(),
                stats,
                engine_tok_s: None,
                engine_reports: false,
            },
        );
    }

    pub fn unregister(&self, model: &str) {
        lock(&self.table).remove(model);
    }

    pub fn set_pid(&self, model: &str, pid: Option<u32>) {
        if let Some(e) = lock(&self.table).get_mut(model) {
            e.target.pid = pid;
        }
    }

    /// The model's phase and loading progress, as the supervisor knows them.
    pub fn set_phase(&self, model: &str, phase: ModelState, load_fraction: Option<f32>) {
        if let Some(e) = lock(&self.table).get_mut(model) {
            e.stats.phase = phase;
            e.stats.load_fraction = load_fraction;
        }
    }

    /// A reply KRAKEN saw: used for the figure when the engine reports none.
    pub fn record_reply(&self, model: &str, tokens: u64, elapsed: Duration) {
        if let Some(e) = lock(&self.table).get_mut(model) {
            e.approx.record(tokens, elapsed);
            refresh_tok_s(e);
        }
    }

    pub fn snapshot(&self, model: &str) -> Option<ModelStats> {
        lock(&self.table).get(model).map(|e| e.stats.clone())
    }

    pub fn snapshots(&self) -> Vec<ModelStats> {
        let mut v: Vec<_> = lock(&self.table)
            .values()
            .map(|e| e.stats.clone())
            .collect();
        v.sort_by(|a, b| a.model.cmp(&b.model));
        v
    }

    /// One round: read every model's engine metrics, card memory and RAM.
    pub async fn tick(&self) {
        let work: Vec<(Target, SharedParser, bool)> = lock(&self.table)
            .values()
            .map(|e| {
                (
                    e.target.clone(),
                    Arc::clone(&e.parser),
                    e.stats.phase == ModelState::Ready,
                )
            })
            .collect();
        if work.is_empty() {
            return;
        }
        let apps = if work.iter().any(|(t, ..)| t.pid.is_some()) {
            self.env.gpu_apps().await
        } else {
            Vec::new()
        };
        for (target, parser, ready) in work {
            let reading = if ready {
                let path = lock(&parser).path();
                match self
                    .env
                    .http_get(target.port, path, target.api_key.as_deref())
                    .await
                {
                    Some(body) => lock(&parser).ingest(&body).ok(),
                    None => None,
                }
            } else {
                None
            };
            let (pids, ram) = target.pid.map_or((Vec::new(), 0), |p| self.env.tree(p));
            let vram = vram_rows(&target, &pids, &apps);
            let mut table = lock(&self.table);
            let Some(e) = table.get_mut(&target.model) else {
                continue;
            };
            e.stats.ram_bytes = ram;
            if !vram.is_empty() {
                e.stats.vram_per_device = vram;
            } else if let Some(r) = &reading {
                e.stats.vram_per_device = engine_card_rows(&target, r);
            }
            // An engine that answers without a figure is idle: nothing is shown until it
            // generates again, rather than the last speed forever.
            e.engine_reports = reading.is_some();
            e.engine_tok_s = reading.and_then(|r| r.tok_s);
            refresh_tok_s(e);
        }
    }
}

impl Drop for StatsSampler {
    fn drop(&mut self) {
        if let Some(h) = lock(&self.task).take() {
            h.abort();
        }
    }
}

fn refresh_tok_s(e: &mut Entry) {
    let (tok_s, source) = match (e.engine_tok_s, e.engine_reports) {
        (Some(t), _) => (Some(t), Some(TokSource::Engine)),
        (None, true) => (None, None),
        (None, false) => match e.approx.tok_s() {
            Some(t) => (Some(t), Some(TokSource::Approx)),
            None => (None, None),
        },
    };
    e.stats.tok_s = tok_s;
    e.stats.tok_s_source = source;
}

fn device_for(target: &Target, uuid: Option<&str>, vendor: GpuVendor) -> Option<DeviceRef> {
    match uuid {
        Some(u) => Some(
            target
                .devices
                .iter()
                .find(|d| d.uuid == u)
                .cloned()
                .unwrap_or_else(|| DeviceRef {
                    uuid: u.to_string(),
                    index: 0,
                    vendor,
                }),
        ),
        None => {
            let mut same = target.devices.iter().filter(|d| d.vendor == vendor);
            match (same.next(), same.next()) {
                (Some(d), None) => Some(d.clone()),
                _ => None,
            }
        }
    }
}

fn vram_rows(target: &Target, pids: &[u32], apps: &[GpuProcUse]) -> Vec<DeviceVram> {
    let tree: HashSet<u32> = pids.iter().copied().collect();
    let mut rows: Vec<DeviceVram> = Vec::new();
    for a in apps.iter().filter(|a| tree.contains(&a.pid)) {
        let Some(device) = device_for(target, a.uuid.as_deref(), a.vendor) else {
            continue;
        };
        match rows.iter_mut().find(|r| r.device.uuid == device.uuid) {
            Some(r) => r.bytes += a.bytes,
            None => rows.push(DeviceVram {
                device,
                bytes: a.bytes,
            }),
        }
    }
    rows
}

/// Card memory from the engine's own report (whole-card figures), matched by index.
fn engine_card_rows(target: &Target, r: &EngineReading) -> Vec<DeviceVram> {
    r.cards
        .iter()
        .filter_map(|c| {
            let device = match c.index {
                Some(i) => target.devices.iter().find(|d| d.index == i).cloned()?,
                None if target.devices.len() == 1 => target.devices[0].clone(),
                None => return None,
            };
            Some(DeviceVram {
                device,
                bytes: c.used,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENERATING: &str = include_str!("../tests/fixtures/stats/strata-metrics-generating.json");
    const IDLE: &str = include_str!("../tests/fixtures/stats/strata-metrics-idle.json");
    const PROM1: &str = include_str!("../tests/fixtures/stats/llama-prometheus-1.txt");
    const PROM2: &str = include_str!("../tests/fixtures/stats/llama-prometheus-2.txt");
    const NVIDIA: &str = include_str!("../tests/fixtures/stats/nvidia-compute-apps.csv");
    const ROCM: &str = include_str!("../tests/fixtures/stats/rocm-showpids.json");

    fn dev(uuid: &str, index: u32, vendor: GpuVendor) -> DeviceRef {
        DeviceRef {
            uuid: uuid.into(),
            index,
            vendor,
        }
    }

    #[test]
    fn strata_generating_has_rate_and_cards() {
        let r = StrataStats.ingest(GENERATING).expect("parses");
        assert_eq!(r.tok_s, Some(31.4));
        assert_eq!(r.cards.len(), 2);
        assert_eq!(r.cards[1].index, Some(2));
        assert_eq!(r.cards[1].used, 10_737_418_240);
    }

    #[test]
    fn strata_idle_has_no_rate_and_one_total() {
        let r = StrataStats.ingest(IDLE).expect("parses");
        assert_eq!(r.tok_s, None);
        assert_eq!(
            r.cards,
            vec![CardMemory {
                index: None,
                used: 20_401_094_656,
                total: Some(25_769_803_776)
            }]
        );
        assert!(StrataStats.ingest("not json").is_err());
    }

    #[test]
    fn llama_rate_comes_from_counter_deltas() {
        let mut p = LlamaStats::default();
        assert_eq!(p.ingest(PROM1).expect("first").tok_s, None);
        // 450 tokens in 10 seconds
        assert_eq!(p.ingest(PROM2).expect("second").tok_s, Some(45.0));
        // nothing new generated: no rate
        assert_eq!(p.ingest(PROM2).expect("third").tok_s, None);
        // counters went backwards (server restarted): start over
        assert_eq!(p.ingest(PROM1).expect("fourth").tok_s, None);
        assert!(p.ingest("# nothing\n").is_err());
    }

    #[test]
    fn prometheus_text_parses_with_labels() {
        let m = parse_prometheus("a_total 3\n# c\nb{x=\"1\"} 2.5\nbad\n");
        assert_eq!(m["a_total"], 3.0);
        assert_eq!(m["b"], 2.5);
    }

    #[test]
    fn approx_meter_averages_the_last_replies() {
        let mut m = ApproxMeter::default();
        assert_eq!(m.tok_s(), None);
        m.record(100, Duration::from_secs(4));
        m.record(100, Duration::from_secs(6));
        m.record(0, Duration::from_secs(1));
        assert_eq!(m.tok_s(), Some(20.0));
    }

    #[test]
    fn nvidia_and_rocm_process_tables_parse() {
        let n = parse_nvidia_compute_apps(NVIDIA);
        assert_eq!(n.len(), 3);
        assert_eq!(n[0].bytes, 12288 * 1024 * 1024);
        assert_eq!(
            n[1].uuid.as_deref(),
            Some("GPU-9a8b7c6d-0000-1111-2222-666677778888")
        );
        let r = parse_rocm_pids(ROCM);
        assert_eq!(r.len(), 2);
        let llama = r.iter().find(|p| p.pid == 31337).expect("llama row");
        assert_eq!(llama.bytes, 8 << 30);
        assert!(parse_rocm_pids("garbage").is_empty());
    }

    fn fake_proc() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("kraken-proc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // 100 -> 101 -> 102; 200 unrelated; the comm of 101 contains ") 9 (".
        for (pid, comm, ppid, kb) in [
            (100, "engine", 1, 1000),
            (101, "py) 9 (x", 100, 2000),
            (102, "worker", 101, 4000),
            (200, "other", 1, 8000),
        ] {
            let d = root.join(pid.to_string());
            std::fs::create_dir_all(&d).expect("mkdir");
            std::fs::write(d.join("stat"), format!("{pid} ({comm}) S {ppid} 0 0\n")).expect("stat");
            std::fs::write(d.join("status"), format!("Name:\tx\nVmRSS:\t{kb} kB\n"))
                .expect("status");
        }
        std::fs::create_dir_all(root.join("self")).expect("self");
        root
    }

    #[test]
    fn ram_is_summed_over_the_process_tree() {
        let root = fake_proc();
        let mut tree = process_tree(&root, 100);
        tree.sort_unstable();
        assert_eq!(tree, vec![100, 101, 102]);
        assert_eq!(rss_sum(&root, &tree), 7000 * 1024);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn real_proc_reports_this_process() {
        let me = std::process::id();
        let (pids, rss) = SystemEnv.tree(me);
        assert!(pids.contains(&me));
        assert!(rss > 0);
    }

    #[derive(Default)]
    struct FakeEnv {
        body: Mutex<Option<String>>,
        apps: Vec<GpuProcUse>,
        bearer: Mutex<Option<String>>,
    }

    #[async_trait]
    impl SamplerEnv for FakeEnv {
        async fn http_get(&self, _: u16, _: &str, bearer: Option<&str>) -> Option<String> {
            *lock(&self.bearer) = bearer.map(str::to_string);
            lock(&self.body).clone()
        }
        async fn gpu_apps(&self) -> Vec<GpuProcUse> {
            self.apps.clone()
        }
        fn tree(&self, pid: u32) -> (Vec<u32>, u64) {
            (vec![pid, pid + 1], 5 << 20)
        }
    }

    fn target(kind: StatsKind, devices: Vec<DeviceRef>) -> Target {
        Target {
            model: "m".into(),
            kind,
            port: 1,
            pid: Some(12345),
            devices,
            api_key: None,
        }
    }

    #[tokio::test]
    async fn sampler_combines_engine_card_and_proc_figures() {
        let a = dev(
            "GPU-1b2c3d4e-0000-1111-2222-333344445555",
            0,
            GpuVendor::Nvidia,
        );
        let b = dev(
            "GPU-9a8b7c6d-0000-1111-2222-666677778888",
            2,
            GpuVendor::Nvidia,
        );
        let env = Arc::new(FakeEnv {
            body: Mutex::new(Some(GENERATING.to_string())),
            apps: parse_nvidia_compute_apps(NVIDIA),
            ..Default::default()
        });
        let s = StatsSampler::new(env.clone());
        s.register(target(StatsKind::Strata, vec![a.clone(), b.clone()]));
        s.tick().await;
        let loading = s.snapshot("m").expect("registered");
        assert_eq!(loading.phase, ModelState::Loading);
        assert_eq!(loading.tok_s, None, "no engine query while loading");
        assert_eq!(loading.ram_bytes, 5 << 20);
        assert_eq!(loading.vram_per_device.len(), 2);

        s.set_phase("m", ModelState::Ready, None);
        s.tick().await;
        let st = s.snapshot("m").expect("registered");
        assert_eq!(st.tok_s, Some(31.4));
        assert_eq!(st.tok_s_source, Some(TokSource::Engine));
        // process 20001 is not ours; 12345 has 12288 MiB on a and 10240 MiB on b
        let on_a = st
            .vram_per_device
            .iter()
            .find(|r| r.device == a)
            .expect("a");
        assert_eq!(on_a.bytes, 12288 << 20);
        let on_b = st
            .vram_per_device
            .iter()
            .find(|r| r.device == b)
            .expect("b");
        assert_eq!(on_b.bytes, 10240 << 20);
    }

    #[tokio::test]
    async fn sampler_falls_back_to_measured_replies() {
        let env = Arc::new(FakeEnv {
            body: Mutex::new(None),
            apps: Vec::new(),
            ..Default::default()
        });
        let s = StatsSampler::new(env);
        s.register(target(StatsKind::Llama, Vec::new()));
        s.set_phase("m", ModelState::Ready, None);
        s.tick().await;
        assert_eq!(s.snapshot("m").expect("m").tok_s, None);
        s.record_reply("m", 90, Duration::from_secs(3));
        let st = s.snapshot("m").expect("m");
        assert_eq!(st.tok_s, Some(30.0));
        assert_eq!(st.tok_s_source, Some(TokSource::Approx));
        s.unregister("m");
        assert!(s.snapshot("m").is_none());
    }

    #[tokio::test]
    async fn one_card_without_uuid_gets_amd_rows() {
        let amd = dev("amd-0", 0, GpuVendor::Amd);
        let env = Arc::new(FakeEnv {
            body: Mutex::new(None),
            apps: parse_rocm_pids(ROCM)
                .into_iter()
                .map(|mut p| {
                    p.pid = 12345;
                    p
                })
                .collect(),
            ..Default::default()
        });
        let s = StatsSampler::new(env);
        s.register(target(StatsKind::Llama, vec![amd.clone()]));
        s.tick().await;
        let st = s.snapshot("m").expect("m");
        assert_eq!(st.vram_per_device.len(), 1);
        assert_eq!(st.vram_per_device[0].device, amd);
        assert_eq!(st.vram_per_device[0].bytes, (8u64 << 30) + (100 << 20));
    }

    #[tokio::test]
    async fn the_speed_goes_away_when_the_engine_is_idle() {
        let env = Arc::new(FakeEnv {
            body: Mutex::new(Some(GENERATING.to_string())),
            ..Default::default()
        });
        let s = StatsSampler::new(env.clone());
        s.register(target(StatsKind::Strata, Vec::new()));
        s.set_phase("m", ModelState::Ready, None);
        s.tick().await;
        assert_eq!(s.snapshot("m").expect("m").tok_s, Some(31.4));
        *lock(&env.body) = Some(IDLE.to_string());
        s.tick().await;
        let st = s.snapshot("m").expect("m");
        assert_eq!((st.tok_s, st.tok_s_source), (None, None), "idle: no figure");
        // A reply KRAKEN measured does not bring an old speed back while the engine says idle.
        s.record_reply("m", 90, Duration::from_secs(3));
        assert_eq!(s.snapshot("m").expect("m").tok_s, None);

        // llama-server: unchanged counters between two scrapes mean nothing was generated.
        let s = StatsSampler::new(env.clone());
        s.register(target(StatsKind::Llama, Vec::new()));
        s.set_phase("m", ModelState::Ready, None);
        *lock(&env.body) = Some(PROM1.to_string());
        s.tick().await;
        *lock(&env.body) = Some(PROM2.to_string());
        s.tick().await;
        assert_eq!(s.snapshot("m").expect("m").tok_s, Some(45.0));
        s.tick().await;
        assert_eq!(s.snapshot("m").expect("m").tok_s, None);
    }

    #[tokio::test]
    async fn the_metrics_scrape_sends_the_per_run_key() {
        let env = Arc::new(FakeEnv {
            body: Mutex::new(Some(PROM1.to_string())),
            ..Default::default()
        });
        let s = StatsSampler::new(env.clone());
        let mut t = target(StatsKind::Llama, Vec::new());
        t.api_key = Some("run-secret".into());
        assert!(
            !format!("{t:?}").contains("run-secret"),
            "the key is never printed"
        );
        s.register(t);
        s.set_phase("m", ModelState::Ready, None);
        s.tick().await;
        assert_eq!(lock(&env.bearer).as_deref(), Some("run-secret"));
    }

    #[tokio::test]
    async fn the_real_http_get_authenticates_like_llama_server_wants() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind((LOOPBACK, 0)).await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut c, _) = listener.accept().await.expect("accept");
                let mut buf = vec![0u8; 4096];
                let n = c.read(&mut buf).await.expect("read");
                let req = String::from_utf8_lossy(&buf[..n]).into_owned();
                let reply = if req.contains("\r\nAuthorization: Bearer k1\r\n") {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                } else {
                    "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"
                };
                c.write_all(reply.as_bytes()).await.expect("write");
            }
        });
        assert_eq!(SystemEnv.http_get(port, "/metrics", None).await, None);
        assert_eq!(
            SystemEnv
                .http_get(port, "/metrics", Some("k1"))
                .await
                .as_deref(),
            Some("ok")
        );
        server.await.expect("server");
    }
}
