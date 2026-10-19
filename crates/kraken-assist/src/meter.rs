//! The one metered path every model call goes through.
//!
//! A [`Meter`] belongs to one piece of AI work (a rewrite job, an assistant task, an Automate
//! run). [`Meter::wrap`] puts it around an [`AssistBackend`]: a model API is metered per request
//! with the tokens the provider reports; a terminal agent per turn or completion, with the time
//! taken and no tokens (it is billed by the agent's own subscription). Every call becomes an
//! [`AiCallRecord`] handed to the meter's sinks (the project ledger, the daily totals) and
//! observers (the daemon's AI job board, the window's activity chip), with an estimated cost
//! from the [`Pricing`] table.
//!
//! Before each call the meter checks the run's limits (most calls, most estimated cost) and the
//! daily budget. A call over a limit is refused with [`AgentError::Limit`], which the callers
//! turn into a clean stop that keeps what was finished.

use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures_util::Stream;
use kraken_agent::{
    AgentError, AgentEvent, AgentRun, ApprovalHandle, ChatProvider, ChatRequest, ChatStream,
    ProviderInfo, StopReason, StreamEvent, Usage,
};
use kraken_model::{DailyLedger, UsageSink};
use kraken_proto::{AiCallRecord, AiFeature, AiOrigin, AiProviderKind, AiUsageTotals, money};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::ai_config::AiLimits;
use crate::backend::{ApiBackend, AssistBackend, BackendInfo, BackendKind, RunSpec, TextFuture};
use crate::host::HostStats;
use crate::pricing::Pricing;

type Replies = std::collections::VecDeque<(u64, f64)>;

static SPEEDS: Mutex<Vec<(String, Replies)>> = Mutex::new(Vec::new());
const SPEED_KEEP: usize = 8;

fn note_speed(provider: &str, output_tokens: u64, wall: Duration) {
    let secs = wall.as_secs_f64();
    if output_tokens == 0 || secs <= 0.0 {
        return;
    }
    let mut all = SPEEDS.lock().unwrap_or_else(PoisonError::into_inner);
    let at = match all.iter().position(|(id, _)| id == provider) {
        Some(i) => i,
        None => {
            all.push((provider.to_string(), Default::default()));
            all.len() - 1
        }
    };
    let q = &mut all[at].1;
    if q.len() == SPEED_KEEP {
        q.pop_front();
    }
    q.push_back((output_tokens, secs));
}

/// Words per second (tokens) the replies of the provider `provider` (its [`ProviderInfo::id`])
/// came at in this process, over the last few; `None` before the first reply that reported
/// tokens. Rough: the time includes the wait for the first word.
pub fn measured_tok_s(provider: &str) -> Option<f32> {
    let all = SPEEDS.lock().unwrap_or_else(PoisonError::into_inner);
    let (_, q) = all.iter().find(|(id, _)| id == provider)?;
    let (n, s) = q.iter().fold((0u64, 0f64), |(n, s), (t, d)| (n + t, s + d));
    (s > 0.0).then(|| (n as f64 / s) as f32)
}

/// Hears every recorded call with the running totals of the meter.
pub type MeterObserver = Arc<dyn Fn(&AiCallRecord, &AiUsageTotals) + Send + Sync>;

/// What a meter's calls are for and whose they are.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeterSpec {
    /// The feature.
    pub feature: AiFeature,
    /// Who started the work.
    pub origin: AiOrigin,
    /// The daemon job, if any.
    pub job_id: Option<String>,
    /// The AI run, if any.
    pub run_id: Option<String>,
}

impl MeterSpec {
    /// A spec for `feature` started by `origin`.
    pub fn new(feature: AiFeature, origin: AiOrigin) -> Self {
        MeterSpec {
            feature,
            origin,
            job_id: None,
            run_id: None,
        }
    }

    /// Sets the daemon job.
    pub fn job(mut self, id: impl Into<String>) -> Self {
        self.job_id = Some(id.into());
        self
    }

    /// Sets the AI run.
    pub fn run(mut self, id: impl Into<String>) -> Self {
        self.run_id = Some(id.into());
        self
    }
}

struct Inner {
    spec: MeterSpec,
    pricing: Pricing,
    limits: AiLimits,
    daily: Option<DailyLedger>,
    sinks: Vec<Arc<dyn UsageSink>>,
    observers: Mutex<Vec<MeterObserver>>,
    kind: Option<AiProviderKind>,
    totals: Mutex<AiUsageTotals>,
    limit_hit: Mutex<Option<String>>,
}

/// Counts, prices and limits the model calls of one piece of AI work. Cheap to clone; clones
/// share their totals.
#[derive(Clone)]
pub struct Meter(Arc<Inner>);

impl std::fmt::Debug for Meter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Meter")
            .field("spec", &self.0.spec)
            .field("totals", &self.totals())
            .finish_non_exhaustive()
    }
}

/// Builds a [`Meter`].
pub struct MeterBuilder {
    spec: MeterSpec,
    pricing: Pricing,
    limits: AiLimits,
    daily: Option<DailyLedger>,
    sinks: Vec<Arc<dyn UsageSink>>,
    observers: Vec<MeterObserver>,
    kind: Option<AiProviderKind>,
}

impl MeterBuilder {
    /// Prices to estimate with (default: the built-in table).
    pub fn pricing(mut self, p: Pricing) -> Self {
        self.pricing = p;
        self
    }

    /// Limits to enforce (default: none).
    pub fn limits(mut self, l: AiLimits) -> Self {
        self.limits = l;
        self
    }

    /// Records every call in the daily totals and checks the daily budget against them.
    pub fn daily(mut self, d: Option<DailyLedger>) -> Self {
        self.daily = d;
        self
    }

    /// Adds a place calls are kept.
    pub fn sink(mut self, s: Arc<dyn UsageSink>) -> Self {
        self.sinks.push(s);
        self
    }

    /// Adds an observer of every call.
    pub fn observer(mut self, o: MeterObserver) -> Self {
        self.observers.push(o);
        self
    }

    /// Says where the model runs, when the caller knows (a local server is free).
    pub fn kind(mut self, k: AiProviderKind) -> Self {
        self.kind = Some(k);
        self
    }

    /// The meter.
    pub fn build(self) -> Meter {
        Meter(Arc::new(Inner {
            spec: self.spec,
            pricing: self.pricing,
            limits: self.limits,
            daily: self.daily,
            sinks: self.sinks,
            observers: Mutex::new(self.observers),
            kind: self.kind,
            totals: Mutex::new(AiUsageTotals::default()),
            limit_hit: Mutex::new(None),
        }))
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

impl Meter {
    /// Starts a meter for `spec`.
    pub fn builder(spec: MeterSpec) -> MeterBuilder {
        MeterBuilder {
            spec,
            pricing: Pricing::default(),
            limits: AiLimits::default(),
            daily: None,
            sinks: Vec::new(),
            observers: Vec::new(),
            kind: None,
        }
    }

    /// What the calls are for.
    pub fn spec(&self) -> &MeterSpec {
        &self.0.spec
    }

    /// Adds an observer after the meter was built.
    pub fn observe(&self, o: MeterObserver) {
        self.0
            .observers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(o);
    }

    /// Usage so far.
    pub fn totals(&self) -> AiUsageTotals {
        *self.0.totals.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The message of the limit that stopped the work, once one did.
    pub fn limit_message(&self) -> Option<String> {
        self.0
            .limit_hit
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn refuse(&self, msg: String) -> AgentError {
        *self
            .0
            .limit_hit
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(msg.clone());
        AgentError::Limit(msg)
    }

    /// Refuses the next call when it would go over a limit.
    pub fn check(&self) -> Result<(), AgentError> {
        let t = self.totals();
        let l = &self.0.limits;
        if let Some(n) = l.max_calls_per_run
            && t.calls >= n
        {
            return Err(self.refuse(format!(
                "Stopped: this run reached its limit of {n} model calls (max_calls_per_run in \
                 the [ai_limits] table of config.toml, or Settings > AI). What it finished is kept."
            )));
        }
        if let Some(c) = l.max_cost_per_run
            && t.cost_usd >= c
        {
            return Err(self.refuse(format!(
                "Stopped: this run reached its cost limit of {} (estimated {} so far; \
                 max_cost_per_run in [ai_limits] of config.toml, or Settings > AI). What it \
                 finished is kept.",
                money(c),
                money(t.cost_usd)
            )));
        }
        if let Some(b) = l.daily_budget {
            let today = match &self.0.daily {
                Some(d) => d.today().cost_usd,
                None => t.cost_usd,
            };
            if today >= b {
                return Err(self.refuse(daily_budget_message(b, today)));
            }
        }
        Ok(())
    }

    fn kind_for(&self, backend: BackendKind) -> AiProviderKind {
        match backend {
            BackendKind::TerminalAgent => AiProviderKind::TerminalAgent,
            BackendKind::Api => self.0.kind.unwrap_or(AiProviderKind::Api),
        }
    }

    /// Records one finished call. `usage` is `None` when the backend does not report tokens.
    pub fn record(
        &self,
        info: &ProviderInfo,
        kind: AiProviderKind,
        usage: Option<Usage>,
        wall: Duration,
    ) -> AiCallRecord {
        if kind != AiProviderKind::TerminalAgent
            && let Some(u) = usage
        {
            note_speed(&info.id, u.output_tokens, wall);
        }
        let (billing, price) = self.0.pricing.billing(kind, &info.model);
        let cost_usd = match (price, usage) {
            (Some(p), Some(u)) => Some(p.cost(u.input_tokens, u.output_tokens)),
            _ if kind == AiProviderKind::Local => Some(0.0),
            _ => None,
        };
        let rec = AiCallRecord {
            ts_ms: now_ms(),
            feature: self.0.spec.feature,
            provider_kind: kind,
            provider: info.id.clone(),
            model: info.model.clone(),
            job_id: self.0.spec.job_id.clone(),
            run_id: self.0.spec.run_id.clone(),
            origin: self.0.spec.origin,
            input_tokens: usage.map(|u| u.input_tokens),
            output_tokens: usage.map(|u| u.output_tokens),
            wall_ms: u64::try_from(wall.as_millis()).unwrap_or(u64::MAX),
            cost_usd,
            billing,
        };
        let totals = {
            let mut t = self.0.totals.lock().unwrap_or_else(PoisonError::into_inner);
            t.add(&rec);
            *t
        };
        for s in &self.0.sinks {
            s.record(&rec);
        }
        // Free calls cannot touch a budget; leaving them out keeps the shared file quiet.
        if let Some(d) = &self.0.daily
            && rec.billing != kraken_proto::AiBilling::Free
        {
            d.record(&rec);
        }
        let observers = self
            .0
            .observers
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        for o in observers {
            o(&rec, &totals);
        }
        rec
    }

    /// `backend` with every model call metered: a model API per request (with tokens), a
    /// terminal agent per turn (time only).
    pub fn wrap(&self, backend: Arc<dyn AssistBackend>) -> Arc<dyn AssistBackend> {
        match backend.chat_provider() {
            Some(p) => Arc::new(ApiBackend::new(self.wrap_provider(p))),
            None => Arc::new(MeteredBackend {
                kind: self.kind_for(backend.info().kind),
                inner: backend,
                meter: self.clone(),
            }),
        }
    }

    /// `provider` with every request metered.
    pub fn wrap_provider(&self, provider: Arc<dyn ChatProvider>) -> Arc<dyn ChatProvider> {
        Arc::new(MeteredProvider {
            inner: provider,
            meter: self.clone(),
            kind: self.0.kind.unwrap_or(AiProviderKind::Api),
        })
    }
}

/// What a refused call says when today's budget is used up.
pub fn daily_budget_message(budget: f64, today: f64) -> String {
    format!(
        "Today's AI budget of {} is used up ({} estimated today). KRAKEN starts no new AI work \
         until tomorrow (the day changes at midnight UTC), unless you raise daily_budget in the \
         [ai_limits] table of config.toml or in Settings > AI.",
        money(budget),
        money(today)
    )
}

/// A chat provider whose requests are metered.
struct MeteredProvider {
    inner: Arc<dyn ChatProvider>,
    meter: Meter,
    kind: AiProviderKind,
}

#[async_trait]
impl ChatProvider for MeteredProvider {
    fn info(&self) -> ProviderInfo {
        self.inner.info()
    }

    async fn complete(
        &self,
        req: ChatRequest,
        cancel: CancellationToken,
    ) -> Result<ChatStream, AgentError> {
        self.meter.check()?;
        let started = Instant::now();
        let stream = self.inner.complete(req, cancel).await?;
        Ok(Box::pin(MeteredStream {
            inner: stream,
            meter: self.meter.clone(),
            info: self.inner.info(),
            kind: self.kind,
            started,
            usage: Usage::default(),
            recorded: false,
        }))
    }
}

/// Passes a provider's stream on and records the call when it ends (or is dropped early: an
/// abandoned request is still billed for what the provider processed).
struct MeteredStream {
    inner: ChatStream,
    meter: Meter,
    info: ProviderInfo,
    kind: AiProviderKind,
    started: Instant,
    usage: Usage,
    recorded: bool,
}

impl MeteredStream {
    fn finish(&mut self) {
        if !self.recorded {
            self.recorded = true;
            self.meter.record(
                &self.info,
                self.kind,
                Some(self.usage),
                self.started.elapsed(),
            );
        }
    }
}

impl Stream for MeteredStream {
    type Item = Result<StreamEvent, AgentError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let polled = self.inner.as_mut().poll_next(cx);
        match &polled {
            Poll::Ready(Some(Ok(StreamEvent::Usage(u)))) => {
                // As the assembler does: the latest non-zero field wins.
                let u = *u;
                if u.input_tokens > 0 {
                    self.usage.input_tokens = u.input_tokens;
                }
                if u.output_tokens > 0 {
                    self.usage.output_tokens = u.output_tokens;
                }
            }
            Poll::Ready(None) => self.finish(),
            _ => {}
        }
        polled
    }
}

impl Drop for MeteredStream {
    fn drop(&mut self) {
        self.finish();
    }
}

/// A backend without a chat provider (a terminal agent), metered per turn.
struct MeteredBackend {
    inner: Arc<dyn AssistBackend>,
    meter: Meter,
    kind: AiProviderKind,
}

impl AssistBackend for MeteredBackend {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }

    fn provider_info(&self) -> ProviderInfo {
        self.inner.provider_info()
    }

    fn start(&self, spec: RunSpec) -> AgentRun {
        if let Err(e) = self.meter.check() {
            let (tx, rx) = mpsc::channel(4);
            let (handle, _rx) = ApprovalHandle::channel();
            let message = e.to_string();
            let _ = tx.try_send(AgentEvent::Error {
                message: message.clone(),
            });
            let _ = tx.try_send(AgentEvent::Done {
                usage: Usage::default(),
                stop: StopReason::TokenBudget,
                message,
            });
            return AgentRun::from_parts(rx, handle, CancellationToken::new());
        }
        let mut run = self.inner.start(spec);
        let (tx, rx) = mpsc::channel(64);
        let approvals = run.approvals();
        let cancel = run.cancel_token();
        let meter = self.meter.clone();
        let kind = self.kind;
        let inner = self.inner.clone();
        let started = Instant::now();
        tokio::spawn(async move {
            while let Some(ev) = run.next_event().await {
                let done = matches!(ev, AgentEvent::Done { .. });
                if done {
                    meter.record(&inner.provider_info(), kind, None, started.elapsed());
                }
                if tx.send(ev).await.is_err() || done {
                    break;
                }
            }
        });
        AgentRun::from_parts(rx, approvals, cancel)
    }

    fn take_stats(&self, run_id: &str) -> Option<HostStats> {
        self.inner.take_stats(run_id)
    }

    fn take_notes(&self) -> Vec<String> {
        self.inner.take_notes()
    }

    fn close(&self) {
        self.inner.close();
    }

    fn complete_text(&self, req: ChatRequest, cancel: CancellationToken) -> TextFuture<'_> {
        Box::pin(async move {
            self.meter.check()?;
            let started = Instant::now();
            let reply = self.inner.complete_text(req, cancel).await?;
            let usage = (reply.usage.total() > 0).then_some(reply.usage);
            self.meter
                .record(&reply.provider, self.kind, usage, started.elapsed());
            Ok(reply)
        })
    }
}

#[cfg(test)]
mod speed_tests {
    use super::*;

    #[test]
    fn replies_with_tokens_give_a_rough_speed_per_provider() {
        assert_eq!(measured_tok_s("speed-test-provider"), None);
        note_speed("speed-test-provider", 0, Duration::from_secs(1));
        assert_eq!(measured_tok_s("speed-test-provider"), None);
        note_speed("speed-test-provider", 100, Duration::from_secs(2));
        note_speed("speed-test-provider", 100, Duration::from_secs(2));
        assert_eq!(measured_tok_s("speed-test-provider"), Some(50.0));
        assert_eq!(measured_tok_s("another-provider"), None);
    }
}
