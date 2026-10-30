//! The translation cache: model replies kept in `rewrite.sqlite` under a fingerprint of the
//! prompt (which carries the function's decompile, its callees' code and its hints), the
//! provider and the model. A hit skips the model call; the reply still goes through parsing, the
//! build and the differential test like a fresh one, so the cache saves money and time, never
//! evidence. A reply whose translation failed its test is forgotten ([`forget_failed`]), so the
//! next run asks again instead of repeating the mistake.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use kraken_agent::{AgentError, AgentRun, ChatRequest, ProviderInfo, Usage};
use kraken_assist::{AssistBackend, BackendInfo, RunSpec, TextFuture, TextReply};
use tokio_util::sync::CancellationToken;

use crate::error::RewriteError;
use crate::store::{CachedReply, RewriteStore};
use crate::task::request_hash;
use crate::unit::{RewriteUnit, sha256_hex};
use kraken_registry::commands::UnitStatus;

/// The cache key of a prompt hash (see [`request_hash`]) answered by `provider` and `model`.
pub fn cache_key(prompt_hash: &str, provider: &str, model: &str) -> String {
    sha256_hex(&format!("{prompt_hash}\n{provider}\n{model}"))
}

/// Replies served from the cache and model calls made in one run.
#[derive(Debug, Default)]
pub struct CacheCounters {
    hits: AtomicU32,
    misses: AtomicU32,
}

impl CacheCounters {
    /// Replies that came from the cache.
    pub fn hits(&self) -> u32 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Requests that went to the model.
    pub fn misses(&self) -> u32 {
        self.misses.load(Ordering::Relaxed)
    }
}

/// A backend that answers text requests from the project's cache when it can.
pub struct CachingBackend {
    inner: Arc<dyn AssistBackend>,
    dir: PathBuf,
    counters: Arc<CacheCounters>,
}

impl CachingBackend {
    /// Wraps `inner`; replies are kept in the store of the project directory `dir`.
    pub fn new(inner: Arc<dyn AssistBackend>, dir: PathBuf, counters: Arc<CacheCounters>) -> Self {
        CachingBackend {
            inner,
            dir,
            counters,
        }
    }
}

async fn on_store<T: Send + 'static>(
    dir: PathBuf,
    f: impl FnOnce(&RewriteStore) -> Result<T, RewriteError> + Send + 'static,
) -> Option<T> {
    tokio::task::spawn_blocking(move || f(&RewriteStore::in_project(&dir).ok()?).ok())
        .await
        .ok()
        .flatten()
}

impl AssistBackend for CachingBackend {
    fn info(&self) -> BackendInfo {
        self.inner.info()
    }

    fn provider_info(&self) -> ProviderInfo {
        self.inner.provider_info()
    }

    fn start(&self, spec: RunSpec) -> AgentRun {
        self.inner.start(spec)
    }

    fn take_notes(&self) -> Vec<String> {
        self.inner.take_notes()
    }

    fn close(&self) {
        self.inner.close()
    }

    fn chat_provider(&self) -> Option<Arc<dyn kraken_agent::ChatProvider>> {
        self.inner.chat_provider()
    }

    fn complete_text(&self, req: ChatRequest, cancel: CancellationToken) -> TextFuture<'_> {
        Box::pin(async move {
            let info = self.inner.provider_info();
            let key = cache_key(&request_hash(&req), &info.id, &info.model);
            let k2 = key.clone();
            if let Some(Some(hit)) = on_store(self.dir.clone(), move |st| st.cache_get(&k2)).await {
                self.counters.hits.fetch_add(1, Ordering::Relaxed);
                return Ok(TextReply {
                    text: hit.text,
                    usage: Usage::default(),
                    provider: ProviderInfo {
                        id: hit.provider,
                        model: hit.model,
                        ..info
                    },
                });
            }
            self.counters.misses.fetch_add(1, Ordering::Relaxed);
            let reply: Result<TextReply, AgentError> = self.inner.complete_text(req, cancel).await;
            let reply = reply?;
            let stored = CachedReply {
                text: reply.text.clone(),
                provider: reply.provider.id.clone(),
                model: reply.provider.model.clone(),
            };
            on_store(self.dir.clone(), move |st| st.cache_put(&key, &stored)).await;
            Ok(reply)
        })
    }
}

/// Forgets the replies behind translations that failed their test.
pub fn forget_failed(dir: &Path, units: &[&RewriteUnit]) {
    let Ok(st) = RewriteStore::in_project(dir) else {
        return;
    };
    for u in units {
        if u.status == UnitStatus::Failed
            && let (Some(p), Some(m)) = (&u.provenance.provider, &u.provenance.model)
        {
            let _ = st.cache_forget(&cache_key(&u.provenance.prompt_hash, p, m));
        }
    }
}
