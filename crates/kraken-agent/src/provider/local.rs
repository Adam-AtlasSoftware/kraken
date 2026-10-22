//! A model served from this computer (`kind = "local"`), found at request time.
//!
//! The configuration only names the model. Where it listens and the per-run key it requires
//! change with every start, so they are asked of a [`LocalResolver`] for each request and never
//! stored. The request itself is an ordinary OpenAI-compatible one.

use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use tokio_util::sync::CancellationToken;

use super::ChatProvider;
use super::openai::OpenAiCompatible;
use crate::error::AgentError;
use crate::types::{ChatRequest, ChatStream, ProviderInfo};

/// Where a running local model answers.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalEndpoint {
    /// OpenAI-compatible base URL on this computer.
    pub base_url: String,
    /// The model name to put in requests.
    pub served_model: String,
    /// The per-run bearer token, when the server needs one.
    pub api_key: Option<String>,
}

impl std::fmt::Debug for LocalEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalEndpoint")
            .field("base_url", &self.base_url)
            .field("served_model", &self.served_model)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// Finds the running server of a local model, starting it when the rules allow.
#[async_trait]
pub trait LocalResolver: Send + Sync {
    /// The endpoint of `model` (its id in `[[local_models]]`), waiting while it loads. Fails with
    /// [`AgentError::ModelNotRunning`] when it is not running and may not be started.
    async fn resolve(&self, model: &str) -> Result<LocalEndpoint, AgentError>;

    /// The context length `model` is served with, in tokens, when it is known.
    fn context_window(&self, _model: &str) -> Option<u32> {
        None
    }
}

/// The chat provider of `kind = "local"`.
pub struct LocalProvider {
    model: String,
    resolver: Arc<dyn LocalResolver>,
    cached: Mutex<Option<(LocalEndpoint, Arc<OpenAiCompatible>)>>,
    thinking: Option<crate::thinking::Effort>,
}

impl std::fmt::Debug for LocalProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalProvider")
            .field("model", &self.model)
            .finish_non_exhaustive()
    }
}

/// Tries after a connection problem (the first request plus this many).
const RETRIES: u32 = 2;

impl LocalProvider {
    /// A provider for the local model `model`.
    pub fn new(model: impl Into<String>, resolver: Arc<dyn LocalResolver>) -> Self {
        Self {
            model: model.into(),
            resolver,
            cached: Mutex::new(None),
            thinking: None,
        }
    }

    /// Passes a thinking effort on to the requests.
    pub fn with_thinking(mut self, e: Option<crate::thinking::Effort>) -> Self {
        self.thinking = e;
        self
    }

    fn forget(&self) {
        *self.cached.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    async fn inner(&self) -> Result<Arc<OpenAiCompatible>, AgentError> {
        let ep = self.resolver.resolve(&self.model).await?;
        let mut cache = self.cached.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some((cached, inner)) = cache.as_ref()
            && *cached == ep
        {
            return Ok(inner.clone());
        }
        let inner = Arc::new(
            OpenAiCompatible::new(&ep.base_url, &ep.served_model, ep.api_key.clone())?
                .with_id("local")
                .with_thinking(self.thinking),
        );
        *cache = Some((ep, inner.clone()));
        Ok(inner)
    }
}

#[async_trait]
impl ChatProvider for LocalProvider {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: "local".into(),
            model: self.model.clone(),
            supports_tools: true,
            context_window: self.resolver.context_window(&self.model),
        }
    }

    async fn complete(
        &self,
        req: ChatRequest,
        cancel: CancellationToken,
    ) -> Result<ChatStream, AgentError> {
        let mut attempt = 0;
        loop {
            let inner = self.inner().await?;
            match inner.complete(req.clone(), cancel.clone()).await {
                Err(e) if e.is_retryable() && attempt < RETRIES && !cancel.is_cancelled() => {
                    // The server may have restarted on another port: ask again.
                    attempt += 1;
                    self.forget();
                    tokio::select! {
                        () = cancel.cancelled() => return Err(AgentError::Cancelled),
                        () = tokio::time::sleep(Duration::from_millis(300 * u64::from(attempt))) => {}
                    }
                }
                other => return other,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Resolver {
        calls: AtomicU32,
        answer: Result<LocalEndpoint, String>,
    }

    #[async_trait]
    impl LocalResolver for Resolver {
        async fn resolve(&self, model: &str) -> Result<LocalEndpoint, AgentError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.answer
                .clone()
                .map_err(|message| AgentError::ModelNotRunning {
                    model: model.into(),
                    message,
                })
        }
    }

    fn request() -> ChatRequest {
        ChatRequest {
            system: "s".into(),
            messages: vec![crate::types::Message::user("hi")],
            tools: vec![],
            max_tokens: None,
            temperature: None,
        }
    }

    #[tokio::test]
    async fn a_model_that_is_not_running_is_reported_once() {
        let r = Arc::new(Resolver {
            calls: AtomicU32::new(0),
            answer: Err("start it with kraken local-model-start x".into()),
        });
        let p = LocalProvider::new("x", r.clone());
        let e = p
            .complete(request(), CancellationToken::new())
            .await
            .err()
            .expect("fails");
        assert!(matches!(e, AgentError::ModelNotRunning { .. }));
        assert!(!e.is_retryable());
        assert_eq!(r.calls.load(Ordering::SeqCst), 1);
        assert_eq!(p.info().model, "x");
        assert_eq!(p.info().context_window, None);
    }

    #[test]
    fn the_resolver_gives_the_context_window() {
        struct Sized;
        #[async_trait]
        impl LocalResolver for Sized {
            async fn resolve(&self, model: &str) -> Result<LocalEndpoint, AgentError> {
                Err(AgentError::ModelNotRunning {
                    model: model.into(),
                    message: String::new(),
                })
            }
            fn context_window(&self, _model: &str) -> Option<u32> {
                Some(32_768)
            }
        }
        let p = LocalProvider::new("x", Arc::new(Sized));
        assert_eq!(p.info().context_window, Some(32_768));
    }

    #[tokio::test]
    async fn a_refused_connection_asks_the_resolver_again() {
        // Nothing listens on port 1: the connection fails like a server that went away.
        let r = Arc::new(Resolver {
            calls: AtomicU32::new(0),
            answer: Ok(LocalEndpoint {
                base_url: "http://127.0.0.1:1/v1".into(),
                served_model: "m".into(),
                api_key: Some("k".into()),
            }),
        });
        let p = LocalProvider::new("x", r.clone());
        let e = p
            .complete(request(), CancellationToken::new())
            .await
            .err()
            .expect("fails");
        assert!(e.is_retryable(), "{e}");
        assert_eq!(r.calls.load(Ordering::SeqCst), RETRIES + 1);
        assert!(
            !format!(
                "{:?}",
                LocalEndpoint {
                    base_url: String::new(),
                    served_model: String::new(),
                    api_key: Some("secret-key".into())
                }
            )
            .contains("secret-key")
        );
    }
}
