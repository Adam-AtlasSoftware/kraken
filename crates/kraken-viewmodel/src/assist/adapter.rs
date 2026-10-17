//! Lets the assistant's tool host run commands through the GUI's own [`Backend`].

use std::sync::Arc;

use async_trait::async_trait;
use kraken_host::backend::CommandBackend;
use kraken_proto::ProtoError;
use kraken_registry::CallContext;
use serde_json::Value;

use crate::backend::{Backend, CallAs};

/// A [`CommandBackend`] over a view-model [`Backend`]. Calls keep the identity of the context
/// they were made with, so the assistant's edits are logged under its agent id and run id and
/// never as the person.
pub struct VmCommands {
    inner: Arc<dyn Backend>,
}

impl VmCommands {
    /// Wraps the backend the GUI already uses (in-process or the daemon client).
    pub fn new(inner: Arc<dyn Backend>) -> Self {
        VmCommands { inner }
    }
}

#[async_trait]
impl CommandBackend for VmCommands {
    async fn call(&self, name: &str, ctx: &CallContext, args: Value) -> Result<Value, ProtoError> {
        let who = CallAs {
            agent: ctx.author.kind == kraken_model::AuthorKind::Agent,
            id: ctx.author.id.clone(),
            run_id: ctx.run_id.as_ref().map(|r| r.0.clone()),
        };
        self.inner.call_as(&who, name, args).await
    }

    fn take_warnings(&self) -> Vec<String> {
        Vec::new()
    }
}
