//! Cassette record/replay (decision 66).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures_util::StreamExt;
use futures_util::stream;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio_util::sync::CancellationToken;

use super::ChatProvider;
use crate::error::AgentError;
use crate::types::{ChatRequest, ChatStream, ProviderInfo, StreamEvent};

pub const CASSETTE_VERSION: u32 = 1;

fn canonical(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push(':');
                canonical(&m[k], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn sha256_hex(data: &str) -> String {
    Sha256::digest(data.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn hash_value(v: &Value) -> String {
    let mut s = String::new();
    canonical(v, &mut s);
    sha256_hex(&s)
}

/// Hash components of a request fingerprint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Fingerprint {
    pub system_hash: String,
    pub tools_hash: String,
    pub messages_hash: String,
    /// Hash over the three components above; the cassette lookup key.
    pub key: String,
}

impl Fingerprint {
    /// Keyed by (system prompt hash, tool schema hash, messages). Model name, token limits and
    /// temperature are deliberately excluded so cassettes survive tuning. Tool order does not
    /// matter; object key order does not matter.
    pub fn of(req: &ChatRequest) -> Self {
        let system_hash = sha256_hex(&req.system);
        let mut tools: Vec<Value> = req
            .tools
            .iter()
            .map(|t| {
                serde_json::json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                })
            })
            .collect();
        tools.sort_by_key(|t| t["name"].as_str().unwrap_or("").to_string());
        let tools_hash = hash_value(&Value::Array(tools));
        let messages_hash = hash_value(&serde_json::to_value(&req.messages).unwrap_or(Value::Null));
        let key = sha256_hex(&format!(
            "kraken-cassette-v{CASSETTE_VERSION}|{system_hash}|{tools_hash}|{messages_hash}"
        ));
        Fingerprint {
            system_hash,
            tools_hash,
            messages_hash,
            key,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CassetteEntry {
    pub fingerprint: Fingerprint,
    pub events: Vec<StreamEvent>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Cassette {
    pub version: u32,
    #[serde(default)]
    pub entries: Vec<CassetteEntry>,
}

impl Default for Cassette {
    fn default() -> Self {
        Self {
            version: CASSETTE_VERSION,
            entries: Vec::new(),
        }
    }
}

impl Cassette {
    pub fn from_json(s: &str) -> Result<Self, AgentError> {
        let c: Cassette =
            serde_json::from_str(s).map_err(|e| AgentError::Cassette(e.to_string()))?;
        if c.version != CASSETTE_VERSION {
            return Err(AgentError::Cassette(format!(
                "unsupported cassette version {}",
                c.version
            )));
        }
        Ok(c)
    }

    pub fn to_json(&self) -> Result<String, AgentError> {
        serde_json::to_string_pretty(self).map_err(|e| AgentError::Cassette(e.to_string()))
    }

    pub fn load(path: &Path) -> Result<Self, AgentError> {
        let s = std::fs::read_to_string(path)
            .map_err(|e| AgentError::Cassette(format!("{}: {e}", path.display())))?;
        Self::from_json(&s)
    }

    pub fn save(&self, path: &Path) -> Result<(), AgentError> {
        std::fs::write(path, self.to_json()?)
            .map_err(|e| AgentError::Cassette(format!("{}: {e}", path.display())))
    }
}

fn events_stream(events: Vec<StreamEvent>) -> ChatStream {
    stream::iter(events.into_iter().map(Ok)).boxed()
}

enum Mode {
    Keyed(HashMap<String, Vec<Vec<StreamEvent>>>),
    /// Responses returned in order regardless of the request.
    Scripted(Vec<Vec<StreamEvent>>),
}

/// Replays recorded responses; never touches the network.
pub struct ReplayProvider {
    info: ProviderInfo,
    mode: Mode,
    cursors: Mutex<HashMap<String, usize>>,
}

impl ReplayProvider {
    fn default_info() -> ProviderInfo {
        ProviderInfo {
            id: "replay".into(),
            model: "cassette".into(),
            supports_tools: true,
            context_window: None,
        }
    }

    /// Replays by request fingerprint. If a key was recorded several times the entries are
    /// returned in order, and the last one repeats.
    pub fn new(cassette: Cassette) -> Self {
        let mut map: HashMap<String, Vec<Vec<StreamEvent>>> = HashMap::new();
        for e in cassette.entries {
            map.entry(e.fingerprint.key).or_default().push(e.events);
        }
        Self {
            info: Self::default_info(),
            mode: Mode::Keyed(map),
            cursors: Mutex::new(HashMap::new()),
        }
    }

    pub fn from_path(path: &Path) -> Result<Self, AgentError> {
        Ok(Self::new(Cassette::load(path)?))
    }

    /// Hand-written script: the n-th call returns the n-th response (the last repeats).
    pub fn scripted(responses: Vec<Vec<StreamEvent>>) -> Self {
        Self {
            info: Self::default_info(),
            mode: Mode::Scripted(responses),
            cursors: Mutex::new(HashMap::new()),
        }
    }

    pub fn with_info(mut self, info: ProviderInfo) -> Self {
        self.info = info;
        self
    }
}

#[async_trait]
impl ChatProvider for ReplayProvider {
    fn info(&self) -> ProviderInfo {
        self.info.clone()
    }

    async fn complete(
        &self,
        req: ChatRequest,
        cancel: CancellationToken,
    ) -> Result<ChatStream, AgentError> {
        if cancel.is_cancelled() {
            return Err(AgentError::Cancelled);
        }
        let (slot, list) = match &self.mode {
            Mode::Keyed(map) => {
                let key = Fingerprint::of(&req).key;
                let list = map
                    .get(&key)
                    .ok_or_else(|| AgentError::CassetteMiss(key.clone()))?;
                (key, list)
            }
            Mode::Scripted(list) => ("scripted".to_string(), list),
        };
        let mut cursors = self
            .cursors
            .lock()
            .map_err(|_| AgentError::Cassette("poisoned lock".into()))?;
        let cur = cursors.entry(slot).or_insert(0);
        let events = list
            .get(*cur)
            .or_else(|| list.last())
            .cloned()
            .ok_or_else(|| AgentError::Cassette("empty script".into()))?;
        *cur += 1;
        Ok(events_stream(events))
    }
}

/// Wraps a real provider and records each exchange into a cassette.
///
/// The inner stream is drained before it is returned, so recording trades live streaming for
/// a complete capture. Call [`RecordingProvider::cassette`] or [`RecordingProvider::save`] after
/// the run.
pub struct RecordingProvider {
    inner: Arc<dyn ChatProvider>,
    cassette: Mutex<Cassette>,
    path: Option<PathBuf>,
}

impl RecordingProvider {
    pub fn new(inner: Arc<dyn ChatProvider>) -> Self {
        Self {
            inner,
            cassette: Mutex::new(Cassette::default()),
            path: None,
        }
    }

    /// Also writes the cassette to `path` after every recorded exchange.
    pub fn with_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn cassette(&self) -> Cassette {
        self.cassette.lock().map(|c| c.clone()).unwrap_or_default()
    }

    pub fn save(&self, path: &Path) -> Result<(), AgentError> {
        self.cassette().save(path)
    }
}

#[async_trait]
impl ChatProvider for RecordingProvider {
    fn info(&self) -> ProviderInfo {
        self.inner.info()
    }

    async fn complete(
        &self,
        req: ChatRequest,
        cancel: CancellationToken,
    ) -> Result<ChatStream, AgentError> {
        let fingerprint = Fingerprint::of(&req);
        let mut s = self.inner.complete(req, cancel).await?;
        let mut events = Vec::new();
        while let Some(ev) = s.next().await {
            events.push(ev?);
        }
        let snapshot = {
            let mut c = self
                .cassette
                .lock()
                .map_err(|_| AgentError::Cassette("poisoned lock".into()))?;
            c.entries.push(CassetteEntry {
                fingerprint,
                events: events.clone(),
            });
            c.clone()
        };
        if let Some(p) = &self.path {
            snapshot.save(p)?;
        }
        Ok(events_stream(events))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tool::{Permission, ToolSpec};
    use crate::types::{FinishReason, Message};
    use serde_json::json;

    fn req(text: &str) -> ChatRequest {
        ChatRequest {
            system: "sys".into(),
            messages: vec![Message::user(text)],
            tools: vec![ToolSpec {
                name: "t".into(),
                description: "d".into(),
                input_schema: json!({"type": "object", "properties": {"a": {"type": "string"}}}),
                permission: Permission::Safe,
            }],
            max_tokens: Some(1),
            temperature: None,
        }
    }

    #[test]
    fn key_is_pinned() {
        // If this changes, every committed cassette is invalidated: bump CASSETTE_VERSION.
        assert_eq!(
            Fingerprint::of(&req("hello")).key,
            "577574ee276142bb9d0057810aec22eaa259f89eaac04f949c031df0a6dc9d7a"
        );
    }

    #[test]
    fn key_ignores_irrelevant_changes_but_not_relevant_ones() {
        let a = Fingerprint::of(&req("hello"));
        let mut b = req("hello");
        b.max_tokens = Some(999);
        b.temperature = Some(0.5);
        assert_eq!(a, Fingerprint::of(&b));

        let mut c = req("hello");
        c.tools[0].input_schema =
            json!({"properties": {"a": {"type": "string"}}, "type": "object"});
        assert_eq!(
            a.key,
            Fingerprint::of(&c).key,
            "object key order is irrelevant"
        );

        assert_ne!(a.key, Fingerprint::of(&req("hellp")).key);
        let mut d = req("hello");
        d.system = "other".into();
        assert_ne!(a.key, Fingerprint::of(&d).key);
        let mut e = req("hello");
        e.tools[0].description = "changed".into();
        assert_ne!(a.key, Fingerprint::of(&e).key);
    }

    #[tokio::test]
    async fn record_then_replay_roundtrip() {
        let events = vec![
            StreamEvent::TextDelta { text: "hi".into() },
            StreamEvent::Finish {
                reason: FinishReason::Stop,
            },
        ];
        let rec = RecordingProvider::new(Arc::new(ReplayProvider::scripted(vec![events.clone()])));
        let mut s = rec
            .complete(req("hello"), CancellationToken::new())
            .await
            .unwrap();
        while s.next().await.is_some() {}
        let json = rec.cassette().to_json().unwrap();

        let replay = ReplayProvider::new(Cassette::from_json(&json).unwrap());
        let got: Vec<_> = replay
            .complete(req("hello"), CancellationToken::new())
            .await
            .unwrap()
            .map(|r| r.unwrap())
            .collect()
            .await;
        assert_eq!(got, events);
        let miss = replay
            .complete(req("other"), CancellationToken::new())
            .await;
        assert!(matches!(miss, Err(AgentError::CassetteMiss(_))));
    }
}
