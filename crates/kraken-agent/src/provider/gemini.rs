//! Google Gemini `streamGenerateContent` (SSE).
//!
//! Gemini does not issue tool-call ids, so ids are synthesised (`gemini_call_N`) and the tool
//! name is used to match `functionResponse` parts. Tool schemas are passed through after
//! dropping JSON Schema keywords that Gemini's OpenAPI subset rejects.

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use super::{
    ChatProvider, ChunkParser, Secret, SseEvent, http_client, send, sse_chat_stream,
    validate_base_url,
};
use crate::error::AgentError;
use crate::types::{
    ChatRequest, ChatStream, FinishReason, Message, ProviderInfo, StreamEvent, Usage,
};

pub const DEFAULT_BASE_URL: &str = "https://generativelanguage.googleapis.com";
pub const DEFAULT_MODEL: &str = "gemini-2.5-pro";

#[derive(Debug)]
pub struct Gemini {
    client: reqwest::Client,
    base_url: String,
    api_key: Secret,
    model: String,
    context_window: Option<u32>,
}

impl Gemini {
    pub fn new(
        api_key: String,
        model: Option<String>,
        base_url: Option<String>,
    ) -> Result<Self, AgentError> {
        let base_url = base_url
            .unwrap_or_else(|| DEFAULT_BASE_URL.into())
            .trim_end_matches('/')
            .to_string();
        validate_base_url(&base_url)?;
        Ok(Self {
            client: http_client()?,
            base_url,
            api_key: Secret(api_key),
            model: model.unwrap_or_else(|| DEFAULT_MODEL.into()),
            context_window: None,
        })
    }

    pub fn with_context_window(mut self, w: Option<u32>) -> Self {
        self.context_window = w;
        self
    }
}

fn clean_schema(v: &Value) -> Value {
    match v {
        Value::Object(m) => Value::Object(
            m.iter()
                .filter(|(k, _)| {
                    !matches!(
                        k.as_str(),
                        "$schema" | "additionalProperties" | "$id" | "$defs" | "title"
                    )
                })
                .map(|(k, v)| (k.clone(), clean_schema(v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(clean_schema).collect()),
        other => other.clone(),
    }
}

/// Builds the request JSON body.
pub fn build_request(req: &ChatRequest) -> Value {
    let mut contents: Vec<Value> = Vec::new();
    for m in &req.messages {
        match m {
            Message::User { content } => {
                contents.push(json!({"role": "user", "parts": [{"text": content}]}));
            }
            Message::Assistant {
                content,
                tool_calls,
            } => {
                let mut parts = Vec::new();
                if !content.is_empty() {
                    parts.push(json!({"text": content}));
                }
                for c in tool_calls {
                    parts.push(json!({"functionCall": {"name": c.name, "args": c.arguments}}));
                }
                if parts.is_empty() {
                    parts.push(json!({"text": "(no output)"}));
                }
                contents.push(json!({"role": "model", "parts": parts}));
            }
            Message::ToolResult {
                name,
                content,
                is_error,
                ..
            } => {
                let key = if *is_error { "error" } else { "output" };
                let part = json!({"functionResponse": {"name": name, "response": {key: content}}});
                let merged = contents.last_mut().is_some_and(|last| {
                    let ok = last["role"] == "user"
                        && last["parts"]
                            .as_array()
                            .is_some_and(|a| a.iter().all(|p| p.get("functionResponse").is_some()));
                    if ok && let Some(a) = last["parts"].as_array_mut() {
                        a.push(part.clone());
                    }
                    ok
                });
                if !merged {
                    contents.push(json!({"role": "user", "parts": [part]}));
                }
            }
        }
    }
    let mut body = json!({
        "systemInstruction": {"parts": [{"text": req.system}]},
        "contents": contents,
    });
    if !req.tools.is_empty() {
        body["tools"] = json!([{
            "functionDeclarations": req.tools.iter().map(|t| json!({
                "name": t.name,
                "description": t.description,
                "parameters": clean_schema(&t.input_schema),
            })).collect::<Vec<_>>()
        }]);
    }
    let mut gen_cfg = serde_json::Map::new();
    if let Some(m) = req.max_tokens {
        gen_cfg.insert("maxOutputTokens".into(), json!(m));
    }
    if let Some(t) = req.temperature {
        gen_cfg.insert("temperature".into(), json!(t));
    }
    if !gen_cfg.is_empty() {
        body["generationConfig"] = Value::Object(gen_cfg);
    }
    body
}

#[derive(Debug, Default)]
pub struct GeminiParser {
    next_call: usize,
    saw_call: bool,
}

impl ChunkParser for GeminiParser {
    fn parse(&mut self, ev: &SseEvent) -> Result<Vec<StreamEvent>, AgentError> {
        let v: Value = serde_json::from_str(&ev.data)
            .map_err(|e| AgentError::Protocol(format!("bad chunk JSON: {e}")))?;
        if let Some(err) = v.get("error") {
            let msg = err["message"].as_str().unwrap_or("unknown error");
            return Err(AgentError::Provider(msg.into()));
        }
        let mut out = Vec::new();
        if let Some(parts) = v
            .pointer("/candidates/0/content/parts")
            .and_then(Value::as_array)
        {
            for p in parts {
                if let Some(t) = p["text"].as_str().filter(|t| !t.is_empty()) {
                    out.push(StreamEvent::TextDelta { text: t.into() });
                } else if let Some(fc) = p.get("functionCall") {
                    let index = self.next_call;
                    self.next_call += 1;
                    self.saw_call = true;
                    let args = fc.get("args").cloned().unwrap_or_else(|| json!({}));
                    out.push(StreamEvent::ToolCallDelta {
                        index,
                        id: Some(format!("gemini_call_{index}")),
                        name: fc["name"].as_str().map(String::from),
                        arguments: args.to_string(),
                    });
                }
            }
        }
        if let Some(r) = v
            .pointer("/candidates/0/finishReason")
            .and_then(Value::as_str)
        {
            let reason = match r {
                _ if self.saw_call => FinishReason::ToolCalls,
                "STOP" => FinishReason::Stop,
                "MAX_TOKENS" => FinishReason::Length,
                _ => FinishReason::Other,
            };
            out.push(StreamEvent::Finish { reason });
        }
        if let Some(u) = v.get("usageMetadata").filter(|u| u.is_object()) {
            out.push(StreamEvent::Usage(Usage {
                input_tokens: u["promptTokenCount"].as_u64().unwrap_or(0),
                output_tokens: u["candidatesTokenCount"].as_u64().unwrap_or(0),
            }));
        }
        Ok(out)
    }
}

#[async_trait]
impl ChatProvider for Gemini {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: "gemini".into(),
            model: self.model.clone(),
            supports_tools: true,
            context_window: self.context_window,
        }
    }

    async fn complete(
        &self,
        req: ChatRequest,
        cancel: CancellationToken,
    ) -> Result<ChatStream, AgentError> {
        let body = build_request(&req);
        let rb = self
            .client
            .post(format!(
                "{}/v1beta/models/{}:streamGenerateContent?alt=sse",
                self.base_url, self.model
            ))
            .header("x-goog-api-key", &self.api_key.0)
            .header("content-type", "application/json")
            .body(body.to_string());
        let resp = send(rb, &cancel).await?;
        Ok(sse_chat_stream(
            resp,
            Box::new(GeminiParser::default()),
            cancel,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::StreamAssembler;

    #[test]
    fn function_call_stream() {
        let mut p = GeminiParser::default();
        let mut asm = StreamAssembler::default();
        for data in [
            r#"{"candidates":[{"content":{"role":"model","parts":[{"text":"Looking"}]}}]}"#,
            r#"{"candidates":[{"content":{"role":"model","parts":[{"functionCall":{"name":"decompile","args":{"address":"0x401000"}}}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":4}}"#,
        ] {
            let ev = SseEvent {
                event: None,
                data: data.into(),
            };
            for se in p.parse(&ev).unwrap() {
                asm.push(&se);
            }
        }
        let c = asm.finish();
        assert_eq!(c.text, "Looking");
        assert_eq!(c.tool_calls[0].name, "decompile");
        assert_eq!(c.tool_calls[0].id, "gemini_call_0");
        assert_eq!(c.finish, Some(FinishReason::ToolCalls));
        assert_eq!(c.usage.input_tokens, 10);
    }

    #[test]
    fn request_shape() {
        let req = ChatRequest {
            system: "s".into(),
            messages: vec![
                Message::user("hi"),
                Message::ToolResult {
                    tool_call_id: "gemini_call_0".into(),
                    name: "decompile".into(),
                    content: "r".into(),
                    is_error: false,
                },
            ],
            tools: vec![crate::tool::ToolSpec {
                name: "decompile".into(),
                description: "d".into(),
                input_schema: json!({"type": "object", "additionalProperties": false}),
                permission: crate::tool::Permission::Safe,
            }],
            max_tokens: Some(10),
            temperature: None,
        };
        let b = build_request(&req);
        assert_eq!(b["systemInstruction"]["parts"][0]["text"], "s");
        assert_eq!(
            b["contents"][1]["parts"][0]["functionResponse"]["response"]["output"],
            "r"
        );
        assert_eq!(
            b["tools"][0]["functionDeclarations"][0]["parameters"],
            json!({"type": "object"})
        );
        assert_eq!(b["generationConfig"]["maxOutputTokens"], 10);
    }
}
