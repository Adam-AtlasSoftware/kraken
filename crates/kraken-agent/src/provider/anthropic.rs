//! Anthropic Messages API.

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

pub const ANTHROPIC_VERSION: &str = "2023-06-01";
pub const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
/// Default model id; override in configuration, model ids change over time.
pub const DEFAULT_MODEL: &str = "claude-sonnet-5-5";
pub const DEFAULT_MAX_TOKENS: u32 = 4096;

#[derive(Debug)]
pub struct Anthropic {
    client: reqwest::Client,
    base_url: String,
    api_key: Secret,
    model: String,
    max_tokens: u32,
    context_window: Option<u32>,
    thinking: Option<crate::thinking::Effort>,
}

impl Anthropic {
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
            max_tokens: DEFAULT_MAX_TOKENS,
            context_window: None,
            thinking: None,
        })
    }

    pub fn with_thinking(mut self, e: Option<crate::thinking::Effort>) -> Self {
        self.thinking = e;
        self
    }

    pub fn with_max_tokens(mut self, n: u32) -> Self {
        self.max_tokens = n;
        self
    }

    pub fn with_context_window(mut self, w: Option<u32>) -> Self {
        self.context_window = w;
        self
    }
}

/// Builds the request JSON body.
pub fn build_request(model: &str, default_max_tokens: u32, req: &ChatRequest) -> Value {
    let mut messages: Vec<Value> = Vec::new();
    for m in &req.messages {
        match m {
            Message::User { content } => {
                messages.push(json!({"role": "user", "content": content}));
            }
            Message::Assistant {
                content,
                tool_calls,
            } => {
                let mut blocks = Vec::new();
                if !content.is_empty() {
                    blocks.push(json!({"type": "text", "text": content}));
                }
                for c in tool_calls {
                    blocks.push(json!({
                        "type": "tool_use", "id": c.id, "name": c.name, "input": c.arguments,
                    }));
                }
                if blocks.is_empty() {
                    blocks.push(json!({"type": "text", "text": "(no output)"}));
                }
                messages.push(json!({"role": "assistant", "content": blocks}));
            }
            Message::ToolResult {
                tool_call_id,
                content,
                is_error,
                ..
            } => {
                let block = json!({
                    "type": "tool_result",
                    "tool_use_id": tool_call_id,
                    "content": content,
                    "is_error": is_error,
                });
                // Consecutive tool results must share one user message.
                let merged = messages.last_mut().is_some_and(|last| {
                    let is_results = last["role"] == "user"
                        && last["content"]
                            .as_array()
                            .is_some_and(|a| a.iter().all(|b| b["type"] == "tool_result"));
                    if is_results && let Some(a) = last["content"].as_array_mut() {
                        a.push(block.clone());
                    }
                    is_results
                });
                if !merged {
                    messages.push(json!({"role": "user", "content": [block]}));
                }
            }
        }
    }
    let mut body = json!({
        "model": model,
        "max_tokens": req.max_tokens.unwrap_or(default_max_tokens),
        "system": req.system,
        "messages": messages,
        "stream": true,
    });
    if !req.tools.is_empty() {
        body["tools"] = req
            .tools
            .iter()
            .map(|t| {
                json!({
                    "name": t.name,
                    "description": t.description,
                    "input_schema": t.input_schema,
                })
            })
            .collect::<Vec<_>>()
            .into();
    }
    if let Some(t) = req.temperature {
        body["temperature"] = json!(t);
    }
    body
}

/// Parses Messages API streaming events.
#[derive(Debug, Default)]
pub struct AnthropicParser {
    /// Content-block index to tool-call index.
    tool_blocks: Vec<(u64, usize)>,
    next_tool: usize,
}

fn stop_reason(s: &str) -> FinishReason {
    match s {
        "end_turn" | "stop_sequence" => FinishReason::Stop,
        "tool_use" => FinishReason::ToolCalls,
        "max_tokens" => FinishReason::Length,
        _ => FinishReason::Other,
    }
}

impl AnthropicParser {
    fn tool_index(&self, block: u64) -> Option<usize> {
        self.tool_blocks
            .iter()
            .find(|(b, _)| *b == block)
            .map(|(_, t)| *t)
    }
}

impl ChunkParser for AnthropicParser {
    fn parse(&mut self, ev: &SseEvent) -> Result<Vec<StreamEvent>, AgentError> {
        let v: Value = serde_json::from_str(&ev.data)
            .map_err(|e| AgentError::Protocol(format!("bad event JSON: {e}")))?;
        let kind = v["type"].as_str().or(ev.event.as_deref()).unwrap_or("");
        let mut out = Vec::new();
        match kind {
            "message_start" => {
                let u = &v["message"]["usage"];
                out.push(StreamEvent::Usage(Usage {
                    input_tokens: u["input_tokens"].as_u64().unwrap_or(0),
                    output_tokens: u["output_tokens"].as_u64().unwrap_or(0),
                }));
            }
            "content_block_start" => {
                let idx = v["index"].as_u64().unwrap_or(0);
                let cb = &v["content_block"];
                if cb["type"] == "tool_use" {
                    let t = self.next_tool;
                    self.next_tool += 1;
                    self.tool_blocks.push((idx, t));
                    out.push(StreamEvent::ToolCallDelta {
                        index: t,
                        id: cb["id"].as_str().map(String::from),
                        name: cb["name"].as_str().map(String::from),
                        arguments: String::new(),
                    });
                } else if let Some(text) = cb["text"].as_str().filter(|t| !t.is_empty()) {
                    out.push(StreamEvent::TextDelta { text: text.into() });
                }
            }
            "content_block_delta" => {
                let idx = v["index"].as_u64().unwrap_or(0);
                let d = &v["delta"];
                match d["type"].as_str() {
                    Some("text_delta") => {
                        if let Some(t) = d["text"].as_str() {
                            out.push(StreamEvent::TextDelta { text: t.into() });
                        }
                    }
                    Some("input_json_delta") => {
                        let index = self.tool_index(idx).ok_or_else(|| {
                            AgentError::Protocol("input_json_delta for a non-tool block".into())
                        })?;
                        out.push(StreamEvent::ToolCallDelta {
                            index,
                            id: None,
                            name: None,
                            arguments: d["partial_json"].as_str().unwrap_or("").into(),
                        });
                    }
                    _ => {}
                }
            }
            "message_delta" => {
                if let Some(r) = v["delta"]["stop_reason"].as_str() {
                    out.push(StreamEvent::Finish {
                        reason: stop_reason(r),
                    });
                }
                if let Some(o) = v["usage"]["output_tokens"].as_u64() {
                    out.push(StreamEvent::Usage(Usage {
                        input_tokens: v["usage"]["input_tokens"].as_u64().unwrap_or(0),
                        output_tokens: o,
                    }));
                }
            }
            "error" => {
                let msg = v["error"]["message"].as_str().unwrap_or("unknown error");
                return Err(AgentError::Provider(msg.into()));
            }
            _ => {}
        }
        Ok(out)
    }
}

#[async_trait]
impl ChatProvider for Anthropic {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: "anthropic".into(),
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
        let mut body = build_request(&self.model, self.max_tokens, &req);
        if let Some(e) = self.thinking {
            let continues = req.messages.iter().any(
                |m| matches!(m, Message::Assistant { tool_calls, .. } if !tool_calls.is_empty()),
            );
            crate::thinking::apply_anthropic(&mut body, e, continues);
        }
        let rb = self
            .client
            .post(format!("{}/v1/messages", self.base_url))
            .header("x-api-key", &self.api_key.0)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .body(body.to_string());
        let resp = send(rb, &cancel).await?;
        Ok(sse_chat_stream(
            resp,
            Box::new(AnthropicParser::default()),
            cancel,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::SseDecoder;
    use crate::tool::{Permission, ToolSpec};
    use crate::types::{StreamAssembler, ToolCall};

    #[test]
    fn request_json_shape_merges_tool_results() {
        let req = ChatRequest {
            system: "sys".into(),
            messages: vec![
                Message::user("go"),
                Message::Assistant {
                    content: "ok".into(),
                    tool_calls: vec![
                        ToolCall {
                            id: "toolu_1".into(),
                            name: "a".into(),
                            arguments: json!({"x": 1}),
                        },
                        ToolCall {
                            id: "toolu_2".into(),
                            name: "b".into(),
                            arguments: json!({}),
                        },
                    ],
                },
                Message::ToolResult {
                    tool_call_id: "toolu_1".into(),
                    name: "a".into(),
                    content: "r1".into(),
                    is_error: false,
                },
                Message::ToolResult {
                    tool_call_id: "toolu_2".into(),
                    name: "b".into(),
                    content: "r2".into(),
                    is_error: true,
                },
            ],
            tools: vec![ToolSpec {
                name: "a".into(),
                description: "d".into(),
                input_schema: json!({"type": "object"}),
                permission: Permission::Safe,
            }],
            max_tokens: None,
            temperature: None,
        };
        let b = build_request("m", 1000, &req);
        let want = json!({
            "model": "m", "max_tokens": 1000, "system": "sys", "stream": true,
            "messages": [
                {"role": "user", "content": "go"},
                {"role": "assistant", "content": [
                    {"type": "text", "text": "ok"},
                    {"type": "tool_use", "id": "toolu_1", "name": "a", "input": {"x": 1}},
                    {"type": "tool_use", "id": "toolu_2", "name": "b", "input": {}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": "r1", "is_error": false},
                    {"type": "tool_result", "tool_use_id": "toolu_2", "content": "r2", "is_error": true}
                ]}
            ],
            "tools": [{"name": "a", "description": "d", "input_schema": {"type": "object"}}]
        });
        assert_eq!(b, want);
    }

    const SSE: &str = concat!(
        "event: message_start\n",
        "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"role\":\"assistant\",\"content\":[],\"usage\":{\"input_tokens\":25,\"output_tokens\":1}}}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n",
        "event: ping\ndata: {\"type\":\"ping\"}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Checking \"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"now.\"}}\n\n",
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n",
        "event: content_block_start\n",
        "data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"toolu_01\",\"name\":\"decompile\",\"input\":{}}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"address\\\": \\\"0x40\"}}\n\n",
        "event: content_block_delta\n",
        "data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"1000\\\"}\"}}\n\n",
        "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":1}\n\n",
        "event: message_delta\n",
        "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":33}}\n\n",
        "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
    );

    #[test]
    fn streaming_events_with_split_tool_input() {
        let mut dec = SseDecoder::default();
        let mut p = AnthropicParser::default();
        let mut asm = StreamAssembler::default();
        for chunk in SSE.as_bytes().chunks(11) {
            for ev in dec.push(chunk) {
                for se in p.parse(&ev).unwrap() {
                    asm.push(&se);
                }
            }
        }
        let c = asm.finish();
        assert_eq!(c.text, "Checking now.");
        assert_eq!(c.tool_calls.len(), 1);
        assert_eq!(c.tool_calls[0].id, "toolu_01");
        assert_eq!(c.tool_calls[0].arguments, json!({"address": "0x401000"}));
        assert_eq!(c.finish, Some(FinishReason::ToolCalls));
        assert_eq!(
            c.usage,
            Usage {
                input_tokens: 25,
                output_tokens: 33
            }
        );
    }

    #[test]
    fn error_event() {
        let ev = SseEvent {
            event: Some("error".into()),
            data: "{\"type\":\"error\",\"error\":{\"type\":\"overloaded_error\",\"message\":\"Overloaded\"}}".into(),
        };
        assert!(matches!(
            AnthropicParser::default().parse(&ev),
            Err(AgentError::Provider(m)) if m == "Overloaded"
        ));
    }

    #[test]
    fn default_model_configurable() {
        let a = Anthropic::new("k".into(), Some("custom-model".into()), None).unwrap();
        assert_eq!(a.info().model, "custom-model");
        let a = Anthropic::new("k".into(), None, None).unwrap();
        assert_eq!(a.info().model, DEFAULT_MODEL);
        assert!(!format!("{a:?}").contains("\"k\""));
    }
}
