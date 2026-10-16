//! OpenAI-compatible Chat Completions (OpenAI, Ollama, LM Studio, llama-server, vLLM).

use async_trait::async_trait;
use serde_json::{Value, json};
use tokio_util::sync::CancellationToken;

use super::{ChatProvider, ChunkParser, Secret, SseEvent, http_client, send, sse_chat_stream};
use crate::error::AgentError;
use crate::types::{
    ChatRequest, ChatStream, FinishReason, Message, ProviderInfo, StreamEvent, Usage,
};

#[derive(Debug)]
pub struct OpenAiCompatible {
    client: reqwest::Client,
    id: String,
    base_url: String,
    api_key: Option<Secret>,
    model: String,
    supports_tools: bool,
    context_window: Option<u32>,
}

impl OpenAiCompatible {
    /// `base_url` is the API root including any version prefix, e.g. `http://localhost:11434/v1`.
    pub fn new(
        base_url: impl Into<String>,
        model: impl Into<String>,
        api_key: Option<String>,
    ) -> Result<Self, AgentError> {
        Ok(Self {
            client: http_client()?,
            id: "openai-compatible".into(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key: api_key.filter(|k| !k.is_empty()).map(Secret),
            model: model.into(),
            supports_tools: true,
            context_window: None,
        })
    }

    pub fn with_id(mut self, id: impl Into<String>) -> Self {
        self.id = id.into();
        self
    }

    pub fn with_tools(mut self, supports_tools: bool) -> Self {
        self.supports_tools = supports_tools;
        self
    }

    pub fn with_context_window(mut self, window: Option<u32>) -> Self {
        self.context_window = window;
        self
    }
}

/// Builds the request JSON body.
pub fn build_request(model: &str, req: &ChatRequest, send_tools: bool) -> Value {
    let mut messages = vec![json!({"role": "system", "content": req.system})];
    for m in &req.messages {
        match m {
            Message::User { content } => messages.push(json!({"role": "user", "content": content})),
            Message::Assistant {
                content,
                tool_calls,
            } => {
                let mut o = json!({
                    "role": "assistant",
                    "content": if content.is_empty() { Value::Null } else { json!(content) },
                });
                if !tool_calls.is_empty() {
                    o["tool_calls"] = tool_calls
                        .iter()
                        .map(|c| {
                            json!({
                                "id": c.id,
                                "type": "function",
                                "function": {
                                    "name": c.name,
                                    "arguments": serde_json::to_string(&c.arguments)
                                        .unwrap_or_else(|_| "{}".into()),
                                },
                            })
                        })
                        .collect::<Vec<_>>()
                        .into();
                }
                messages.push(o);
            }
            Message::ToolResult {
                tool_call_id,
                content,
                ..
            } => messages.push(json!({
                "role": "tool",
                "tool_call_id": tool_call_id,
                "content": content,
            })),
        }
    }
    let mut body = json!({
        "model": model,
        "messages": messages,
        "stream": true,
        "stream_options": {"include_usage": true},
    });
    if send_tools && !req.tools.is_empty() {
        body["tools"] = req
            .tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.input_schema,
                    },
                })
            })
            .collect::<Vec<_>>()
            .into();
    }
    if let Some(m) = req.max_tokens {
        body["max_tokens"] = json!(m);
    }
    if let Some(t) = req.temperature {
        body["temperature"] = json!(t);
    }
    body
}

/// Parses `chat.completion.chunk` payloads.
#[derive(Debug, Default)]
pub struct OpenAiParser;

fn finish_reason(s: &str) -> FinishReason {
    match s {
        "stop" => FinishReason::Stop,
        "tool_calls" | "function_call" => FinishReason::ToolCalls,
        "length" => FinishReason::Length,
        _ => FinishReason::Other,
    }
}

impl ChunkParser for OpenAiParser {
    fn parse(&mut self, ev: &SseEvent) -> Result<Vec<StreamEvent>, AgentError> {
        let data = ev.data.trim();
        if data == "[DONE]" {
            return Ok(vec![]);
        }
        let v: Value = serde_json::from_str(data)
            .map_err(|e| AgentError::Protocol(format!("bad chunk JSON: {e}")))?;
        if let Some(err) = v.get("error") {
            let msg = err
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown error");
            return Err(AgentError::Provider(msg.to_string()));
        }
        let mut out = Vec::new();
        if let Some(choice) = v.pointer("/choices/0") {
            if let Some(text) = choice.pointer("/delta/content").and_then(Value::as_str)
                && !text.is_empty()
            {
                out.push(StreamEvent::TextDelta { text: text.into() });
            }
            if let Some(calls) = choice
                .pointer("/delta/tool_calls")
                .and_then(Value::as_array)
            {
                for (pos, c) in calls.iter().enumerate() {
                    let index = c
                        .get("index")
                        .and_then(Value::as_u64)
                        .map_or(pos, |i| i as usize);
                    out.push(StreamEvent::ToolCallDelta {
                        index,
                        id: c.get("id").and_then(Value::as_str).map(String::from),
                        name: c
                            .pointer("/function/name")
                            .and_then(Value::as_str)
                            .map(String::from),
                        arguments: c
                            .pointer("/function/arguments")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_string(),
                    });
                }
            }
            if let Some(r) = choice.get("finish_reason").and_then(Value::as_str) {
                out.push(StreamEvent::Finish {
                    reason: finish_reason(r),
                });
            }
        }
        if let Some(u) = v.get("usage").filter(|u| u.is_object()) {
            out.push(StreamEvent::Usage(Usage {
                input_tokens: u["prompt_tokens"].as_u64().unwrap_or(0),
                output_tokens: u["completion_tokens"].as_u64().unwrap_or(0),
            }));
        }
        Ok(out)
    }
}

#[async_trait]
impl ChatProvider for OpenAiCompatible {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: self.id.clone(),
            model: self.model.clone(),
            supports_tools: self.supports_tools,
            context_window: self.context_window,
        }
    }

    async fn complete(
        &self,
        req: ChatRequest,
        cancel: CancellationToken,
    ) -> Result<ChatStream, AgentError> {
        let body = build_request(&self.model, &req, self.supports_tools);
        let mut rb = self
            .client
            .post(format!("{}/chat/completions", self.base_url))
            .header("content-type", "application/json")
            .header("accept", "text/event-stream")
            .body(body.to_string());
        if let Some(k) = &self.api_key {
            rb = rb.bearer_auth(&k.0);
        }
        let resp = send(rb, &cancel).await?;
        Ok(sse_chat_stream(resp, Box::new(OpenAiParser), cancel))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::SseDecoder;
    use crate::tool::{Permission, ToolSpec};
    use crate::types::{StreamAssembler, ToolCall};

    #[test]
    fn request_json_shape() {
        let req = ChatRequest {
            system: "sys".into(),
            messages: vec![
                Message::user("hi"),
                Message::Assistant {
                    content: String::new(),
                    tool_calls: vec![ToolCall {
                        id: "call_1".into(),
                        name: "list_functions".into(),
                        arguments: json!({"limit": 5}),
                    }],
                },
                Message::ToolResult {
                    tool_call_id: "call_1".into(),
                    name: "list_functions".into(),
                    content: "<tool_result/>".into(),
                    is_error: false,
                },
            ],
            tools: vec![ToolSpec {
                name: "list_functions".into(),
                description: "d".into(),
                input_schema: json!({"type": "object"}),
                permission: Permission::Safe,
            }],
            max_tokens: Some(256),
            temperature: None,
        };
        let b = build_request("m", &req, true);
        let want = json!({
            "model": "m",
            "stream": true,
            "stream_options": {"include_usage": true},
            "max_tokens": 256,
            "messages": [
                {"role": "system", "content": "sys"},
                {"role": "user", "content": "hi"},
                {"role": "assistant", "content": null, "tool_calls": [{
                    "id": "call_1", "type": "function",
                    "function": {"name": "list_functions", "arguments": "{\"limit\":5}"}
                }]},
                {"role": "tool", "tool_call_id": "call_1", "content": "<tool_result/>"}
            ],
            "tools": [{"type": "function", "function": {
                "name": "list_functions", "description": "d", "parameters": {"type": "object"}
            }}]
        });
        assert_eq!(b, want);
        assert!(build_request("m", &req, false).get("tools").is_none());
    }

    const SSE: &str = concat!(
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Let me \"}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"look.\"}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_a\",\"type\":\"function\",\"function\":{\"name\":\"decompile\",\"arguments\":\"\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"addr\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"ess\\\":\\\"0x40\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":1,\"id\":\"call_b\",\"function\":{\"name\":\"xrefs\",\"arguments\":\"{}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"1000\\\"}\"}}]}}]}\n\n",
        "data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n",
        "data: {\"choices\":[],\"usage\":{\"prompt_tokens\":42,\"completion_tokens\":7,\"total_tokens\":49}}\n\n",
        "data: [DONE]\n\n",
    );

    #[test]
    fn streaming_split_tool_call_arguments() {
        let mut dec = SseDecoder::default();
        let mut parser = OpenAiParser;
        let mut asm = StreamAssembler::default();
        // Feed in awkward 7-byte slices.
        for chunk in SSE.as_bytes().chunks(7) {
            for ev in dec.push(chunk) {
                for se in parser.parse(&ev).unwrap() {
                    asm.push(&se);
                }
            }
        }
        let c = asm.finish();
        assert_eq!(c.text, "Let me look.");
        assert_eq!(c.tool_calls.len(), 2);
        assert_eq!(c.tool_calls[0].id, "call_a");
        assert_eq!(c.tool_calls[0].name, "decompile");
        assert_eq!(c.tool_calls[0].arguments, json!({"address": "0x401000"}));
        assert_eq!(c.tool_calls[1].name, "xrefs");
        assert_eq!(c.finish, Some(FinishReason::ToolCalls));
        assert_eq!(
            c.usage,
            Usage {
                input_tokens: 42,
                output_tokens: 7
            }
        );
    }

    #[test]
    fn error_chunk_is_an_error() {
        let ev = SseEvent {
            event: None,
            data: "{\"error\":{\"message\":\"rate limited\"}}".into(),
        };
        assert!(matches!(
            OpenAiParser.parse(&ev),
            Err(AgentError::Provider(m)) if m == "rate limited"
        ));
    }

    #[test]
    fn debug_does_not_leak_key() {
        let p = OpenAiCompatible::new("http://x/v1/", "m", Some("sk-secret".into())).unwrap();
        assert!(!format!("{p:?}").contains("sk-secret"));
        assert_eq!(p.base_url, "http://x/v1");
    }
}
