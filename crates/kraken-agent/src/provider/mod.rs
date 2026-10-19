//! Chat providers and shared streaming plumbing.

use std::collections::VecDeque;
use std::fmt;

use async_trait::async_trait;
use futures_util::StreamExt;
use futures_util::stream::{self, BoxStream};
use tokio_util::sync::CancellationToken;

use crate::error::AgentError;
use crate::types::{ChatRequest, ChatStream, ProviderInfo, StreamEvent};

pub mod anthropic;
pub mod gemini;
pub mod local;
pub mod openai;
pub mod replay;

#[async_trait]
pub trait ChatProvider: Send + Sync {
    fn info(&self) -> ProviderInfo;
    async fn complete(
        &self,
        req: ChatRequest,
        cancel: CancellationToken,
    ) -> Result<ChatStream, AgentError>;
}

/// One decoded server-sent event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event: Option<String>,
    pub data: String,
}

/// Incremental SSE decoder (WHATWG event-stream format, the subset providers use).
#[derive(Debug, Default)]
pub struct SseDecoder {
    buf: Vec<u8>,
    event: Option<String>,
    data: Vec<String>,
}

impl SseDecoder {
    /// Feeds raw bytes (chunk boundaries may fall anywhere) and returns completed events.
    pub fn push(&mut self, bytes: &[u8]) -> Vec<SseEvent> {
        self.buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(pos) = self.buf.iter().position(|b| *b == b'\n') {
            let mut line: Vec<u8> = self.buf.drain(..=pos).collect();
            line.pop();
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            self.line(&String::from_utf8_lossy(&line), &mut out);
        }
        out
    }

    /// Flushes a trailing event that was not terminated by a blank line.
    pub fn finish(&mut self) -> Vec<SseEvent> {
        let mut out = Vec::new();
        if !self.buf.is_empty() {
            let line = std::mem::take(&mut self.buf);
            self.line(
                String::from_utf8_lossy(&line).trim_end_matches('\r'),
                &mut out,
            );
        }
        self.dispatch(&mut out);
        out
    }

    fn line(&mut self, line: &str, out: &mut Vec<SseEvent>) {
        if line.is_empty() {
            self.dispatch(out);
        } else if line.starts_with(':') {
        } else {
            let (field, value) = line.split_once(':').unwrap_or((line, ""));
            let value = value.strip_prefix(' ').unwrap_or(value);
            match field {
                "data" => self.data.push(value.to_string()),
                "event" => self.event = Some(value.to_string()),
                _ => {}
            }
        }
    }

    fn dispatch(&mut self, out: &mut Vec<SseEvent>) {
        if !self.data.is_empty() {
            out.push(SseEvent {
                event: self.event.take(),
                data: self.data.join("\n"),
            });
        }
        self.data.clear();
        self.event = None;
    }
}

/// Provider-specific translation from SSE events to [`StreamEvent`]s.
pub trait ChunkParser: Send {
    fn parse(&mut self, ev: &SseEvent) -> Result<Vec<StreamEvent>, AgentError>;
    /// Called at end of stream.
    fn finish(&mut self) -> Vec<StreamEvent> {
        Vec::new()
    }
}

struct SseState {
    bytes: BoxStream<'static, Result<Vec<u8>, reqwest::Error>>,
    decoder: SseDecoder,
    parser: Box<dyn ChunkParser>,
    pending: VecDeque<Result<StreamEvent, AgentError>>,
    cancel: CancellationToken,
    done: bool,
}

/// Turns an HTTP response into a [`ChatStream`] using `parser`.
pub(crate) fn sse_chat_stream(
    resp: reqwest::Response,
    parser: Box<dyn ChunkParser>,
    cancel: CancellationToken,
) -> ChatStream {
    let bytes = resp.bytes_stream().map(|r| r.map(|b| b.to_vec())).boxed();
    let state = SseState {
        bytes,
        decoder: SseDecoder::default(),
        parser,
        pending: VecDeque::new(),
        cancel,
        done: false,
    };
    stream::unfold(state, |mut st| async move {
        loop {
            if let Some(item) = st.pending.pop_front() {
                return Some((item, st));
            }
            if st.done {
                return None;
            }
            let next = tokio::select! {
                _ = st.cancel.cancelled() => {
                    st.done = true;
                    return Some((Err(AgentError::Cancelled), st));
                }
                n = st.bytes.next() => n,
            };
            match next {
                Some(Ok(chunk)) => {
                    for ev in st.decoder.push(&chunk) {
                        match st.parser.parse(&ev) {
                            Ok(evs) => st.pending.extend(evs.into_iter().map(Ok)),
                            Err(e) => {
                                st.pending.push_back(Err(e));
                                st.done = true;
                                break;
                            }
                        }
                    }
                }
                Some(Err(e)) => {
                    st.done = true;
                    st.pending
                        .push_back(Err(AgentError::Transport(e.to_string())));
                }
                None => {
                    st.done = true;
                    for ev in st.decoder.finish() {
                        match st.parser.parse(&ev) {
                            Ok(evs) => st.pending.extend(evs.into_iter().map(Ok)),
                            Err(e) => st.pending.push_back(Err(e)),
                        }
                    }
                    let tail = st.parser.finish();
                    st.pending.extend(tail.into_iter().map(Ok));
                }
            }
        }
    })
    .boxed()
}

/// Sends a request, mapping transport failures and non-2xx statuses to [`AgentError`].
pub(crate) async fn send(
    req: reqwest::RequestBuilder,
    cancel: &CancellationToken,
) -> Result<reqwest::Response, AgentError> {
    let resp = tokio::select! {
        _ = cancel.cancelled() => return Err(AgentError::Cancelled),
        r = req.send() => r.map_err(|e| AgentError::Transport(e.without_url().to_string()))?,
    };
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let mut body = resp.text().await.unwrap_or_default();
    body.truncate(body.floor_char_boundary(2000));
    Err(AgentError::Http {
        status: status.as_u16(),
        body,
    })
}

/// A secret that never prints.
#[derive(Clone)]
pub(crate) struct Secret(pub String);

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Checks a provider `base_url`: it must be `https`, or plain `http` only to a loopback host.
///
/// API keys travel in headers, so sending them over cleartext to a remote host is refused.
pub(crate) fn validate_base_url(raw: &str) -> Result<(), AgentError> {
    use std::net::IpAddr;
    let url = reqwest::Url::parse(raw)
        .map_err(|e| AgentError::Config(format!("invalid base_url {raw:?}: {e}")))?;
    match url.scheme() {
        "https" => Ok(()),
        "http" => {
            let loopback = match url.host_str() {
                Some(h) => {
                    let h = h.trim_start_matches('[').trim_end_matches(']');
                    h.eq_ignore_ascii_case("localhost")
                        || h.parse::<IpAddr>().is_ok_and(|a| a.is_loopback())
                }
                None => false,
            };
            if loopback {
                Ok(())
            } else {
                Err(AgentError::Config(format!(
                    "base_url {} must use https unless it points at localhost/loopback",
                    redact_url(&url)
                )))
            }
        }
        other => Err(AgentError::Config(format!(
            "base_url scheme {other:?} is not allowed; use https (or http to loopback)"
        ))),
    }
}

fn redact_url(u: &reqwest::Url) -> String {
    format!("{}://{}", u.scheme(), u.host_str().unwrap_or("?"))
}

pub(crate) fn http_client() -> Result<reqwest::Client, AgentError> {
    reqwest::Client::builder()
        // A redirect could carry `x-api-key` / `x-goog-api-key` to another origin.
        .redirect(reqwest::redirect::Policy::none())
        .user_agent(concat!("kraken-agent/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|e| AgentError::Config(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_requires_https_or_loopback() {
        for ok in [
            "https://api.anthropic.com",
            "https://example.com/v1",
            "http://localhost:11434/v1",
            "http://LOCALHOST/v1",
            "http://127.0.0.1:8080/v1",
            "http://127.9.9.9/v1",
            "http://[::1]:8080/v1",
        ] {
            assert!(validate_base_url(ok).is_ok(), "{ok}");
        }
        for bad in [
            "http://example.com/v1",
            "http://10.0.0.5:9000/v1",
            "http://localhost.evil.com/v1",
            "http://127.0.0.1.evil.com/v1",
            "ftp://localhost/v1",
            "file:///etc/passwd",
            "not a url",
            "",
        ] {
            assert!(
                matches!(validate_base_url(bad), Err(AgentError::Config(_))),
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn clients_do_not_follow_redirects() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = l.local_addr().unwrap().port();
        let srv = tokio::spawn(async move {
            let mut hits = 0;
            // Serve at most two connections; a followed redirect would make a second one.
            while let Ok(Ok((mut s, _))) =
                tokio::time::timeout(std::time::Duration::from_millis(500), l.accept()).await
            {
                hits += 1;
                let mut buf = [0u8; 2048];
                let _ = s.read(&mut buf).await;
                let _ = s
                    .write_all(
                        b"HTTP/1.1 302 Found\r\nLocation: /elsewhere\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await;
            }
            hits
        });
        let resp = http_client()
            .unwrap()
            .get(format!("http://127.0.0.1:{port}/"))
            .header("x-api-key", "k")
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 302);
        assert_eq!(srv.await.unwrap(), 1, "redirect must not be followed");
    }

    #[test]
    fn sse_decoder_handles_split_chunks_and_crlf() {
        let mut d = SseDecoder::default();
        let mut evs = d.push(b"event: a\r\ndata: {\"x\"");
        assert!(evs.is_empty());
        evs.extend(d.push(b":1}\r\n\r\n: comment\ndata: one\ndata: two\n\ndata: [DONE]"));
        evs.extend(d.finish());
        assert_eq!(evs.len(), 3);
        assert_eq!(evs[0].event.as_deref(), Some("a"));
        assert_eq!(evs[0].data, "{\"x\":1}");
        assert_eq!(evs[1].data, "one\ntwo");
        assert_eq!(evs[2].data, "[DONE]");
    }
}
