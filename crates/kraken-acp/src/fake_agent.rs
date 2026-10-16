//! A fake ACP agent for tests: newline-delimited JSON-RPC over stdio, written by hand (not with
//! the ACP crate) so the host is checked against the wire format, not against itself.
//!
//! It implements the subset KRAKEN uses: `initialize`, `session/new` (which must carry KRAKEN's
//! MCP server, or it answers with an error), `session/prompt` with streamed `session/update`
//! notifications, a `session/request_permission` round trip, and `session/cancel`.
//!
//! The prompt text picks the behaviour:
//!
//! - anything else: a chunk, a tool call, a plan, a permission request, the tool result, a chunk
//! - `report`: one chunk describing what `session/new` carried
//! - `env`: one chunk listing the interesting environment variable names it can see
//! - `fs`: tries `fs/write_text_file` and says whether the client declined
//! - `wait`: streams a chunk, then waits for `session/cancel` and ends with `cancelled`
//! - `kraken`: a session like a real one: KRAKEN MCP tool calls, then the agent's own shell tool
//!   waiting for permission
//! - `die`: exits with status 7 without answering
//!
//! `FAKE_ACP_SCRIPT=kraken` makes every other prompt play the `kraken` turn.
//! `FAKE_ACP_REQUIRE_AUTH=1` makes `session/new` fail with an authentication error.
//! `FAKE_ACP_RECORD=<file>` appends every message received, one JSON document per line.

use std::fs::OpenOptions;
use std::io::{self, BufRead, Write};

use serde_json::{Value, json};

const SESSION_ID: &str = "fake-session-1";

struct Fake<R, W> {
    input: R,
    output: W,
    next_id: u64,
    record: Option<std::fs::File>,
    mcp_servers: Value,
    client_caps: Value,
    cwd: String,
}

/// Runs the fake agent until its input ends.
pub fn serve(input: impl BufRead, output: impl Write) -> io::Result<()> {
    let record = std::env::var_os("FAKE_ACP_RECORD")
        .and_then(|p| OpenOptions::new().create(true).append(true).open(p).ok());
    Fake {
        input,
        output,
        next_id: 1000,
        record,
        mcp_servers: Value::Null,
        client_caps: Value::Null,
        cwd: String::new(),
    }
    .run()
}

impl<R: BufRead, W: Write> Fake<R, W> {
    fn read(&mut self) -> io::Result<Option<Value>> {
        loop {
            let mut line = String::new();
            if self.input.read_line(&mut line)? == 0 {
                return Ok(None);
            }
            if line.trim().is_empty() {
                continue;
            }
            let v: Value = serde_json::from_str(line.trim())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            if let Some(f) = self.record.as_mut() {
                writeln!(f, "{v}")?;
            }
            return Ok(Some(v));
        }
    }

    fn send(&mut self, v: &Value) -> io::Result<()> {
        writeln!(self.output, "{v}")?;
        self.output.flush()
    }

    fn respond(&mut self, id: &Value, result: Value) -> io::Result<()> {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "result": result}))
    }

    fn fail(&mut self, id: &Value, code: i64, message: &str) -> io::Result<()> {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}))
    }

    fn update(&mut self, update: Value) -> io::Result<()> {
        self.send(&json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {"sessionId": SESSION_ID, "update": update}
        }))
    }

    fn chunk(&mut self, text: &str) -> io::Result<()> {
        self.update(json!({
            "sessionUpdate": "agent_message_chunk",
            "content": {"type": "text", "text": text}
        }))
    }

    /// Sends a request to the client and waits for its answer. A `session/cancel` that arrives
    /// meanwhile is remembered in the returned flag; the answer is still awaited.
    fn ask(&mut self, method: &str, params: Value) -> io::Result<(Value, bool)> {
        let id = self.next_id;
        self.next_id += 1;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;
        let mut cancelled = false;
        loop {
            let Some(msg) = self.read()? else {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "client went away",
                ));
            };
            if msg.get("method").and_then(Value::as_str) == Some("session/cancel") {
                cancelled = true;
                continue;
            }
            if msg.get("id") == Some(&json!(id)) && msg.get("method").is_none() {
                return Ok((msg, cancelled));
            }
        }
    }

    fn run(&mut self) -> io::Result<()> {
        while let Some(msg) = self.read()? {
            let Some(method) = msg
                .get("method")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                continue;
            };
            let id = msg.get("id").cloned();
            let params = msg.get("params").cloned().unwrap_or(Value::Null);
            match (method.as_str(), id) {
                ("initialize", Some(id)) => self.initialize(&id, &params)?,
                ("session/new", Some(id)) => self.new_session(&id, &params)?,
                ("session/prompt", Some(id)) => self.prompt(&id, &params)?,
                ("session/cancel", None) => {}
                (_, Some(id)) => self.fail(&id, -32601, &format!("method not found: {method}"))?,
                _ => {}
            }
        }
        Ok(())
    }

    fn initialize(&mut self, id: &Value, params: &Value) -> io::Result<()> {
        self.client_caps = params
            .get("clientCapabilities")
            .cloned()
            .unwrap_or(Value::Null);
        let fs = &self.client_caps["fs"];
        let advertised = fs["readTextFile"] == json!(true)
            || fs["writeTextFile"] == json!(true)
            || self.client_caps["terminal"] == json!(true);
        if advertised {
            return self.fail(
                id,
                -32602,
                "the client advertised fs or terminal capabilities; KRAKEN must not",
            );
        }
        self.respond(
            id,
            json!({
                "protocolVersion": 1,
                "agentCapabilities": {
                    "loadSession": false,
                    "promptCapabilities": {},
                    "mcpCapabilities": {"http": false, "sse": false}
                },
                "authMethods": [{"id": "fake-login", "name": "Fake login"}],
                "agentInfo": {"name": "kraken-fake-acp-agent", "title": "Fake agent", "version": "0.0.0"}
            }),
        )
    }

    fn new_session(&mut self, id: &Value, params: &Value) -> io::Result<()> {
        if std::env::var_os("FAKE_ACP_REQUIRE_AUTH").is_some() {
            return self.fail(id, -32000, "Authentication required");
        }
        let servers = params.get("mcpServers").cloned().unwrap_or(Value::Null);
        let kraken = servers.as_array().and_then(|a| {
            a.iter()
                .find(|s| s.get("name").and_then(Value::as_str) == Some("kraken"))
        });
        let ok = kraken.is_some_and(|s| {
            s.get("command")
                .and_then(Value::as_str)
                .is_some_and(|c| !c.is_empty())
                && s.get("args")
                    .and_then(Value::as_array)
                    .and_then(|a| a.first())
                    .and_then(Value::as_str)
                    == Some("mcp")
        });
        if !ok {
            return self.fail(
                id,
                -32602,
                "session/new did not include the `kraken` stdio MCP server running `mcp`",
            );
        }
        let cwd = params
            .get("cwd")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if !std::path::Path::new(cwd).is_absolute() {
            return self.fail(id, -32602, "session/new needs an absolute cwd");
        }
        self.cwd = cwd.to_string();
        self.mcp_servers = servers;
        self.respond(
            id,
            json!({
                "sessionId": SESSION_ID,
                "configOptions": [{
                    "id": "model",
                    "name": "Model",
                    "category": "model",
                    "type": "select",
                    "currentValue": "fake-1",
                    "options": [
                        {"value": "fake-1", "name": "Fake model 1"},
                        {"value": "fake-2", "name": "Fake model 2"}
                    ]
                }]
            }),
        )
    }

    fn prompt(&mut self, id: &Value, params: &Value) -> io::Result<()> {
        let text = params
            .pointer("/prompt/0/text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        match text.as_str() {
            "report" => {
                let report = json!({
                    "cwd": self.cwd,
                    "mcpServers": self.mcp_servers,
                    "clientCapabilities": self.client_caps,
                });
                self.chunk(&report.to_string())?;
                self.end(id, "end_turn")
            }
            "env" => {
                let mut names: Vec<String> = std::env::vars_os()
                    .map(|(k, _)| k.to_string_lossy().into_owned())
                    .filter(|k| {
                        k.starts_with("KRAKEN_")
                            || k.starts_with("SECRET_")
                            || k.starts_with("ANTHROPIC_")
                            || k == "FAKE_ACP_EXTRA"
                            || k == "HOME"
                    })
                    .collect();
                names.sort();
                self.chunk(&format!("env: {}", names.join(",")))?;
                self.end(id, "end_turn")
            }
            "fs" => {
                let (resp, _) = self.ask(
                    "fs/write_text_file",
                    json!({"sessionId": SESSION_ID, "path": "/tmp/kraken-fake.txt", "content": "x"}),
                )?;
                let declined = resp.get("error").is_some();
                self.chunk(if declined {
                    "fs write: declined"
                } else {
                    "fs write: accepted"
                })?;
                self.end(id, "end_turn")
            }
            "wait" => {
                self.chunk("waiting for cancel")?;
                loop {
                    let Some(msg) = self.read()? else {
                        return Ok(());
                    };
                    if msg.get("method").and_then(Value::as_str) == Some("session/cancel") {
                        break;
                    }
                }
                self.end(id, "cancelled")
            }
            "die" => std::process::exit(7),
            "kraken" => self.kraken_turn(id),
            _ if std::env::var("FAKE_ACP_SCRIPT").as_deref() == Ok("kraken") => {
                self.kraken_turn(id)
            }
            _ => self.scripted_turn(id),
        }
    }

    fn scripted_turn(&mut self, id: &Value) -> io::Result<()> {
        self.chunk("Hello ")?;
        self.chunk("from the fake agent. ")?;
        self.update(json!({
            "sessionUpdate": "agent_thought_chunk",
            "content": {"type": "text", "text": "thinking about main.c"}
        }))?;
        self.update(json!({
            "sessionUpdate": "tool_call",
            "toolCallId": "call-1",
            "title": "Run rm -rf build",
            "kind": "execute",
            "status": "pending",
            "locations": [{"path": "/tmp/project/build"}],
            "rawInput": {"command": "rm -rf build"}
        }))?;
        self.update(json!({
            "sessionUpdate": "plan",
            "entries": [
                {"content": "Clean the build", "priority": "high", "status": "in_progress"},
                {"content": "Rebuild", "priority": "medium", "status": "pending"}
            ]
        }))?;
        let (answer, cancelled) = self.ask(
            "session/request_permission",
            json!({
                "sessionId": SESSION_ID,
                "toolCall": {
                    "toolCallId": "call-1",
                    "title": "Run rm -rf build",
                    "kind": "execute",
                    "rawInput": {"command": "rm -rf build"}
                },
                "options": [
                    {"optionId": "allow", "name": "Allow once", "kind": "allow_once"},
                    {"optionId": "reject", "name": "Reject", "kind": "reject_once"}
                ]
            }),
        )?;
        let outcome = &answer["result"]["outcome"];
        let verdict = match (outcome["outcome"].as_str(), outcome["optionId"].as_str()) {
            (Some("selected"), Some("allow")) => "granted",
            (Some("selected"), _) => "denied",
            _ => "cancelled",
        };
        self.update(json!({
            "sessionUpdate": "tool_call_update",
            "toolCallId": "call-1",
            "status": if verdict == "granted" { "completed" } else { "failed" },
            "content": [{"type": "content", "content": {"type": "text", "text": format!("permission {verdict}")}}]
        }))?;
        self.chunk(&format!("permission {verdict}."))?;
        self.end(id, if cancelled { "cancelled" } else { "end_turn" })
    }

    fn tool(&mut self, id: &str, title: &str, input: Value, output: &str) -> io::Result<()> {
        self.update(json!({
            "sessionUpdate": "tool_call",
            "toolCallId": id,
            "title": title,
            "kind": "other",
            "status": "in_progress",
            "rawInput": input
        }))?;
        self.update(json!({
            "sessionUpdate": "tool_call_update",
            "toolCallId": id,
            "status": "completed",
            "content": [{"type": "content", "content": {"type": "text", "text": output}}]
        }))
    }

    /// KRAKEN MCP tool calls (named like Claude Code names them), then a shell command that
    /// needs permission, then the answer.
    fn kraken_turn(&mut self, id: &Value) -> io::Result<()> {
        self.chunk("I'll start with the function the program enters at.\n\n")?;
        self.tool(
            "k2",
            "mcp__kraken__decompile",
            json!({"address": "0x401340"}),
            "void FUN_00401340(void) { ... }",
        )?;
        self.chunk(
            "`FUN_00401340` prints a message and exits, so it looks like a fatal error handler. I'll name it and then check the strings in the file.",
        )?;
        self.tool(
            "k3",
            "mcp__kraken__rename_symbol",
            json!({"address": "0x401340", "new_name": "fatal_error_exit"}),
            "renamed",
        )?;
        self.update(json!({
            "sessionUpdate": "tool_call",
            "toolCallId": "s1",
            "title": "Run strings -n 8 ./sample",
            "kind": "execute",
            "status": "pending",
            "rawInput": {"command": "strings -n 8 ./sample"}
        }))?;
        let (answer, cancelled) = self.ask(
            "session/request_permission",
            json!({
                "sessionId": SESSION_ID,
                "toolCall": {
                    "toolCallId": "s1",
                    "title": "Run strings -n 8 ./sample",
                    "kind": "execute",
                    "rawInput": {"command": "strings -n 8 ./sample"}
                },
                "options": [
                    {"optionId": "allow", "name": "Allow once", "kind": "allow_once"},
                    {"optionId": "reject", "name": "Deny", "kind": "reject_once"}
                ]
            }),
        )?;
        let outcome = &answer["result"]["outcome"];
        let granted = outcome["optionId"].as_str() == Some("allow");
        self.update(json!({
            "sessionUpdate": "tool_call_update",
            "toolCallId": "s1",
            "status": if granted { "completed" } else { "failed" },
            "content": [{"type": "content", "content": {"type": "text", "text": if granted { "ran" } else { "not run" }}}]
        }))?;
        self.chunk(if granted {
            "\n\nDone: the strings match the error handler."
        } else {
            "\n\nUnderstood, I did not run the command."
        })?;
        self.end(id, if cancelled { "cancelled" } else { "end_turn" })
    }

    fn end(&mut self, id: &Value, reason: &str) -> io::Result<()> {
        self.respond(id, json!({"stopReason": reason}))
    }
}
