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
//! A prompt that contains `<kraken-result>` is an assistant task (explain, overview, auto-name):
//! the agent reads through KRAKEN tool calls and answers with prose and a result block shaped
//! for that task, like a real agent following the task prompt. `FAKE_ACP_TASK_PERMISSION=1`
//! makes such a turn ask for permission to run a shell command first.
//!
//! A prompt that contains `Task: automate` is the Automate task: the agent calls a few KRAKEN
//! tools, asks permission for `rewrite_program` and `rewrite_accept` (as Claude Code asks for
//! each MCP tool) and says which were allowed.
//!
//! A prompt that contains `<kraken-eval id="...">` is an evaluation task (`kraken eval`): the
//! agent replays the tool calls and the answer the JSON file named by `FAKE_ACP_EVAL_ANSWERS`
//! holds for that id.
//!
//! A prompt that starts with `KRAKEN text-only request.` is a text-only request (the rewrite
//! pipeline): the agent answers with the reply `FAKE_ACP_COMPLETION_ANSWERS` holds for it.
//!
//! `FAKE_ACP_SCRIPT=kraken` makes every other prompt play the `kraken` turn.
//! `FAKE_ACP_REQUIRE_AUTH=1` makes `session/new` fail with an authentication error.
//! `FAKE_ACP_ALLOW_NO_MCP=1` lets `session/new` succeed without the KRAKEN MCP server (the
//! settings' connection test starts agents without KRAKEN's tools).
//! `FAKE_ACP_RECORD=<file>` appends every message received, one JSON document per line.
//! `FAKE_ACP_MCP_CALLS=<json>` (an array of `{"name", "arguments"}`) makes every prompt first
//! start the KRAKEN MCP server `session/new` carried, as a real agent does, call those tools
//! through it and report each result in a chunk (`mcp <name>: ok|error <text>`).

use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Write};
use std::process::{Command, Stdio};

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
        let none_needed = std::env::var_os("FAKE_ACP_ALLOW_NO_MCP").is_some()
            && servers.as_array().is_some_and(Vec::is_empty);
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
        if !ok && !none_needed {
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

    /// Runs the tool calls of `FAKE_ACP_MCP_CALLS` through the KRAKEN MCP server of the session.
    fn mcp_calls(&mut self) -> io::Result<()> {
        let Some(spec) = std::env::var_os("FAKE_ACP_MCP_CALLS") else {
            return Ok(());
        };
        let calls: Vec<Value> = serde_json::from_str(&spec.to_string_lossy())
            .map_err(|e| io::Error::other(format!("FAKE_ACP_MCP_CALLS: {e}")))?;
        let server = self
            .mcp_servers
            .as_array()
            .and_then(|a| {
                a.iter()
                    .find(|s| s.get("name").and_then(Value::as_str) == Some("kraken"))
            })
            .cloned()
            .ok_or_else(|| io::Error::other("no kraken MCP server in session/new"))?;
        let text = |v: &Value| v.as_str().unwrap_or_default().to_string();
        let mut cmd = Command::new(text(&server["command"]));
        for a in server["args"].as_array().into_iter().flatten() {
            cmd.arg(text(a));
        }
        for e in server["env"].as_array().into_iter().flatten() {
            cmd.env(text(&e["name"]), text(&e["value"]));
        }
        if !self.cwd.is_empty() {
            cmd.current_dir(&self.cwd);
        }
        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("no stdin"))?;
        let mut stdout = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| io::Error::other("no stdout"))?,
        );
        let mut rpc = move |msg: Value| -> io::Result<Value> {
            writeln!(stdin, "{msg}")?;
            stdin.flush()?;
            let Some(want) = msg.get("id").cloned() else {
                return Ok(Value::Null);
            };
            loop {
                let mut line = String::new();
                if stdout.read_line(&mut line)? == 0 {
                    return Err(io::Error::other("the MCP server closed its output"));
                }
                if let Ok(v) = serde_json::from_str::<Value>(&line)
                    && v.get("id") == Some(&want)
                {
                    return Ok(v);
                }
            }
        };
        rpc(
            json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "fake-acp-agent", "version": "1.0"}
            }}),
        )?;
        rpc(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))?;
        let mut lines = Vec::new();
        for (i, call) in calls.iter().enumerate() {
            let name = text(&call["name"]);
            let r = rpc(
                json!({"jsonrpc": "2.0", "id": 2 + i, "method": "tools/call", "params": {
                    "name": name,
                    "arguments": call.get("arguments").cloned().unwrap_or_else(|| json!({}))
                }}),
            )?;
            let failed = r.get("error").is_some()
                || r.pointer("/result/isError").and_then(Value::as_bool) == Some(true);
            let detail = r
                .pointer("/result/content/0/text")
                .or_else(|| r.pointer("/error/message"))
                .map(text)
                .unwrap_or_default();
            let status = if failed { "error" } else { "ok" };
            lines.push(format!("mcp {name}: {status} {detail}\n"));
        }
        drop(rpc);
        let _ = child.wait();
        for l in lines {
            self.chunk(&l)?;
        }
        Ok(())
    }

    fn prompt(&mut self, id: &Value, params: &Value) -> io::Result<()> {
        let text = params
            .pointer("/prompt/0/text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        self.mcp_calls()?;
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
            _ if text.starts_with("KRAKEN text-only request.") => self.completion_turn(id, &text),
            _ if text.contains("<kraken-eval id=\"") => self.eval_turn(id, &text),
            _ if text.contains("Task: automate the work") => self.automate_turn(id),
            _ if text.contains("<kraken-result>") => self.task_turn(id, &text),
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

    /// A text-only request (the rewrite pipeline): the prompt starts with `KRAKEN text-only
    /// request.` and the whole job is the reply text. The answer comes from the JSON file named
    /// by `FAKE_ACP_COMPLETION_ANSWERS`: `[{"match": "text the prompt contains", "reply":
    /// "text"}]`; the first entry whose `match` occurs in the prompt wins, and a prompt no entry
    /// matches gets a reply with no answer block, as an agent that gave up would.
    ///
    /// `FAKE_ACP_COMPLETION_MISBEHAVE=<file>` makes the agent first ask for permission to write
    /// a file and to run a command, like an agent that wants to "just build it"; it creates
    /// `<file>` (the marker) for every request that is granted, and says so in its reply.
    fn completion_turn(&mut self, id: &Value, prompt: &str) -> io::Result<()> {
        if let Some(marker) = std::env::var_os("FAKE_ACP_COMPLETION_MISBEHAVE") {
            for (i, (title, kind)) in [
                ("Write translation.rs", "edit"),
                ("Run cargo build", "execute"),
            ]
            .into_iter()
            .enumerate()
            {
                let (answer, cancelled) = self.ask(
                    "session/request_permission",
                    json!({
                        "sessionId": SESSION_ID,
                        "toolCall": {
                            "toolCallId": format!("own{i}"),
                            "title": title,
                            "kind": kind,
                            "rawInput": {"command": "cargo build"}
                        },
                        "options": [
                            {"optionId": "allow", "name": "Allow once", "kind": "allow_once"},
                            {"optionId": "reject", "name": "Deny", "kind": "reject_once"}
                        ]
                    }),
                )?;
                if answer["result"]["outcome"]["optionId"].as_str() == Some("allow") {
                    let _ = std::fs::write(&marker, title);
                }
                if cancelled {
                    return self.end(id, "cancelled");
                }
            }
        }
        let answers: Value = std::env::var_os("FAKE_ACP_COMPLETION_ANSWERS")
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(Value::Null);
        let reply = answers
            .as_array()
            .into_iter()
            .flatten()
            .find(|e| e["match"].as_str().is_some_and(|m| prompt.contains(m)))
            .and_then(|e| e["reply"].as_str())
            .unwrap_or("I could not work this out.")
            .to_string();
        let mut rest = reply.as_str();
        while !rest.is_empty() {
            let mut cut = rest.len().min(200);
            while !rest.is_char_boundary(cut) {
                cut -= 1;
            }
            let (head, tail) = rest.split_at(cut);
            self.chunk(head)?;
            rest = tail;
        }
        self.end(id, "end_turn")
    }

    /// An evaluation task (`kraken eval`): the prompt names its task in
    /// `<kraken-eval id="...">`, and the answer comes from the JSON file named by
    /// `FAKE_ACP_EVAL_ANSWERS`: `{"<id>": {"tools": [{"name": "decompile", "arguments": {...}}],
    /// "answer": "text"}}`. A task the file does not know gets a reply with no answer block, as
    /// an agent that gave up would.
    fn eval_turn(&mut self, id: &Value, prompt: &str) -> io::Result<()> {
        let task = prompt
            .split_once("<kraken-eval id=\"")
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(task, _)| task.to_string())
            .unwrap_or_default();
        let script: Value = std::env::var_os("FAKE_ACP_EVAL_ANSWERS")
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or(Value::Null);
        let entry = &script[task.as_str()];
        self.chunk("Let me look at the program. ")?;
        for (i, call) in entry["tools"].as_array().into_iter().flatten().enumerate() {
            let name = call["name"].as_str().unwrap_or("project_info");
            self.tool(
                &format!("e{i}"),
                &format!("mcp__kraken__{name}"),
                call["arguments"].clone(),
                "ok",
            )?;
        }
        match entry["answer"].as_str() {
            Some(answer) => self.chunk(answer)?,
            None => self.chunk("I could not work this out.")?,
        }
        self.end(id, "end_turn")
    }

    /// The Automate task: a few tool calls, then a permission question for two tools.
    fn automate_turn(&mut self, id: &Value) -> io::Result<()> {
        self.chunk("Starting. ")?;
        self.tool("a1", "mcp__kraken__project_info", json!({}), "{}")?;
        for (n, name) in ["rewrite_program", "rewrite_accept"].iter().enumerate() {
            let (answer, cancelled) = self.ask(
                "session/request_permission",
                json!({
                    "sessionId": SESSION_ID,
                    "toolCall": {
                        "toolCallId": format!("p{n}"),
                        "title": format!("mcp__kraken__{name}"),
                        "kind": "other",
                        "rawInput": {}
                    },
                    "options": [
                        {"optionId": "allow", "name": "Allow once", "kind": "allow_once"},
                        {"optionId": "reject", "name": "Deny", "kind": "reject_once"}
                    ]
                }),
            )?;
            if cancelled {
                return self.end(id, "cancelled");
            }
            let granted = answer["result"]["outcome"]["optionId"].as_str() == Some("allow");
            self.chunk(&format!(
                "({name} {}) ",
                if granted { "allowed" } else { "denied" }
            ))?;
        }
        self.chunk("Finished. Accepting units is for the person.")?;
        self.end(id, "end_turn")
    }

    /// An assistant task: KRAKEN tool calls, then prose and the `<kraken-result>` block.
    fn task_turn(&mut self, id: &Value, prompt: &str) -> io::Result<()> {
        if std::env::var_os("FAKE_ACP_TASK_PERMISSION").is_some() {
            let (answer, cancelled) = self.ask(
                "session/request_permission",
                json!({
                    "sessionId": SESSION_ID,
                    "toolCall": {
                        "toolCallId": "own1",
                        "title": "Run strings ./sample",
                        "kind": "execute",
                        "rawInput": {"command": "strings ./sample"}
                    },
                    "options": [
                        {"optionId": "allow", "name": "Allow once", "kind": "allow_once"},
                        {"optionId": "reject", "name": "Deny", "kind": "reject_once"}
                    ]
                }),
            )?;
            let granted = answer["result"]["outcome"]["optionId"].as_str() == Some("allow");
            self.chunk(if granted {
                "(shell allowed) "
            } else {
                "(shell denied) "
            })?;
            if cancelled {
                return self.end(id, "cancelled");
            }
        }
        self.chunk("Let me look at the program. ")?;
        let (prose, result) = if prompt.contains("Task: explain one function") {
            self.tool(
                "t1",
                "mcp__kraken__get_function",
                json!({"address": "0x401000"}),
                "{\"name\":\"FUN_00401000\"}",
            )?;
            self.tool(
                "t2",
                "mcp__kraken__decompile",
                json!({"address": "0x401000"}),
                "int FUN_00401000(int argc) { return helper(argc); }",
            )?;
            (
                "This is the program's starting function.",
                json!({
                    "summary": "It calls a helper and returns its answer.",
                    "key_behaviours": ["calls helper with its first argument", "returns the result"],
                    "suggested_names": [{"name": "program_main", "reason": "takes argc"}],
                    "caveats": []
                }),
            )
        } else if prompt.contains("Task: explain a selection") {
            (
                "The selection calls a helper.",
                json!({
                    "summary": "It calls helper and stores the result in x.",
                    "key_behaviours": ["calls helper"],
                    "suggested_names": [],
                    "caveats": ["only the selection was read"]
                }),
            )
        } else if prompt.contains("Task: give a first overview") {
            self.tool(
                "t1",
                "mcp__kraken__project_info",
                json!({}),
                "{\"analysis\":\"complete\"}",
            )?;
            self.tool(
                "t2",
                "mcp__kraken__list_functions",
                json!({"limit": 50}),
                "{\"items\":[]}",
            )?;
            (
                "A tiny test program.",
                json!({
                    "what_it_is": "A small command-line program.",
                    "components": [{"name": "entry", "description": "starts the program"}],
                    "interesting_functions": [
                        {"address": "0x401000", "name": "FUN_00401000", "reason": "takes argc and argv"}
                    ],
                    "next_steps": ["Ask for an explanation of the first function"]
                }),
            )
        } else {
            self.tool(
                "t1",
                "mcp__kraken__list_functions",
                json!({"name_filter": "FUN_"}),
                "{\"items\":[]}",
            )?;
            self.tool(
                "t2",
                "mcp__kraken__decompile",
                json!({"address": "0x401000"}),
                "int FUN_00401000(int argc) { return helper(argc); }",
            )?;
            if !prompt.contains("This is a dry run") {
                self.tool(
                    "t3",
                    "mcp__kraken__rename_symbol",
                    json!({"address": "0x401000", "new_name": "program_main"}),
                    "{\"status\":\"applied\",\"entry_id\":1}",
                )?;
                self.tool(
                    "t4",
                    "mcp__kraken__set_comment",
                    json!({"address": "0x401000", "kind": "plate", "text": "Program entry."}),
                    "{\"status\":\"applied\",\"entry_id\":2}",
                )?;
                self.tool(
                    "t5",
                    "mcp__kraken__rename_symbol",
                    json!({"address": "0x401040", "new_name": "assistant_guess"}),
                    "{\"status\":\"proposed\",\"proposal_id\":7,\"key\":\"name@0x401040\",\"reason\":\"overwrites a user edit\"}",
                )?;
            }
            (
                "Named one function.",
                json!({"suggestions": [
                    {"address": "0x401000", "current_name": "FUN_00401000",
                     "new_name": "program_main", "comment": "Program entry.",
                     "evidence": [
                        {"kind": "string", "detail": "usage text"},
                        {"kind": "import", "detail": "puts"},
                        {"kind": "caller", "detail": "called from the entry stub"}
                     ]},
                    {"address": "0x401040", "new_name": "assistant_guess",
                     "evidence": [{"kind": "decompile", "detail": "short body"}]}
                ]}),
            )
        };
        self.chunk(&format!("{prose}\n<krak"))?;
        self.chunk(&format!("en-result>{result}</kraken-"))?;
        self.chunk("result>")?;
        self.end(id, "end_turn")
    }

    fn end(&mut self, id: &Value, reason: &str) -> io::Result<()> {
        self.respond(id, json!({"stopReason": reason}))
    }
}
