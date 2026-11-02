//! An ACP agent made of a command-line tool that has no ACP mode.
//!
//! `kraken agents bridge` speaks ACP on stdin and stdout and runs the tool once per turn in its
//! print mode, so a tool like this gets everything a real ACP agent gets: the chat, tool chips,
//! Stop and a session that goes on. Two kinds of tool are understood:
//!
//! - [`BridgeStyle::Agy`], Google Antigravity's `agy`: its `stream-json` output carries text and
//!   tool steps, and `--conversation` continues a conversation on its side.
//! - [`BridgeStyle::Text`], any other tool: `{prompt}` in its arguments becomes the message (or
//!   the message goes to its stdin), and what it prints is the answer. Such a tool remembers
//!   nothing, so the bridge sends the conversation so far with every message.
//!
//! `agy` takes its MCP servers and permission rules from its own global configuration only, and
//! in print mode it refuses what it may not do, since it cannot ask. The bridge adds KRAKEN's
//! server and one rule that allows that server alone for the length of a turn, and removes both
//! again, so the person's configuration is left as it was.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use serde_json::{Value, json};

const SESSION_ID: &str = "bridge-session";
/// The name KRAKEN's server has in `agy`'s configuration. Tools reach the agent under it, and it
/// differs from any server called `kraken` the person may have set up themselves.
const AGY_SERVER: &str = "kraken-assistant";
/// The rule that lets `agy` use KRAKEN's server, and nothing else, in print mode.
const AGY_RULE: &str = "mcp(kraken-assistant/*)";
/// The placeholder for the message in a tool's arguments.
pub const PROMPT_PLACEHOLDER: &str = "{prompt}";

/// How a tool is driven.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeStyle {
    /// Google Antigravity's `agy`.
    Agy,
    /// Any tool that takes a message and prints an answer.
    Text,
}

impl BridgeStyle {
    /// The value of `--style`.
    pub fn as_str(self) -> &'static str {
        match self {
            BridgeStyle::Agy => "agy",
            BridgeStyle::Text => "text",
        }
    }

    /// The style called `s`.
    pub fn parse(s: &str) -> Option<Self> {
        [BridgeStyle::Agy, BridgeStyle::Text]
            .into_iter()
            .find(|b| b.as_str() == s)
    }
}

/// The ACP updates of one line of `agy --output-format stream-json`, or the failure it reports.
pub fn agy_line(line: &str, conversation: &mut Option<String>) -> Result<Vec<Value>, String> {
    let Ok(v) = serde_json::from_str::<Value>(line) else {
        return Ok(Vec::new());
    };
    match v["event"].as_str() {
        Some("init") => {
            if let Some(id) = v["conversation_id"].as_str() {
                *conversation = Some(id.to_string());
            }
            Ok(Vec::new())
        }
        Some("result") => match v["result"]["status"].as_str() {
            Some("SUCCESS") | None => Ok(agy_refused(&v["result"])),
            Some(status) => Err(v["result"]["error"].as_str().map_or_else(
                || format!("the agent stopped with {status}"),
                str::to_string,
            )),
        },
        Some("step_update") => Ok(agy_step(&v["step_update"])),
        _ => Ok(Vec::new()),
    }
}

/// Says what `agy` refused by its own rules: a tool that just failed would explain nothing.
fn agy_refused(result: &Value) -> Vec<Value> {
    let names: Vec<&str> = result["denied_actions"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|a| a["display_name"].as_str().or(a["action"].as_str()))
        .collect();
    if names.is_empty() {
        return Vec::new();
    }
    vec![chunk(&format!(
        "\n\n(Antigravity's own rules refused: {}. It cannot ask in this mode; allow it under \
         `permissions.allow` in its settings.json to use it here.)",
        names.join(", ")
    ))]
}

/// A tool's name and input as KRAKEN should see them: a call to KRAKEN's server under the name
/// other agents give it.
fn agy_tool(name: &str, input: &Value) -> (String, Value) {
    if name == "call_mcp_tool"
        && input["ServerName"] == AGY_SERVER
        && let Some(tool) = input["ToolName"].as_str()
    {
        return (format!("mcp__kraken__{tool}"), input["Arguments"].clone());
    }
    (name.to_string(), input.clone())
}

fn agy_step(s: &Value) -> Vec<Value> {
    match s["step_type"].as_str() {
        Some("agent_response") => s["text_delta"]
            .as_str()
            .filter(|t| !t.is_empty())
            .map(chunk)
            .into_iter()
            .collect(),
        Some("tool") => {
            let id = format!("step-{}", s["step_index"].as_u64().unwrap_or(0));
            let info = &s["tool_info"];
            let name = s["tool_name"].as_str().unwrap_or("tool");
            match s["state"].as_str() {
                Some("ACTIVE") => {
                    let (title, input) = agy_tool(name, &info["parameters"]);
                    vec![json!({
                        "sessionUpdate": "tool_call",
                        "toolCallId": id,
                        "title": title,
                        "kind": "other",
                        "status": "in_progress",
                        "rawInput": input,
                    })]
                }
                Some(state) => vec![json!({
                    "sessionUpdate": "tool_call_update",
                    "toolCallId": id,
                    "status": if state == "DONE" { "completed" } else { "failed" },
                    "content": [{"type": "content", "content": {
                        "type": "text",
                        "text": info["output"]
                            .as_str()
                            .or(info["error"]["message"].as_str())
                            .unwrap_or(state),
                    }}],
                })],
                None => Vec::new(),
            }
        }
        _ => Vec::new(),
    }
}

fn chunk(text: &str) -> Value {
    json!({
        "sessionUpdate": "agent_message_chunk",
        "content": {"type": "text", "text": text},
    })
}

/// A plain tool's arguments with the message in place; `None` when it has no placeholder, and
/// reads the message from its stdin.
pub fn with_prompt(args: &[String], prompt: &str) -> Option<Vec<String>> {
    args.iter()
        .any(|a| a.contains(PROMPT_PLACEHOLDER))
        .then(|| {
            args.iter()
                .map(|a| a.replace(PROMPT_PLACEHOLDER, prompt))
                .collect()
        })
}

/// What a tool without a memory is sent: the conversation so far, then the message.
pub fn with_history(turns: &[(String, String)], prompt: &str) -> String {
    if turns.is_empty() {
        return prompt.to_string();
    }
    let mut out = String::from("The conversation so far:\n");
    for (person, you) in turns {
        out.push_str(&format!("Person: {person}\nYou: {you}\n"));
    }
    out.push_str(&format!("\n---\n\n{prompt}"));
    out
}

/// The text of a prompt request. A tool without ACP takes words only.
fn prompt_text(params: &Value) -> String {
    let blocks = params["prompt"].as_array().map_or(&[][..], Vec::as_slice);
    let mut text: Vec<&str> = blocks.iter().filter_map(|b| b["text"].as_str()).collect();
    if blocks.iter().any(|b| b["type"] == "image") {
        text.insert(
            0,
            "(A picture was attached, but it cannot reach this agent.)",
        );
    }
    text.join("\n\n")
}

/// `settings` with KRAKEN's rule added; `None` when it is there already or the file is not one
/// the bridge understands, which only costs KRAKEN's tools.
fn with_rule(settings: &str) -> Option<String> {
    let mut v: Value = if settings.trim().is_empty() {
        json!({})
    } else {
        serde_json::from_str(settings).ok()?
    };
    let allow = v
        .as_object_mut()?
        .entry("permissions")
        .or_insert_with(|| json!({}))
        .as_object_mut()?
        .entry("allow")
        .or_insert_with(|| json!([]))
        .as_array_mut()?;
    if allow.iter().any(|r| r == AGY_RULE) {
        return None;
    }
    allow.push(json!(AGY_RULE));
    serde_json::to_string_pretty(&v).ok()
}

/// `settings` without KRAKEN's rule, however else it changed meanwhile.
fn without_rule(settings: &str) -> Option<String> {
    let mut v: Value = serde_json::from_str(settings).ok()?;
    v.pointer_mut("/permissions/allow")?
        .as_array_mut()?
        .retain(|r| r != AGY_RULE);
    serde_json::to_string_pretty(&v).ok()
}

/// `agy`'s settings file.
fn agy_settings() -> Option<PathBuf> {
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".gemini/antigravity-cli/settings.json"))
}

/// `agy mcp add` arguments for KRAKEN's server, from ACP's `mcpServers`.
fn agy_mcp_add(server: &Value) -> Option<Vec<String>> {
    let command = server["command"].as_str()?;
    let mut args = vec!["mcp".to_string(), "add".to_string()];
    for e in server["env"].as_array().into_iter().flatten() {
        args.push("--env".into());
        args.push(format!(
            "{}={}",
            e["name"].as_str()?,
            e["value"].as_str().unwrap_or_default()
        ));
    }
    args.extend([
        AGY_SERVER.to_string(),
        "--".to_string(),
        command.to_string(),
    ]);
    for a in server["args"].as_array().into_iter().flatten() {
        args.push(a.as_str()?.to_string());
    }
    Some(args)
}

#[derive(Clone)]
struct Out(Arc<Mutex<io::Stdout>>);

impl Out {
    fn send(&self, msg: &Value) {
        let mut out = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let _ = writeln!(out, "{msg}");
        let _ = out.flush();
    }

    fn update(&self, update: Value) {
        self.send(&json!({
            "jsonrpc": "2.0",
            "method": "session/update",
            "params": {"sessionId": SESSION_ID, "update": update},
        }));
    }

    fn respond(&self, id: &Value, result: Value) {
        self.send(&json!({"jsonrpc": "2.0", "id": id, "result": result}));
    }

    fn fail(&self, id: &Value, code: i64, message: &str) {
        self.send(&json!({
            "jsonrpc": "2.0", "id": id,
            "error": {"code": code, "message": message},
        }));
    }
}

/// What lasts between turns.
#[derive(Default)]
struct Memory {
    conversation: Option<String>,
    turns: Vec<(String, String)>,
}

struct Bridge {
    style: BridgeStyle,
    program: PathBuf,
    args: Vec<String>,
    cwd: Mutex<Option<PathBuf>>,
    /// KRAKEN's MCP server, as `agy mcp add` arguments.
    mcp: Mutex<Option<Vec<String>>>,
    memory: Mutex<Memory>,
    child: Mutex<Option<Child>>,
    stopped: AtomicBool,
    out: Out,
}

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Bridge {
    fn command(&self, args: &[String]) -> Command {
        let mut c = Command::new(&self.program);
        c.args(args);
        if let Some(dir) = &*lock(&self.cwd) {
            c.current_dir(dir);
        }
        c
    }

    /// Runs `agy mcp ...`. Without it the agent only lacks KRAKEN's tools, so a failure is not
    /// the end of the turn.
    fn agy_mcp(&self, args: &[String]) {
        let _ = self
            .command(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }

    /// Starts the tool for `prompt`; the second value is what goes to its stdin.
    fn spawn(&self, prompt: &str) -> io::Result<(Child, Option<String>)> {
        let (args, stdin) = match self.style {
            BridgeStyle::Agy => {
                let mut a = vec![
                    "--print".to_string(),
                    prompt.to_string(),
                    "--output-format".to_string(),
                    "stream-json".to_string(),
                ];
                a.extend(self.args.iter().cloned());
                if let Some(id) = &lock(&self.memory).conversation {
                    a.push("--conversation".into());
                    a.push(id.clone());
                }
                (a, None)
            }
            BridgeStyle::Text => {
                let message = with_history(&lock(&self.memory).turns, prompt);
                match with_prompt(&self.args, &message) {
                    Some(a) => (a, None),
                    None => (self.args.clone(), Some(message)),
                }
            }
        };
        let child = self
            .command(&args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        Ok((child, stdin))
    }

    fn turn(&self, id: &Value, prompt: &str) {
        let mcp = lock(&self.mcp).clone();
        let settings = mcp.is_some().then(agy_settings).flatten();
        let mut added_rule = false;
        if let Some(add) = &mcp {
            self.agy_mcp(add);
            if let Some(path) = &settings {
                let old = std::fs::read_to_string(path).unwrap_or_default();
                added_rule = with_rule(&old).is_some_and(|t| std::fs::write(path, t).is_ok());
            }
        }
        let result = self.run_tool(prompt);
        if mcp.is_some() {
            self.agy_mcp(&["mcp".into(), "remove".into(), AGY_SERVER.into()]);
        }
        if added_rule
            && let Some(path) = &settings
            && let Some(t) = std::fs::read_to_string(path)
                .ok()
                .and_then(|t| without_rule(&t))
        {
            let _ = std::fs::write(path, t);
        }
        if self.stopped.swap(false, Ordering::SeqCst) {
            self.out.respond(id, json!({"stopReason": "cancelled"}));
            return;
        }
        match result {
            Ok(answer) => {
                lock(&self.memory).turns.push((prompt.to_string(), answer));
                self.out.respond(id, json!({"stopReason": "end_turn"}));
            }
            Err(why) => self.out.fail(id, -32000, &why),
        }
    }

    /// Runs the tool and streams its output; returns all it said.
    fn run_tool(&self, prompt: &str) -> Result<String, String> {
        let name = self.program.display().to_string();
        let (mut child, input) = self
            .spawn(prompt)
            .map_err(|e| format!("{name} could not be started: {e}"))?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        let mut stdin = child.stdin.take();
        *lock(&self.child) = Some(child);
        if let (Some(mut pipe), Some(text)) = (stdin.take(), input) {
            std::thread::spawn(move || {
                let _ = pipe.write_all(text.as_bytes());
            });
        }
        let errors = std::thread::spawn(move || {
            let mut text = String::new();
            if let Some(mut e) = stderr {
                let _ = e.read_to_string(&mut text);
            }
            text
        });
        let mut said = String::new();
        let mut failed = None;
        for line in stdout.into_iter().flat_map(|s| BufReader::new(s).lines()) {
            let Ok(line) = line else { break };
            match self.style {
                BridgeStyle::Agy => {
                    let mut conversation = lock(&self.memory).conversation.clone();
                    match agy_line(&line, &mut conversation) {
                        Ok(updates) => {
                            for u in updates {
                                if let Some(t) = u.pointer("/content/text").and_then(Value::as_str)
                                {
                                    said.push_str(t);
                                }
                                self.out.update(u);
                            }
                        }
                        Err(why) => failed = Some(why),
                    }
                    lock(&self.memory).conversation = conversation;
                }
                BridgeStyle::Text => {
                    let text = format!("{line}\n");
                    said.push_str(&text);
                    self.out.update(chunk(&text));
                }
            }
        }
        let status = lock(&self.child).take().and_then(|mut c| c.wait().ok());
        let errors = errors.join().unwrap_or_default();
        if let Some(why) = failed {
            return Err(why);
        }
        match status {
            Some(s) if !s.success() => {
                let tail: Vec<&str> = errors.lines().rev().take(4).collect();
                let tail: Vec<&str> = tail.into_iter().rev().collect();
                Err(format!("{name} failed ({s}): {}", tail.join(" ")))
            }
            _ => Ok(said),
        }
    }

    fn stop(&self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Some(c) = lock(&self.child).as_mut() {
            let _ = c.kill();
        }
    }

    fn new_session(&self, params: &Value) {
        *lock(&self.cwd) = params["cwd"].as_str().map(PathBuf::from);
        if self.style == BridgeStyle::Agy {
            *lock(&self.mcp) = params["mcpServers"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["command"].is_string()))
                .and_then(agy_mcp_add);
        }
    }
}

/// Serves ACP on this process's stdin and stdout until the client goes away.
pub fn run(style: BridgeStyle, program: &Path, args: Vec<String>) -> io::Result<()> {
    let bridge = Arc::new(Bridge {
        style,
        program: program.to_path_buf(),
        args,
        cwd: Mutex::new(None),
        mcp: Mutex::new(None),
        memory: Mutex::new(Memory::default()),
        child: Mutex::new(None),
        stopped: AtomicBool::new(false),
        out: Out(Arc::new(Mutex::new(io::stdout()))),
    });
    for line in io::stdin().lock().lines() {
        let line = line?;
        let Ok(msg) = serde_json::from_str::<Value>(&line) else {
            continue;
        };
        let method = msg["method"].as_str().unwrap_or_default();
        let params = &msg["params"];
        let id = msg.get("id").cloned();
        match (method, id) {
            ("initialize", Some(id)) => bridge.out.respond(
                &id,
                json!({
                    "protocolVersion": 1,
                    "agentCapabilities": {
                        "loadSession": false,
                        "promptCapabilities": {},
                        "mcpCapabilities": {"http": false, "sse": false},
                    },
                    "authMethods": [],
                    "agentInfo": {
                        "name": "kraken-print-bridge",
                        "title": "KRAKEN bridge",
                        "version": env!("CARGO_PKG_VERSION"),
                    },
                }),
            ),
            ("session/new", Some(id)) => {
                bridge.new_session(params);
                bridge.out.respond(&id, json!({"sessionId": SESSION_ID}));
            }
            ("session/prompt", Some(id)) => {
                let (b, text) = (bridge.clone(), prompt_text(params));
                std::thread::spawn(move || b.turn(&id, &text));
            }
            ("session/cancel", None) => bridge.stop(),
            (_, Some(id)) => {
                bridge
                    .out
                    .fail(&id, -32601, &format!("method not found: {method}"));
            }
            _ => {}
        }
    }
    bridge.stop();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Lines as agy 1.4.2 writes them.
    const TEXT: &str = r#"{"event":"step_update","step_update":{"step_index":6,"state":"ACTIVE","step_type":"agent_response","text_delta":"The file"}}"#;
    const TOOL_ON: &str = r#"{"event":"step_update","step_update":{"step_index":5,"state":"ACTIVE","step_type":"tool","tool_name":"read_file","tool_info":{"name":"read_file","parameters":{"Path":"/a"}}}}"#;
    const TOOL_OFF: &str = r#"{"event":"step_update","step_update":{"step_index":5,"state":"DONE","step_type":"tool","tool_name":"read_file","tool_info":{"name":"read_file","parameters":{"Path":"/a"},"output":"1 lines, 3 bytes"}}}"#;

    #[test]
    fn agy_text_and_tools_become_acp_updates() {
        let mut c = None;
        let t = agy_line(TEXT, &mut c).unwrap();
        assert_eq!(t[0]["content"]["text"], "The file");
        let on = agy_line(TOOL_ON, &mut c).unwrap();
        assert_eq!(on[0]["sessionUpdate"], "tool_call");
        assert_eq!(on[0]["toolCallId"], "step-5");
        assert_eq!(on[0]["title"], "read_file");
        assert_eq!(on[0]["rawInput"]["Path"], "/a");
        let off = agy_line(TOOL_OFF, &mut c).unwrap();
        assert_eq!(off[0]["sessionUpdate"], "tool_call_update");
        assert_eq!(off[0]["toolCallId"], "step-5");
        assert_eq!(off[0]["status"], "completed");
    }

    #[test]
    fn agy_gives_its_conversation_and_reports_failure() {
        let mut c = None;
        agy_line(r#"{"event":"init","conversation_id":"abc"}"#, &mut c).unwrap();
        assert_eq!(c.as_deref(), Some("abc"));
        assert!(
            agy_line(
                r#"{"event":"result","result":{"status":"SUCCESS"}}"#,
                &mut c
            )
            .is_ok()
        );
        let e = agy_line(r#"{"event":"result","result":{"status":"ERROR"}}"#, &mut c);
        assert!(e.unwrap_err().contains("ERROR"));
        assert!(agy_line("not json", &mut c).unwrap().is_empty());
    }

    #[test]
    fn the_prompt_goes_in_its_place_or_to_stdin() {
        let args = vec!["-p".to_string(), "{prompt}".to_string()];
        assert_eq!(with_prompt(&args, "hi").unwrap(), ["-p", "hi"]);
        assert_eq!(with_prompt(&["--json".to_string()], "hi"), None);
    }

    #[test]
    fn a_tool_without_memory_is_told_the_conversation() {
        assert_eq!(with_history(&[], "q"), "q");
        let t = with_history(&[("a".into(), "b".into())], "q");
        assert!(t.contains("Person: a\nYou: b") && t.ends_with("q"), "{t}");
    }

    #[test]
    fn kraken_s_server_is_added_under_its_own_name() {
        let add = agy_mcp_add(&json!({
            "name": "kraken", "command": "/bin/kraken", "args": ["mcp", "--run-id", "r1"],
            "env": [{"name": "A", "value": "1"}],
        }))
        .unwrap();
        assert_eq!(
            add,
            [
                "mcp",
                "add",
                "--env",
                "A=1",
                AGY_SERVER,
                "--",
                "/bin/kraken",
                "mcp",
                "--run-id",
                "r1"
            ]
        );
    }

    #[test]
    fn a_call_to_kraken_s_server_reads_like_a_kraken_tool() {
        let mut c = None;
        let line = r#"{"event":"step_update","step_update":{"step_index":4,"state":"ACTIVE","step_type":"tool","tool_name":"call_mcp_tool","tool_info":{"parameters":{"Arguments":{"limit":3},"ServerName":"kraken-assistant","ToolName":"list_functions"}}}}"#;
        let u = agy_line(line, &mut c).unwrap();
        assert_eq!(u[0]["title"], "mcp__kraken__list_functions");
        assert_eq!(u[0]["rawInput"]["limit"], 3);
    }

    #[test]
    fn what_agy_refuses_is_said_and_why_a_tool_failed_is_kept() {
        let mut c = None;
        let u = agy_line(
            r#"{"event":"result","result":{"status":"SUCCESS","denied_actions":[{"action":"mcp","display_name":"CallMcpTool"}]}}"#,
            &mut c,
        )
        .unwrap();
        assert!(
            u[0]["content"]["text"]
                .as_str()
                .unwrap()
                .contains("CallMcpTool")
        );
        let u = agy_line(
            r#"{"event":"step_update","step_update":{"step_index":4,"state":"ERROR","step_type":"tool","tool_name":"x","tool_info":{"error":{"message":"no such file"}}}}"#,
            &mut c,
        )
        .unwrap();
        assert_eq!(u[0]["status"], "failed");
        assert_eq!(u[0]["content"][0]["content"]["text"], "no such file");
    }

    #[test]
    fn the_allow_rule_comes_and_goes_and_leaves_the_rest() {
        let old = r#"{"colorScheme":"dark","permissions":{"allow":["command(ls)"]}}"#;
        let on = with_rule(old).unwrap();
        assert!(on.contains(AGY_RULE) && on.contains("command(ls)"));
        assert!(with_rule(&on).is_none(), "already there");
        let off: Value = serde_json::from_str(&without_rule(&on).unwrap()).unwrap();
        assert_eq!(off, serde_json::from_str::<Value>(old).unwrap());
        assert!(with_rule("").unwrap().contains(AGY_RULE));
        assert!(with_rule("not json").is_none());
    }

    #[test]
    fn styles_have_stable_names() {
        for s in [BridgeStyle::Agy, BridgeStyle::Text] {
            assert_eq!(BridgeStyle::parse(s.as_str()), Some(s));
        }
        assert_eq!(BridgeStyle::parse("x"), None);
    }
}
