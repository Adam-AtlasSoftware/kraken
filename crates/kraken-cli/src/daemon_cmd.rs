//! `kraken daemon status|stop|start|approvals`.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use clap::ArgMatches;
use kraken_host::daemon::{DaemonClient, wait_until_stopped};
use kraken_ipc::{ClientKind, RuntimeDir};
use kraken_proto::{ErrorCode, ProtoError};
use serde_json::{Value, json};

use crate::app::{BUILD, CliEnv, DaemonAuto, DaemonMode, emit, fail};
use crate::render::table;

/// How long `daemon stop` waits for the daemon to finish closing projects and stopping Ghidra.
const STOP_TIMEOUT: Duration = Duration::from_secs(30);

fn internal(msg: impl std::fmt::Display) -> ProtoError {
    ProtoError::new(ErrorCode::Internal, msg.to_string())
}

fn auto_of(env: &CliEnv) -> DaemonAuto {
    match &env.daemon {
        DaemonMode::Auto(a) => a.clone(),
        _ => DaemonAuto::default(),
    }
}

fn runtime_dir(env: &CliEnv) -> Result<RuntimeDir, ProtoError> {
    match &auto_of(env).runtime_dir {
        Some(d) => Ok(d.clone()),
        None => RuntimeDir::resolve().map_err(|e| internal(format!("runtime dir: {e}"))),
    }
}

/// The running daemon, if any (never starts one).
async fn running(env: &CliEnv) -> Result<Option<Arc<DaemonClient>>, ProtoError> {
    if let DaemonMode::Connected(c) = &env.daemon {
        return Ok(Some(c.clone()));
    }
    let dir = runtime_dir(env)?;
    DaemonClient::connect_running(&dir, ClientKind::Cli, BUILD)
        .await
        .map(|c| c.map(Arc::new))
        .map_err(|e| {
            let hint = if e.restart_required() {
                "; run `kraken daemon stop`"
            } else {
                ""
            };
            internal(format!("{e}{hint}"))
        })
}

fn secs(n: u64) -> String {
    match n {
        0..=119 => format!("{n}s"),
        120..=7199 => format!("{}m", n / 60),
        _ => format!("{}h", n / 3600),
    }
}

fn render_status(st: &Value) -> String {
    let d = &st["daemon"];
    let mut s = format!(
        "krakend {} running (pid {}, up {}, protocol {})\nruntime dir: {}\nidle exit after {}, sessions close after {} idle (max {}); {} client(s), {} running job(s)\n",
        d["build"].as_str().unwrap_or("?"),
        d["pid"],
        secs(d["uptime_secs"].as_u64().unwrap_or(0)),
        d["protocol"],
        d["runtime_dir"].as_str().unwrap_or("?"),
        secs(d["idle_timeout_secs"].as_u64().unwrap_or(0)),
        secs(d["session_idle_secs"].as_u64().unwrap_or(0)),
        d["max_sessions"],
        d["clients"],
        d["running_jobs"],
    );
    let sessions = st["sessions"].as_array().cloned().unwrap_or_default();
    if sessions.is_empty() {
        s.push_str("no open projects\n");
    } else {
        let rows: Vec<Vec<String>> = sessions
            .iter()
            .map(|x| {
                vec![
                    x["project_dir"].as_str().unwrap_or("?").to_string(),
                    x["analysis"]["phase"].as_str().unwrap_or("-").to_string(),
                    x["pending_entries"]
                        .as_u64()
                        .map_or("-".into(), |n| n.to_string()),
                    x["running_jobs"].as_u64().unwrap_or(0).to_string(),
                    format!("{}s", x["idle_secs"].as_u64().unwrap_or(0)),
                ]
            })
            .collect();
        s.push_str(&table(
            &["project", "analysis", "pending", "jobs", "idle"],
            &rows,
        ));
    }
    for e in st["engines"].as_array().cloned().unwrap_or_default() {
        let g = &e["diagnostics"];
        let conf = &g["confinement"];
        s.push_str(&format!(
            "engine {}: {}{}{}{}\n",
            e["engine_dir"].as_str().unwrap_or("?"),
            g["state"].as_str().unwrap_or("?"),
            g["pid"]
                .as_u64()
                .map_or(String::new(), |p| format!(", pid {p}")),
            g["ghidra_version"]
                .as_str()
                .map_or(String::new(), |v| format!(", Ghidra {v}")),
            match conf.get("filesystem") {
                Some(Value::Bool(true)) => ", confined (Landlock)".to_string(),
                Some(Value::Bool(false)) => ", UNCONFINED".to_string(),
                _ => String::new(),
            },
        ));
    }
    s
}

pub(crate) async fn run_daemon(
    env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let Some((action, _)) = sm.subcommand() else {
        return 2;
    };
    match action {
        "status" => status(env, json_out, out, err).await,
        "stop" => stop(env, json_out, out, err).await,
        "start" => start(env, json_out, out, err).await,
        "approvals" => {
            let m = sm.subcommand_matches("approvals").expect("subcommand");
            approvals(env, m, json_out, out, err).await
        }
        other => fail(
            &ProtoError::new(
                ErrorCode::InvalidArgument,
                format!("unknown daemon action `{other}`"),
            ),
            json_out,
            err,
        ),
    }
}

/// `kraken daemon approvals [--approve ID | --deny ID]`: what agents wait for, and the answer.
async fn approvals(
    env: &CliEnv,
    m: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let client = match running(env).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            emit(out, "krakend is not running; nothing waits for approval\n");
            return 0;
        }
        Err(e) => return fail(&e, json_out, err),
    };
    let answer = m
        .get_one::<u64>("approve")
        .map(|id| (*id, true))
        .or_else(|| m.get_one::<u64>("deny").map(|id| (*id, false)));
    if let Some((id, allow)) = answer {
        return match client
            .rpc("approval_decide", json!({"id": id, "allow": allow}))
            .await
        {
            Ok(v) if v["decided"] == true => {
                if json_out {
                    emit(out, &format!("{v}\n"));
                } else {
                    emit(
                        out,
                        &format!(
                            "{} request {id}\n",
                            if allow { "approved" } else { "denied" }
                        ),
                    );
                }
                0
            }
            Ok(_) => fail(
                &ProtoError::new(
                    ErrorCode::NotFound,
                    format!("no request {id} is waiting (it may have timed out)"),
                ),
                json_out,
                err,
            ),
            Err(e) => fail(&e, json_out, err),
        };
    }
    match client.rpc("approvals", Value::Null).await {
        Ok(v) => {
            if json_out {
                emit(out, &format!("{v}\n"));
                return 0;
            }
            let list = v["pending"].as_array().cloned().unwrap_or_default();
            if list.is_empty() {
                emit(out, "nothing waits for your approval\n");
                return 0;
            }
            let rows: Vec<Vec<String>> = list
                .iter()
                .map(|x| {
                    vec![
                        x["id"].to_string(),
                        x["author_id"].as_str().unwrap_or("?").to_string(),
                        x["summary"].as_str().unwrap_or("?").to_string(),
                    ]
                })
                .collect();
            emit(out, &table(&["id", "agent", "wants to"], &rows));
            emit(
                out,
                "answer with `kraken daemon approvals --approve ID` or `--deny ID`\n",
            );
            0
        }
        Err(e) => fail(&e, json_out, err),
    }
}

async fn status(env: &CliEnv, json_out: bool, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let client = match running(env).await {
        Ok(c) => c,
        Err(e) => return fail(&e, json_out, err),
    };
    let Some(client) = client else {
        let dir = runtime_dir(env).ok();
        if json_out {
            emit(
                out,
                &format!(
                    "{}\n",
                    json!({"running": false, "runtime_dir": dir.map(|d| d.path().to_path_buf())})
                ),
            );
        } else {
            emit(out, "krakend is not running\n");
        }
        return 0;
    };
    match client.status().await {
        Ok(mut st) => {
            if json_out {
                st["running"] = json!(true);
                emit(out, &format!("{st}\n"));
            } else {
                emit(out, &render_status(&st));
            }
            0
        }
        Err(e) => fail(&e, json_out, err),
    }
}

async fn stop(env: &CliEnv, json_out: bool, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let client = match running(env).await {
        Ok(c) => c,
        Err(e) => return fail(&e, json_out, err),
    };
    let Some(client) = client else {
        if json_out {
            emit(
                out,
                &format!("{}\n", json!({"running": false, "stopped": false})),
            );
        } else {
            emit(out, "krakend is not running\n");
        }
        return 0;
    };
    let pid = client.daemon_pid();
    if let Err(e) = client.shutdown().await {
        return fail(&e, json_out, err);
    }
    let stopped = match runtime_dir(env) {
        Ok(dir) => wait_until_stopped(&dir, STOP_TIMEOUT).await,
        Err(_) => true,
    };
    if !stopped {
        return fail(
            &internal(format!(
                "krakend (pid {pid}) did not stop within {}s",
                STOP_TIMEOUT.as_secs()
            )),
            json_out,
            err,
        );
    }
    if json_out {
        emit(
            out,
            &format!(
                "{}\n",
                json!({"running": false, "stopped": true, "pid": pid})
            ),
        );
    } else {
        emit(out, &format!("krakend stopped (pid {pid})\n"));
    }
    0
}

async fn start(env: &CliEnv, json_out: bool, out: &mut dyn Write, err: &mut dyn Write) -> i32 {
    let existing = match running(env).await {
        Ok(c) => c,
        Err(e) => return fail(&e, json_out, err),
    };
    let (client, started) = match existing {
        Some(c) => (c, false),
        None => match auto_of(env).connect(ClientKind::Cli).await {
            Ok(c) => (Arc::new(c), true),
            Err(e) => return fail(&internal(e), json_out, err),
        },
    };
    let pid = client.daemon_pid();
    if json_out {
        emit(
            out,
            &format!(
                "{}\n",
                json!({"running": true, "started": started, "pid": pid, "build": client.daemon_build()})
            ),
        );
    } else if started {
        emit(out, &format!("krakend started (pid {pid})\n"));
    } else {
        emit(out, &format!("krakend is already running (pid {pid})\n"));
    }
    0
}
