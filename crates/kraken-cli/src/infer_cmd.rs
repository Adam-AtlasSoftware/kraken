//! `kraken infer list | start | status | stop | logs | setup llama`: local models.
//!
//! The model runs as a supervised child of `krakend` (so it outlives this command), or, with
//! `--no-daemon`, of this process for as long as the command runs. See `docs/local-models.md`.

use std::ffi::OsString;
use std::io::{BufRead, IsTerminal, Write};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::ArgMatches;
use kraken_host::KrakenConfig;
use kraken_host::infer::{
    InferApi, InferListReply, LogsParams, ModelLogsParams, ModelStatus, ServingApi, StartOptions,
    StatusReply, gib, gpu_names, local_provider_table, model_setting, new_local_model,
    provider_table, settings_from_pairs, upsert_local_model, write_provider,
};
use kraken_host::llama_setup::{LlamaLayout, choose, current_releases, install_llama};
use kraken_host::provision::{HttpsFetcher, ProvisionError};
use kraken_proto::infer::{LocalEngine, ModelState};
use kraken_proto::{ErrorCode, ProtoError};
use serde_json::{Value, json};

use crate::app::{CliEnv, DaemonMode, bad, emit, fail};
use crate::render::table;
use crate::setup::Printer;

const DEFAULT_WAIT_SECS: u64 = 900;
const POLL: Duration = Duration::from_millis(400);

fn os_env(env: &CliEnv) -> impl Fn(&str) -> Option<OsString> + '_ {
    move |k| env.var(k).map(OsString::from)
}

fn internal(msg: impl std::fmt::Display) -> ProtoError {
    ProtoError::new(ErrorCode::Internal, msg.to_string())
}

/// Where the model runs for this invocation.
#[derive(Clone)]
struct Target {
    api: Arc<dyn InferApi>,
    serving: Arc<dyn ServingApi>,
    /// True when this process owns the model (no daemon).
    local: bool,
}

fn local_target(env: &CliEnv) -> Target {
    let manager = env.owner_manager();
    Target {
        serving: Arc::new(manager.holder(kraken_host::infer::Holder::Owner)),
        api: manager,
        local: true,
    }
}

fn daemon_target(c: Arc<kraken_host::daemon::DaemonClient>) -> Target {
    Target {
        api: c.clone(),
        serving: c,
        local: false,
    }
}

/// The daemon, started when needed, else this process (with a warning when the daemon fails).
async fn target_for_start(
    env: &CliEnv,
    sm: &ArgMatches,
    err: &mut dyn Write,
) -> Result<Target, ProtoError> {
    if env.session.is_some() || env.no_daemon(sm) {
        return Ok(local_target(env));
    }
    match &env.daemon {
        DaemonMode::Direct => Ok(local_target(env)),
        DaemonMode::Connected(c) => Ok(daemon_target(c.clone())),
        DaemonMode::Auto(auto) => match auto.connect(kraken_ipc::ClientKind::Cli).await {
            Ok(c) => Ok(daemon_target(Arc::new(c))),
            Err(e) if e.restart_required() => Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!("{e}; run `kraken daemon stop` and retry"),
            )),
            Err(e) => {
                emit(
                    err,
                    &format!(
                        "warning: cannot use krakend ({e}); the model will run inside this \
                         command only (--no-daemon silences this)\n"
                    ),
                );
                Ok(local_target(env))
            }
        },
    }
}

/// The running daemon for read-only operations; `None` when there is none (never starts one).
async fn running_daemon(env: &CliEnv, sm: &ArgMatches) -> Result<Option<Target>, ProtoError> {
    if env.session.is_some() || env.no_daemon(sm) {
        return Ok(None);
    }
    match &env.daemon {
        DaemonMode::Direct => Ok(None),
        DaemonMode::Connected(c) => Ok(Some(daemon_target(c.clone()))),
        DaemonMode::Auto(auto) => match auto.connect_running(kraken_ipc::ClientKind::Cli).await {
            Ok(c) => Ok(c.map(|c| daemon_target(Arc::new(c)))),
            Err(e) if e.restart_required() => Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!("{e}; run `kraken daemon stop` and retry"),
            )),
            Err(e) => Err(internal(e)),
        },
    }
}

fn no_model_running() -> ProtoError {
    ProtoError::new(
        ErrorCode::NotFound,
        "no model is running under krakend. `kraken infer start` keeps one running in the \
         daemon; with --no-daemon the model only lives as long as that command",
    )
}

pub(crate) async fn run_infer(
    env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let result = match sm.subcommand() {
        Some(("list", m)) => list(env, m, json_out, out).await,
        Some(("start", m)) => start(env, m, json_out, out, err).await,
        Some(("status", m)) => status(env, m, json_out, out).await,
        Some(("stop", m)) => stop(env, m, json_out, out).await,
        Some(("logs", m)) => logs(env, m, json_out, out).await,
        Some(("setup", m)) => match m.subcommand() {
            Some(("llama", lm)) => setup_llama(env, lm, json_out, out, err).await,
            _ => Err(bad("choose what to set up: llama")),
        },
        _ => Err(bad("choose one of: list, start, status, stop, logs, setup")),
    };
    match result {
        Ok(code) => code,
        Err(e) => fail(&e, json_out, err),
    }
}

// ---------------------------------------------------------------------------------------------
// list

fn schema_summary(schema: &Value) -> String {
    let required: Vec<&str> = schema
        .get("required")
        .and_then(Value::as_array)
        .map(|r| r.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    let Some(props) = schema.get("properties").and_then(Value::as_object) else {
        return String::new();
    };
    props
        .iter()
        .map(|(k, p)| {
            let ty = p.get("type").and_then(Value::as_str).unwrap_or("string");
            let mut s = format!("{k} ({ty}");
            if required.contains(&k.as_str()) {
                s.push_str(", required");
            }
            if let Some(d) = p.get("default") {
                s.push_str(&format!(", default {d}"));
            }
            s.push(')');
            s
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_list(l: &InferListReply) -> String {
    let mut s = format!("Local models on {} {}\n\n", l.platform.os, l.platform.arch);
    if l.memory.total_ram > 0 {
        s.push_str(&format!(
            "Memory: {} RAM, {} held by open Ghidra sessions, {} left for a model.\n\n",
            gib(l.memory.total_ram),
            gib(l.memory.ghidra_reserved),
            gib(l.memory.available_ram)
        ));
    }
    let rows: Vec<Vec<String>> = l
        .backends
        .iter()
        .map(|b| {
            vec![
                b.id.clone(),
                b.display_name.clone(),
                gpu_names(&b.capabilities.gpu_apis).join("/"),
                if b.capabilities.supports_moe_offload {
                    "yes"
                } else {
                    "no"
                }
                .into(),
                match b.installed {
                    Some(true) => "installed".into(),
                    Some(false) => "not installed".into(),
                    None if b.builtin => "built in".into(),
                    None => "from manifest".into(),
                },
            ]
        })
        .collect();
    s.push_str(&table(
        &["engine", "name", "gpu", "moe offload", "state"],
        &rows,
    ));
    for b in &l.backends {
        s.push_str(&format!(
            "\n{} settings: {}\n",
            b.id,
            schema_summary(&b.settings_schema)
        ));
        if let Some(h) = &b.setup_hint {
            s.push_str(&format!("  {h}\n"));
        }
    }
    if let Some(i) = &l.llama.installed {
        s.push_str(&format!(
            "\nllama.cpp {} ({}) installed at {}\n",
            i.tag,
            i.variant,
            i.binary.display()
        ));
    } else {
        s.push_str(&format!(
            "\nllama.cpp {} can be downloaded for this computer: variants {}\n",
            l.llama.pinned_tag,
            if l.llama.variants.is_empty() {
                "none (install llama-server yourself)".into()
            } else {
                l.llama.variants.join(", ")
            }
        ));
    }
    if let Some(d) = &l.manifests_dir {
        s.push_str(&format!("Engine manifests are read from {}\n", d.display()));
    }
    for w in &l.warnings {
        s.push_str(&format!("warning: {w}\n"));
    }
    s.push_str(
        "\nStart one with: kraken infer start <engine> --model <file> [--set key=value ...] [--use]\n",
    );
    s
}

async fn list(
    env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
) -> Result<i32, ProtoError> {
    let api = match running_daemon(env, sm).await? {
        Some(t) => t.api,
        None => local_target(env).api,
    };
    let l = api.list().await?;
    if json_out {
        emit(
            out,
            &format!("{}\n", serde_json::to_value(&l).map_err(internal)?),
        );
    } else {
        emit(out, &render_list(&l));
    }
    Ok(0)
}

// ---------------------------------------------------------------------------------------------
// start

fn status_line(s: &StatusReply) -> String {
    match s.fraction {
        Some(f) => format!("{} ({:.0}%): {}", s.phase, f * 100.0, s.message),
        None => format!("{}: {}", s.phase, s.message),
    }
}

async fn start(
    env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<i32, ProtoError> {
    let backend = sm.get_one::<String>("engine").cloned().ok_or_else(|| {
        bad("name a model or an engine, for example `kraken infer start llama-server`")
    })?;
    let target = target_for_start(env, sm, err).await?;

    // A model set up in the configuration: a pinned start by id.
    let models = target.serving.models().await?;
    if models.models.iter().any(|m| m.id == backend) {
        if sm.get_one::<String>("model").is_some() || sm.get_many::<String>("set").is_some() {
            return Err(bad(format!(
                "`{backend}` is a model you have set up; its file and settings come from the \
                 configuration, so --model and --set do not apply"
            )));
        }
        if sm.get_flag("use") {
            set_assistant_model(env, &backend)?;
        }
        return start_model(env, sm, &target, &backend, json_out, out, err).await;
    }

    let listing = target.api.list().await?;
    let info = listing
        .backends
        .iter()
        .find(|b| b.id == backend)
        .ok_or_else(|| {
            let ids: Vec<&str> = listing.backends.iter().map(|b| b.id.as_str()).collect();
            let have: Vec<&str> = models.models.iter().map(|m| m.id.as_str()).collect();
            ProtoError::new(
                ErrorCode::NotFound,
                format!(
                    "no model or engine called `{backend}`. Models you have set up: {}. Engines \
                     this computer can run: {} (see `kraken infer list`)",
                    if have.is_empty() {
                        "none".into()
                    } else {
                        have.join(", ")
                    },
                    ids.join(", ")
                ),
            )
        })?;

    let cwd = std::env::current_dir().ok();
    let mut pairs: Vec<String> = sm
        .get_many::<String>("set")
        .map(|v| v.cloned().collect())
        .unwrap_or_default();
    let model_key = sm
        .get_one::<String>("model")
        .map(|model| {
            let key = model_setting(&info.settings_schema).ok_or_else(|| {
                bad(format!(
                    "`{backend}` has no model setting; use --set key=value (see `kraken infer list`)"
                ))
            })?;
            pairs.insert(0, format!("{key}={model}"));
            Ok::<_, ProtoError>(key)
        })
        .transpose()?;
    let settings =
        settings_from_pairs(&info.settings_schema, &pairs, cwd.as_deref()).map_err(bad)?;

    let own_model = matches!(backend.as_str(), "llama-server" | "strata");
    if sm.get_flag("use") && own_model {
        // `--use` makes the model one of yours: it is written to the configuration with these
        // settings and the assistant is pointed at it, then it is started like any other.
        let id = register_model(env, &backend, &settings, model_key)?;
        let models = target.serving.models().await?;
        if !models.models.iter().any(|m| m.id == id) {
            return Err(internal(
                "the model was written to the configuration but the serving service does not \
                 see it; restart krakend (`kraken daemon stop`) and retry",
            ));
        }
        return start_model(env, sm, &target, &id, json_out, out, err).await;
    }

    let started = target.api.start(&backend, settings).await?;
    for w in &started.warnings {
        emit(err, &format!("warning: {w}\n"));
    }
    if !json_out {
        emit(
            err,
            &format!(
                "started {backend} (pid {}) at {}\n",
                started.pid.map_or("?".into(), |p| p.to_string()),
                started.base_url
            ),
        );
    }

    let wait = !sm.get_flag("no-wait");
    let mut ready = false;
    if wait {
        let secs = wait_secs(sm)?;
        let deadline = Instant::now() + Duration::from_secs(secs);
        let mut last = String::new();
        loop {
            let s = target.api.status().await?;
            let line = status_line(&s);
            if line != last && !json_out {
                emit(err, &format!("  {line}\n"));
                last = line;
            }
            if s.is_ready() {
                ready = true;
                break;
            }
            if s.is_failed() || !s.running {
                let logs = target
                    .api
                    .logs(LogsParams {
                        after_seq: None,
                        limit: Some(15),
                    })
                    .await
                    .map(|l| l.lines)
                    .unwrap_or_default();
                let tail: Vec<String> = logs.into_iter().map(|l| l.text).collect();
                return Err(ProtoError::new(
                    ErrorCode::Internal,
                    format!(
                        "the model did not start ({}). Last log lines:\n{}",
                        s.message,
                        tail.join("\n")
                    ),
                ));
            }
            if Instant::now() >= deadline {
                return Err(timeout_error(
                    secs,
                    "kraken infer status` and `kraken infer logs",
                ));
            }
            tokio::time::sleep(POLL).await;
        }
    }

    // An engine described by a manifest cannot be a model of yours: the assistant is pointed at
    // this run's address instead.
    let mut provider_path = None;
    if sm.get_flag("use") {
        let path = config_path(env)?;
        write_provider(
            &path,
            provider_table(
                &started.base_url,
                started.model.as_deref(),
                info.capabilities.supports_tool_calls,
                started.api_key.is_some(),
            ),
        )
        .map_err(|e| internal(format!("cannot write {}: {e}", path.display())))?;
        provider_path = Some(path);
    }

    if json_out {
        let mut v = serde_json::to_value(&started).map_err(internal)?;
        v["ready"] = json!(ready);
        if let Some(p) = &provider_path {
            v["provider_written_to"] = json!(p);
        }
        emit(out, &format!("{v}\n"));
    } else {
        emit(
            out,
            &format!(
                "{} at {}{}\n",
                if ready { "Ready" } else { "Loading" },
                started.base_url,
                started
                    .model
                    .as_deref()
                    .map_or(String::new(), |m| format!(" (model {m})"))
            ),
        );
        if let Some(p) = &provider_path {
            emit(
                out,
                &format!(
                    "The assistant now uses it: wrote [provider] to {}. It points at this run's \
                     address; start with --set port=<n> to keep the address stable.\n",
                    p.display()
                ),
            );
            if let Some(k) = &started.api_key {
                emit(
                    out,
                    &format!(
                        "The server requires this run's key; export it where the assistant \
                         runs:\n  export {}={k}\n",
                        kraken_host::infer::LOCAL_KEY_ENV
                    ),
                );
            }
        }
    }

    if target.local {
        hold_local(env, &target, None, json_out, err).await;
    }
    Ok(0)
}

fn wait_secs(sm: &ArgMatches) -> Result<u64, ProtoError> {
    Ok(sm
        .get_one::<String>("timeout")
        .map(|t| t.parse::<u64>().map_err(|_| bad("--timeout needs seconds")))
        .transpose()?
        .unwrap_or(DEFAULT_WAIT_SECS))
}

fn timeout_error(secs: u64, follow: &str) -> ProtoError {
    ProtoError::new(
        ErrorCode::Timeout,
        format!(
            "the model is still loading after {secs} s; it keeps loading in the background, \
             follow it with `{follow}`"
        ),
    )
}

fn config_path(env: &CliEnv) -> Result<std::path::PathBuf, ProtoError> {
    KrakenConfig::default_path_with(&os_env(env))
        .ok_or_else(|| internal("there is no config location (HOME is not set)"))
}

/// Points the assistant at the model `id`, which must be one of the configured models.
fn set_assistant_model(env: &CliEnv, id: &str) -> Result<(), ProtoError> {
    let path = config_path(env)?;
    let mut cfg = KrakenConfig::from_file(&path).map_err(internal)?;
    if !cfg.local_models.iter().any(|m| m.id == id) {
        return Err(bad(format!("`{id}` is not set up in {}", path.display())));
    }
    cfg.provider = Some(local_provider_table(id));
    cfg.save(&path)
        .map_err(|e| internal(format!("cannot write {}: {e}", path.display())))
}

/// Writes the model started from an engine and a file to the configuration as one of the
/// person's models, points the assistant at it and returns its id.
fn register_model(
    env: &CliEnv,
    backend: &str,
    settings: &Value,
    model_key: Option<&str>,
) -> Result<String, ProtoError> {
    let engine = match backend {
        "strata" => LocalEngine::Strata,
        "llama-server" => LocalEngine::Llama,
        other => {
            return Err(bad(format!(
                "--use works with llama-server and strata; `{other}` can be started without it"
            )));
        }
    };
    let mut extra = settings.clone();
    let file = model_key
        .and_then(|k| extra.as_object_mut().and_then(|o| o.remove(k)))
        .and_then(|v| v.as_str().map(std::path::PathBuf::from))
        .ok_or_else(|| bad("--use needs --model <file>"))?;
    let id = file
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| bad("--use needs a model file with a name"))?;
    let mut model = new_local_model(&id, engine, file);
    let has_extra = extra.as_object().is_some_and(|o| !o.is_empty());
    model.extra = has_extra.then_some(extra);
    let path = config_path(env)?;
    upsert_local_model(&path, model, true)
        .map_err(|e| internal(format!("cannot write {}: {e}", path.display())))?;
    Ok(id)
}

fn model_line(m: &ModelStatus) -> String {
    match (&m.state, m.load_fraction) {
        (ModelState::Loading, Some(f)) => format!("loading ({:.0}%)", f * 100.0),
        (ModelState::Loading, None) => "loading".into(),
        (ModelState::Ready, _) => "ready".into(),
        (ModelState::Stopping, _) => "stopping".into(),
        (ModelState::Stopped, _) => "stopped".into(),
        (ModelState::Failed { message }, _) => format!("failed: {message}"),
    }
}

/// A pinned start of the configured model `id`: it runs until `kraken infer stop <id>`.
async fn start_model(
    env: &CliEnv,
    sm: &ArgMatches,
    target: &Target,
    id: &str,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<i32, ProtoError> {
    let opts = StartOptions {
        force: sm.get_flag("force"),
        cpu: sm.get_flag("cpu"),
    };
    let mut status = target.serving.start_model(id, opts).await?;
    for w in &status.warnings {
        emit(err, &format!("warning: {w}\n"));
    }
    if !json_out {
        emit(err, &format!("started {id}\n"));
    }
    if !sm.get_flag("no-wait") {
        let secs = wait_secs(sm)?;
        let deadline = Instant::now() + Duration::from_secs(secs);
        let mut last = String::new();
        loop {
            let all = target.serving.models().await?;
            if let Some(m) = all.models.into_iter().find(|m| m.id == id) {
                let line = model_line(&m);
                if line != last && !json_out {
                    emit(err, &format!("  {line}\n"));
                    last = line;
                }
                match m.state {
                    ModelState::Ready => {
                        status = m;
                        break;
                    }
                    ModelState::Failed { .. } | ModelState::Stopped => {
                        let logs = target
                            .serving
                            .model_logs(ModelLogsParams {
                                model: id.to_string(),
                                after_seq: None,
                                limit: Some(15),
                            })
                            .await
                            .map(|l| l.lines)
                            .unwrap_or_default();
                        let tail: Vec<String> = logs.into_iter().map(|l| l.text).collect();
                        return Err(ProtoError::new(
                            ErrorCode::Internal,
                            format!(
                                "the model did not start ({}). Last log lines:\n{}",
                                model_line(&m),
                                tail.join("\n")
                            ),
                        ));
                    }
                    _ => {}
                }
            }
            if Instant::now() >= deadline {
                return Err(timeout_error(secs, "kraken local-model-status"));
            }
            tokio::time::sleep(POLL).await;
        }
    }
    // The per-run key stays between krakend and the programs it serves.
    status.api_key = None;
    if json_out {
        emit(
            out,
            &format!("{}\n", serde_json::to_value(&status).map_err(internal)?),
        );
    } else {
        emit(
            out,
            &format!(
                "{} {id}{}\n",
                if status.is_ready() {
                    "Ready:"
                } else {
                    "Loading:"
                },
                status
                    .base_url
                    .as_deref()
                    .map_or(String::new(), |u| format!(" at {u}"))
            ),
        );
        if sm.get_flag("use") {
            emit(out, "The assistant now uses it.\n");
        }
    }
    if target.local {
        hold_local(env, target, Some(id), json_out, err).await;
    }
    Ok(0)
}

async fn hold_local(
    env: &CliEnv,
    target: &Target,
    model: Option<&str>,
    json_out: bool,
    err: &mut dyn Write,
) {
    if env.interactive && std::io::stdin().is_terminal() {
        if !json_out {
            emit(
                err,
                "Running inside this command (no daemon). Press Ctrl-C to stop the model.\n",
            );
        }
        let _ = tokio::signal::ctrl_c().await;
    } else if !json_out {
        emit(
            err,
            "note: without krakend the model stops when this command ends\n",
        );
    }
    match model {
        Some(id) => {
            let _ = target.serving.stop_model(id).await;
        }
        None => {
            let _ = target.api.stop().await;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// status, stop, logs

async fn status(
    env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
) -> Result<i32, ProtoError> {
    let Some(api) = running_daemon(env, sm).await?.map(|t| t.api) else {
        if json_out {
            emit(
                out,
                &format!("{}\n", json!({"running": false, "phase": "none"})),
            );
        } else {
            emit(out, "No krakend is running, so no model is loaded.\n");
        }
        return Ok(0);
    };
    let s = api.status().await?;
    if json_out {
        emit(
            out,
            &format!("{}\n", serde_json::to_value(&s).map_err(internal)?),
        );
        return Ok(0);
    }
    if s.phase == "none" {
        emit(out, "No model has been started.\n");
        return Ok(0);
    }
    emit(
        out,
        &format!(
            "{} {}: {}\nAddress: {}\nModel: {}\nUp for {} s, {} restart(s){}\n",
            s.backend.as_deref().unwrap_or("?"),
            s.phase,
            s.message,
            s.base_url.as_deref().unwrap_or("?"),
            s.model.as_deref().unwrap_or("?"),
            s.uptime_secs.unwrap_or(0),
            s.restarts,
            s.pid.map_or(String::new(), |p| format!(", pid {p}")),
        ),
    );
    Ok(0)
}

async fn stop(
    env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
) -> Result<i32, ProtoError> {
    let target = running_daemon(env, sm)
        .await?
        .ok_or_else(no_model_running)?;
    if let Some(model) = sm.get_one::<String>("model") {
        let r = target.serving.stop_model(model).await?;
        if json_out {
            emit(
                out,
                &format!("{}\n", serde_json::to_value(&r).map_err(internal)?),
            );
        } else if r.stopped {
            emit(out, &format!("Stopped {model}.\n"));
        } else {
            emit(out, &format!("{model} was not running.\n"));
        }
        return Ok(0);
    }
    let r = target.api.stop().await?;
    if json_out {
        emit(
            out,
            &format!("{}\n", serde_json::to_value(&r).map_err(internal)?),
        );
    } else if r.stopped {
        emit(out, "Stopped the model.\n");
    } else {
        emit(out, "No model was running.\n");
    }
    Ok(0)
}

async fn logs(
    env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
) -> Result<i32, ProtoError> {
    let api = running_daemon(env, sm)
        .await?
        .map(|t| t.api)
        .ok_or_else(no_model_running)?;
    let tail = sm
        .get_one::<String>("tail")
        .map(|t| t.parse::<usize>().map_err(|_| bad("--tail needs a number")))
        .transpose()?
        .unwrap_or(100);
    let follow = sm.get_flag("follow");
    let mut after = None;
    let mut limit = Some(tail);
    loop {
        let r = api
            .logs(LogsParams {
                after_seq: after,
                limit,
            })
            .await?;
        after = Some(r.last_seq);
        limit = None;
        if json_out {
            emit(
                out,
                &format!("{}\n", serde_json::to_value(&r).map_err(internal)?),
            );
        } else {
            for l in &r.lines {
                emit(out, &format!("[{}] {}\n", l.stream, l.text));
            }
        }
        let _ = out.flush();
        if !follow {
            return Ok(0);
        }
        let s = api.status().await?;
        if !s.running && r.lines.is_empty() {
            return Ok(0);
        }
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(500)) => {}
            _ = tokio::signal::ctrl_c() => return Ok(0),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// setup llama

fn to_proto(e: ProvisionError) -> ProtoError {
    let code = match e {
        ProvisionError::NoBuild(_) | ProvisionError::UnsupportedPlatform(_) => {
            ErrorCode::Unsupported
        }
        ProvisionError::NotHttps(_) => ErrorCode::InvalidArgument,
        _ => ErrorCode::Internal,
    };
    ProtoError::new(code, e.to_string())
}

fn confirm(
    question: &str,
    yes: bool,
    interactive: bool,
    err: &mut dyn Write,
) -> Result<bool, ProtoError> {
    if yes {
        return Ok(true);
    }
    if !interactive || !std::io::stdin().is_terminal() {
        return Err(bad(
            "this needs your approval to download files; run it in a terminal or pass --yes",
        ));
    }
    emit(err, &format!("{question} [y/N] "));
    let _ = err.flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(internal)?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

async fn setup_llama(
    env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<i32, ProtoError> {
    let layout = LlamaLayout::from_env_with(&os_env(env))
        .ok_or_else(|| internal("cannot place llama.cpp: neither XDG_DATA_HOME nor HOME is set"))?;
    let releases = current_releases();
    let release = choose(
        &releases,
        sm.get_one::<String>("variant").map(String::as_str),
    )
    .map_err(to_proto)?;
    let force = sm.get_flag("force");
    if let Some(i) = layout.installed()
        && !force
        && i.tag == release.tag
        && i.variant == release.variant
    {
        if json_out {
            emit(
                out,
                &format!("{}\n", serde_json::to_value(&i).map_err(internal)?),
            );
        } else {
            emit(
                out,
                &format!(
                    "llama.cpp {} ({}) is already installed: {}\n",
                    i.tag,
                    i.variant,
                    i.binary.display()
                ),
            );
        }
        return Ok(0);
    }
    let question = format!(
        "Download llama.cpp {} ({} build, {:.0} MiB) from {} and verify its SHA-256?",
        release.tag,
        release.variant,
        release.size as f64 / (1024.0 * 1024.0),
        release.url
    );
    if !confirm(&question, sm.get_flag("yes"), env.interactive, err)? {
        return Err(ProtoError::new(
            ErrorCode::Cancelled,
            "nothing was downloaded",
        ));
    }
    let fetcher = HttpsFetcher::new().map_err(to_proto)?;
    let mut printer = Printer::new();
    let result = install_llama(&layout, &fetcher, &release, force, &mut |p| {
        printer.show(p);
    })
    .await;
    printer.end_line();
    let installed = result.map_err(to_proto)?;
    if json_out {
        emit(
            out,
            &format!("{}\n", serde_json::to_value(&installed).map_err(internal)?),
        );
    } else {
        emit(
            out,
            &format!(
                "llama-server {} ({}) installed: {}\n\nKRAKEN finds it on its own. Start a model with:\n  kraken infer start llama-server --model /path/to/model.gguf --use\n\nKRAKEN never downloads models; see docs/local-models.md for where to get a GGUF file.\n",
                installed.tag,
                installed.variant,
                installed.binary.display()
            ),
        );
    }
    Ok(0)
}
