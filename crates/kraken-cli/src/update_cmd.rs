//! `kraken update` (ADR 0015): checks for a new release and installs it for the installs KRAKEN
//! updates itself; package-managed installs get their command. The same backend as the
//! `update_*` commands (`kraken_host::update`). Also the daily notice after interactive commands.

use std::io::{BufRead, IsTerminal, Write};
use std::time::Duration;

use clap::ArgMatches;
use kraken_host::update::HostUpdater;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{UpdateBackend, UpdateStatusOut};
use kraken_registry::jobs::JobProgress;

use crate::app::{CliEnv, emit, fail};

fn confirm(question: &str, yes: bool, err: &mut dyn Write) -> Result<bool, ProtoError> {
    if yes {
        return Ok(true);
    }
    if !std::io::stdin().is_terminal() {
        return Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            "this replaces KRAKEN's programs and needs your approval; run it in a terminal or pass --yes",
        ));
    }
    emit(err, &format!("{question} [y/N] "));
    let _ = err.flush();
    let mut line = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut line)
        .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))?;
    Ok(matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

fn when(secs: Option<u64>) -> String {
    let Some(t) = secs else {
        return "never".into();
    };
    let now = kraken_host::update::state::now_secs();
    let ago = now.saturating_sub(t);
    match ago {
        0..120 => "just now".into(),
        120..7200 => format!("{} minutes ago", ago / 60),
        7200..172_800 => format!("{} hours ago", ago / 3600),
        _ => format!("{} days ago", ago / 86_400),
    }
}

/// The status in words.
pub(crate) fn status_text(s: &UpdateStatusOut) -> String {
    let mut t = format!(
        "KRAKEN {} ({}, {} build)\nInstalled as: {}\nThis computer: {}, {}, {}\n",
        s.version,
        s.target,
        s.build_channel,
        s.install.label,
        s.system.os,
        s.system.arch,
        s.system.session
    );
    t.push_str(&format!(
        "Update checks: {} (channel {}), last {}\n",
        match &s.checks_disabled_by {
            None => "on".to_string(),
            Some(by) => format!("off ({by})"),
        },
        s.channel,
        when(s.last_check)
    ));
    if let Some(e) = &s.last_error {
        t.push_str(&format!("Last check failed: {e}\n"));
    }
    if let Some(b) = &s.install.self_update_blocked {
        t.push_str(&format!("KRAKEN cannot update itself here: {b}\n"));
    }
    t.push_str(&s.summary);
    t.push('\n');
    t
}

pub(crate) async fn run_update(
    _env: &CliEnv,
    sm: &ArgMatches,
    json_out: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> i32 {
    let flag = |n: &str| sm.try_get_one::<bool>(n).ok().flatten().copied() == Some(true);
    let yes = flag("yes");
    let updater = HostUpdater::system();

    if flag("rollback") {
        let target = updater.status_now().rollback_to;
        let Some(target) = target else {
            return fail(
                &ProtoError::new(
                    ErrorCode::NotFound,
                    "no earlier version is kept; nothing to roll back to",
                ),
                json_out,
                err,
            );
        };
        match confirm(
            &format!("Go back to KRAKEN {target}?"),
            yes || json_out,
            err,
        ) {
            Ok(true) => {}
            Ok(false) => return 1,
            Err(e) => return fail(&e, json_out, err),
        }
        return match updater.rollback() {
            Ok(r) if json_out => {
                emit(out, &format!("{}\n", serde_json::json!(r)));
                0
            }
            Ok(r) => {
                emit(out, &format!("{}\n", r.message));
                0
            }
            Err(e) => fail(&e, json_out, err),
        };
    }

    let status = updater.check_now(true).await;
    if flag("check") || !status.update_available || !status.install.can_self_update {
        if json_out {
            emit(out, &format!("{}\n", serde_json::json!(status)));
        } else {
            emit(out, &status_text(&status));
        }
        return i32::from(status.last_error.is_some());
    }
    let latest = status.latest.clone().unwrap_or_default();
    if !json_out {
        emit(err, &format!("{}\n", status.summary));
    }
    if json_out && !yes {
        return fail(
            &ProtoError::new(
                ErrorCode::InvalidArgument,
                "installing replaces KRAKEN's programs; pass --yes with --json",
            ),
            json_out,
            err,
        );
    }
    match confirm(
        &format!("Install KRAKEN {latest} now (the current version is kept for --rollback)?"),
        yes,
        err,
    ) {
        Ok(true) => {}
        Ok(false) => return 1,
        Err(e) => return fail(&e, json_out, err),
    }
    let printer = std::sync::Mutex::new(crate::setup::Printer::new());
    let on = |p: JobProgress| {
        if let Ok(mut pr) = printer.lock() {
            pr.show_job(&p);
        }
    };
    let result = tokio::select! {
        r = updater.apply(&on) => r,
        _ = tokio::signal::ctrl_c() => Err(ProtoError::new(
            ErrorCode::Cancelled,
            "update cancelled; nothing was replaced",
        )),
    };
    if let Ok(mut pr) = printer.lock() {
        pr.end_line();
    }
    match result {
        Ok(r) if json_out => {
            emit(out, &format!("{}\n", serde_json::json!(r)));
            0
        }
        Ok(r) => {
            emit(out, &format!("{}\n", r.message));
            0
        }
        Err(e) => fail(&e, json_out, err),
    }
}

/// After an interactive command: refreshes a stale cache (3 s at most) and prints the daily
/// notice or the one-time notice that checks exist. Never for `mcp`, `--json` or when stderr is
/// not a terminal.
pub(crate) async fn after_command(sub: &str, json_out: bool, err: &mut dyn Write) {
    if json_out || matches!(sub, "mcp" | "update") || !std::io::stderr().is_terminal() {
        return;
    }
    let updater = HostUpdater::system().with_check_timeout(Duration::from_secs(3));
    if updater.check_due() {
        let _ = tokio::time::timeout(Duration::from_secs(3), updater.check_now(false)).await;
    }
    if let Some(line) = updater.take_cli_notice() {
        emit(err, &format!("{line}\n"));
    }
}
