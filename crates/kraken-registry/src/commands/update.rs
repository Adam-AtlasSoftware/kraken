//! Updates (ADR 0015): what is installed and how, whether a newer release exists, and installing
//! it for the kinds of install KRAKEN updates itself.
//!
//! `update_status` reads the cached result and works out the install; `update_check` asks GitHub
//! (at most once a day unless `force`). Both are read-only and agents may call them.
//! `update_apply` (a job) and `update_rollback` replace programs, so only a person may run them.
//! The work is done by an [`UpdateBackend`] that `kraken-host` provides; `kraken update` runs the
//! same code.

use std::sync::Arc;

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::setup::GlobalJobOut;
use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::jobs::JobProgress;
use crate::session::{Session, blocking};

/// How KRAKEN was installed, and how it is updated.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct InstallView {
    /// `script`, `archive`, `appimage`, `portable`, `windows_installer`, `aur`, `package`,
    /// `cargo`, `source`, `python` or `unknown`.
    pub kind: String,
    /// In plain words: "AppImage at ~/Apps/KRAKEN.AppImage".
    pub label: String,
    /// KRAKEN can download and install updates itself.
    pub can_self_update: bool,
    /// Why it cannot, when it is a kind that normally could.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_update_blocked: Option<String>,
    /// The command the person runs to update a package-managed install.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// The running program.
    pub program: String,
}

/// The computer KRAKEN runs on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SystemView {
    /// Operating system with its version ("Arch Linux", "Ubuntu 24.04.1 LTS", "Windows 10.0.26100").
    pub os: String,
    /// Processor architecture (`x86_64`, `aarch64`).
    pub arch: String,
    /// C library the build uses (`glibc`, `musl`, `msvc`, `macos`).
    pub libc: String,
    /// The session: desktop and display server, a terminal, or SSH.
    pub session: String,
}

/// Where updates stand.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct UpdateStatusOut {
    /// The running version.
    pub version: String,
    /// The target triple compiled in.
    pub target: String,
    /// `release` for builds from the release workflow, `source` otherwise.
    pub build_channel: String,
    /// `stable` or `prerelease`: which releases the check looks at.
    pub channel: String,
    /// How KRAKEN was installed.
    pub install: InstallView,
    /// This computer.
    pub system: SystemView,
    /// Checks are on.
    pub checks_enabled: bool,
    /// Why checks are off (`KRAKEN_NO_UPDATE_CHECK`, `CI`, `updates.check = false`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checks_disabled_by: Option<String>,
    /// Unix seconds of the last check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_check: Option<u64>,
    /// The newest release the last check saw.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest: Option<String>,
    /// Its release notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes_url: Option<String>,
    /// The newest release carries a signature (`SHA256SUMS.minisig`); unsigned ones cannot be
    /// installed by KRAKEN.
    pub latest_signed: bool,
    /// `latest` is newer than the running version.
    pub update_available: bool,
    /// The version the person chose to skip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skipped: Option<String>,
    /// What went wrong in the last check.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// The version `update_rollback` would go back to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_to: Option<String>,
    /// One sentence for a person: what to do, if anything.
    pub summary: String,
}

/// Result of `update_apply` and `update_rollback`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct UpdateApplied {
    /// The version that ran before.
    pub from: String,
    /// The version now installed.
    pub to: String,
    /// Files and directories replaced.
    pub replaced: Vec<String>,
    /// For a person: "Updated to 0.4.0. Restart KRAKEN to use it."
    pub message: String,
}

/// Works out the install, checks GitHub and installs updates; provided by `kraken-host`.
#[async_trait]
pub trait UpdateBackend: Send + Sync + std::fmt::Debug {
    /// The cached state and the install. Blocking: it reads files and may ask a package manager.
    fn status(&self) -> Result<UpdateStatusOut, ProtoError>;
    /// Asks GitHub when the cache is older than a day, or always with `force`.
    async fn check(&self, force: bool) -> Result<UpdateStatusOut, ProtoError>;
    /// Downloads, verifies and installs the newest release.
    async fn apply(
        &self,
        progress: &(dyn Fn(JobProgress) + Send + Sync),
    ) -> Result<UpdateApplied, ProtoError>;
    /// Puts back the version kept by the last update. Blocking.
    fn rollback(&self) -> Result<UpdateApplied, ProtoError>;
    /// Stops telling about `version` (`None` forgets the choice). Blocking.
    fn skip(&self, version: Option<String>) -> Result<(), ProtoError>;
}

impl Session {
    /// The attached update backend.
    pub fn update(&self) -> Result<&Arc<dyn UpdateBackend>, ProtoError> {
        self.update_backend().ok_or_else(|| {
            ProtoError::new(
                ErrorCode::Unsupported,
                "updates are not attached to this session; use the kraken CLI, krakend or the GUI",
            )
        })
    }
}

fn people_only(ctx: &CallContext, what: &str) -> Result<(), ProtoError> {
    if ctx.needs_user_approval() {
        return Err(ProtoError::new(
            ErrorCode::RejectedHumanPriority,
            format!(
                "{what} replaces KRAKEN's programs, which only a person may do; ask the person to \
                 run `kraken update`"
            ),
        ));
    }
    Ok(())
}

/// Reports the version, the install and the last update check.
pub struct UpdateStatus;

#[async_trait]
impl Command for UpdateStatus {
    type Args = super::NoArgs;
    type Output = UpdateStatusOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "update_status",
            "Show the version, how KRAKEN was installed and whether an update is available",
            CommandKind::Query,
            Permission::Safe,
        )
        .global()
        .doc(
            "Needs no project and uses no network: reads the result of the last check. Reports the \
             version, target and build channel, the install kind in plain words (`install.label`), \
             whether KRAKEN can update itself or the command your package manager uses, this \
             computer, and the newest release seen.\n\
             Example: update_status {}",
        )
        .details(
            "`update_available` compares `latest` with the running version (semver). A release \
             without `SHA256SUMS.minisig` (`latest_signed` false) cannot be installed by KRAKEN. \
             `checks_disabled_by` names what turned checks off.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        _args: super::NoArgs,
    ) -> Result<UpdateStatusOut, ProtoError> {
        let b = s.update()?.clone();
        blocking(move || b.status()).await
    }
}

/// Arguments of `update_check`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpdateCheckArgs {
    /// Ask GitHub now even when the last check is less than a day old.
    #[serde(default)]
    pub force: bool,
}

/// Asks GitHub for the newest release.
pub struct UpdateCheck;

#[async_trait]
impl Command for UpdateCheck {
    type Args = UpdateCheckArgs;
    type Output = UpdateStatusOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "update_check",
            "Check GitHub for a newer KRAKEN release (at most once a day unless forced)",
            CommandKind::Query,
            Permission::Safe,
        )
        .global()
        .doc(
            "Needs no project. Sends one HTTPS GET to api.github.com with the User-Agent \
             `kraken/<version>`; nothing else. Without `force` a result less than a day old is \
             returned as is. Checks that are off (`updates.check = false`, \
             `KRAKEN_NO_UPDATE_CHECK`, `CI`) still run when forced. Installs nothing.\n\
             Example: update_check {\"force\": true}",
        )
        .details(
            "Only tags of the form `vX.Y.Z` or `vX.Y.Z-pre` count. `channel = \"prerelease\"` in \
             `[updates]` also considers prereleases. The result is kept in `update-state.json` in \
             KRAKEN's data directory.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: UpdateCheckArgs,
    ) -> Result<UpdateStatusOut, ProtoError> {
        s.update()?.check(args.force).await
    }
}

/// Downloads and installs the newest release.
pub struct UpdateApply;

#[async_trait]
impl Command for UpdateApply {
    type Args = super::NoArgs;
    type Output = GlobalJobOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "update_apply",
            "Download, verify and install the newest KRAKEN release (job, people only)",
            CommandKind::Job,
            Permission::Mutating,
        )
        .global()
        .doc(
            "Needs no project. For installs KRAKEN updates itself (the script install, a release \
             archive, the AppImage, the Windows zip): downloads the release's SHA256SUMS, checks \
             its signature against the key compiled into KRAKEN, downloads the archive, checks its \
             SHA-256, tries the new `kraken --version` and swaps the files, keeping the old ones \
             for `update_rollback`. Package-managed installs are refused with their command. An \
             agent or the MCP surface is refused. Returns a `job_id` (`job-gN`).\n\
             Example: update_apply {}",
        )
        .details(
            "Never downgrades and never installs an unsigned release. Refuses to run as root and \
             refuses when a file it would replace is a link or belongs to someone else. Restart \
             KRAKEN afterwards to use the new version.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        _args: super::NoArgs,
    ) -> Result<GlobalJobOut, ProtoError> {
        let backend = s.update()?.clone();
        people_only(ctx, "update_apply")?;
        let id = s.jobs().spawn("update_apply", move |reporter| async move {
            let token = reporter.cancel_token();
            let on = move |p: JobProgress| reporter.progress(p);
            tokio::select! {
                biased;
                () = token.cancelled() => Err(ProtoError::new(ErrorCode::Cancelled, "update cancelled; nothing was replaced")),
                r = backend.apply(&on) => r.and_then(|v| serde_json::to_value(v)
                    .map_err(|e| ProtoError::new(ErrorCode::Internal, e.to_string()))),
            }
        });
        Ok(GlobalJobOut { job_id: id.0 })
    }
}

/// Goes back to the version the last update replaced.
pub struct UpdateRollback;

#[async_trait]
impl Command for UpdateRollback {
    type Args = super::NoArgs;
    type Output = UpdateApplied;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "update_rollback",
            "Go back to the version the last update replaced (people only)",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .global()
        .doc(
            "Needs no project. Puts back the one generation `update_apply` kept in \
             `<data dir>/previous/`. An agent or the MCP surface is refused.\n\
             Example: update_rollback {}",
        )
        .details("Fails when nothing was kept. Restart KRAKEN afterwards.")
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        _args: super::NoArgs,
    ) -> Result<UpdateApplied, ProtoError> {
        let b = s.update()?.clone();
        people_only(ctx, "update_rollback")?;
        blocking(move || b.rollback()).await
    }
}
