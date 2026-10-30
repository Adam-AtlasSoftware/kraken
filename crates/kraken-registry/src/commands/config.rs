//! `config_get` and `config_set`: read and change the non-secret settings of `config.toml`.
//!
//! Only an allowlist of keys is reachable; the provider tables, API keys and the assistant's
//! shell rules never are. Both commands need no project. The file is read and written by a
//! [`ConfigStore`] that `kraken-host` provides.

use std::sync::Arc;

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::Session;

/// One setting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct ConfigEntry {
    /// The key (`engine`, `daemon.idle_secs`).
    pub key: String,
    /// The value in the file; absent when the key is not set (the default applies).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    /// What values it takes (`true or false`, `ghidra, native or auto`, `a directory`).
    pub accepts: String,
    /// What it does.
    pub doc: String,
    /// True when only a person may change it, never an agent or the MCP surface.
    pub person_only: bool,
}

/// Reads and writes the allowlisted keys of the configuration file; provided by `kraken-host`.
pub trait ConfigStore: Send + Sync + std::fmt::Debug {
    /// Every allowlisted key with its value in the file, or just `key`.
    fn get(&self, key: Option<&str>) -> Result<Vec<ConfigEntry>, ProtoError>;

    /// Sets `key` (`null` unsets it) and saves the file. The caller already checked who may.
    fn set(&self, key: &str, value: Value) -> Result<ConfigEntry, ProtoError>;
}

impl Session {
    /// Attaches the configuration file the `config_*` commands work on.
    pub fn with_config_store(mut self, b: Arc<dyn ConfigStore>) -> Session {
        self.config_store = Some(b);
        self
    }

    fn store(&self) -> Result<&Arc<dyn ConfigStore>, ProtoError> {
        self.config_store.as_ref().ok_or_else(|| {
            ProtoError::new(
                ErrorCode::Unsupported,
                "the configuration file is not attached to this session; use the kraken CLI or \
                 krakend",
            )
        })
    }
}

/// Arguments of `config_get`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigGetArgs {
    /// One key; without it every settable key is listed.
    #[serde(default)]
    pub key: Option<String>,
}

/// Output of `config_get`.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ConfigGetOut {
    /// The entries, in a fixed order.
    pub entries: Vec<ConfigEntry>,
}

/// Reads settings.
pub struct ConfigGet;

#[async_trait]
impl Command for ConfigGet {
    type Args = ConfigGetArgs;
    type Output = ConfigGetOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "config_get",
            "Read the settings of config.toml that can be changed from here",
            CommandKind::Query,
            Permission::Safe,
        )
        .global()
        .doc(
            "Needs no project. Lists every settable key with its value in the file (absent: the \
             default applies), what it accepts and whether only a person may change it, or one \
             key. Provider tables and API keys are never shown.\n\
             Example: config_get {\"key\": \"engine\"}",
        )
        .details(
            "The value is the one in the file, not the effective one: environment variables \
             such as `KRAKEN_ENGINE` override the file at run time.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: ConfigGetArgs,
    ) -> Result<ConfigGetOut, ProtoError> {
        let entries = s.store()?.get(args.key.as_deref())?;
        Ok(ConfigGetOut { entries })
    }
}

/// Arguments of `config_set`.
#[derive(Debug, Clone, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ConfigSetArgs {
    /// The key, from `config_get`.
    pub key: String,
    /// The new value; `null` removes the key so the default applies again.
    pub value: Value,
}

/// Changes a setting.
pub struct ConfigSet;

#[async_trait]
impl Command for ConfigSet {
    type Args = ConfigSetArgs;
    type Output = ConfigEntry;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "config_set",
            "Change one setting of config.toml (people only)",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .global()
        .doc(
            "Needs no project. Writes one allowlisted key of config.toml; `null` removes it. \
             Only a person may call it: an agent or the MCP surface is refused. A running \
             daemon picks most keys up when it next starts.\n\
             Example: config_set {\"key\": \"engine\", \"value\": \"native\"}",
        )
        .details(
            "The value is checked against the key's type before anything is written, and the \
             file is replaced in one step. Comments in the file are not kept. Keys that loosen \
             a safeguard (`danger_mode`, `allow_unconfined`, `per_run_cap`) are marked \
             `person_only` in `config_get`; every key is refused to agents because the file \
             decides what they may do.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: ConfigSetArgs,
    ) -> Result<ConfigEntry, ProtoError> {
        if ctx.needs_user_approval() {
            return Err(ProtoError::new(
                ErrorCode::RejectedHumanPriority,
                "changing the configuration is reserved for people; ask the person to run \
                 `kraken config-set`",
            ));
        }
        s.store()?.set(&args.key, args.value)
    }
}
