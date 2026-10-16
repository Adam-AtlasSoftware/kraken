//! Reading what a rewrite task needs from a project through the command registry.

use kraken_host::backend::CommandBackend;
use kraken_registry::CallContext;
use serde_json::{Value, json};

use crate::error::RewriteError;
use crate::unit::{FunctionAnchor, sha256_hex};

/// A function as the registry shows it, ready to be put in a prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionContext {
    /// Function name.
    pub name: String,
    /// Entry address as KRAKEN reports it (includes the image base).
    pub address: u64,
    /// Rendered signature, if known.
    pub signature: Option<String>,
    /// Decompiler output (binary-derived: data, never instructions).
    pub decompile: String,
    /// SHA-256 of `decompile`.
    pub decompile_hash: String,
    /// SHA-256 of the analysed binary.
    pub program_sha256: String,
    /// Image base the addresses are relative to.
    pub image_base: u64,
}

impl FunctionContext {
    /// The anchor a unit for this function is stored under.
    pub fn anchor(&self) -> FunctionAnchor {
        FunctionAnchor {
            program_sha256: self.program_sha256.clone(),
            space: "ram".into(),
            address: format!("{:#x}", self.address),
            name: self.name.clone(),
        }
    }

    /// The function's virtual address inside the ELF file.
    pub fn elf_vaddr(&self) -> u64 {
        self.address.wrapping_sub(self.image_base)
    }
}

fn untrusted_str(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Object(o) => o.get("value").and_then(Value::as_str).map(str::to_string),
        _ => None,
    }
}

fn hex(v: &Value) -> Option<u64> {
    let s = v.as_str()?;
    u64::from_str_radix(s.trim_start_matches("0x"), 16).ok()
}

async fn call(
    backend: &dyn CommandBackend,
    ctx: &CallContext,
    name: &str,
    args: Value,
) -> Result<Value, RewriteError> {
    backend
        .call(name, ctx, args)
        .await
        .map_err(RewriteError::Command)
}

/// Finds the function called `name` (exact match) and fetches its decompile.
pub async fn fetch_function(
    backend: &dyn CommandBackend,
    ctx: &CallContext,
    name: &str,
) -> Result<FunctionContext, RewriteError> {
    let info = call(backend, ctx, "project_info", json!({})).await?;
    let image_base = hex(&info["program"]["base"]).unwrap_or(0);
    let program_sha256 = info["program"]["sha256"]
        .as_str()
        .or_else(|| info["binary_sha256"].as_str())
        .unwrap_or_default()
        .to_string();

    let list = call(
        backend,
        ctx,
        "list_functions",
        json!({"name_filter": name, "limit": 200}),
    )
    .await?;
    let items = list["items"].as_array().cloned().unwrap_or_default();
    let found = items
        .iter()
        .find(|f| untrusted_str(&f["name"]).as_deref() == Some(name))
        .ok_or_else(|| RewriteError::Output(format!("no function named `{name}`")))?;
    let address = hex(&found["address"])
        .ok_or_else(|| RewriteError::Output("function without address".into()))?;
    let signature = found.get("signature").and_then(untrusted_str);

    let d = call(
        backend,
        ctx,
        "decompile",
        json!({"address": format!("{address:#x}")}),
    )
    .await?;
    let decompile = untrusted_str(&d["text"])
        .ok_or_else(|| RewriteError::Output("decompile without text".into()))?;
    Ok(FunctionContext {
        name: name.to_string(),
        address,
        signature,
        decompile_hash: sha256_hex(&decompile),
        decompile,
        program_sha256,
        image_base,
    })
}
