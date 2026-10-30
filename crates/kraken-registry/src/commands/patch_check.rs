//! `patch_lint` and `patch_verify`: checks on the byte patches before they are exported.
//!
//! `patch_lint` looks at what the patches sit on (a slot the loader rewrites, a function
//! boundary, a PE checksum or signature) without running anything. `patch_verify` runs the
//! original and the patched program on the same input through `emulate_compare` and keeps the
//! verdict, keyed by a hash of the patches that were on, so `patch_list` can say whether the
//! current set was verified and with what result.

use std::path::PathBuf;

use async_trait::async_trait;
use kraken_engine::{Cap, unsupported};
use kraken_model::{Patch, PatchVerdict};
use kraken_proto::{ErrorCode, Hex64, PageRequest, ProtoError, Untrusted, hex_bytes, sanitize};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use super::emulate::{EmulateCompareArgs, EmulateCompareOut, compare_variants};
use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::patchfile::{apply_project_patches, image_findings};
use crate::session::{Session, blocking};
use crate::views::locator_parts;

/// Pages of functions read when checking function boundaries.
const FUNCTION_PAGES: usize = 100;

/// A hash that names the patches that are switched on: their addresses and bytes, not their
/// notes or sets, so it changes exactly when the bytes a run would see change. Empty when no
/// patch is on.
pub(crate) fn patch_set_hash(active: &[Patch]) -> String {
    use sha2::{Digest, Sha256};
    if active.is_empty() {
        return String::new();
    }
    let mut sorted: Vec<&Patch> = active.iter().collect();
    sorted.sort_by_key(|p| p.address);
    let mut h = Sha256::new();
    for p in sorted {
        h.update(format!(
            "{:x}:{}:{}\n",
            p.address,
            hex_bytes(&p.original),
            hex_bytes(&p.replacement)
        ));
    }
    hex_bytes(&h.finalize())[..16].to_string()
}

/// The verdict of a verification run, as `patch_list` and `patch_verify` show it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PatchVerdictView {
    /// Hash of the patches that were on when it ran.
    pub set_hash: String,
    /// True when the original and the patched program behaved the same on the inputs given.
    pub same: bool,
    /// The first difference between the runs, or empty when they agree. Program output, so
    /// untrusted.
    pub summary: Untrusted<String>,
    /// When it ran, milliseconds since the Unix epoch.
    pub ts_ms: i64,
}

impl From<PatchVerdict> for PatchVerdictView {
    fn from(v: PatchVerdict) -> Self {
        PatchVerdictView {
            set_hash: v.set_hash,
            same: v.same,
            summary: crate::validate::untrusted(&v.summary),
            ts_ms: v.ts_ms,
        }
    }
}

// ---- patch_lint -------------------------------------------------------------------------

/// Arguments of `patch_lint`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchLintArgs {
    /// Check only the patches of this patch set. Absent checks every patch that is switched on.
    #[serde(default)]
    pub group: Option<String>,
}

/// One thing `patch_lint` noticed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct LintFinding {
    /// `relocation`, `function_boundary`, `pe_checksum` or `signature`.
    pub kind: String,
    /// `warning` (the patch may not do what was meant) or `info`.
    pub severity: String,
    /// The patch it is about, when it is about one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Hex64>,
    /// What it means, in plain language.
    pub message: String,
}

/// Result of `patch_lint`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PatchLintOut {
    /// Patches checked.
    pub patches_checked: u32,
    /// What was found; empty when every check passed.
    pub findings: Vec<LintFinding>,
}

/// Checks the patches for things that make them misbehave.
pub struct PatchLint;

#[async_trait]
impl Command for PatchLint {
    type Args = PatchLintArgs;
    type Output = PatchLintOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "patch_lint",
            "Warn about patches over loader-rewritten bytes, across function ends, or on signed files",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Checks the byte patches that are switched on (or one patch set) against the binary \
             without running anything: a patch over a PE base-relocation slot or an ELF dynamic \
             relocation (the loader overwrites those bytes, so the patch has no effect), a patch \
             that spans the end of a function, a PE checksum that goes stale (`patch_export` \
             recomputes it) and an Authenticode signature the patch invalidates (kept, not \
             stripped). Findings are warnings; nothing is changed.\n\
             Example: patch_lint {}",
        )
        .details(
            "Relocation checks read the file's own relocation tables; function boundaries use \
             the engine's function sizes, so a function without a known size is not checked. \
             Mach-O code signatures are not looked at. A patch that does not line up with the \
             file fails with the same error `patch_export` gives.",
        )
        .needs(&[Cap::FunctionLister])
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: PatchLintArgs,
    ) -> Result<PatchLintOut, ProtoError> {
        let project = s.project()?;
        let binary = PathBuf::from(project.meta().binary_path);
        let group = args.group.clone();
        let patches = project
            .with_store(move |st| {
                if let Some(g) = &group
                    && !st.patch_groups()?.iter().any(|(n, _)| n == g)
                {
                    return Err(ProtoError::new(
                        ErrorCode::InvalidArgument,
                        format!("there is no patch set named {g:?}"),
                    ));
                }
                st.active_patches(group.as_deref())
            })
            .await?;
        let base = project.program().base.0;
        let mut findings = {
            let patches = patches.clone();
            blocking(move || {
                let image = std::fs::read(&binary).map_err(|e| {
                    ProtoError::new(
                        ErrorCode::NotFound,
                        format!("cannot read the project's binary {}: {e}", binary.display()),
                    )
                })?;
                let (_, applied) = apply_project_patches(&binary, &patches, base)?;
                Ok(image_findings(&image, &applied)
                    .into_iter()
                    .map(|f| LintFinding {
                        kind: f.kind.to_string(),
                        severity: if f.kind == "pe_checksum" {
                            "info"
                        } else {
                            "warning"
                        }
                        .into(),
                        address: f.address.map(Hex64),
                        message: f.message,
                    })
                    .collect::<Vec<_>>())
            })
            .await?
        };

        if !patches.is_empty() {
            let engine = project.engine();
            let lister = engine
                .function_lister()
                .ok_or_else(|| unsupported("function_lister"))?;
            let mut funcs: Vec<(u64, u64, String)> = Vec::new();
            let mut cursor = None;
            for _ in 0..FUNCTION_PAGES {
                let page = lister
                    .list_functions(
                        &PageRequest {
                            cursor: cursor.clone(),
                            limit: Some(200),
                        },
                        &ctx.cancel,
                    )
                    .await?;
                for f in &page.items {
                    if let Some(size) = f.size.filter(|n| *n > 0) {
                        funcs.push((locator_parts(&f.locator).1.0, size, sanitize(&f.name)));
                    }
                }
                cursor = page.next_cursor;
                if cursor.is_none() {
                    break;
                }
            }
            funcs.sort_by_key(|f| f.0);
            for p in &patches {
                findings.extend(boundary_finding(&funcs, p));
            }
        }
        findings.sort_by_key(|f| f.address.map_or(u64::MAX, |a| a.0));
        Ok(PatchLintOut {
            patches_checked: patches.len() as u32,
            findings,
        })
    }
}

/// A warning when `patch` starts inside a function and runs past its end, or ends inside a
/// different one.
fn boundary_finding(funcs: &[(u64, u64, String)], patch: &Patch) -> Option<LintFinding> {
    let start = patch.address;
    let last = start.checked_add(patch.len() as u64)?.checked_sub(1)?;
    let holds = |a: u64| funcs.iter().find(|f| f.0 <= a && a - f.0 < f.1);
    let first = holds(start);
    let end = holds(last);
    let message = match (first, end) {
        (Some(a), Some(b)) if a.0 != b.0 => format!(
            "the patch at {start:#x} spans from function {} into {}",
            a.2, b.2
        ),
        (Some(a), None) => format!(
            "the patch at {start:#x} starts in function {} and runs past its end ({:#x})",
            a.2,
            a.0 + a.1
        ),
        (None, Some(b)) => format!(
            "the patch at {start:#x} starts outside any function and ends inside {}",
            b.2
        ),
        _ => return None,
    };
    Some(LintFinding {
        kind: "function_boundary".into(),
        severity: "warning".into(),
        address: Some(Hex64(start)),
        message,
    })
}

// ---- patch_verify -----------------------------------------------------------------------

/// Arguments of `patch_verify`: the inputs both runs get.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PatchVerifyArgs {
    /// What both runs read as standard input (default empty; at most 1 MiB).
    #[serde(default)]
    pub stdin: String,
    /// Command-line arguments after `argv[0]` of both runs.
    #[serde(default)]
    pub argv: Vec<String>,
    /// `argv[0]` of both runs (default `prog`).
    #[serde(default)]
    pub argv0: Option<String>,
    /// Environment variables of both runs.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    /// Files seeded into `/work` of both runs.
    #[serde(default)]
    pub inputs: Vec<super::emulate::EmulateInput>,
    /// Instruction budget of each run (default 20000000, at most 200000000).
    #[serde(default)]
    pub max_steps: Option<u64>,
    /// Wall-clock limit of each run in seconds (default 20, at most 120).
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
}

/// Result of `patch_verify`: the comparison, and the verdict kept for the patch set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct PatchVerifyOut {
    /// The two runs and how they differ.
    #[serde(flatten)]
    pub compare: EmulateCompareOut,
    /// The verdict now recorded for the patches that are on.
    pub verdict: PatchVerdictView,
}

/// Runs the original and the patched program on the same input and records the verdict.
pub struct PatchVerify;

#[async_trait]
impl Command for PatchVerify {
    type Args = PatchVerifyArgs;
    type Output = PatchVerifyOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "patch_verify",
            "Run the original and the patched program on the same input and record whether they agree",
            CommandKind::Mutation,
            Permission::Mutating,
        )
        .doc(
            "Like `emulate_compare` with the default variants (original against the patches that \
             are on), then keeps the result as the verdict of exactly that set of patches: \
             `patch_list` shows it on each patch until a patch is added, removed, switched or \
             changed, which makes a new set with no verdict. A verdict of `same: false` is not a \
             failure: a patch is meant to change behaviour, and the first difference says how.\n\
             Example: patch_verify {\"stdin\": \"1 + 2\\n\", \"argv\": [\"-v\"], \"env\": {\"MODE\": \"fast\"}}",
        )
        .details(
            "Both runs are sandboxed as `emulate_run` describes, with the same arguments, \
             standard input, environment and seeded files. The verdict is keyed by a hash of the \
             addresses and bytes of the patches that are switched on, so it follows the bytes, \
             not the notes or sets. With no patch switched on the command fails. The verdict is \
             project state, not an edit-log entry: `undo` does not remove it.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        _ctx: &CallContext,
        args: PatchVerifyArgs,
    ) -> Result<PatchVerifyOut, ProtoError> {
        let project = s.project()?;
        let active = project.with_store(|st| st.active_patches(None)).await?;
        // The run uses exactly the patches the verdict is stored for, even if the set changes
        // while it runs.
        let set_hash = patch_set_hash(&active);
        let compare = compare_variants(
            s,
            EmulateCompareArgs {
                stdin: args.stdin,
                argv: args.argv,
                argv0: args.argv0,
                env: args.env,
                inputs: args.inputs,
                max_steps: args.max_steps,
                timeout_seconds: args.timeout_seconds,
                a: None,
                b: None,
            },
            Some(active),
        )
        .await?;
        let same = compare.same;
        let summary = compare.first_divergence.0.clone();
        let hash = set_hash.clone();
        let stored = project
            .with_store(move |st| {
                st.patch_verdict_put(&hash, same, &summary)?;
                st.patch_verdict(&hash)
            })
            .await?
            .ok_or_else(|| {
                ProtoError::new(
                    ErrorCode::Internal,
                    "the verdict was not stored".to_string(),
                )
            })?;
        Ok(PatchVerifyOut {
            compare,
            verdict: stored.into(),
        })
    }
}
