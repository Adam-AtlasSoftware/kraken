//! `next_steps`: what to do next in the open project, from the rules in [`crate::guide`].

use async_trait::async_trait;
use kraken_proto::{DwarfState, Hex64, PageRequest, ProtoError, TokenKind};
use object::Object;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::guide::{
    AutoLocal, CurrentFunction, DebugFacts, Facts, Suggestion, is_auto_function, is_auto_local,
    suggest,
};
use crate::session::{AnalysisPhase, Session, blocking};

use super::debuginfo::{DebugStatus, probe as probe_debug_info};
use super::locator_in;

/// Most suggestions returned.
pub const MAX_SUGGESTIONS: usize = 10;
/// Suggestions returned when `limit` is not given.
pub const DEFAULT_SUGGESTIONS: usize = 5;
/// Pages of functions read to count the default names, so a huge program costs a bounded scan.
const MAX_SCAN_PAGES: usize = 50;

/// Arguments of `next_steps`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NextStepsArgs {
    /// The function in view, as `0x...`: adds suggestions about its variables.
    #[serde(default)]
    pub function: Option<Hex64>,
    /// Most suggestions to return (default 5, at most 10).
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Result of `next_steps`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct NextStepsOut {
    /// What to do, most useful first. Empty when nothing stands out.
    pub suggestions: Vec<Suggestion>,
    /// The facts the rules looked at.
    pub facts: Facts,
}

/// Suggests what to do next.
pub struct NextSteps;

#[async_trait]
impl Command for NextSteps {
    type Args = NextStepsArgs;
    type Output = NextStepsOut;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "next_steps",
            "Suggest what to do next in this project",
            CommandKind::Query,
            Permission::Safe,
        )
        .doc(
            "Looks at the open project (analysis, debug information, function names, patches, \
             emulator setup, and the function in view) and returns up to a few suggestions, each \
             with a title, the reason, and the command with arguments that does it. Start here \
             when you do not know what to do next. Nothing is changed.\n\
             Example: next_steps {\"function\": \"0x401136\"}",
        )
        .details(
            "Each suggestion has an `id` (stable, so a client can remember a dismissal), \
             `title`, `reason`, `command` and `args`. `runnable: true` means `command` with \
             `args` can be called as it stands; `false` means it still needs something from the \
             person (a name for a variable) or the step is outside KRAKEN (`command` absent). \
             `facts` shows what the rules saw. Paid steps such as `assist_auto_name` ask first \
             when run. Pass `function` to also look at that function's variables: this \
             decompiles it.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: NextStepsArgs,
    ) -> Result<NextStepsOut, ProtoError> {
        let limit = args
            .limit
            .unwrap_or(DEFAULT_SUGGESTIONS)
            .clamp(1, MAX_SUGGESTIONS);
        let facts = gather(s, ctx, args.function).await?;
        let mut suggestions = suggest(&facts);
        suggestions.truncate(limit);
        Ok(NextStepsOut { suggestions, facts })
    }
}

async fn gather(
    s: &Session,
    ctx: &CallContext,
    function: Option<Hex64>,
) -> Result<Facts, ProtoError> {
    let project = s.project()?;
    let meta = project.meta();
    let program = project.program();
    let phase = project.analysis().phase;
    let mut facts = Facts {
        binary: meta.binary_path.clone(),
        format: program.format.clone(),
        arch: program.arch.clone(),
        analysed: phase == AnalysisPhase::Complete,
        analysis_running: phase == AnalysisPhase::Running,
        analysis_failed: phase == AnalysisPhase::Failed,
        ..Facts::default()
    };

    let engine = project.engine();
    if facts.analysed
        && let Some(lister) = engine.function_lister()
    {
        let mut cursor = None;
        let mut total = 0u64;
        for _ in 0..MAX_SCAN_PAGES {
            let page = lister
                .list_functions(
                    &PageRequest {
                        cursor: cursor.clone(),
                        limit: Some(1000),
                    },
                    &ctx.cancel,
                )
                .await?;
            total += page.items.len() as u64;
            facts.auto_named += page
                .items
                .iter()
                .filter(|f| is_auto_function(&f.name))
                .count() as u64;
            cursor = page.next_cursor;
            if cursor.is_none() {
                break;
            }
        }
        facts.function_count = total;
    }

    let attached = meta.loader.as_ref().and_then(|l| l.debug_file.clone());
    let binary = std::path::PathBuf::from(&meta.binary_path);
    let extra = attached.as_ref().map(std::path::PathBuf::from);
    let looked = {
        let binary = binary.clone();
        blocking(move || Ok(probe_debug_info(&binary, extra.as_deref()).ok())).await?
    };
    if attached.is_some() {
        facts.debug = DebugFacts::Have;
    } else if let Some(p) = looked {
        facts.names_pdb = p.refs.pdb.is_some();
        facts.debug = match p.status {
            DebugStatus::Embedded => DebugFacts::Have,
            DebugStatus::Found => DebugFacts::FileFound,
            DebugStatus::Missing => DebugFacts::FileMissing,
            DebugStatus::None => DebugFacts::None,
        };
        // DWARF that is inside but compressed still counts as held.
        if matches!(
            p.refs.dwarf,
            Some(DwarfState::Embedded | DwarfState::Compressed)
        ) {
            facts.debug = DebugFacts::Have;
        }
        facts.debug_candidate = p.best.map(|b| b.0);
    }

    let (on, verified) = project
        .with_store(|st| {
            let active = st.active_patches(None)?;
            let hash = super::patch_check::patch_set_hash(&active);
            let verified = !hash.is_empty() && st.patch_verdict(&hash)?.is_some();
            Ok((active.len() as u64, verified))
        })
        .await?;
    facts.patches_on = on;
    facts.patches_verified = verified;

    facts.needs_sysroot = {
        let binary = binary.clone();
        blocking(move || Ok(super::emulate::needs_sysroot(&binary))).await?
    };

    if let Some(address) = function {
        facts.current = current_function(s, ctx, address).await;
    }
    Ok(facts)
}

/// The function at `address` with the variables the decompiler named itself; absent when it
/// cannot be decompiled.
async fn current_function(
    s: &Session,
    ctx: &CallContext,
    address: Hex64,
) -> Option<CurrentFunction> {
    let project = s.project().ok()?;
    let engine = project.engine();
    let loc = locator_in(address, None).ok()?;
    let name = engine
        .function_lister()?
        .get_function(&loc, &ctx.cancel)
        .await
        .ok()?
        .name;
    let r = engine
        .decompiler()?
        .decompile(&loc, &ctx.cancel)
        .await
        .ok()?;
    let mut seen = std::collections::BTreeSet::new();
    let mut auto_locals = Vec::new();
    for t in r.tokens.iter().filter(|t| t.kind == TokenKind::Variable) {
        let Some(storage) = t.varnode.as_deref().and_then(storage_of) else {
            continue;
        };
        let text = r.text.get(t.start as usize..t.end as usize).unwrap_or("");
        let name = t.symbol.as_deref().unwrap_or(text);
        if is_auto_local(name) && seen.insert(storage.clone()) {
            auto_locals.push(AutoLocal {
                name: kraken_proto::sanitize(name),
                storage,
            });
        }
    }
    Some(CurrentFunction {
        address: format!("{:#x}", address.0),
        name: kraken_proto::sanitize(&name),
        auto_locals,
    })
}

/// The storage `set_local` takes from a token's varnode (`stack:0x..:4` without the size);
/// temporaries have no stable storage.
fn storage_of(varnode: &str) -> Option<String> {
    let mut parts = varnode.split(':');
    let space = parts.next()?;
    let offset = parts.next()?;
    matches!(space, "stack" | "register").then(|| format!("{space}:{offset}"))
}

/// Whether the file is a dynamically linked ELF that the emulator cannot run for want of a sysroot.
pub(super) fn dynamic_elf_arch(path: &std::path::Path) -> Option<kraken_emu::Arch> {
    let data = std::fs::read(path).ok()?;
    let arch = kraken_emu::Arch::from_elf(&data).ok()?;
    let file = object::File::parse(&*data).ok()?;
    file.section_by_name(".interp")?;
    Some(arch)
}

#[cfg(test)]
mod tests {
    use super::storage_of;

    #[test]
    fn storage_drops_the_size_and_skips_temporaries() {
        assert_eq!(
            storage_of("stack:0xffffffffffffffd8:4").as_deref(),
            Some("stack:0xffffffffffffffd8")
        );
        assert_eq!(
            storage_of("register:0x38:8").as_deref(),
            Some("register:0x38")
        );
        assert_eq!(storage_of("unique:0x1f80:4"), None);
    }
}
