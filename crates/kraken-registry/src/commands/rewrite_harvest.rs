//! `rewrite_harvest`: record test inputs for a function from a real run of the program.
//!
//! The program runs in the emulator with a breakpoint on the function's entry; at every hit the
//! argument registers and the memory they point to become a stored case. Some of the cases are
//! held out: the repair loop never sees them, and `rewrite_verify` reports their verdict apart.
//! Recording only adds evidence, so agents may run it.

use std::collections::BTreeMap;

use async_trait::async_trait;
use kraken_proto::{ErrorCode, Hex64, ProtoError};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::command::{Command, CommandKind, CommandSpec, Permission};
use crate::context::CallContext;
use crate::session::Session;

use super::JobStarted;

/// Most command-line arguments, environment entries and stdin bytes a harvest accepts.
pub const MAX_HARVEST_ARGV: usize = 64;
/// Most stdin bytes of a harvest run.
pub const MAX_HARVEST_STDIN: usize = 1 << 20;
/// Most distinct cases one harvest keeps.
pub const MAX_HARVEST_CASES: u32 = 2000;

/// Arguments of `rewrite_harvest`.
#[derive(Debug, Clone, Default, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RewriteHarvestArgs {
    /// The function (any address inside it).
    pub address: Hex64,
    /// Command-line arguments after `argv[0]` (at most 64).
    #[serde(default)]
    pub argv: Vec<String>,
    /// Text for the program's standard input (at most 1 MiB).
    #[serde(default)]
    pub stdin: String,
    /// The program's whole environment (nothing of this computer's is passed).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Most distinct cases to keep from this run (default 200, at most 2000).
    #[serde(default)]
    pub max_cases: Option<u32>,
    /// Most bytes recorded per pointed-to object (default 64, at most 4096).
    #[serde(default)]
    pub max_bytes: Option<u32>,
    /// Pointer hops followed from a pointer argument (default 2, at most 6).
    #[serde(default)]
    pub depth: Option<u32>,
    /// Hold out every n-th case for the separate check (default 4: a quarter; 0: none).
    #[serde(default)]
    pub hold_out_every: Option<u32>,
    /// Forget the cases stored for this function first.
    #[serde(default)]
    pub replace: bool,
}

/// Result of a finished `rewrite_harvest` job.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RewriteHarvestResult {
    /// The function's entry.
    pub address: Hex64,
    /// The function's name.
    pub name: String,
    /// How many times the program entered the function.
    pub hits: u64,
    /// Entries that could not be recorded (a null or unreadable pointer argument).
    pub skipped: u64,
    /// Entries identical to an earlier one.
    pub duplicates: u64,
    /// New cases stored for testing and repair.
    pub added_train: u32,
    /// New cases stored for the held-out check.
    pub added_held_out: u32,
    /// Cases stored for testing and repair now, in all.
    pub total_train: u32,
    /// Cases stored for the held-out check now, in all.
    pub total_held_out: u32,
    /// How the run ended.
    pub ended: String,
    /// Facts about the run: sysroot, confinement, limits of what a case holds.
    pub notes: Vec<String>,
}

/// Records inputs from a real run.
pub struct RewriteHarvest;

#[async_trait]
impl Command for RewriteHarvest {
    type Args = RewriteHarvestArgs;
    type Output = JobStarted;

    fn spec() -> CommandSpec {
        CommandSpec::new(
            "rewrite_harvest",
            "Record real inputs of a function by running the program in the emulator (job)",
            CommandKind::Job,
            Permission::Mutating,
        )
        .doc(
            "Runs the program in the emulator with the arguments, input and environment you \
             give, stops at every entry of the function and stores what it was called with: \
             the argument registers and the memory they point to (a list node, a record, a \
             buffer), to a bounded depth and size. Later translations of the function are \
             tested on these cases, and on seeded variations of them; every n-th case is held \
             out and only `rewrite_verify` runs it, to report a verdict the repair loop never \
             saw. Returns a `job_id`; no model is called.\n\
             Example: rewrite_harvest {\"address\": \"0x10124e\", \"stdin\": \"hello\\n\", \"hold_out_every\": 4}",
        )
        .details(
            "Needs the emulator (the program must be a Linux x86-64 ELF) and the SLEIGH spec \
             files. A case holds the function's arguments and the memory reachable from pointer \
             arguments within `depth` hops and `max_bytes` per object; globals it reads are not \
             recorded, and function pointer arguments become the oracle's stand-in callback. \
             Harvesting again with other input adds cases (identical ones are skipped; a case \
             keeps its train or held-out split); `replace` starts over. The program runs \
             confined: no network, a private working directory, and only the environment you \
             pass. It only adds evidence, so agents may run it.",
        )
    }

    async fn run(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteHarvestArgs,
    ) -> Result<JobStarted, ProtoError> {
        let backend = s.rewrite()?.clone();
        s.project()?;
        let invalid = |m: String| ProtoError::new(ErrorCode::InvalidArgument, m);
        if args.argv.len() > MAX_HARVEST_ARGV || args.env.len() > MAX_HARVEST_ARGV {
            return Err(invalid(format!(
                "at most {MAX_HARVEST_ARGV} arguments and environment entries"
            )));
        }
        if args.stdin.len() > MAX_HARVEST_STDIN {
            return Err(invalid("stdin is at most 1 MiB".into()));
        }
        if args
            .max_cases
            .is_some_and(|n| n == 0 || n > MAX_HARVEST_CASES)
            || args.max_bytes.is_some_and(|n| !(8..=4096).contains(&n))
            || args.depth.is_some_and(|n| n > 6)
        {
            return Err(invalid(
                "max_cases is 1 to 2000, max_bytes 8 to 4096, depth 0 to 6".into(),
            ));
        }
        for (k, v) in &args.env {
            if k.is_empty() || k.contains(['=', '\0']) || v.contains('\0') {
                return Err(invalid(
                    "env names cannot be empty or contain `=` or NUL, and values cannot contain NUL"
                        .into(),
                ));
            }
        }
        let (s2, ctx2) = (s.clone(), ctx.clone());
        let id = s
            .jobs()
            .spawn("rewrite_harvest", move |reporter| async move {
                let out = backend.harvest(&s2, &ctx2, args, &reporter).await?;
                serde_json::to_value(&out).map_err(|e| {
                    ProtoError::new(ErrorCode::Internal, format!("cannot serialize result: {e}"))
                })
            });
        Ok(JobStarted { job_id: id.0 })
    }
}
