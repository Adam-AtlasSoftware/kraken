//! The body of `rewrite_harvest`, and how stored harvested cases reach a rewrite and its replay.

use kraken_emu::confined::{DebugChild, find_runner};
use kraken_emu::linux::RunSpec;
use kraken_proto::{ErrorCode, Hex64, ProtoError};
use kraken_registry::commands::{RewriteHarvestArgs, RewriteHarvestResult, with_sysroot};
use kraken_registry::{CallContext, JobReporter, Session};
use kraken_sidecar::ConfinementOptions;

use super::{RewriteService, progress, proto, with_store};
use crate::abi::{Arg, Signature};
use crate::error::RewriteError;
use crate::fuzz::{FuzzOptions, fuzz_cases};
use crate::harvest::{HarvestOptions, harvest_child};
use crate::inputs::{Chain, InputSource, InputSpec, Recorded};
use crate::lift::Lift;
use crate::store::HarvestSplit;

/// Default share held out: every fourth case.
pub(crate) const DEFAULT_HOLD_OUT_EVERY: u32 = 4;

fn problem(code: ErrorCode, m: impl Into<String>) -> ProtoError {
    ProtoError::new(code, m)
}

/// `generated` inputs with the training half of the harvested cases and seeded mutations of
/// them in front. Held-out cases are never part of it.
pub(crate) fn with_harvested(
    generated: InputSpec,
    train: Vec<Vec<Arg>>,
    sig: &Signature,
    seed: u64,
) -> InputSpec {
    let usable: Vec<Vec<Arg>> = train
        .into_iter()
        .filter(|c| crate::inputs::case_fits(sig, c))
        .collect();
    if usable.is_empty() {
        return generated;
    }
    let fuzzed = Recorded::fuzzed(fuzz_cases(
        &usable,
        &FuzzOptions {
            seed,
            ..FuzzOptions::default()
        },
    ));
    let harvested = Recorded::harvested(usable);
    let mut fixed = Chain(vec![&harvested, &fuzzed]).cases(seed, 0);
    fixed.extend(generated.fixed.clone());
    InputSpec { fixed, ..generated }
}

impl RewriteService {
    pub(crate) async fn harvest_job(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: RewriteHarvestArgs,
        job: &JobReporter,
    ) -> Result<RewriteHarvestResult, ProtoError> {
        let project = s.project()?;
        let dir = project.dir().to_path_buf();
        progress(job, "load", 0, 4, "reading the function");
        let prepared = self.prepare(s, ctx, args.address.0).await?;
        let (f, sig) = (prepared.function, prepared.signature);
        let lift = Lift::new(s, ctx);
        let (sha, image_base) = lift.program().map_err(proto)?;
        let (binary, _) = lift.binary().map_err(proto)?;
        let address = format!("{:#x}", f.address);

        let mut opts = HarvestOptions::default();
        if let Some(n) = args.max_cases {
            opts.max_cases = n as usize;
        }
        if let Some(n) = args.max_bytes {
            opts.max_bytes = n as usize;
        }
        if let Some(n) = args.depth {
            opts.depth = n as usize;
        }
        let stride = args.hold_out_every.unwrap_or(DEFAULT_HOLD_OUT_EVERY);
        let replace = args.replace;
        let entry_listing = f.address;
        progress(job, "run", 1, 4, "running the program to the function");
        let sig2 = sig.clone();
        let (run, mut notes) = tokio::task::spawn_blocking(move || {
            run_and_record(&binary, &args, &sig2, entry_listing, image_base, &opts)
        })
        .await
        .map_err(|e| problem(ErrorCode::Internal, format!("harvest task failed: {e}")))??;

        progress(job, "store", 3, 4, "storing the cases");
        let cases = run.cases.clone();
        let (added_train, added_held_out, total_train, total_held_out) =
            with_store(dir, move |st| {
                if replace {
                    st.clear_harvest(&sha, &address)?;
                }
                let (t, h) = st.add_harvest(&sha, &address, "emulator run", &cases, stride)?;
                let tt = st.harvested(&sha, &address, HarvestSplit::Train)?.len();
                let hh = st.harvested(&sha, &address, HarvestSplit::HeldOut)?.len();
                Ok((t, h, tt, hh))
            })
            .await?;
        if stride > 0 && total_held_out == 0 {
            notes.push(format!(
                "no case is held out yet: every {stride}th case is, so {stride} cases are needed"
            ));
        }
        progress(job, "done", 4, 4, "finished");
        let n = |v: usize| u32::try_from(v).unwrap_or(u32::MAX);
        Ok(RewriteHarvestResult {
            address: Hex64(f.address),
            name: f.name,
            hits: run.hits,
            skipped: run.skipped,
            duplicates: run.duplicates,
            added_train: n(added_train),
            added_held_out: n(added_held_out),
            total_train: n(total_train),
            total_held_out: n(total_held_out),
            ended: run.ended,
            notes,
        })
    }
}

/// Starts the program confined, runs it to every entry of the function and records the cases.
fn run_and_record(
    binary: &std::path::Path,
    args: &RewriteHarvestArgs,
    sig: &Signature,
    entry_listing: u64,
    image_base: u64,
    opts: &HarvestOptions,
) -> Result<(crate::harvest::HarvestRun, Vec<String>), ProtoError> {
    let runner = find_runner().filter(|p| p.is_file()).ok_or_else(|| {
        problem(
            ErrorCode::Unsupported,
            "the emulator's child program `kraken-emu-run` was not found next to this executable: \
             build it (`cargo build -p kraken-emu --bin kraken-emu-run`) or set KRAKEN_EMU_RUN \
             to its path",
        )
    })?;
    let work = tempfile::Builder::new()
        .prefix("kraken-harvest-")
        .tempdir()
        .map_err(|e| problem(ErrorCode::Internal, format!("private directory: {e}")))?;
    let mut spec = RunSpec::new(binary);
    spec.args = args.argv.clone();
    spec.stdin = args.stdin.clone().into_bytes();
    spec.env = args
        .env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    spec.output_cap = 64 * 1024;
    spec.workdir = Some(work.path().to_path_buf());
    let mut notes = Vec::new();
    let start = |spec: &RunSpec| DebugChild::start(spec, &runner, ConfinementOptions::default());
    let (mut child, _libs) = with_sysroot(&mut spec, binary, binary, &mut notes, start)?;
    if !child.report().is_confined() {
        notes.push(format!(
            "the emulator child ran with limited confinement: {}",
            child.report()
        ));
    }
    let bias = child.initial.main_bias;
    let delta = if bias == 0 {
        0
    } else {
        bias.wrapping_sub(image_base)
    };
    let run = harvest_child(&mut child, sig, entry_listing.wrapping_add(delta), opts).map_err(
        |e| match e {
            RewriteError::Unsupported(m) => problem(ErrorCode::Unsupported, m),
            other => problem(ErrorCode::Internal, other.to_string()),
        },
    )?;
    notes.extend(run.notes.iter().cloned());
    Ok((run, notes))
}
