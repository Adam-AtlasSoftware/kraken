//! A scripted rewrite pipeline for the demo project and the `--scene rewrite` screenshot.
//!
//! It implements the registry's [`RewriteBackend`] with canned answers, so the Rewrite tab in
//! `kraken-gui --demo` exercises the real commands (permissions, jobs, events) with nothing
//! running and no model involved. `rewrite_unit` hands out the stored Rust code and the version
//! history in the registry's own shape (see the module docs of [`crate::rewrite`]).
//! Nothing here is random, so a screenshot of it is the same every time.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{
    ExportRequest, RewriteAcceptArgs, RewriteAcceptOut, RewriteAddCaseArgs, RewriteBackend,
    RewriteBuildArgs, RewriteBuildResult, RewriteCheckOut, RewriteExportResult,
    RewriteFunctionArgs, RewriteFunctionResult, RewritePlanArgs, RewritePlanOut,
    RewriteProgramArgs, RewriteProgramResult, RewriteProgramStatusArgs, RewriteProgramStatusOut,
    RewriteRejectArgs, RewriteSpecArgs, RewriteSpecResult, RewriteStatusArgs, RewriteStatusOut,
    RewriteUnaccept, RewriteUnitArgs, RewriteUnitOut, RewriteVerifyArgs, RewriteVerifyResult,
    UnitChangeOut,
};
use kraken_registry::{CallContext, JobProgress, JobReporter, Session};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// Time one phase of a scripted job takes, so the progress bar is visible.
const STEP: Duration = Duration::from_millis(450);
const PROVIDER: &str = "demo";
const MODEL: &str = "scripted";

struct F {
    addr: u64,
    name: &'static str,
    callees: &'static [u64],
    imports: &'static [&'static str],
    stubs: &'static [&'static str],
    flags: &'static [&'static str],
    proto: &'static str,
}

/// The demo program's functions, callees first.
const FUNCS: &[F] = &[
    F {
        addr: 0x401440,
        name: "FUN_00401440",
        callees: &[],
        imports: &[],
        stubs: &[],
        flags: &[],
        proto: "pub unsafe extern \"C\" fn FUN_00401440(param_1: *const u8, param_2: usize) -> u32",
    },
    F {
        addr: 0x401240,
        name: "checksum",
        callees: &[],
        imports: &[],
        stubs: &[],
        flags: &[],
        proto: "pub unsafe extern \"C\" fn checksum(buf: *const u8, len: usize) -> u32",
    },
    F {
        addr: 0x401040,
        name: "helper",
        callees: &[],
        imports: &[],
        stubs: &[],
        flags: &[],
        proto: "pub extern \"C\" fn helper(n: i32)",
    },
    F {
        addr: 0x401080,
        name: "cleanup",
        callees: &[],
        imports: &[],
        stubs: &[],
        flags: &["uses_globals"],
        proto: "pub extern \"C\" fn cleanup()",
    },
    F {
        addr: 0x4012a0,
        name: "log_error",
        callees: &[],
        imports: &["fprintf"],
        stubs: &["fprintf"],
        flags: &["needs_stubs"],
        proto: "pub unsafe extern \"C\" fn log_error(msg: *const core::ffi::c_char, code: i32)",
    },
    F {
        addr: 0x401340,
        name: "FUN_00401340",
        callees: &[0x4012a0],
        imports: &["exit"],
        stubs: &["exit", "fprintf"],
        flags: &["needs_stubs"],
        proto: "pub unsafe extern \"C\" fn FUN_00401340(param_1: i32)",
    },
    F {
        addr: 0x401300,
        name: "FUN_00401300",
        callees: &[0x401340],
        imports: &["malloc"],
        stubs: &["malloc", "exit", "fprintf"],
        flags: &["needs_stubs"],
        proto: "pub unsafe extern \"C\" fn FUN_00401300(param_1: i32) -> u64",
    },
    F {
        addr: 0x401380,
        name: "handle_hello",
        callees: &[0x401440],
        imports: &[],
        stubs: &[],
        flags: &[],
        proto: "pub unsafe extern \"C\" fn handle_hello(payload: *const u8, len: usize) -> i32",
    },
    F {
        addr: 0x4011a0,
        name: "process_packet",
        callees: &[0x4012a0, 0x401240, 0x401380],
        imports: &[],
        stubs: &["fprintf"],
        flags: &["needs_stubs"],
        proto: "pub unsafe extern \"C\" fn process_packet(buf: *const u8, len: usize) -> i32",
    },
    F {
        addr: 0x4013e0,
        name: "read_config",
        callees: &[0x4012a0],
        imports: &["fopen", "fread", "fclose"],
        stubs: &["fopen", "fread", "fclose", "fprintf"],
        flags: &["needs_stubs", "uses_globals"],
        proto: "pub unsafe extern \"C\" fn read_config(path: *const core::ffi::c_char, cfg: *mut u8) -> i32",
    },
    F {
        addr: 0x4010c0,
        name: "parse_args",
        callees: &[0x4013e0],
        imports: &[],
        stubs: &["fopen", "fread", "fclose", "fprintf"],
        flags: &["needs_stubs"],
        proto: "pub unsafe extern \"C\" fn parse_args(argc: i32, argv: *const *const core::ffi::c_char, cfg: *mut u8) -> i32",
    },
    F {
        addr: 0x401120,
        name: "init_session",
        callees: &[0x401300],
        imports: &[],
        stubs: &["malloc", "exit", "fprintf"],
        flags: &["needs_stubs"],
        proto: "pub unsafe extern \"C\" fn init_session(cfg: *mut u8)",
    },
    F {
        addr: 0x401000,
        name: "main",
        callees: &[0x4010c0, 0x401120, 0x401040, 0x4011a0, 0x4012a0, 0x401080],
        imports: &[],
        stubs: &["malloc", "exit", "fprintf", "fopen", "fread", "fclose"],
        flags: &["needs_stubs", "uses_globals"],
        proto: "pub unsafe extern \"C\" fn main(argc: i32, argv: *const *const core::ffi::c_char) -> i32",
    },
];

struct Ver {
    version: u32,
    unit: String,
    status: &'static str,
    verdict: &'static str,
    detail: Option<&'static str>,
    cases_run: u32,
    passed: u32,
    skipped: u32,
    counterexample: Option<Value>,
    code: String,
    assumptions: Vec<&'static str>,
}

#[derive(Default)]
struct Inner {
    versions: BTreeMap<u64, Vec<Ver>>,
    accepted: BTreeMap<u64, u32>,
    specs: BTreeMap<u64, (u64, String)>,
    program_spec: Option<(u64, String)>,
    next_spec: u64,
    /// Stored whole-program runs, oldest first.
    program_runs: Vec<Value>,
    /// Cases the person added, per unit.
    user_cases: BTreeMap<String, u32>,
    /// The coverage a replay measured, per unit.
    coverage: BTreeMap<String, Value>,
}

/// The scripted pipeline. Clones share state.
#[derive(Clone)]
pub struct DemoRewrite {
    inner: Arc<Mutex<Inner>>,
}

const CHECKSUM_V1: &str = "#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn checksum(buf: *const u8, len: usize) -> u32 {
    let bytes = unsafe { core::slice::from_raw_parts(buf, len) };
    let mut sum: u32 = 0;
    for &b in bytes {
        // the bytes are read as signed
        sum = (sum << 5).wrapping_add(sum).wrapping_add(b as i8 as i32 as u32);
    }
    sum
}
";

const CHECKSUM_V2: &str = "#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn checksum(buf: *const u8, len: usize) -> u32 {
    let bytes = unsafe { core::slice::from_raw_parts(buf, len + 1) };
    let mut sum: u32 = 0;
    for &b in bytes {
        sum = (sum << 5).wrapping_add(sum).wrapping_add(b as u32);
    }
    sum
}
";

const CHECKSUM_V3: &str = "#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn checksum(buf: *const u8, len: usize) -> u32 {
    let bytes = unsafe { core::slice::from_raw_parts(buf, len) };
    let mut sum: u32 = 0;
    for &b in bytes {
        sum = (sum << 5).wrapping_add(sum).wrapping_add(b as u32);
    }
    sum
}
";

/// The demo's whole-program run `n`: run 1 is a first attempt whose `main` prints a second space
/// (a program-level difference the function-level checks could not see); run 2 is the same program
/// after one repair round fixed it.
fn demo_program_run(n: u64) -> Value {
    let obj = |s: &str| json!({"untrusted": true, "value": s});
    let fixed = n >= 2;
    let funcs: Vec<Value> = FUNCS
        .iter()
        .take(9)
        .enumerate()
        .map(|(i, f)| {
            let compare = f.flags.is_empty() && f.callees.len() < 2;
            let repaired = fixed && f.name == "process_packet";
            json!({
                "order": i, "address": format!("{:#x}", f.addr), "name": obj(f.name),
                "unit": unit_id(f.addr, 1 + u32::from(repaired)), "version": 1 + u32::from(repaired),
                "status": if compare { "verified" } else { "translated" },
                "verdict": if compare { "pass" } else { "inconclusive" },
                "check": if compare { "differential" } else { "compile_only" },
                "check_note": if compare { Value::Null } else {
                    obj("calls fprintf, which the function-level test does not model")
                },
                "attempts": 1 + u32::from(repaired),
                "reused_callees": f.callees.iter().filter_map(|c| FUNCS.iter().find(|g| g.addr == *c))
                    .map(|g| g.name).collect::<Vec<_>>(),
                "included": true,
            })
        })
        .collect();
    let case = |name: &str, origin: &str, argv: &[&str], agree: bool, rewritten: &str| {
        let original = "packet ok\nchecksum=0x3a7f\nstatus: 2 handled\n";
        let side = |out: &str| {
            json!({"exit": "exit 0", "stdout": obj(out), "stdout_bytes": out.len(),
                   "stderr": obj(""), "stderr_bytes": 0})
        };
        json!({
            "name": name, "origin": origin, "argv": argv.iter().map(|a| obj(a)).collect::<Vec<_>>(),
            "stdin_bytes": 0, "agree": agree,
            "original": side(original), "rewritten": side(rewritten),
            "differences": if agree { vec![] } else {
                vec![obj("stdout: 44 bytes vs 45 bytes, first difference at byte 29: original `status: 2`, rewritten `status:  2`")]
            },
        })
    };
    let wrong = "packet ok\nchecksum=0x3a7f\nstatus:  2 handled\n";
    let right = "packet ok\nchecksum=0x3a7f\nstatus: 2 handled\n";
    let cases = if fixed {
        vec![
            case("baseline", "baseline", &[], true, right),
            case("-v", "corpus", &["-v"], true, right),
            case("generated-1", "generated", &["x y"], true, right),
        ]
    } else {
        vec![
            case("baseline", "baseline", &[], false, wrong),
            case("-v", "corpus", &["-v"], false, wrong),
            case("generated-1", "generated", &["x y"], true, right),
        ]
    };
    let failed = cases.iter().filter(|c| c["agree"] == false).count();
    json!({
        "run": n, "program_sha256": "00", "entry": "0x401500", "entry_name": obj("main"),
        "functions_planned": funcs.len(), "skipped": 0, "translated": funcs.len(),
        "reused_from_store": 0, "failed": 0, "included": funcs.len(), "functions": funcs,
        "crate_dir": "/work/demo/rewrite-program", "built": true,
        "crate_sha256": "5c0f9a4e1b7d2368a4f10c93e5d7b1aa80c2e4f6", "provider": PROVIDER,
        "model": MODEL, "created": 1_760_000_000u64 + n * 600,
        "verdict": {
            "verdict": if failed == 0 { "pass" } else { "fail" }, "cases_run": cases.len(),
            "passed": cases.len() - failed, "failed": failed, "cases": cases,
            "sandbox": "landlock-v6+netns",
        },
        "repairs": if fixed { json!([{
            "round": 1, "address": "0x4011a0", "name": obj("process_packet"), "case": "baseline",
            "at": "writing byte 29 of its standard output", "stack": ["process_packet", "main"],
            "why": obj("it was running when the first differing output was produced; it has no passing function-level test"),
            "outcome": "replaced", "version_before": 1, "version_after": 2, "verdict_after": "pass",
        }]) } else { json!([]) },
    })
}

fn unit_id(addr: u64, version: u32) -> String {
    format!("ru-demo{addr:06x}{version:02x}")
}

impl Default for DemoRewrite {
    fn default() -> Self {
        Self::new()
    }
}

impl DemoRewrite {
    /// The pipeline in its starting state: one accepted function, one waiting for a decision,
    /// one that failed twice, one the test could not decide, and the rest planned.
    pub fn new() -> DemoRewrite {
        let mut inner = Inner {
            next_spec: 1,
            program_runs: vec![demo_program_run(1)],
            ..Inner::default()
        };
        let ver = |addr: u64, version: u32, status, verdict, run: u32, pass: u32, skip: u32| Ver {
            version,
            unit: unit_id(addr, version),
            status,
            verdict,
            detail: None,
            cases_run: run,
            passed: pass,
            skipped: skip,
            counterexample: None,
            code: String::new(),
            assumptions: Vec::new(),
        };
        inner.versions.insert(
            0x401440,
            vec![Ver {
                code: "#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn FUN_00401440(param_1: *const u8, param_2: usize) -> u32 {
    let word = unsafe { core::ptr::read_unaligned(param_1 as *const u32) };
    word ^ (param_2 as u32)
}
"
                .into(),
                assumptions: vec!["param_1 points at four readable bytes"],
                ..ver(0x401440, 1, "verified", "pass", 200, 200, 0)
            }],
        );
        inner.accepted.insert(0x401440, 1);
        inner.versions.insert(
            0x401240,
            vec![
                Ver {
                    counterexample: Some(json!({
                        "args": ["buf[8]=80 00 00 00 00 00 00 00", "len=1"],
                        "differences": [{"untrusted": true, "value": "result: original 0x80, Rust 0xffffff80"}],
                    })),
                    code: CHECKSUM_V1.into(),
                    ..ver(0x401240, 1, "failed", "fail", 37, 36, 0)
                },
                Ver {
                    counterexample: Some(json!({
                        "args": ["buf[8]=41 07 00 00 00 00 00 00", "len=1"],
                        "differences": [{"untrusted": true, "value": "result: original 0x41, Rust 0x88e"}],
                    })),
                    code: CHECKSUM_V2.into(),
                    assumptions: vec!["len is the number of bytes to hash"],
                    ..ver(0x401240, 2, "failed", "fail", 12, 11, 0)
                },
            ],
        );
        inner.versions.insert(
            0x401040,
            vec![Ver {
                code: "#[unsafe(no_mangle)]
pub extern \"C\" fn helper(n: i32) {
    let _ = n;
}
"
                .into(),
                ..ver(0x401040, 1, "verified", "pass", 200, 200, 0)
            }],
        );
        inner.versions.insert(
            0x4012a0,
            vec![Ver {
                detail: Some(
                    "188 of 200 cases ended in a library call the test cannot imitate (fprintf).",
                ),
                code: "#[unsafe(no_mangle)]
pub unsafe extern \"C\" fn log_error(msg: *const core::ffi::c_char, code: i32) {
    let text = unsafe { core::ffi::CStr::from_ptr(msg) }.to_string_lossy();
    eprintln!(\"error {code}: {text}\");
}
"
                .into(),
                ..ver(0x4012a0, 1, "translated", "inconclusive", 12, 12, 188)
            }],
        );
        DemoRewrite {
            inner: Arc::new(Mutex::new(inner)),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn func(addr: u64) -> Result<&'static F, ProtoError> {
        FUNCS.iter().find(|f| f.addr == addr).ok_or_else(|| {
            ProtoError::new(ErrorCode::NotFound, format!("no function at {addr:#x}"))
        })
    }

    fn plan_entry(order: usize, f: &F, status: &str) -> Value {
        json!({
            "order": order, "address": format!("{:#x}", f.addr),
            "name": {"untrusted": true, "value": f.name},
            "group": order, "group_size": 1,
            "callees": f.callees.iter().map(|c| format!("{c:#x}")).collect::<Vec<_>>(),
            "imports": f.imports.iter().map(|i| json!({"untrusted": true, "value": i})).collect::<Vec<_>>(),
            "needs_stubs": f.stubs.iter().map(|i| json!({"untrusted": true, "value": i})).collect::<Vec<_>>(),
            "flags": f.flags, "status": status,
        })
    }

    fn status_of(st: &Inner, addr: u64) -> &'static str {
        match st.versions.get(&addr).and_then(|v| v.last()) {
            None => "planned",
            Some(v) if st.accepted.get(&addr) == Some(&v.version) => "accepted",
            Some(v) => v.status,
        }
    }
}

/// Writes the file that marks a folder as KRAKEN's own, so the build step accepts it. Nothing
/// else is generated: the demo has no Rust project.
fn write_marker(dir: &std::path::Path, file: &str, generator: &str) {
    if std::fs::create_dir_all(dir).is_ok() {
        let _ = std::fs::write(
            dir.join(file),
            format!("{{\"generator\":\"{generator}\",\"note\":\"written by the demo script\"}}"),
        );
    }
}

fn typed<T: DeserializeOwned>(v: Value) -> Result<T, ProtoError> {
    serde_json::from_value(v).map_err(|e| {
        ProtoError::new(
            ErrorCode::Internal,
            format!("the demo script is out of date: {e}"),
        )
    })
}

fn version_json(addr: u64, v: &Ver, accepted: bool) -> Value {
    let f = FUNCS.iter().find(|f| f.addr == addr);
    let (name, proto) = f.map_or(("?", ""), |f| (f.name, f.proto));
    let mut j = json!({
        "unit": v.unit, "address": format!("{addr:#x}"),
        "name": {"untrusted": true, "value": name},
        "version": v.version, "mode": "incremental", "status": v.status, "accepted": accepted,
        "verdict": v.verdict, "cases_run": v.cases_run, "passed": v.passed, "skipped": v.skipped,
        "rust_prototype": proto, "sandbox": "demo script (nothing was run)",
        "provider": PROVIDER, "model": MODEL,
        "assumptions": v.assumptions.iter().map(|a| json!({"untrusted": true, "value": a})).collect::<Vec<_>>(),
        "unsupported": [],
    });
    if let Some(d) = v.detail {
        j["verdict_detail"] = json!({"untrusted": true, "value": d});
    }
    if let Some(c) = &v.counterexample {
        j["counterexample"] = c.clone();
    }
    j
}

fn spec_markdown(f: &F) -> String {
    if f.addr == 0x401240 {
        return "# checksum

## Purpose
Computes a 32-bit rolling hash over a byte buffer. `process_packet` [@0x4011a0] compares it with the first four bytes of every packet.

## Inputs
- `buf`: pointer to `len` readable bytes [@0x401240]
- `len`: how many bytes to hash; the loop runs while `i < len` [@0x401240]

## Outputs
- The 32-bit sum, computed as `sum = sum * 33 + byte`, wrapping on overflow, starting from 0 [@0x401240]

## Side effects
- None. The function only reads `buf` [@0x401240]

## Invariants
- An empty buffer hashes to 0 [@0x401240]

## Open questions
- Whether callers rely on the sum wrapping at 32 bits [@0x4011a0]
"
        .into();
    }
    let callees: Vec<String> = f.callees.iter().map(|c| format!("[@{c:#x}]")).collect();
    let calls = if callees.is_empty() {
        "- Calls no other function of the program [@".to_string() + &format!("{:#x}]", f.addr)
    } else {
        format!("- Calls {}", callees.join(", "))
    };
    format!(
        "# {}\n\n## Purpose\nThe function at [@{:#x}] as read from its decompile.\n\n## Inputs\n- See the signature at [@{:#x}]\n\n## Outputs\n- See the return statement at [@{:#x}]\n\n## Side effects\n{calls}\n\n## Invariants\n- None found\n\n## Open questions\n- Everything the decompile does not show\n",
        f.name, f.addr, f.addr, f.addr
    )
}

fn spec_json(id: u64, addr: Option<u64>, md: &str) -> Value {
    let blocks = super::parse_spec(md);
    let citations: Vec<String> = super::citations(&blocks)
        .iter()
        .map(|a| format!("{a:#x}"))
        .collect();
    let facts = md
        .lines()
        .filter(|l| l.starts_with("- ") && l.contains("[@"))
        .count();
    let mut j = json!({
        "spec": id, "scope": if addr.is_some() { "function" } else { "all" },
        "functions": if addr.is_some() { 1 } else { FUNCS.len() }, "facts": facts,
        "citations": citations, "markdown": {"untrusted": true, "value": md},
        "provider": PROVIDER, "model": MODEL,
    });
    if let Some(a) = addr {
        j["address"] = json!(format!("{a:#x}"));
    }
    j
}

#[async_trait]
impl RewriteBackend for DemoRewrite {
    fn require_sandbox(&self) -> Result<(), ProtoError> {
        Ok(())
    }

    fn source_patch(&self) -> Option<Arc<dyn kraken_registry::commands::SourcePatchBackend>> {
        Some(Arc::new(DemoSourcePatch))
    }

    async fn plan(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewritePlanArgs,
    ) -> Result<RewritePlanOut, ProtoError> {
        let st = self.lock();
        let entries: Vec<Value> = match args.address {
            Some(a) => {
                let f = Self::func(a.0)?;
                let mut leaves: Vec<&F> = f
                    .callees
                    .iter()
                    .filter_map(|c| FUNCS.iter().find(|g| g.addr == *c))
                    .collect();
                leaves.push(f);
                leaves
                    .iter()
                    .enumerate()
                    .map(|(i, g)| Self::plan_entry(i, g, Self::status_of(&st, g.addr)))
                    .collect()
            }
            None => FUNCS
                .iter()
                .enumerate()
                .map(|(i, f)| Self::plan_entry(i, f, Self::status_of(&st, f.addr)))
                .collect(),
        };
        typed(json!({
            "scope": if args.address.is_some() { "function" } else { "all" },
            "program_sha256": "00", "functions_total": 21, "functions_planned": FUNCS.len(),
            "skipped_imports": 6, "skipped_runtime": 2, "groups": FUNCS.len(),
            "truncated": false, "entries": entries,
        }))
    }

    async fn status(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        _args: RewriteStatusArgs,
    ) -> Result<RewriteStatusOut, ProtoError> {
        let st = self.lock();
        let mut counts =
            json!({"planned": 0, "translated": 0, "verified": 0, "failed": 0, "accepted": 0});
        let mut units = Vec::new();
        for (i, f) in FUNCS.iter().enumerate() {
            let status = Self::status_of(&st, f.addr);
            counts[status] = json!(counts[status].as_u64().unwrap_or(0) + 1);
            let last = st.versions.get(&f.addr).and_then(|v| v.last());
            let mut row = json!({
                "unit": last.map_or("", |v| v.unit.as_str()), "order": i, "address": format!("{:#x}", f.addr),
                "name": {"untrusted": true, "value": f.name},
                "status": status, "version": last.map_or(0, |v| v.version),
                "cases_run": last.map_or(0, |v| v.cases_run), "passed": last.map_or(0, |v| v.passed),
                "counterexamples": u32::from(last.is_some_and(|v| v.counterexample.is_some())),
                "flags": f.flags,
            });
            if let Some(v) = last {
                row["mode"] = json!("incremental");
                row["verdict"] = json!(v.verdict);
                row["provider"] = json!(PROVIDER);
                row["model"] = json!(MODEL);
            }
            if let Some(a) = st.accepted.get(&f.addr) {
                row["accepted_version"] = json!(a);
            }
            units.push(row);
        }
        typed(json!({
            "program_sha256": "00", "plan_present": true, "counts": counts, "units": units,
        }))
    }

    async fn unit(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteUnitArgs,
    ) -> Result<RewriteUnitOut, ProtoError> {
        let st = self.lock();
        let addr = match (args.address, args.unit) {
            (Some(a), None) => Self::func(a.0)?.addr,
            (None, Some(id)) => st
                .versions
                .iter()
                .find(|(_, vs)| vs.iter().any(|v| v.unit == id))
                .map(|(a, _)| *a)
                .ok_or_else(|| {
                    ProtoError::new(ErrorCode::NotFound, format!("no rewrite unit `{id}`"))
                })?,
            _ => {
                return Err(ProtoError::new(
                    ErrorCode::InvalidArgument,
                    "give exactly one of `address` and `unit`",
                ));
            }
        };
        let versions: Vec<Value> = st
            .versions
            .get(&addr)
            .map(|vs| {
                vs.iter()
                    .map(|v| {
                        let mut j =
                            version_json(addr, v, st.accepted.get(&addr) == Some(&v.version));
                        j["rust_code"] = json!({"untrusted": true, "value": v.code});
                        j["signature"] = j["rust_prototype"].clone();
                        j["oracle_kind"] = json!("demo script");
                        j["created"] = json!(0);
                        if let Some(c) = st.coverage.get(&v.unit) {
                            j["coverage"] = c.clone();
                        }
                        j["user_cases"] = json!(st.user_cases.get(&v.unit).copied().unwrap_or(0));
                        j
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut out = json!({ "address": format!("{addr:#x}"), "versions": versions });
        if let Some((id, md)) = st.specs.get(&addr) {
            out["spec"] = spec_json(*id, Some(addr), md);
        }
        typed(out)
    }

    async fn function(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteFunctionArgs,
        job: &JobReporter,
    ) -> Result<RewriteFunctionResult, ProtoError> {
        let f = Self::func(args.address.0)?;
        let phases = [
            (
                "Decompiling",
                "Reading the decompile and the functions it calls",
            ),
            ("Translating", "Asking the model for a Rust version"),
            ("Building", "Compiling the Rust in the sandbox"),
            ("Testing", "Running both versions on the same inputs"),
        ];
        for (i, (phase, message)) in phases.iter().enumerate() {
            job.progress(JobProgress {
                phase: (*phase).into(),
                done: i as u64,
                total: phases.len() as u64,
                message: (*message).into(),
                ..Default::default()
            });
            tokio::time::sleep(STEP).await;
        }
        let mut st = self.lock();
        let list = st.versions.entry(f.addr).or_default();
        let version = list.len() as u32 + 1;
        let code = if f.addr == 0x401240 {
            CHECKSUM_V3.to_string()
        } else {
            format!(
                "// written by the demo script\n#[unsafe(no_mangle)]\n{} {{\n    todo!()\n}}\n",
                f.proto
            )
        };
        let v = Ver {
            version,
            unit: unit_id(f.addr, version),
            status: "verified",
            verdict: "pass",
            detail: None,
            cases_run: 200,
            passed: 200,
            skipped: 0,
            counterexample: None,
            code,
            assumptions: Vec::new(),
        };
        let json = version_json(f.addr, &v, false);
        list.push(v);
        typed(json)
    }

    async fn accept(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteAcceptArgs,
    ) -> Result<RewriteAcceptOut, ProtoError> {
        let mut st = self.lock();
        let found = st.versions.iter().find_map(|(a, vs)| {
            vs.iter()
                .find(|v| v.unit == args.unit)
                .map(|v| (*a, v.version, v.status))
        });
        let Some((addr, version, status)) = found else {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("no rewrite unit `{}`", args.unit),
            ));
        };
        if status != "verified" {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "unit `{}` is {status}; only a verified unit can be accepted",
                    args.unit
                ),
            ));
        }
        let replaced = st.accepted.insert(addr, version);
        typed(json!({
            "status": "accepted", "unit": args.unit, "address": format!("{addr:#x}"),
            "version": version, "replaced_version": replaced,
        }))
    }

    async fn reject(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteRejectArgs,
    ) -> Result<UnitChangeOut, ProtoError> {
        let mut st = self.lock();
        let Some((addr, v)) = st
            .versions
            .iter_mut()
            .find_map(|(a, vs)| vs.iter_mut().find(|v| v.unit == args.unit).map(|v| (*a, v)))
        else {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("no rewrite unit `{}`", args.unit),
            ));
        };
        if !matches!(v.status, "verified" | "translated") {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "unit `{}` is {}; it cannot be rejected",
                    args.unit, v.status
                ),
            ));
        }
        v.status = "failed";
        let version = v.version;
        typed(json!({
            "status": "failed", "unit": args.unit, "address": format!("{addr:#x}"),
            "version": version,
        }))
    }

    async fn unaccept(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteUnaccept,
    ) -> Result<UnitChangeOut, ProtoError> {
        let mut st = self.lock();
        let found = st.versions.iter().find_map(|(a, vs)| {
            vs.iter()
                .find(|v| v.unit == args.unit)
                .map(|v| (*a, v.version))
        });
        let Some((addr, version)) = found else {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("no rewrite unit `{}`", args.unit),
            ));
        };
        if st.accepted.get(&addr) != Some(&version) {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                format!("unit `{}` is not accepted", args.unit),
            ));
        }
        st.accepted.remove(&addr);
        typed(json!({
            "status": "verified", "unit": args.unit, "address": format!("{addr:#x}"),
            "version": version,
        }))
    }

    async fn verify(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteVerifyArgs,
        job: &JobReporter,
    ) -> Result<RewriteVerifyResult, ProtoError> {
        self.replay(&args.unit, None, job).await
    }

    async fn add_case(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteAddCaseArgs,
        job: &JobReporter,
    ) -> Result<RewriteVerifyResult, ProtoError> {
        self.replay(&args.unit, Some(args.args.len()), job).await
    }

    async fn check(&self, _s: &Session, _ctx: &CallContext) -> Result<RewriteCheckOut, ProtoError> {
        typed(json!({"ready": true, "checks": [
            {"id": "sandbox", "title": "Sandbox", "level": "ok",
             "detail": "The demo runs a script; nothing is built or run."},
            {"id": "toolchain", "title": "Rust toolchain", "level": "ok",
             "detail": "The demo needs no compiler."},
            {"id": "specs", "title": "Spec files", "level": "ok",
             "detail": "The demo needs no emulator."},
            {"id": "program", "title": "Program", "level": "ok",
             "detail": "This is the demo program."},
        ]}))
    }

    async fn spec(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteSpecArgs,
        job: &JobReporter,
    ) -> Result<RewriteSpecResult, ProtoError> {
        job.progress(JobProgress {
            phase: "Writing".into(),
            done: 0,
            total: 1,
            message: "Asking the model for a cited spec".into(),
            ..Default::default()
        });
        tokio::time::sleep(STEP).await;
        let mut st = self.lock();
        let id = st.next_spec;
        st.next_spec += 1;
        match args.address {
            Some(a) => {
                let md = spec_markdown(Self::func(a.0)?);
                let j = spec_json(id, Some(a.0), &md);
                st.specs.insert(a.0, (id, md));
                typed(j)
            }
            None => {
                let md = "# demo-server\n\n## Purpose\nReads a configuration file named on the command line, then checks and handles packets from it [@0x401000].\n\n## Inputs\n- Command-line arguments, parsed by [@0x4010c0]\n- Packets whose first four bytes are a checksum of the rest [@0x4011a0]\n\n## Outputs\n- Exit status: 0 on success, the packet status otherwise [@0x401000]\n- Error lines on stderr [@0x4012a0]\n\n## Side effects\n- Reads the configuration file [@0x4013e0]\n- Allocates the packet buffer, and exits when that fails [@0x401300]\n\n## Invariants\n- A packet shorter than 12 bytes is rejected [@0x4011a0]\n\n## Open questions\n- What the greeting payload is meant to carry [@0x401380]\n".to_string();
                let j = spec_json(id, None, &md);
                st.program_spec = Some((id, md));
                typed(j)
            }
        }
    }

    async fn program(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteProgramArgs,
        job: &JobReporter,
    ) -> Result<RewriteProgramResult, ProtoError> {
        let phases = [
            ("translate", "Translating the functions, callees first"),
            ("build", "Building the crate in the sandbox"),
            ("verify", "Running both programs on the same inputs"),
            (
                "repair",
                "Translating the function the first difference points to again",
            ),
            ("verify", "Running both programs again"),
        ];
        for (i, (phase, message)) in phases.iter().enumerate() {
            job.progress(JobProgress {
                phase: (*phase).into(),
                done: i as u64,
                total: phases.len() as u64,
                message: (*message).into(),
                ..Default::default()
            });
            tokio::time::sleep(STEP).await;
        }
        let run = {
            let mut st = self.lock();
            let n = st.program_runs.len() as u64 + 1;
            let run = demo_program_run(n.max(2));
            let mut stored = run.clone();
            stored["run"] = json!(n);
            if let Some(dir) = &args.dir {
                write_marker(
                    std::path::Path::new(dir),
                    "kraken-program.json",
                    "kraken-rewrite/program",
                );
                stored["crate_dir"] = json!(dir);
            }
            st.program_runs.push(stored.clone());
            stored
        };
        typed(run)
    }

    async fn build(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteBuildArgs,
        job: &JobReporter,
    ) -> Result<RewriteBuildResult, ProtoError> {
        let mut steps = vec![(
            "build",
            "cargo build --release\n   Compiling demo-server v0.1.0\n    Finished `release` profile [optimized] target(s) in 3.2s\n",
        )];
        if args.test.unwrap_or(true) {
            steps.push((
                "test",
                "running 3 tests\ntest tests::checksum_of_empty_is_zero ... ok\ntest tests::checksum_matches ... ok\ntest tests::rejects_short_packets ... ok\n\ntest result: ok. 3 passed; 0 failed\n",
            ));
        }
        if args.run_args.is_some() {
            steps.push(("run", "status: 2 handled\n"));
        }
        let total = steps.len() as u64;
        let mut out = Vec::new();
        for (i, (name, log)) in steps.into_iter().enumerate() {
            job.progress(JobProgress {
                phase: name.into(),
                done: i as u64,
                total,
                message: format!("cargo {name} in the sandbox"),
                ..Default::default()
            });
            tokio::time::sleep(STEP).await;
            out.push(json!({
                "step": name, "passed": true, "exit": "exit 0", "seconds": 1.5,
                "log_tail": {"untrusted": true, "value": log},
            }));
        }
        let kind = if std::path::Path::new(&args.dir)
            .join("kraken-program.json")
            .exists()
        {
            "program"
        } else {
            "export"
        };
        typed(json!({
            "dir": args.dir, "kind": kind, "passed": true, "steps": out,
            "sandbox": "demo script (nothing was run)",
        }))
    }

    async fn program_status(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        args: RewriteProgramStatusArgs,
    ) -> Result<RewriteProgramStatusOut, ProtoError> {
        let st = self.lock();
        let runs: Vec<Value> = st
            .program_runs
            .iter()
            .rev()
            .map(|r| {
                json!({"run": r["run"], "created": r["created"], "entry": r["entry"],
                       "verdict": r["verdict"]["verdict"], "cases_run": r["verdict"]["cases_run"],
                       "passed": r["verdict"]["passed"], "crate_dir": r["crate_dir"]})
            })
            .collect();
        let mut shown = match args.run {
            Some(n) => st.program_runs.iter().find(|r| r["run"] == n).cloned(),
            None => st.program_runs.last().cloned(),
        };
        if let Some(r) = shown.as_mut()
            && !args.all_cases
            && let Some(cases) = r["verdict"]["cases"].as_array_mut()
        {
            cases.retain(|c| c["agree"] == false);
        }
        typed(json!({
            "program_sha256": "00", "present": !runs.is_empty(), "runs": runs, "run": shown,
        }))
    }

    async fn export(
        &self,
        _s: &Session,
        _ctx: &CallContext,
        request: ExportRequest,
        job: &JobReporter,
    ) -> Result<RewriteExportResult, ProtoError> {
        job.progress(JobProgress {
            phase: "Writing".into(),
            done: 0,
            total: 2,
            message: "Writing the workspace".into(),
            ..Default::default()
        });
        tokio::time::sleep(STEP).await;
        write_marker(&request.dir, "manifest.json", "kraken-rewrite");
        let st = self.lock();
        let symbols: Vec<&str> = FUNCS
            .iter()
            .filter(|f| st.accepted.contains_key(&f.addr))
            .map(|f| f.name)
            .collect();
        typed(json!({
            "dir": request.dir.display().to_string(),
            "crates": ["demo_server", "demo_server_shim"],
            "symbols": symbols, "built": request.build,
            "sandbox": if request.build { "demo script (nothing was run)" } else { "none" },
            "coverage": {"accepted": st.accepted.len(), "planned": FUNCS.len(), "functions_total": 21},
            "readme": {"untrusted": true, "value": "README.md"},
        }))
    }
}

/// A scripted `patch_from_source`: the function's first instruction becomes `nop`s, and the
/// "check" says it matches when the edit is in the source. No model, nothing decompiled again.
pub struct DemoSourcePatch;

#[async_trait]
impl kraken_registry::commands::SourcePatchBackend for DemoSourcePatch {
    async fn patch_from_source(
        &self,
        s: &Session,
        ctx: &CallContext,
        args: kraken_registry::commands::PatchFromSourceArgs,
        job: &JobReporter,
    ) -> Result<kraken_registry::commands::PatchFromSourceResult, ProtoError> {
        use kraken_registry::Command;
        use kraken_registry::commands::{
            Disassemble, DisassembleArgs, PatchFromSourceResult, PlannedPatch, SourcePatchCheck,
            SourcePatchVerdict,
        };
        job.progress(JobProgress {
            phase: "plan".into(),
            done: 1,
            total: 3,
            message: "planning the patch (demo)".into(),
            ..Default::default()
        });
        tokio::time::sleep(STEP).await;
        let page = Disassemble
            .run(
                s,
                ctx,
                DisassembleArgs {
                    address: None,
                    function: Some(args.address),
                    max_instructions: Some(4),
                    cursor: None,
                },
            )
            .await?;
        let first = page.items.first().ok_or_else(|| {
            ProtoError::new(ErrorCode::NotFound, "the function has no instructions")
        })?;
        let n = first.bytes.len() / 2;
        Ok(PatchFromSourceResult {
            function: args.address,
            patches: vec![PlannedPatch {
                address: first.address,
                original: first.bytes.clone(),
                replacement: "90".repeat(n),
                explanation: kraken_proto::Untrusted(format!(
                    "Replaces `{}` with {n} nop{} (demo).",
                    first.mnemonic,
                    if n == 1 { "" } else { "s" }
                )),
            }],
            summary: kraken_proto::Untrusted(
                "A scripted plan for the demo project: the first instruction is skipped.".into(),
            ),
            check: SourcePatchCheck {
                verdict: SourcePatchVerdict::Matches,
                reason: kraken_proto::Untrusted(
                    "The demo does not decompile again; this verdict is scripted.".into(),
                ),
                patched_decompile: Some(kraken_proto::Untrusted(args.source)),
            },
            attempts: 1,
            warnings: Vec::new(),
        })
    }
}

impl DemoRewrite {
    /// The scripted replay of a version's cases: a few blocks of the function stay unreached
    /// until a case of the person's own is added.
    async fn replay(
        &self,
        unit: &str,
        added: Option<usize>,
        job: &JobReporter,
    ) -> Result<RewriteVerifyResult, ProtoError> {
        job.progress(JobProgress {
            phase: "Replaying".into(),
            done: 1,
            total: 3,
            message: "Running the stored cases on the Rust".into(),
            ..Default::default()
        });
        tokio::time::sleep(STEP).await;
        let mut st = self.lock();
        let found = st.versions.iter().find_map(|(a, vs)| {
            vs.iter()
                .find(|v| v.unit == unit)
                .map(|v| (*a, version_json(*a, v, false)))
        });
        let Some((addr, mut j)) = found else {
            return Err(ProtoError::new(
                ErrorCode::NotFound,
                format!("no rewrite unit `{unit}`"),
            ));
        };
        if added.is_some() {
            *st.user_cases.entry(unit.to_string()).or_default() += 1;
        }
        let yours = st.user_cases.get(unit).copied().unwrap_or(0);
        let total = 6u32;
        let hit = (4 + yours).min(total);
        let missed: Vec<String> = (hit..total)
            .map(|k| format!("{:#x}", addr + 0x10 * u64::from(k + 1)))
            .collect();
        let cov = json!({"blocks": total, "hit": hit, "missed": missed, "cases": j["cases_run"].as_u64().unwrap_or(0) + u64::from(yours)});
        st.coverage.insert(unit.to_string(), cov.clone());
        j["coverage"] = cov;
        j["user_cases"] = json!(yours);
        typed(j)
    }
}
