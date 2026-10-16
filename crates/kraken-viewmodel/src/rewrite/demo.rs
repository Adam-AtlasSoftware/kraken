//! A scripted rewrite pipeline for the demo project and the `--scene rewrite` screenshot.
//!
//! It implements the registry's [`RewriteBackend`] with canned answers, so the Rewrite tab in
//! `kraken-gui --demo` exercises the real commands (permissions, jobs, events) with nothing
//! running and no model involved. It also answers `rewrite_unit`, the query that hands out the
//! stored Rust code and the version history (see the module docs of [`crate::rewrite`]).
//! Nothing here is random, so a screenshot of it is the same every time.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use async_trait::async_trait;
use kraken_proto::{ErrorCode, ProtoError};
use kraken_registry::commands::{
    ExportRequest, RewriteAcceptArgs, RewriteAcceptOut, RewriteBackend, RewriteExportResult,
    RewriteFunctionArgs, RewriteFunctionResult, RewritePlanArgs, RewritePlanOut, RewriteSpecArgs,
    RewriteSpecResult, RewriteStatusArgs, RewriteStatusOut,
};
use kraken_registry::{CallContext, JobProgress, JobReporter, Session};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::backend::{CommandInfo, CommandKind, Permission};
use crate::inprocess::ExtraQuery;

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

    /// The `rewrite_unit` query this scripted pipeline answers.
    pub fn unit_query(&self) -> ExtraQuery {
        let me = self.clone();
        ExtraQuery {
            info: CommandInfo {
                name: "rewrite_unit".into(),
                summary: "Show the stored Rust versions of one function (demo)".into(),
                kind: CommandKind::Query,
                permission: Permission::Safe,
            },
            run: Arc::new(move |args| me.unit(args)),
        }
    }

    fn unit(&self, args: &Value) -> Result<Value, ProtoError> {
        let addr = arg_addr(args)?;
        let st = self.lock();
        let versions: Vec<Value> = st
            .versions
            .get(&addr)
            .map(|vs| {
                vs.iter()
                    .map(|v| {
                        let mut j =
                            version_json(addr, v, st.accepted.get(&addr) == Some(&v.version));
                        j["rust_code"] = json!({"untrusted": true, "value": v.code});
                        j
                    })
                    .collect()
            })
            .unwrap_or_default();
        let mut out = json!({ "versions": versions });
        if let Some((id, md)) = st.specs.get(&addr) {
            out["spec"] = spec_json(*id, Some(addr), md);
        }
        Ok(out)
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

fn arg_addr(args: &Value) -> Result<u64, ProtoError> {
    args.get("address")
        .and_then(Value::as_str)
        .and_then(|s| s.strip_prefix("0x"))
        .and_then(|s| u64::from_str_radix(s, 16).ok())
        .ok_or_else(|| {
            ProtoError::new(
                ErrorCode::InvalidArgument,
                "`address` must be a hex address",
            )
        })
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
                "order": i, "address": format!("{:#x}", f.addr),
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
        });
        tokio::time::sleep(STEP).await;
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
            "readme": "README.md",
        }))
    }
}
