//! Program-level blame: when the rewritten program differs from the original on an input, which
//! translated function is most likely responsible?
//!
//! The heuristic, in order:
//!
//! 1. **Where it shows.** The first difference between the two runs is a byte of stdout or stderr
//!    that differs (or output that is missing), or an exit status. The rewritten program is run
//!    again on the same input with a trace armed (`KRAKEN_TRACE_AT`, see the runtime shim): at
//!    the call that writes that byte, or at `exit` when the rewrite stopped writing too early, it
//!    prints its call stack. The functions on that stack are where the wrong output was made
//!    or at least written.
//! 2. **How much each function has already been trusted.** A function that passed the
//!    function-level differential test against the original under emulation (or is an accepted
//!    unit from an earlier run) is evidence-backed; one that was only compiled, or whose test
//!    could not tell, is not. The unverified are suspected before the verified.
//! 3. **Data flow.** Output is often printed by a caller of the function that computed it, and
//!    that function has returned by then, so it is not on the stack. Direct and indirect callees
//!    of the functions on the stack are suspects too, after the stack functions of the same
//!    trust level, nearest first.
//!
//! Tiers: unverified on the stack (innermost first), unverified callees (nearest first, then in
//! translation order), verified on the stack, verified callees. The first few become the
//! suspects of one repair round. This is a ranking, not a proof; the repair loop reruns the whole
//! program afterwards and a round that changes nothing ends the repair.
//!
//! The original is not traced: it is only ever run natively as a whole, and the function-level
//! oracle (emulation) is the place where individual originals can be run. Where a function has a
//! passing function-level test, that test stands in for "bisecting with the accepted original".

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::process::{Exit, Outcome};

/// Frames kept from a trace.
const MAX_FRAMES: usize = 64;

/// What to trace in the rewritten program.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceSpec {
    /// The call that writes byte `n` of stdout.
    Out(usize),
    /// The call that writes byte `n` of stderr.
    Err(usize),
    /// The call to `exit`.
    Exit,
}

impl TraceSpec {
    /// The value of `KRAKEN_TRACE_AT`.
    pub fn env_value(self) -> String {
        match self {
            TraceSpec::Out(n) => format!("out:{n}"),
            TraceSpec::Err(n) => format!("err:{n}"),
            TraceSpec::Exit => "exit".to_string(),
        }
    }

    /// A phrase for the feedback text.
    pub fn describe(self) -> String {
        match self {
            TraceSpec::Out(n) => format!("writing byte {n} of its standard output"),
            TraceSpec::Err(n) => format!("writing byte {n} of its standard error"),
            TraceSpec::Exit => {
                "ending (it stopped producing output or chose its exit status)".to_string()
            }
        }
    }
}

fn first_diff(a: &[u8], b: &[u8]) -> Option<usize> {
    if a == b {
        return None;
    }
    Some(
        a.iter()
            .zip(b)
            .position(|(x, y)| x != y)
            .unwrap_or(a.len().min(b.len())),
    )
}

/// What to trace for the first difference between `original` and `rewritten`, or `None` when
/// they agree. Standard output comes before standard error before the exit status.
pub fn trace_for(original: &Outcome, rewritten: &Outcome) -> Option<TraceSpec> {
    if let Some(at) = first_diff(&original.stdout, &rewritten.stdout) {
        return Some(if rewritten.stdout.len() > at {
            TraceSpec::Out(at)
        } else {
            TraceSpec::Exit
        });
    }
    if let Some(at) = first_diff(&original.stderr, &rewritten.stderr) {
        return Some(if rewritten.stderr.len() > at {
            TraceSpec::Err(at)
        } else {
            TraceSpec::Exit
        });
    }
    (original.exit != rewritten.exit).then_some(TraceSpec::Exit)
}

/// The Rust symbols of translated functions on the stack in `stderr` of a traced run, innermost
/// first. `modules` maps a module name (`u_vm_run`) to the symbol it holds. The stack is the last
/// `KRAKEN-TRACE-BEGIN` block; failing that, the backtrace a panic printed.
pub fn parse_stack(stderr: &[u8], modules: &BTreeMap<String, String>) -> Vec<String> {
    let text = String::from_utf8_lossy(stderr);
    let block: &str = match text.rfind("KRAKEN-TRACE-BEGIN") {
        Some(i) => {
            let rest = &text[i..];
            rest.split("KRAKEN-TRACE-END").next().unwrap_or(rest)
        }
        None => &text,
    };
    // A frame shows as `N: <symbol>` and, with line tables, `at <path>:<line>`. The symbol
    // carries the module path when the function is not `extern "C"` and without debug
    // information; the path of the source file always does (`src/u_<symbol>.rs`).
    let mut out: Vec<String> = Vec::new();
    for line in block.lines().take(MAX_FRAMES * 8) {
        let t = line.trim();
        let module = if let Some(path) = t.strip_prefix("at ") {
            let file = path.rsplit('/').next().unwrap_or("");
            let stem = file.split(".rs").next().unwrap_or("");
            modules.contains_key(stem).then_some(stem)
        } else {
            let sym = t.split_once(": ").map_or("", |(_, s)| s);
            sym.split("::")
                .map(str::trim)
                .find(|seg| modules.contains_key(*seg))
        };
        if let Some(symbol) = module.and_then(|m| modules.get(m))
            && !out.contains(symbol)
        {
            out.push(symbol.clone());
        }
        if out.len() >= MAX_FRAMES {
            break;
        }
    }
    out
}

/// What blame needs to know about one function of the crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Entry address.
    pub address: u64,
    /// Original name.
    pub name: String,
    /// Rust symbol.
    pub symbol: String,
    /// True when its translation passed the function-level differential test against the
    /// original (or is an accepted unit).
    pub verified: bool,
    /// Entries of the functions it calls, among the candidates.
    pub callees: Vec<u64>,
}

/// A function suspected of causing a difference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Suspect {
    /// Entry address.
    pub address: u64,
    /// Original name.
    pub name: String,
    /// Rust symbol.
    pub symbol: String,
    /// Why it is suspected.
    pub why: String,
}

fn trust(c: &Candidate) -> &'static str {
    if c.verified {
        "passed its function-level test"
    } else {
        "has no passing function-level test"
    }
}

/// Ranks the functions of the crate for a difference whose stack at the point of the first
/// differing output was `stack` (Rust symbols, innermost first), and returns the first `max`.
/// With an empty stack (no trace), the unverified functions are suspected in translation order,
/// last (nearest the entry) first.
pub fn rank(stack: &[String], all: &[Candidate], max: usize) -> Vec<Suspect> {
    let by_symbol: BTreeMap<&str, &Candidate> =
        all.iter().map(|c| (c.symbol.as_str(), c)).collect();
    let by_addr: BTreeMap<u64, &Candidate> = all.iter().map(|c| (c.address, c)).collect();
    let on_stack: Vec<&Candidate> = stack
        .iter()
        .filter_map(|s| by_symbol.get(s.as_str()).copied())
        .collect();

    // Callees of the stack functions by distance from the stack.
    let mut dist: BTreeMap<u64, usize> = BTreeMap::new();
    let mut queue: VecDeque<(u64, usize)> = VecDeque::new();
    for c in &on_stack {
        dist.insert(c.address, 0);
        queue.push_back((c.address, 0));
    }
    while let Some((a, d)) = queue.pop_front() {
        let Some(c) = by_addr.get(&a) else { continue };
        for callee in &c.callees {
            if !dist.contains_key(callee) {
                dist.insert(*callee, d + 1);
                queue.push_back((*callee, d + 1));
            }
        }
    }
    let mut callees: Vec<&Candidate> = dist
        .iter()
        .filter(|(_, d)| **d > 0)
        .filter_map(|(a, _)| by_addr.get(a).copied())
        .collect();
    callees.sort_by_key(|c| (dist[&c.address], c.address));

    let mut out: Vec<Suspect> = Vec::new();
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    let mut push = |c: &Candidate, role: &str| {
        if seen.insert(c.address) {
            out.push(Suspect {
                address: c.address,
                name: c.name.clone(),
                symbol: c.symbol.clone(),
                why: format!("{role}; it {}", trust(c)),
            });
        }
    };
    if on_stack.is_empty() {
        for c in all.iter().rev().filter(|c| !c.verified) {
            push(
                c,
                "no call stack was available, so it is suspected for being unverified",
            );
        }
    }
    for c in on_stack.iter().filter(|c| !c.verified) {
        push(
            c,
            "it was running when the first differing output was produced",
        );
    }
    for c in callees.iter().filter(|c| !c.verified) {
        push(
            c,
            "it is called, directly or not, by a function that was running when the first \
             differing output was produced",
        );
    }
    for c in on_stack.iter().filter(|c| c.verified) {
        push(
            c,
            "it was running when the first differing output was produced",
        );
    }
    for c in callees.iter().filter(|c| c.verified) {
        push(
            c,
            "it is called by a function that was running when the first differing output was \
             produced",
        );
    }
    out.truncate(max);
    out
}

/// What the feedback for a suspect is made from.
#[derive(Debug, Clone, Copy)]
pub struct FeedbackInput<'a> {
    /// Label of the program-level case.
    pub case_name: &'a str,
    /// Its arguments after `argv[0]`.
    pub argv: &'a [String],
    /// Its standard input.
    pub stdin: &'a [u8],
    /// The original's run.
    pub original: &'a Outcome,
    /// The rewrite's run.
    pub rewritten: &'a Outcome,
    /// What differs.
    pub differences: &'a [String],
    /// What was traced.
    pub trace: Option<TraceSpec>,
    /// The Rust symbols on the stack at the trace, innermost first.
    pub stack: &'a [String],
    /// The function the feedback is for.
    pub suspect: &'a Suspect,
    /// What its own checks said (`compiled only`, `passed the differential test`, ...).
    pub own_check: &'a str,
}

/// The text of the repair feedback for a program-level difference: the input, what both programs
/// did, the stack, and why this function is suspected. Program output is untrusted data; the
/// caller puts it in an untrusted block.
pub fn feedback_text(f: &FeedbackInput<'_>) -> String {
    let FeedbackInput {
        case_name,
        argv,
        stdin,
        original,
        rewritten,
        differences,
        trace,
        stack,
        suspect,
        own_check,
    } = *f;
    fn shown(b: &[u8], max: usize) -> String {
        let cut = &b[..b.len().min(max)];
        let mut s: String = String::from_utf8_lossy(cut)
            .chars()
            .flat_map(char::escape_default)
            .collect();
        if b.len() > max {
            s.push_str(&format!(" [... {} more bytes]", b.len() - max));
        }
        s
    }
    fn exit(e: Exit) -> String {
        e.describe()
    }
    let mut t = String::new();
    t.push_str(&format!(
        "Your function compiled{}, but the whole program built from it and the other \
         translations behaves differently from the original binary.\n\
         Input: case `{case_name}`, arguments {argv:?}, {} bytes of standard input{}.\n",
        if own_check.is_empty() {
            String::new()
        } else {
            format!(" ({own_check})")
        },
        stdin.len(),
        if stdin.is_empty() {
            String::new()
        } else {
            format!(" `{}`", shown(stdin, 200))
        },
    ));
    t.push_str("Differences:\n");
    for d in differences.iter().take(4) {
        t.push_str(&format!("- {d}\n"));
    }
    t.push_str(&format!(
        "Original: {}; stdout `{}`; stderr `{}`\nRewritten: {}; stdout `{}`; stderr `{}`\n",
        exit(original.exit),
        shown(&original.stdout, 700),
        shown(&original.stderr, 300),
        exit(rewritten.exit),
        shown(&rewritten.stdout, 700),
        shown(&rewritten.stderr, 300),
    ));
    match trace {
        Some(spec) if !stack.is_empty() => t.push_str(&format!(
            "The rewritten program was {} inside: {}.\n",
            spec.describe(),
            stack.join(" <- ")
        )),
        _ => t.push_str("No call stack could be taken from the rewritten program.\n"),
    }
    t.push_str(&format!(
        "Your function `{}` is suspected because {}. It may be right and a function it calls or \
         is called by wrong; fix what the evidence shows is wrong in this function, keep its \
         signature, and do not change behaviour the evidence does not contradict.\n",
        suspect.symbol, suspect.why
    ));
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    fn out(stdout: &str, stderr: &str, code: i32) -> Outcome {
        Outcome {
            exit: Exit::Code(code),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        }
    }

    fn cand(address: u64, name: &str, verified: bool, callees: &[u64]) -> Candidate {
        Candidate {
            address,
            name: name.into(),
            symbol: name.into(),
            verified,
            callees: callees.to_vec(),
        }
    }

    #[test]
    fn the_trace_follows_the_first_difference() {
        let a = out("out: 5\nout: 4\n", "", 0);
        assert_eq!(trace_for(&a, &a), None);
        // A wrong byte in stdout: trace the write of that byte.
        let b = out("out: 5\nout:  4\n", "", 0);
        assert_eq!(trace_for(&a, &b), Some(TraceSpec::Out(12)));
        // The rewrite stops early: trace its exit.
        let c = out("out: 5\n", "", 0);
        assert_eq!(trace_for(&a, &c), Some(TraceSpec::Exit));
        // The rewrite writes more than the original: the extra byte is the first difference.
        let d = out("out: 5\nout: 4\nmore", "", 0);
        assert_eq!(trace_for(&a, &d), Some(TraceSpec::Out(14)));
        // stderr after stdout, then the exit status.
        let e = out("out: 5\nout: 4\n", "oops", 0);
        assert_eq!(trace_for(&a, &e), Some(TraceSpec::Err(0)));
        let f = out("out: 5\nout: 4\n", "", 3);
        assert_eq!(trace_for(&a, &f), Some(TraceSpec::Exit));
        assert_eq!(TraceSpec::Out(12).env_value(), "out:12");
        assert_eq!(TraceSpec::Exit.env_value(), "exit");
    }

    fn modules() -> BTreeMap<String, String> {
        ["main", "evaluate", "parse_expr"]
            .iter()
            .map(|s| (format!("u_{s}"), (*s).to_string()))
            .collect()
    }

    #[test]
    fn the_stack_is_read_from_the_trace_block_or_a_panic_backtrace() {
        let trace = "noise\nKRAKEN-TRACE-BEGIN out\n   0: calc::rt::trace_emit\n             at ./src/rt.rs:1\n   1: calc::rt::write_stdout\n   2: calc::rt::printf\n   3: calc::u_evaluate::evaluate\n   4: calc::u_parse_expr::parse_expr\n   5: calc::u_evaluate::evaluate\n   6: calc::u_main::main::h0123456789abcdef\n   7: std::rt::lang_start\nKRAKEN-TRACE-END\n";
        assert_eq!(
            parse_stack(trace.as_bytes(), &modules()),
            ["evaluate", "parse_expr", "main"]
        );
        // With line tables the symbol is the bare function name and the source path says which
        // module it is in.
        let tables = "KRAKEN-TRACE-BEGIN out\n   0: trace_emit\n             at /w/ws/src/rt.rs:366:14\n   4: vm_run\n             at /w/ws/src/u_vm_run.rs:92:21\n   5: fn_101707\n             at /w/ws/src/u_fn_101707.rs:31:17\nKRAKEN-TRACE-END\n";
        let mut m = modules();
        m.insert("u_vm_run".into(), "vm_run".into());
        m.insert("u_fn_101707".into(), "fn_101707".into());
        assert_eq!(parse_stack(tables.as_bytes(), &m), ["vm_run", "fn_101707"]);
        let panic = "thread 'main' panicked at src/u_main.rs:3:5:\nboom\nstack backtrace:\n   0: rust_begin_unwind\n   1: calc::u_parse_expr::parse_expr\n   2: calc::u_main::main\n";
        assert_eq!(
            parse_stack(panic.as_bytes(), &modules()),
            ["parse_expr", "main"]
        );
        assert!(parse_stack(b"nothing here", &modules()).is_empty());
    }

    #[test]
    fn unverified_functions_on_the_stack_come_first_then_their_callees() {
        // main -> evaluate -> parse_expr -> skip_ws; main prints.
        let all = vec![
            cand(1, "skip_ws", true, &[]),
            cand(2, "parse_expr", false, &[1]),
            cand(3, "evaluate", false, &[2, 1]),
            cand(4, "main", false, &[3]),
        ];
        let s = rank(&["main".to_string()], &all, 4);
        let names: Vec<&str> = s.iter().map(|x| x.name.as_str()).collect();
        // The unverified stack function, then its unverified callees by distance, then the
        // verified leaf.
        assert_eq!(names, ["main", "evaluate", "parse_expr", "skip_ws"]);
        assert!(s[0].why.contains("running when the first differing output"));
        assert!(s[1].why.contains("called"));
        assert!(s[3].why.contains("passed its function-level test"));
        // Only two are asked for.
        assert_eq!(rank(&["main".to_string()], &all, 2).len(), 2);
    }

    #[test]
    fn a_verified_function_is_suspected_after_the_unverified_ones() {
        let all = vec![cand(1, "leaf", false, &[]), cand(2, "printer", true, &[1])];
        let s = rank(&["printer".to_string()], &all, 4);
        assert_eq!(
            s.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(),
            ["leaf", "printer"]
        );
    }

    #[test]
    fn without_a_stack_the_unverified_functions_are_suspected_nearest_the_entry_first() {
        let all = vec![
            cand(1, "leaf", false, &[]),
            cand(2, "verified", true, &[]),
            cand(3, "main", false, &[1, 2]),
        ];
        let s = rank(&[], &all, 4);
        assert_eq!(
            s.iter().map(|x| x.name.as_str()).collect::<Vec<_>>(),
            ["main", "leaf"]
        );
    }

    #[test]
    fn the_feedback_names_the_input_the_outputs_and_the_stack() {
        let a = out("out: 5\n", "", 0);
        let b = out("out:  5\n", "", 0);
        let s = Suspect {
            address: 4,
            name: "main".into(),
            symbol: "main".into(),
            why: "it was running; it has no passing function-level test".into(),
        };
        let t = feedback_text(&FeedbackInput {
            case_name: "baseline",
            argv: &[],
            stdin: b"",
            original: &a,
            rewritten: &b,
            differences: &["stdout: first difference at byte 5".to_string()],
            trace: Some(TraceSpec::Out(5)),
            stack: &["vm_run".to_string(), "main".to_string()],
            suspect: &s,
            own_check: "compiled only",
        });
        assert!(t.contains("case `baseline`"), "{t}");
        assert!(t.contains("first difference at byte 5"));
        assert!(t.contains("writing byte 5 of its standard output inside: vm_run <- main"));
        assert!(t.contains("Original: exit 0; stdout `out: 5\\n`"));
        assert!(t.contains("Rewritten: exit 0; stdout `out:  5\\n`"));
        assert!(t.contains("`main` is suspected because"));
    }
}
