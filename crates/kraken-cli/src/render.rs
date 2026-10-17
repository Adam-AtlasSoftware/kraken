//! Human-readable output: aligned tables, key/value blocks and plain text.

use serde_json::Value;

/// What to print for a result: stdout text plus notes for stderr.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Rendered {
    /// Main output (ends with a newline when not empty).
    pub stdout: String,
    /// Notes such as decompiler warnings.
    pub stderr: String,
}

/// Replaces `{"untrusted": true, "value": X}` wrappers by `X`, recursively.
pub fn unwrap_untrusted(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            if m.get("untrusted") == Some(&Value::Bool(true))
                && m.len() == 2
                && let Some(inner) = m.get("value")
            {
                return unwrap_untrusted(inner);
            }
            Value::Object(
                m.iter()
                    .map(|(k, x)| (k.clone(), unwrap_untrusted(x)))
                    .collect(),
            )
        }
        Value::Array(a) => Value::Array(a.iter().map(unwrap_untrusted).collect()),
        other => other.clone(),
    }
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::Null => Some("-".into()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        Value::String(s) => Some(one_line(s)),
        _ => None,
    }
}

fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

/// Renders rows as left-aligned columns separated by two spaces, without trailing blanks.
pub fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for r in rows {
        for (i, c) in r.iter().enumerate() {
            if let Some(w) = widths.get_mut(i) {
                *w = (*w).max(c.chars().count());
            }
        }
    }
    let line = |cells: &[String]| {
        let mut s = String::new();
        for (i, c) in cells.iter().enumerate() {
            if i > 0 {
                s.push_str("  ");
            }
            s.push_str(c);
            if i + 1 < cells.len() {
                let pad = widths
                    .get(i)
                    .copied()
                    .unwrap_or(0)
                    .saturating_sub(c.chars().count());
                s.push_str(&" ".repeat(pad));
            }
        }
        s.trim_end().to_string()
    };
    let mut out = String::new();
    let head: Vec<String> = headers.iter().map(|h| h.to_uppercase()).collect();
    out.push_str(&line(&head));
    out.push('\n');
    for r in rows {
        out.push_str(&line(r));
        out.push('\n');
    }
    out
}

fn str_of(v: Option<&Value>) -> String {
    v.and_then(scalar).unwrap_or_else(|| "-".into())
}

fn paging_footer(page: &Value) -> String {
    let mut parts = Vec::new();
    if let Some(t) = page.get("total").and_then(Value::as_u64) {
        parts.push(format!("{t} total"));
    }
    let mut s = parts.join(", ");
    if let Some(c) = page.get("next_cursor").and_then(Value::as_str) {
        if !s.is_empty() {
            s.push_str("; ");
        }
        s.push_str(&format!("more: --cursor {c}"));
    }
    if s.is_empty() { s } else { format!("{s}\n") }
}

fn list_functions(v: &Value) -> String {
    let items = v
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let rows: Vec<Vec<String>> = items
        .iter()
        .map(|f| {
            vec![
                str_of(f.get("address")),
                str_of(f.get("size")),
                str_of(f.get("name")),
                str_of(f.get("signature")),
            ]
        })
        .collect();
    let mut out = table(&["address", "size", "name", "signature"], &rows);
    out.push_str(&paging_footer(v));
    out
}

fn items_of(v: &Value) -> Vec<Value> {
    v.get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn text_of(v: Option<&Value>) -> String {
    v.and_then(Value::as_str).unwrap_or_default().to_string()
}

/// Operand tokens joined into the text a listing shows.
fn operand_text(operands: &Value) -> String {
    operands
        .as_array()
        .map(|a| {
            a.iter()
                .map(|t| {
                    // symbol tokens show the name, everything else its text
                    let name = t.get("symbol").and_then(Value::as_str);
                    name.unwrap_or_else(|| t.get("text").and_then(Value::as_str).unwrap_or(""))
                        .to_string()
                })
                .collect::<String>()
        })
        .unwrap_or_default()
}

fn disassemble(v: &Value) -> String {
    let mut out = String::new();
    for r in items_of(v) {
        for l in r
            .get("labels")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if let Some(l) = l.as_str() {
                out.push_str(&format!("{}:\n", one_line(l)));
            }
        }
        let mut line = format!(
            "{:<10}  {:<16}  {:<7} {}",
            text_of(r.get("address")),
            text_of(r.get("bytes")),
            text_of(r.get("mnemonic")),
            operand_text(r.get("operands").unwrap_or(&Value::Null)),
        );
        if let Some(c) = r.get("comment").and_then(Value::as_str) {
            line.push_str(&format!("  ; {}", one_line(c)));
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out.push_str(&paging_footer(v));
    out
}

fn memory_map(v: &Value) -> String {
    let rows: Vec<Vec<String>> = v
        .get("blocks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|b| {
            vec![
                str_of(b.get("name")),
                str_of(b.get("start")),
                str_of(b.get("end")),
                str_of(b.get("size")),
                str_of(b.get("perms")),
                if b.get("initialized") == Some(&Value::Bool(true)) {
                    "yes".into()
                } else {
                    "no".into()
                },
                str_of(b.get("kind")),
            ]
        })
        .collect();
    table(
        &["name", "start", "end", "size", "perms", "init", "kind"],
        &rows,
    )
}

fn xrefs(v: &Value) -> String {
    let rows: Vec<Vec<String>> = items_of(v)
        .iter()
        .map(|x| {
            let name = |f: &str| {
                x.get(f)
                    .and_then(|f| f.get("name"))
                    .and_then(Value::as_str)
                    .map_or("-".to_string(), one_line)
            };
            vec![
                str_of(x.get("from")),
                str_of(x.get("to")),
                str_of(x.get("kind")),
                name("from_function"),
                name("to_function"),
            ]
        })
        .collect();
    let mut out = table(
        &["from", "to", "kind", "from_function", "to_function"],
        &rows,
    );
    out.push_str(&paging_footer(v));
    out
}

fn strings(v: &Value) -> String {
    let rows: Vec<Vec<String>> = items_of(v)
        .iter()
        .map(|s| {
            let value = text_of(s.get("value"));
            vec![
                str_of(s.get("address")),
                str_of(s.get("encoding")),
                str_of(s.get("length")),
                format!("{value:?}"),
            ]
        })
        .collect();
    let mut out = table(&["address", "encoding", "length", "value"], &rows);
    out.push_str(&paging_footer(v));
    out
}

fn symbols(v: &Value) -> String {
    let rows: Vec<Vec<String>> = items_of(v)
        .iter()
        .map(|s| {
            vec![
                str_of(s.get("address")),
                str_of(s.get("kind")),
                str_of(s.get("name")),
                str_of(s.get("library")),
            ]
        })
        .collect();
    let mut out = table(&["address", "kind", "name", "library"], &rows);
    out.push_str(&paging_footer(v));
    out
}

fn cfg(v: &Value) -> String {
    let blocks: Vec<Vec<String>> = v
        .get("blocks")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|b| {
            vec![
                str_of(b.get("start")),
                str_of(b.get("end")),
                str_of(b.get("instructions")),
            ]
        })
        .collect();
    let edges: Vec<Vec<String>> = v
        .get("edges")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|e| {
            vec![
                str_of(e.get("from")),
                str_of(e.get("to")),
                str_of(e.get("kind")),
            ]
        })
        .collect();
    let mut out = table(&["block", "end", "instructions"], &blocks);
    out.push('\n');
    out.push_str(&table(&["from", "to", "kind"], &edges));
    if v.get("truncated") == Some(&Value::Bool(true)) {
        out.push_str("\nnote: blocks beyond the first 4000 were left out\n");
    }
    out
}

fn decode_base64(s: &str) -> Vec<u8> {
    let val = |c: u8| -> Option<u32> {
        match c {
            b'A'..=b'Z' => Some(u32::from(c - b'A')),
            b'a'..=b'z' => Some(u32::from(c - b'a') + 26),
            b'0'..=b'9' => Some(u32::from(c - b'0') + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    };
    let digits: Vec<u32> = s.bytes().filter_map(val).collect();
    let mut out = Vec::with_capacity(digits.len() * 3 / 4);
    for chunk in digits.chunks(4) {
        let acc = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, d)| acc | (d << (18 - 6 * i)));
        for i in 0..chunk.len().saturating_sub(1) {
            out.push((acc >> (16 - 8 * i)) as u8);
        }
    }
    out
}

fn hexdump(base: u64, bytes: &[u8]) -> String {
    let mut out = String::new();
    for (i, row) in bytes.chunks(16).enumerate() {
        let hex: Vec<String> = row.iter().map(|b| format!("{b:02x}")).collect();
        let ascii: String = row
            .iter()
            .map(|b| {
                if (0x20..0x7f).contains(b) {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        out.push_str(&format!(
            "{:#010x}  {:<47}  {ascii}\n",
            base + (i * 16) as u64,
            hex.join(" ")
        ));
    }
    out
}

fn read_bytes(v: &Value) -> Rendered {
    let start = text_of(v.get("start"));
    let base = u64::from_str_radix(start.trim_start_matches("0x"), 16).unwrap_or(0);
    let bytes = decode_base64(&text_of(v.get("bytes")));
    let mut r = Rendered {
        stdout: hexdump(base, &bytes),
        stderr: String::new(),
    };
    if v.get("complete") == Some(&Value::Bool(false)) {
        r.stderr
            .push_str("note: the read stopped at the end of mapped memory\n");
    }
    if let Some(u) = v.get("uninitialized").and_then(Value::as_array) {
        for range in u {
            r.stderr.push_str(&format!(
                "note: {}..{} is uninitialized (zeros)\n",
                str_of(range.get("start")),
                str_of(range.get("end"))
            ));
        }
    }
    r
}

fn decompile(v: &Value) -> Rendered {
    let mut r = Rendered::default();
    let text = v.get("text").and_then(Value::as_str).unwrap_or_default();
    r.stdout = text.to_string();
    if !r.stdout.ends_with('\n') {
        r.stdout.push('\n');
    }
    if let Some(ws) = v.get("warnings").and_then(Value::as_array) {
        for w in ws.iter().filter_map(Value::as_str) {
            r.stderr.push_str(&format!("warning: {}\n", one_line(w)));
        }
    }
    if v.get("truncated") == Some(&Value::Bool(true)) {
        r.stderr.push_str("note: output truncated\n");
    }
    r
}

fn joined(v: Option<&Value>, empty: &str) -> String {
    let items: Vec<String> = v
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(scalar).collect())
        .unwrap_or_default();
    if items.is_empty() {
        empty.to_string()
    } else {
        items.join(",")
    }
}

fn count(v: &Value, key: &str) -> u64 {
    v.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// `rewrite_plan`: the rewrite order, one row per function, callees first.
fn rewrite_plan(v: &Value) -> String {
    let rows: Vec<Vec<String>> = v
        .get("entries")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|e| {
                    let group = match e.get("group_size").and_then(Value::as_u64) {
                        Some(n) if n > 1 => format!("{} (x{n})", str_of(e.get("group"))),
                        _ => str_of(e.get("group")),
                    };
                    vec![
                        str_of(e.get("order")),
                        str_of(e.get("address")),
                        str_of(e.get("name")),
                        group,
                        str_of(e.get("status")),
                        joined(e.get("flags"), "-"),
                        joined(e.get("needs_stubs"), "-"),
                    ]
                })
                .collect()
        })
        .unwrap_or_default();
    let mut out = format!(
        "{} of {} functions planned in {} groups ({} import thunks and {} runtime functions left out{})\n",
        count(v, "functions_planned"),
        count(v, "functions_total"),
        count(v, "groups"),
        count(v, "skipped_imports"),
        count(v, "skipped_runtime"),
        if v.get("truncated") == Some(&Value::Bool(true)) {
            "; the function cap cut the program short"
        } else {
            ""
        },
    );
    out.push_str(&table(
        &[
            "order",
            "address",
            "name",
            "group",
            "status",
            "flags",
            "needs stubs",
        ],
        &rows,
    ));
    if let Some(c) = v.get("next_cursor").and_then(Value::as_str) {
        out.push_str(&format!("more: --cursor {c}\n"));
    }
    out
}

/// `rewrite_status`: counts per status, then one row per function.
fn rewrite_status(v: &Value) -> String {
    let counts = v.get("counts").cloned().unwrap_or(Value::Null);
    let total: u64 = ["planned", "translated", "verified", "failed", "accepted"]
        .iter()
        .map(|k| count(&counts, k))
        .sum();
    let mut out = format!(
        "{} planned, {} translated, {} verified, {} failed, {} accepted ({total} functions{})\n",
        count(&counts, "planned"),
        count(&counts, "translated"),
        count(&counts, "verified"),
        count(&counts, "failed"),
        count(&counts, "accepted"),
        if v.get("plan_present") == Some(&Value::Bool(true)) {
            ""
        } else {
            "; no plan stored, run rewrite-plan"
        }
    );
    let rows: Vec<Vec<String>> = v
        .get("units")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|u| {
                    let version = match u.get("accepted_version").and_then(Value::as_u64) {
                        Some(av) => format!("{} (accepted {av})", str_of(u.get("version"))),
                        None => str_of(u.get("version")),
                    };
                    vec![
                        str_of(u.get("order")),
                        str_of(u.get("address")),
                        str_of(u.get("name")),
                        str_of(u.get("status")),
                        version,
                        str_of(u.get("verdict")),
                        format!(
                            "{}/{}",
                            u.get("passed").and_then(Value::as_u64).unwrap_or(0),
                            u.get("cases_run").and_then(Value::as_u64).unwrap_or(0)
                        ),
                        joined(u.get("flags"), "-"),
                    ]
                })
                .collect()
        })
        .unwrap_or_default();
    out.push_str(&table(
        &[
            "order", "address", "name", "status", "version", "verdict", "cases", "flags",
        ],
        &rows,
    ));
    if let Some(c) = v.get("next_cursor").and_then(Value::as_str) {
        out.push_str(&format!("more: --cursor {c}\n"));
    }
    out
}

/// `rewrite_unit`: the versions of one function as a table, then the newest version's details and
/// code, then the spec.
fn rewrite_unit(v: &Value) -> String {
    let versions: &[Value] = v
        .get("versions")
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice);
    let mut out = format!(
        "{}: {} stored version{}\n",
        str_of(v.get("address")),
        versions.len(),
        if versions.len() == 1 { "" } else { "s" }
    );
    if !versions.is_empty() {
        let rows: Vec<Vec<String>> = versions
            .iter()
            .map(|x| {
                vec![
                    str_of(x.get("version")),
                    str_of(x.get("unit")),
                    str_of(x.get("status")),
                    str_of(x.get("verdict")),
                    format!(
                        "{}/{}",
                        x.get("passed").and_then(Value::as_u64).unwrap_or(0),
                        x.get("cases_run").and_then(Value::as_u64).unwrap_or(0)
                    ),
                    str_of(x.get("mode")),
                    format!("{} {}", str_of(x.get("provider")), str_of(x.get("model"))),
                ]
            })
            .collect();
        out.push_str(&table(
            &[
                "version", "unit", "status", "verdict", "cases", "mode", "model",
            ],
            &rows,
        ));
    }
    if let Some(x) = versions.last() {
        out.push_str(&format!(
            "\nnewest, version {}{}:\nchecked at: {}\noracle: {}; sandbox: {}\n",
            str_of(x.get("version")),
            if x.get("accepted") == Some(&Value::Bool(true)) {
                " (accepted)"
            } else {
                ""
            },
            str_of(x.get("signature")),
            str_of(x.get("oracle_kind")),
            str_of(x.get("sandbox")),
        ));
        if let Some(d) = x.get("verdict_detail").and_then(Value::as_str) {
            out.push_str(&format!("reason: {}\n", one_line(d)));
        }
        if let Some(c) = x.get("counterexample").filter(|c| !c.is_null()) {
            out.push_str(&format!(
                "counterexample args: {}\n",
                joined(c.get("args"), "-")
            ));
            if let Some(ds) = c.get("differences").and_then(Value::as_array) {
                for d in ds.iter().filter_map(Value::as_str) {
                    out.push_str(&format!("  {}\n", one_line(d)));
                }
            }
        }
        if let Some(code) = x.get("rust_code").and_then(Value::as_str) {
            out.push('\n');
            out.push_str(code);
            if !code.ends_with('\n') {
                out.push('\n');
            }
        }
    }
    if let Some(md) = v
        .get("spec")
        .and_then(|sp| sp.get("markdown"))
        .and_then(Value::as_str)
    {
        out.push_str("\nspec:\n");
        out.push_str(md);
        if !md.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

/// The result of a `rewrite_function` job: verdict first, the counterexample if there is one.
fn rewrite_function(v: &Value) -> String {
    let mut out = format!(
        "{} {} (unit {} v{}, {} mode): {} -- {}/{} cases agreed",
        str_of(v.get("name")),
        str_of(v.get("address")),
        str_of(v.get("unit")),
        str_of(v.get("version")),
        str_of(v.get("mode")),
        str_of(v.get("verdict")),
        str_of(v.get("passed")),
        str_of(v.get("cases_run")),
    );
    if v.get("skipped").and_then(Value::as_u64).unwrap_or(0) > 0 {
        out.push_str(&format!(", {} not evaluated", str_of(v.get("skipped"))));
    }
    out.push('\n');
    if let Some(d) = v.get("verdict_detail").and_then(Value::as_str) {
        out.push_str(&format!("reason: {}\n", one_line(d)));
    }
    out.push_str(&format!("status: {}\n", str_of(v.get("status"))));
    out.push_str(&format!(
        "checked at: {}\n",
        str_of(v.get("rust_prototype"))
    ));
    out.push_str(&format!(
        "model: {} {}; sandbox: {}\n",
        str_of(v.get("provider")),
        str_of(v.get("model")),
        str_of(v.get("sandbox"))
    ));
    if let Some(c) = v.get("counterexample").filter(|c| !c.is_null()) {
        out.push_str(&format!(
            "counterexample args: {}\n",
            joined(c.get("args"), "-")
        ));
        if let Some(ds) = c.get("differences").and_then(Value::as_array) {
            for d in ds.iter().filter_map(Value::as_str) {
                out.push_str(&format!("  {}\n", one_line(d)));
            }
        }
    }
    for key in ["assumptions", "unsupported"] {
        if let Some(a) = v.get(key).and_then(Value::as_array) {
            for x in a.iter().filter_map(Value::as_str) {
                out.push_str(&format!("{key}: {}\n", one_line(x)));
            }
        }
    }
    out.push_str(&format!(
        "accept it with: kraken rewrite-accept --unit {}\n",
        str_of(v.get("unit"))
    ));
    out
}

/// One program-level case: what it ran with, then what differed.
fn program_case(c: &Value, out: &mut String) {
    let argv = joined(c.get("argv"), "(no arguments)");
    out.push_str(&format!(
        "  case {} ({}): arguments {argv}, {} bytes of input -- {}\n",
        str_of(c.get("name")),
        str_of(c.get("origin")),
        count(c, "stdin_bytes"),
        if c.get("agree") == Some(&Value::Bool(true)) {
            "agreed"
        } else {
            "DIFFERED"
        }
    ));
    if let Some(ds) = c.get("differences").and_then(Value::as_array) {
        for d in ds.iter().filter_map(Value::as_str) {
            out.push_str(&format!("    {}\n", one_line(d)));
        }
    }
}

/// The result of a `rewrite_program` job, or one stored run of `rewrite_program_status`: the
/// function table, the crate, and the program-level verdict with the cases that differed.
fn rewrite_program(v: &Value) -> String {
    let verdict = v.get("verdict").cloned().unwrap_or(Value::Null);
    let mut out = format!(
        "run {}: entry {} {} -- {} functions planned ({} not reached from the entry), {} translated, \
         {} taken from accepted units, {} without a usable translation, {} in the crate\n",
        str_of(v.get("run")),
        str_of(v.get("entry_name")),
        str_of(v.get("entry")),
        count(v, "functions_planned"),
        count(v, "skipped"),
        count(v, "translated"),
        count(v, "reused_from_store"),
        count(v, "failed"),
        count(v, "included"),
    );
    let crate_dir = v.get("crate_dir").and_then(Value::as_str).unwrap_or("");
    if crate_dir.is_empty() {
        out.push_str("crate: not written\n");
    } else {
        out.push_str(&format!(
            "crate: {crate_dir} ({})\n",
            if v.get("built") == Some(&Value::Bool(true)) {
                "built in the sandbox"
            } else {
                "not built"
            }
        ));
    }
    out.push_str(&format!(
        "model: {} {}\n",
        str_of(v.get("provider")),
        str_of(v.get("model"))
    ));
    let rows: Vec<Vec<String>> = v
        .get("functions")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .map(|f| {
                    vec![
                        str_of(f.get("order")),
                        str_of(f.get("address")),
                        str_of(f.get("name")),
                        str_of(f.get("status")),
                        str_of(f.get("verdict")),
                        str_of(f.get("check")),
                        str_of(f.get("attempts")),
                        joined(f.get("reused_callees"), "-"),
                        if f.get("included") == Some(&Value::Bool(true)) {
                            "yes".to_string()
                        } else {
                            "no".to_string()
                        },
                    ]
                })
                .collect()
        })
        .unwrap_or_default();
    out.push_str(&table(
        &[
            "order", "address", "name", "status", "verdict", "check", "tries", "calls", "in crate",
        ],
        &rows,
    ));
    for f in v
        .get("functions")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice)
    {
        if let Some(n) = f.get("check_note").and_then(Value::as_str) {
            out.push_str(&format!("  {}: {}\n", str_of(f.get("name")), one_line(n)));
        }
    }
    out.push_str(&format!(
        "\nprogram verdict: {} -- {}/{} cases agreed",
        str_of(verdict.get("verdict")),
        count(&verdict, "passed"),
        count(&verdict, "cases_run"),
    ));
    let sandbox = str_of(verdict.get("sandbox"));
    if sandbox != "-" && !sandbox.is_empty() {
        out.push_str(&format!(" (sandbox {sandbox})"));
    }
    out.push('\n');
    if let Some(d) = verdict.get("detail").and_then(Value::as_str) {
        out.push_str(&format!("reason: {}\n", one_line(d)));
    }
    if let Some(rounds) = v.get("repairs").and_then(Value::as_array) {
        for r in rounds {
            let after = str_of(r.get("verdict_after"));
            out.push_str(&format!(
                "repair round {}: {} {} (v{} -> v{}){}\n",
                count(r, "round"),
                str_of(r.get("name")),
                str_of(r.get("outcome")),
                count(r, "version_before"),
                count(r, "version_after"),
                if after == "-" || after.is_empty() {
                    String::new()
                } else {
                    format!(", then {after}")
                }
            ));
            let at = str_of(r.get("at"));
            if at != "-" && !at.is_empty() {
                let stack = r
                    .get("stack")
                    .and_then(Value::as_array)
                    .map(|s| {
                        s.iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join(" <- ")
                    })
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "no call stack".to_string());
                out.push_str(&format!(
                    "  case {}: the Rust program was {at}, inside {stack}\n",
                    str_of(r.get("case"))
                ));
            }
        }
    }
    let cases = verdict
        .get("cases")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    let differing: Vec<&Value> = cases
        .iter()
        .filter(|c| c.get("agree") != Some(&Value::Bool(true)))
        .collect();
    if differing.is_empty() && count(&verdict, "failed") == 0 {
        return out;
    }
    for c in differing.iter().take(20) {
        program_case(c, &mut out);
    }
    if differing.len() > 20 {
        out.push_str(&format!("  ... and {} more\n", differing.len() - 20));
    }
    out
}

/// `rewrite_program_status`: the stored runs, then the selected one in full.
fn rewrite_program_status(v: &Value) -> String {
    let runs = v
        .get("runs")
        .and_then(Value::as_array)
        .map_or(&[][..], Vec::as_slice);
    if runs.is_empty() {
        return "no program rewrite is stored for this binary; run rewrite-program\n".to_string();
    }
    let rows: Vec<Vec<String>> = runs
        .iter()
        .map(|r| {
            vec![
                str_of(r.get("run")),
                str_of(r.get("entry")),
                str_of(r.get("verdict")),
                format!("{}/{}", count(r, "passed"), count(r, "cases_run")),
                str_of(r.get("crate_dir")),
            ]
        })
        .collect();
    let mut out = table(&["run", "entry", "verdict", "cases", "crate"], &rows);
    if let Some(run) = v.get("run").filter(|r| !r.is_null()) {
        out.push('\n');
        out.push_str(&rewrite_program(run));
    }
    out
}

fn generic(v: &Value, indent: usize, out: &mut String) {
    let pad = " ".repeat(indent);
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                if let Some(s) = scalar(x) {
                    out.push_str(&format!("{pad}{k}: {s}\n"));
                } else if matches!(x, Value::Array(a) if a.is_empty()) {
                    out.push_str(&format!("{pad}{k}: (none)\n"));
                } else if matches!(x, Value::Object(o) if o.is_empty()) {
                    out.push_str(&format!("{pad}{k}: (empty)\n"));
                } else {
                    out.push_str(&format!("{pad}{k}:\n"));
                    generic(x, indent + 2, out);
                }
            }
        }
        Value::Array(a) => {
            if let Some((headers, rows)) = as_table(a) {
                let hs: Vec<&str> = headers.iter().map(String::as_str).collect();
                for l in table(&hs, &rows).lines() {
                    out.push_str(&format!("{pad}{l}\n"));
                }
            } else {
                for x in a {
                    if let Some(s) = scalar(x) {
                        out.push_str(&format!("{pad}- {s}\n"));
                    } else {
                        out.push_str(&format!("{pad}-\n"));
                        generic(x, indent + 2, out);
                    }
                }
            }
        }
        other => {
            if let Some(s) = scalar(other) {
                out.push_str(&format!("{pad}{s}\n"));
            }
        }
    }
}

/// Rows and headers when every element is an object whose values are all scalars.
fn as_table(a: &[Value]) -> Option<(Vec<String>, Vec<Vec<String>>)> {
    if a.is_empty() {
        return None;
    }
    let mut headers: Vec<String> = Vec::new();
    for x in a {
        let m = x.as_object()?;
        if m.values().any(|v| scalar(v).is_none()) {
            return None;
        }
        for k in m.keys() {
            if !headers.contains(k) {
                headers.push(k.clone());
            }
        }
    }
    let rows = a
        .iter()
        .map(|x| headers.iter().map(|h| str_of(x.get(h))).collect())
        .collect();
    Some((headers, rows))
}

fn plain(stdout: String) -> Rendered {
    Rendered {
        stdout,
        stderr: String::new(),
    }
}

/// Renders the result of command `name` for people.
pub fn render(name: &str, output: &Value) -> Rendered {
    let v = unwrap_untrusted(output);
    match name {
        "list_functions" => Rendered {
            stdout: list_functions(&v),
            stderr: String::new(),
        },
        "decompile" => decompile(&v),
        "read_bytes" => read_bytes(&v),
        "disassemble" => plain(disassemble(&v)),
        "memory_map" => plain(memory_map(&v)),
        "xrefs" | "callers" | "callees" => plain(xrefs(&v)),
        "strings" => plain(strings(&v)),
        "imports" | "exports" => plain(symbols(&v)),
        "cfg" => plain(cfg(&v)),
        "rewrite_plan" => plain(rewrite_plan(&v)),
        "rewrite_status" => plain(rewrite_status(&v)),
        "rewrite_unit" => plain(rewrite_unit(&v)),
        "rewrite_program_status" => plain(rewrite_program_status(&v)),
        "rewrite_program"
            if v.get("result")
                .is_some_and(|r| r.get("functions").is_some())
                || v.get("functions").is_some() =>
        {
            plain(rewrite_program(v.get("result").unwrap_or(&v)))
        }
        // A finished job prints as a job view with the command's result inside.
        "rewrite_function"
            if v.get("result").is_some_and(|r| r.get("verdict").is_some())
                || v.get("verdict").is_some() =>
        {
            plain(rewrite_function(v.get("result").unwrap_or(&v)))
        }
        _ => {
            let mut s = String::new();
            generic(&v, 0, &mut s);
            Rendered {
                stdout: s,
                stderr: String::new(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn u(s: &str) -> Value {
        json!({"untrusted": true, "value": s})
    }

    #[test]
    fn tables_are_aligned_without_trailing_blanks() {
        let t = table(
            &["a", "bb"],
            &[
                vec!["1".into(), "x".into()],
                vec!["333".into(), "yy".into()],
            ],
        );
        assert_eq!(t, "A    BB\n1    x\n333  yy\n");
    }

    #[test]
    fn function_lists_are_columns() {
        let page = json!({"items": [
            {"address": "0x401000", "size": 12, "name": u("main"), "signature": u("int main(void)")},
            {"address": "0x401020", "name": u("helper_with_long_name")}
        ], "next_cursor": "ram:401020", "total": 2});
        let r = render("list_functions", &page);
        let lines: Vec<&str> = r.stdout.lines().collect();
        assert_eq!(lines[0], "ADDRESS   SIZE  NAME                   SIGNATURE");
        assert_eq!(
            lines[1],
            "0x401000  12    main                   int main(void)"
        );
        assert_eq!(lines[2], "0x401020  -     helper_with_long_name  -");
        assert_eq!(lines[3], "2 total; more: --cursor ram:401020");
    }

    #[test]
    fn decompile_prints_the_text() {
        let v = json!({"text": u("int main(void) {\n  return 0;\n}"), "warnings": [u("w1")], "truncated": true});
        let r = render("decompile", &v);
        assert_eq!(r.stdout, "int main(void) {\n  return 0;\n}\n");
        assert!(r.stderr.contains("warning: w1"));
        assert!(r.stderr.contains("truncated"));
    }

    #[test]
    fn listings_xrefs_and_hexdumps_are_readable() {
        let listing = json!({"items": [
            {"address": "0x401000", "bytes": "e800000000", "mnemonic": "call", "flow": "call",
             "labels": [u("main")], "comment": u("go"),
             "operands": [{"kind": "symbol", "text": "0x401040", "symbol": u("helper"), "target": "0x401040"}]},
            {"address": "0x401005", "bytes": "c3", "mnemonic": "ret", "operands": [], "flow": "return"}
        ], "next_cursor": "0x401006"});
        let r = render("disassemble", &listing);
        assert_eq!(
            r.stdout,
            "main:\n0x401000    e800000000        call    helper  ; go\n\
             0x401005    c3                ret\nmore: --cursor 0x401006\n"
        );
        let x = json!({"items": [{"from": "0x401004", "to": "0x401040", "kind": "call",
            "from_function": {"address": "0x401000", "name": u("main")}}]});
        let r = render("callers", &x);
        assert!(r.stdout.starts_with("FROM"), "{}", r.stdout);
        assert!(
            r.stdout
                .contains("0x401004  0x401040  call  main           -")
        );
        let dump = render(
            "read_bytes",
            &json!({"start": "0x401000", "bytes": "SGk=", "length": 2, "complete": false}),
        );
        assert_eq!(dump.stdout, format!("0x00401000  {:<47}  Hi\n", "48 69"));
        assert!(dump.stderr.contains("end of mapped memory"));
        assert_eq!(decode_base64("AAEC/4A="), [0, 1, 2, 0xff, 0x80]);
    }

    #[test]
    fn generic_objects_and_arrays() {
        let v = json!({"status": "applied", "versions": {"k": 1}, "list": [{"a": 1, "b": "x"}], "none": []});
        let r = render("rename_symbol", &v);
        assert!(r.stdout.contains("status: applied\n"));
        assert!(r.stdout.contains("versions:\n  k: 1\n"));
        assert!(r.stdout.contains("list:\n  A  B\n  1  x\n"));
        assert!(r.stdout.contains("none: (none)\n"));
    }

    #[test]
    fn rewrite_plan_and_status_are_tables() {
        let plan = json!({
            "scope": "all", "functions_total": 9, "functions_planned": 2, "groups": 1,
            "skipped_imports": 4, "skipped_runtime": 3, "truncated": true,
            "entries": [
                {"order": 0, "address": "0x10", "name": u("leaf"), "group": 0, "group_size": 1,
                 "status": "planned", "flags": [], "needs_stubs": []},
                {"order": 1, "address": "0x20", "name": u("even"), "group": 1, "group_size": 2,
                 "status": "verified", "flags": ["recursive", "needs_stubs"],
                 "needs_stubs": [u("calloc")]}
            ],
            "next_cursor": "2"
        });
        let r = render("rewrite_plan", &plan);
        let lines: Vec<&str> = r.stdout.lines().collect();
        assert_eq!(
            lines[0],
            "2 of 9 functions planned in 1 groups (4 import thunks and 3 runtime functions left \
             out; the function cap cut the program short)"
        );
        let cells = |l: &str| l.split_whitespace().map(str::to_string).collect::<Vec<_>>();
        assert_eq!(
            cells(lines[1]),
            [
                "ORDER", "ADDRESS", "NAME", "GROUP", "STATUS", "FLAGS", "NEEDS", "STUBS"
            ]
        );
        assert_eq!(
            cells(lines[2]),
            ["0", "0x10", "leaf", "0", "planned", "-", "-"]
        );
        assert_eq!(
            cells(lines[3]),
            [
                "1",
                "0x20",
                "even",
                "1",
                "(x2)",
                "verified",
                "recursive,needs_stubs",
                "calloc"
            ]
        );
        assert_eq!(lines[4], "more: --cursor 2");

        let status = json!({
            "plan_present": false,
            "counts": {"planned": 1, "translated": 0, "verified": 1, "failed": 0, "accepted": 2},
            "units": [{"address": "0x10", "name": u("f"), "status": "accepted", "version": 3,
                       "accepted_version": 2, "verdict": "pass", "passed": 5, "cases_run": 5,
                       "flags": []}]
        });
        let r = render("rewrite_status", &status);
        let lines: Vec<&str> = r.stdout.lines().collect();
        assert_eq!(
            lines[0],
            "1 planned, 0 translated, 1 verified, 0 failed, 2 accepted (4 functions; no plan \
             stored, run rewrite-plan)"
        );
        assert_eq!(
            cells(lines[2]),
            [
                "-",
                "0x10",
                "f",
                "accepted",
                "3",
                "(accepted",
                "2)",
                "pass",
                "5/5",
                "-"
            ]
        );
    }

    #[test]
    fn rewrite_unit_lists_versions_then_the_newest_code_and_the_spec() {
        let out = json!({
            "address": "0x10",
            "versions": [
                {"unit": "ru-a", "version": 1, "mode": "incremental", "status": "failed",
                 "accepted": false, "verdict": "fail", "cases_run": 9, "passed": 7,
                 "rust_code": u("old"), "signature": "fn f()", "oracle_kind": "emu",
                 "sandbox": "landlock", "created": 5, "provider": "p", "model": "m"},
                {"unit": "ru-b", "version": 2, "mode": "incremental", "status": "accepted",
                 "accepted": true, "verdict": "pass", "cases_run": 9, "passed": 9,
                 "rust_code": u("fn f() {}\n"), "signature": "fn f()", "oracle_kind": "emu",
                 "sandbox": "landlock", "created": 6, "provider": "p", "model": "m"}
            ],
            "spec": {"spec": 1, "markdown": u("# f"), "citations": []}
        });
        let cells = |l: &str| l.split_whitespace().map(str::to_string).collect::<Vec<_>>();
        let r = render("rewrite_unit", &out);
        let lines: Vec<&str> = r.stdout.lines().collect();
        assert_eq!(lines[0], "0x10: 2 stored versions");
        assert_eq!(cells(lines[2])[..3], ["1", "ru-a", "failed"]);
        assert_eq!(cells(lines[3])[..3], ["2", "ru-b", "accepted"]);
        assert!(r.stdout.contains("newest, version 2 (accepted):"));
        assert!(r.stdout.contains("\nfn f() {}\n"));
        assert!(!r.stdout.contains("old"));
        assert!(r.stdout.ends_with("spec:\n# f\n"));
        let empty = render("rewrite_unit", &json!({"address": "0x10", "versions": []}));
        assert_eq!(empty.stdout, "0x10: 0 stored versions\n");
    }

    #[test]
    fn rewrite_function_results_lead_with_the_verdict_and_the_counterexample() {
        let result = json!({
            "unit": "ru-1", "address": "0x10", "name": u("cmp"), "version": 2, "mode": "spec",
            "status": "failed", "verdict": "fail", "cases_run": 9, "passed": 7, "skipped": 2,
            "rust_prototype": "pub unsafe extern \"C\" fn cmp()", "sandbox": "landlock-v6",
            "provider": "p", "model": "m",
            "counterexample": {"args": ["1", "buf[4]=00000000"],
                               "differences": [u("return value: original Some(1), translation Some(2)")]},
            "assumptions": [u("a record is 40 bytes")], "unsupported": []
        });
        let job = json!({"job_id": "job-1", "status": "succeeded", "result": result});
        let r = render("rewrite_function", &job);
        assert!(
            r.stdout.starts_with(
                "cmp 0x10 (unit ru-1 v2, spec mode): fail -- 7/9 cases agreed, 2 not evaluated\n"
            ),
            "{}",
            r.stdout
        );
        assert!(
            r.stdout
                .contains("counterexample args: 1,buf[4]=00000000\n")
        );
        assert!(
            r.stdout
                .contains("  return value: original Some(1), translation Some(2)\n")
        );
        assert!(r.stdout.contains("assumptions: a record is 40 bytes\n"));
        // Anything else falls back to the generic view.
        let other = render(
            "rewrite_function",
            &json!({"job_id": "job-1", "status": "running"}),
        );
        assert!(other.stdout.contains("status: running"));
    }

    #[test]
    fn rewrite_program_results_show_the_functions_and_only_the_differing_cases() {
        let result = json!({
            "run": 2, "entry": "0x101707", "entry_name": u("main"), "functions_planned": 2,
            "translated": 2, "reused_from_store": 0, "failed": 0, "included": 2,
            "crate_dir": "/p/rewrite-program", "built": true, "provider": "replay",
            "model": "cassette",
            "functions": [
                {"order": 0, "address": "0x101194", "name": u("push"), "status": "verified",
                 "verdict": "pass", "check": "differential", "attempts": 1, "included": true},
                {"order": 1, "address": "0x101707", "name": u("main"), "status": "translated",
                 "verdict": "inconclusive", "check": "compile_only", "attempts": 1,
                 "reused_callees": ["push"], "included": true,
                 "check_note": u("pointer result")}
            ],
            "repairs": [{"round": 1, "address": "0x101707", "name": u("main"), "case": "gen-1",
                "at": "writing byte 2 of its standard output", "stack": ["push", "fn_101707"],
                "why": u("it was running"), "outcome": "replaced", "version_before": 1,
                "version_after": 2, "verdict_after": "fail"}],
            "verdict": {"verdict": "fail", "cases_run": 3, "passed": 2, "failed": 1,
                "sandbox": "landlock-v6+netns",
                "cases": [
                    {"name": "gen-1", "origin": "generated", "argv": [u("a b")], "stdin_bytes": 4,
                     "agree": false, "differences": [u("stdout: 3 bytes vs 4 bytes, first difference at byte 2")]},
                    {"name": "baseline", "origin": "baseline", "argv": [], "stdin_bytes": 0,
                     "agree": true, "differences": []}
                ]}
        });
        let job = json!({"job_id": "job-1", "status": "succeeded", "result": result});
        let r = render("rewrite_program", &job);
        let lines: Vec<&str> = r.stdout.lines().collect();
        assert!(
            lines[0].starts_with("run 2: entry main 0x101707 -- 2 functions planned (0 not reached from the entry), 2 translated"),
            "{}",
            r.stdout
        );
        assert!(
            r.stdout
                .contains("crate: /p/rewrite-program (built in the sandbox)\n")
        );
        assert!(r.stdout.contains("main"), "{}", r.stdout);
        assert!(r.stdout.contains("  main: pointer result\n"));
        assert!(
            r.stdout.contains(
                "program verdict: fail -- 2/3 cases agreed (sandbox landlock-v6+netns)\n"
            )
        );
        assert!(
            r.stdout
                .contains("repair round 1: main replaced (v1 -> v2), then fail\n"),
            "{}",
            r.stdout
        );
        assert!(r.stdout.contains(
            "  case gen-1: the Rust program was writing byte 2 of its standard output, inside push <- fn_101707\n"
        ));
        assert!(
            r.stdout.contains(
                "  case gen-1 (generated): arguments a b, 4 bytes of input -- DIFFERED\n"
            )
        );
        assert!(
            r.stdout
                .contains("    stdout: 3 bytes vs 4 bytes, first difference at byte 2\n")
        );
        assert!(
            !r.stdout.contains("case baseline"),
            "agreeing cases are not listed"
        );

        let none = render(
            "rewrite_program_status",
            &json!({"present": false, "runs": []}),
        );
        assert!(none.stdout.starts_with("no program rewrite is stored"));
        let status = render(
            "rewrite_program_status",
            &json!({"present": true,
                "runs": [{"run": 2, "entry": "0x101707", "verdict": "fail", "cases_run": 3,
                          "passed": 2, "crate_dir": "/p/c"}],
                "run": result}),
        );
        assert!(status.stdout.starts_with("RUN  ENTRY"), "{}", status.stdout);
        assert!(status.stdout.contains("program verdict: fail"));
    }

    #[test]
    fn untrusted_wrappers_are_removed() {
        assert_eq!(unwrap_untrusted(&u("x")), json!("x"));
        assert_eq!(
            unwrap_untrusted(&json!({"a": [u("y")]})),
            json!({"a": ["y"]})
        );
    }
}
