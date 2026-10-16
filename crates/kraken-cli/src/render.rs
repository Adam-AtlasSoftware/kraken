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
    fn untrusted_wrappers_are_removed() {
        assert_eq!(unwrap_untrusted(&u("x")), json!("x"));
        assert_eq!(
            unwrap_untrusted(&json!({"a": [u("y")]})),
            json!({"a": ["y"]})
        );
    }
}
