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

/// Renders the result of command `name` for people.
pub fn render(name: &str, output: &Value) -> Rendered {
    let v = unwrap_untrusted(output);
    match name {
        "list_functions" => Rendered {
            stdout: list_functions(&v),
            stderr: String::new(),
        },
        "decompile" => decompile(&v),
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
