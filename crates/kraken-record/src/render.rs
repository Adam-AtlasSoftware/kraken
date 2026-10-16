//! Stable, diff-friendly JSON: keys sorted, 2-space indent, and any object or array whose compact
//! form is short (a token, a locator, a parameter) on a single line.

use serde_json::Value;

const INLINE_MAX: usize = 200;

/// Renders `v` with a trailing newline.
pub fn render(v: &Value) -> String {
    let mut out = String::new();
    write(v, 0, &mut out);
    out.push('\n');
    out
}

fn compact(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            out.push('{');
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                out.push_str(&Value::String(k.clone()).to_string());
                out.push_str(": ");
                compact(&m[k], out);
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push_str(", ");
                }
                compact(x, out);
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn write(v: &Value, depth: usize, out: &mut String) {
    let container = matches!(v, Value::Object(m) if !m.is_empty())
        || matches!(v, Value::Array(a) if !a.is_empty());
    if !container {
        compact(v, out);
        return;
    }
    let mut one = String::new();
    compact(v, &mut one);
    if one.len() <= INLINE_MAX && !one.contains("\\n") {
        out.push_str(&one);
        return;
    }
    let pad = "  ".repeat(depth + 1);
    match v {
        Value::Object(m) => {
            out.push_str("{\n");
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort();
            let last = keys.len() - 1;
            for (i, k) in keys.into_iter().enumerate() {
                out.push_str(&pad);
                out.push_str(&Value::String(k.clone()).to_string());
                out.push_str(": ");
                write(&m[k], depth + 1, out);
                out.push_str(if i == last { "\n" } else { ",\n" });
            }
            out.push_str(&"  ".repeat(depth));
            out.push('}');
        }
        Value::Array(a) => {
            out.push_str("[\n");
            let last = a.len() - 1;
            for (i, x) in a.iter().enumerate() {
                out.push_str(&pad);
                write(x, depth + 1, out);
                out.push_str(if i == last { "\n" } else { ",\n" });
            }
            out.push_str(&"  ".repeat(depth));
            out.push(']');
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_sorted_and_small_values_inline() {
        let v = json!({"b": [1, 2], "a": {"z": 1, "y": "x"}});
        assert_eq!(
            render(&v),
            "{\"a\": {\"y\": \"x\", \"z\": 1}, \"b\": [1, 2]}\n"
        );
    }

    #[test]
    fn long_values_break_and_round_trip() {
        let long = "x".repeat(300);
        let v = json!({"text": long, "list": [{"k": 1}, {"k": 2}], "n": null});
        let s = render(&v);
        assert!(s.starts_with("{\n  \"list\""));
        assert_eq!(serde_json::from_str::<Value>(&s).expect("valid json"), v);
    }
}
