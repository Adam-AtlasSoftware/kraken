//! Reading an answer and scoring it against the ground truth.
//!
//! Scores are between 0 and 1 and need no model to compute:
//!
//! - **names**: for each function, the F1 of the token multisets of the predicted name and the
//!   DWARF name (`parse_header` and `header_parse` score 1, `parse_file` scores 0.5, a function
//!   left out scores 0); the task score is the mean over its functions. Tokens are lowercase
//!   words split at underscores, case changes and digits, with a plural `s` removed and filler
//!   words (`fn`, `func`, `do`, `the`, ...) dropped.
//! - **function**: 1 when the answer is an address inside the truth function, else 0.
//! - **yes/no**: 1 for the right answer.
//! - **set**: F1 of the answered names against the true names.
//! - **text**: 1 when the answer equals the true text (or contains it), else 0.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::prompt::{ANSWER_CLOSE, ANSWER_OPEN};
use crate::suite::Expected;

/// Words that say nothing about what a function does.
const FILLER: &[&str] = &[
    "fn", "func", "function", "sub", "fun", "do", "the", "a", "an", "my",
];

/// The score of one answer.
#[derive(Debug, Clone, PartialEq)]
pub struct Scored {
    /// 0 to 1.
    pub score: f64,
    /// True when the score is 1.
    pub correct: bool,
    /// What was compared: the truth, the answer, and the parts of the score.
    pub detail: Value,
    /// Why the answer could not be read or scored, when it could not.
    pub problem: Option<String>,
}

impl Scored {
    fn new(score: f64, detail: Value) -> Scored {
        Scored {
            score,
            correct: score >= 0.999_999,
            detail,
            problem: None,
        }
    }

    fn unreadable(problem: impl Into<String>, detail: Value) -> Scored {
        Scored {
            score: 0.0,
            correct: false,
            detail,
            problem: Some(problem.into()),
        }
    }
}

/// Splits an identifier into comparable words.
pub fn name_tokens(name: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut prev: Option<char> = None;
    let flush = |cur: &mut String, words: &mut Vec<String>| {
        if !cur.is_empty() {
            words.push(std::mem::take(cur));
        }
    };
    for c in name.chars() {
        if !c.is_alphanumeric() {
            flush(&mut cur, &mut words);
            prev = None;
            continue;
        }
        if let Some(p) = prev {
            let boundary = (p.is_lowercase() && c.is_uppercase())
                || (p.is_alphabetic() && c.is_ascii_digit())
                || (p.is_ascii_digit() && c.is_alphabetic());
            if boundary {
                flush(&mut cur, &mut words);
            }
        }
        cur.extend(c.to_lowercase());
        prev = Some(c);
    }
    flush(&mut cur, &mut words);
    words
        .into_iter()
        .map(|w| stem(&w))
        .filter(|w| !w.is_empty() && !FILLER.contains(&w.as_str()))
        .collect()
}

fn stem(w: &str) -> String {
    if w.len() > 4 && w.ends_with("ies") {
        return format!("{}y", &w[..w.len() - 3]);
    }
    if w.len() > 3 && w.ends_with('s') && !w.ends_with("ss") && !w.ends_with("us") {
        return w[..w.len() - 1].to_string();
    }
    w.to_string()
}

/// Precision, recall and F1 of the multiset overlap of two token lists. Two empty lists agree.
pub fn token_f1(predicted: &[String], truth: &[String]) -> (f64, f64, f64) {
    if predicted.is_empty() && truth.is_empty() {
        return (1.0, 1.0, 1.0);
    }
    fn count(v: &[String]) -> BTreeMap<&str, usize> {
        let mut m: BTreeMap<&str, usize> = BTreeMap::new();
        for t in v {
            *m.entry(t.as_str()).or_default() += 1;
        }
        m
    }
    let (p, t) = (count(predicted), count(truth));
    let overlap: usize = p
        .iter()
        .map(|(k, n)| (*n).min(t.get(k).copied().unwrap_or(0)))
        .sum();
    if overlap == 0 {
        return (0.0, 0.0, 0.0);
    }
    let precision = overlap as f64 / predicted.len() as f64;
    let recall = overlap as f64 / truth.len() as f64;
    (
        precision,
        recall,
        2.0 * precision * recall / (precision + recall),
    )
}

/// The answer block of a reply: the JSON between the last pair of answer tags, else the last JSON
/// object in the text. `Err` says what was wrong.
pub fn extract_answer(text: &str) -> Result<Value, String> {
    let block = match text.rfind(ANSWER_OPEN) {
        Some(i) => {
            let rest = &text[i + ANSWER_OPEN.len()..];
            let end = rest.find(ANSWER_CLOSE).unwrap_or(rest.len());
            Some(rest[..end].trim())
        }
        None => None,
    };
    if let Some(b) = block {
        let b = b
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();
        return serde_json::from_str(b).map_err(|e| format!("the answer block is not JSON ({e})"));
    }
    last_json_object(text).ok_or_else(|| "the reply has no answer block".to_string())
}

fn last_json_object(text: &str) -> Option<Value> {
    let bytes = text.as_bytes();
    let mut end = bytes.len();
    while let Some(close) = text[..end].rfind('}') {
        let mut depth = 0usize;
        for (i, b) in text[..=close].bytes().enumerate().rev() {
            match b {
                b'}' => depth += 1,
                b'{' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        if let Ok(v @ Value::Object(_)) = serde_json::from_str(&text[i..=close]) {
                            return Some(v);
                        }
                        break;
                    }
                }
                _ => {}
            }
        }
        end = close;
    }
    None
}

fn parse_address(v: &Value) -> Option<u64> {
    match v {
        Value::String(s) => {
            let s = s.trim().trim_matches('`');
            let hex = s
                .strip_prefix("0x")
                .or_else(|| s.strip_prefix("0X"))
                .unwrap_or(s);
            u64::from_str_radix(hex, 16).ok()
        }
        Value::Number(n) => n.as_u64(),
        _ => None,
    }
}

fn clean_name(s: &str) -> String {
    s.trim()
        .trim_matches(|c| matches!(c, '`' | '"' | '\''))
        .trim()
        .to_string()
}

fn as_items(v: &Value) -> Vec<String> {
    match v {
        Value::Array(a) => a
            .iter()
            .filter_map(Value::as_str)
            .map(clean_name)
            .filter(|s| !s.is_empty())
            .collect(),
        Value::String(s) => s
            .split([',', '\n'])
            .map(clean_name)
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

fn normalize_text(s: &str) -> String {
    clean_name(&s.replace("\r\n", "\n").replace('\n', "\\n"))
}

/// Scores `answer` (as read by [`extract_answer`]) against `expected`.
pub fn score(expected: &Expected, answer: Result<&Value, &str>) -> Scored {
    let answer = match answer {
        Ok(a) => a,
        Err(problem) => return Scored::unreadable(problem, expected_detail(expected)),
    };
    match expected {
        Expected::Names { functions } => {
            let names = answer.get("names").and_then(Value::as_object);
            let Some(names) = names else {
                return Scored::unreadable(
                    "the answer has no \"names\" object",
                    expected_detail(expected),
                );
            };
            let mut by_address: BTreeMap<u64, &Value> = BTreeMap::new();
            for (k, v) in names {
                if let Some(a) = parse_address(&Value::String(k.clone())) {
                    by_address.insert(a, v);
                }
            }
            let mut rows = Vec::new();
            let mut total = 0.0;
            let mut exact = 0;
            for f in functions {
                let predicted = by_address
                    .get(&f.address)
                    .and_then(|v| v.as_str())
                    .map(clean_name);
                let (p, r, f1) = match &predicted {
                    Some(n) => token_f1(&name_tokens(n), &name_tokens(&f.name)),
                    None => (0.0, 0.0, 0.0),
                };
                total += f1;
                if f1 >= 0.999_999 {
                    exact += 1;
                }
                rows.push(json!({
                    "address": format!("{:#x}", f.address),
                    "truth": f.name,
                    "predicted": predicted,
                    "precision": round(p),
                    "recall": round(r),
                    "f1": round(f1),
                }));
            }
            let mean = total / functions.len().max(1) as f64;
            Scored::new(
                mean,
                json!({"functions": rows, "exact": exact, "asked": functions.len()}),
            )
        }
        Expected::Function { name, start, size } => {
            let got = answer.get("address").and_then(parse_address);
            let detail = json!({
                "truth": name,
                "range": [format!("{start:#x}"), format!("{:#x}", start + size)],
                "answered": got.map(|a| format!("{a:#x}")),
            });
            match got {
                None => Scored::unreadable("the answer has no \"address\"", detail),
                Some(a) => {
                    Scored::new(f64::from(u8::from(a >= *start && a < start + size)), detail)
                }
            }
        }
        Expected::YesNo { value } => {
            let raw = answer.get("answer");
            let got = match raw {
                Some(Value::Bool(b)) => Some(*b),
                Some(Value::String(s)) => match s.trim().to_ascii_lowercase().as_str() {
                    "yes" | "y" | "true" => Some(true),
                    "no" | "n" | "false" => Some(false),
                    _ => None,
                },
                _ => None,
            };
            let detail = json!({"truth": value, "answered": got});
            match got {
                None => Scored::unreadable("the answer is not yes or no", detail),
                Some(g) => Scored::new(f64::from(u8::from(g == *value)), detail),
            }
        }
        Expected::Set { items } => {
            let Some(raw) = answer.get("items") else {
                return Scored::unreadable(
                    "the answer has no \"items\" list",
                    expected_detail(expected),
                );
            };
            let mut got = as_items(raw);
            got.sort();
            got.dedup();
            let mut truth = items.clone();
            truth.sort();
            truth.dedup();
            let hit = got.iter().filter(|g| truth.contains(g)).count();
            let (p, r) = (
                if got.is_empty() {
                    0.0
                } else {
                    hit as f64 / got.len() as f64
                },
                if truth.is_empty() {
                    1.0
                } else {
                    hit as f64 / truth.len() as f64
                },
            );
            let f1 = if hit == 0 { 0.0 } else { 2.0 * p * r / (p + r) };
            let missing: Vec<&String> = truth.iter().filter(|t| !got.contains(t)).collect();
            let extra: Vec<&String> = got.iter().filter(|g| !truth.contains(g)).collect();
            Scored::new(
                f1,
                json!({"truth": truth, "answered": got, "missing": missing, "extra": extra}),
            )
        }
        Expected::Text { text } => {
            let got = answer.get("text").and_then(Value::as_str);
            let detail = json!({"truth": text, "answered": got});
            match got {
                None => Scored::unreadable("the answer has no \"text\"", detail),
                Some(g) => {
                    let (g, t) = (normalize_text(g), normalize_text(text));
                    Scored::new(f64::from(u8::from(g == t || g.contains(&t))), detail)
                }
            }
        }
    }
}

fn round(x: f64) -> f64 {
    (x * 1000.0).round() / 1000.0
}

fn expected_detail(expected: &Expected) -> Value {
    match expected {
        Expected::Names { functions } => {
            json!({"asked": functions.len(), "truth": functions.iter().map(|f| f.name.clone()).collect::<Vec<_>>()})
        }
        Expected::Function { name, .. } => json!({"truth": name}),
        Expected::YesNo { value } => json!({"truth": value}),
        Expected::Set { items } => json!({"truth": items}),
        Expected::Text { text } => json!({"truth": text}),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::suite::NameTruth;

    fn toks(s: &str) -> Vec<String> {
        name_tokens(s)
    }

    #[test]
    fn names_split_into_lowercase_words() {
        assert_eq!(toks("parse_header"), ["parse", "header"]);
        assert_eq!(toks("parseHeader"), ["parse", "header"]);
        assert_eq!(toks("HTTPServer2"), ["httpserver", "2"]);
        assert_eq!(toks("list_free_nodes"), ["list", "free", "node"]);
        assert_eq!(toks("do_the_thing"), ["thing"]);
        assert_eq!(toks("FUN_00101159"), ["00101159"]);
    }

    #[test]
    fn token_overlap_is_an_f1() {
        let f = |a: &str, b: &str| token_f1(&toks(a), &toks(b)).2;
        assert!((f("parse_header", "header_parse") - 1.0).abs() < 1e-9);
        assert!((f("parse_file", "parse_header") - 0.5).abs() < 1e-9);
        assert_eq!(f("send_packet", "parse_header"), 0.0);
        let (p, r, f1) = token_f1(&toks("parse_the_http_header"), &toks("parse_header"));
        assert!((p - 0.666_666).abs() < 1e-3 && (r - 1.0).abs() < 1e-9 && f1 > 0.79 && f1 < 0.81);
    }

    #[test]
    fn answers_are_read_from_the_tagged_block_or_the_last_object() {
        let t = "Done.\n<kraken-answer>{\"address\": \"0x10\"}</kraken-answer>";
        assert_eq!(extract_answer(t).unwrap()["address"], "0x10");
        let fenced = "<kraken-answer>\n```json\n{\"answer\": \"yes\"}\n```\n</kraken-answer>";
        assert_eq!(extract_answer(fenced).unwrap()["answer"], "yes");
        let loose = "I think it is {\"address\": \"0x20\"} - sure.";
        assert_eq!(extract_answer(loose).unwrap()["address"], "0x20");
        let nested = "x {\"names\": {\"0x1\": \"a\"}} y";
        assert_eq!(extract_answer(nested).unwrap()["names"]["0x1"], "a");
        assert!(extract_answer("no answer here").is_err());
        assert!(extract_answer("<kraken-answer>{oops</kraken-answer>").is_err());
        let two = "<kraken-answer>{\"a\":1}</kraken-answer> then <kraken-answer>{\"a\":2}</kraken-answer>";
        assert_eq!(extract_answer(two).unwrap()["a"], 2);
    }

    #[test]
    fn name_scores_average_the_per_function_overlap() {
        let expected = Expected::Names {
            functions: vec![
                NameTruth {
                    address: 0x1000,
                    name: "list_push".into(),
                },
                NameTruth {
                    address: 0x1040,
                    name: "cmp_name".into(),
                },
                NameTruth {
                    address: 0x1080,
                    name: "list_free".into(),
                },
            ],
        };
        let a = json!({"names": {"0x1000": "push_node", "0x1040": "compare_names", "0x1080": "list_free"}});
        let s = score(&expected, Ok(&a));
        // push_node vs list_push: 0.5; compare_names vs cmp_name: 0.5 (they share `name`); list_free: 1.
        assert!((s.score - 2.0 / 3.0).abs() < 1e-9, "{s:?}");
        assert!(!s.correct);
        assert_eq!(s.detail["exact"], 1);
        // A function left out scores 0.
        let a = json!({"names": {"0x1080": "list_free"}});
        assert!((score(&expected, Ok(&a)).score - 1.0 / 3.0).abs() < 1e-9);
        // Keys are read as hex whatever the spelling.
        let a =
            json!({"names": {"1000": "list_push", "0X1040": "cmp_name", "0x1080": "list_free"}});
        assert!(score(&expected, Ok(&a)).correct);
    }

    #[test]
    fn a_function_answer_may_point_anywhere_inside_the_function() {
        let e = Expected::Function {
            name: "vm_run".into(),
            start: 0x1255,
            size: 0x3eb,
        };
        for (a, ok) in [
            ("0x1255", true),
            ("0x1300", true),
            ("0x1640", false),
            ("0x1254", false),
        ] {
            let s = score(&e, Ok(&json!({"address": a})));
            assert_eq!(s.correct, ok, "{a}");
        }
        assert!(score(&e, Ok(&json!({}))).problem.is_some());
        assert!(score(&e, Err("no block")).problem.is_some());
    }

    #[test]
    fn yes_no_set_and_text_answers_are_scored() {
        let yes = Expected::YesNo { value: true };
        assert!(score(&yes, Ok(&json!({"answer": "Yes"}))).correct);
        assert!(score(&yes, Ok(&json!({"answer": true}))).correct);
        assert!(!score(&yes, Ok(&json!({"answer": "no"}))).correct);
        assert!(
            score(&yes, Ok(&json!({"answer": "maybe"})))
                .problem
                .is_some()
        );

        let set = Expected::Set {
            items: vec!["exit".into(), "fprintf".into(), "printf".into()],
        };
        let s = score(&set, Ok(&json!({"items": ["printf", "exit", "puts"]})));
        // two of three right, one extra: precision 2/3, recall 2/3.
        assert!((s.score - 2.0 / 3.0).abs() < 1e-9, "{s:?}");
        assert_eq!(s.detail["missing"], json!(["fprintf"]));
        assert_eq!(s.detail["extra"], json!(["puts"]));
        assert!(score(&set, Ok(&json!({"items": "printf, exit, fprintf"}))).correct);

        let text = Expected::Text {
            text: "count=%d total=%.2f\n".into(),
        };
        assert!(score(&text, Ok(&json!({"text": "count=%d total=%.2f\\n"}))).correct);
        assert!(score(&text, Ok(&json!({"text": "\"count=%d total=%.2f\\n\""}))).correct);
        assert!(!score(&text, Ok(&json!({"text": "count=%d"}))).correct);
    }
}
