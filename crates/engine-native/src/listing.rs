//! Disassembly rows: Sleigh's operand text split into typed tokens.

use engine_native_sys::Flow;
use kraken_proto::{FlowKind, Locator, OperandKind, OperandToken};

/// Size and pointer keywords Sleigh prints inside x86 operands.
const KEYWORDS: &[&str] = &[
    "byte", "word", "dword", "qword", "tword", "xmmword", "ymmword", "zmmword", "ptr", "far",
    "short", "near",
];

/// Maps the Sleigh-derived flow onto the protocol's.
pub fn flow_kind(f: Flow) -> FlowKind {
    match f {
        Flow::Fallthrough => FlowKind::Fallthrough,
        Flow::Jump => FlowKind::Jump,
        Flow::ConditionalJump => FlowKind::ConditionalJump,
        Flow::Call => FlowKind::Call,
        Flow::Return => FlowKind::Return,
        Flow::IndirectJump | Flow::IndirectCall => FlowKind::Indirect,
    }
}

fn parse_number(s: &str) -> Option<i128> {
    let (neg, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let v = if let Some(h) = digits.strip_prefix("0x") {
        i128::from_str_radix(h, 16).ok()?
    } else {
        digits.parse::<i128>().ok()?
    };
    Some(if neg { -v } else { v })
}

/// Splits Sleigh operand text into tokens. `symbol_at` names an address that has a symbol and
/// `mapped` says whether a value is an address in the program.
pub fn operands(
    body: &str,
    symbol_at: impl Fn(u64) -> Option<String>,
    mapped: impl Fn(u64) -> bool,
) -> Vec<OperandToken> {
    let mut out: Vec<OperandToken> = Vec::new();
    let mut other = String::new();
    let flush = |other: &mut String, out: &mut Vec<OperandToken>| {
        if !other.is_empty() {
            out.push(OperandToken {
                text: std::mem::take(other),
                kind: OperandKind::Other,
                target: None,
            });
        }
    };
    let chars: Vec<char> = body.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let starts_number = c.is_ascii_digit()
            || (c == '-' && chars.get(i + 1).is_some_and(|d| d.is_ascii_digit()));
        if c.is_ascii_alphabetic() || c == '_' {
            let s = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[s..i].iter().collect();
            if KEYWORDS.contains(&word.as_str()) {
                other.push_str(&word);
                continue;
            }
            flush(&mut other, &mut out);
            out.push(OperandToken {
                text: word,
                kind: OperandKind::Register,
                target: None,
            });
        } else if starts_number {
            let s = i;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_hexdigit() || chars[i] == 'x') {
                i += 1;
            }
            let text: String = chars[s..i].iter().collect();
            flush(&mut other, &mut out);
            let value = parse_number(&text);
            let addr = value.filter(|v| *v > 0).and_then(|v| u64::try_from(v).ok());
            match addr {
                Some(a) if mapped(a) => match symbol_at(a) {
                    Some(name) => out.push(OperandToken {
                        text: name,
                        kind: OperandKind::Symbol,
                        target: Some(Locator::ram(a)),
                    }),
                    None => out.push(OperandToken {
                        text,
                        kind: OperandKind::Address,
                        target: Some(Locator::ram(a)),
                    }),
                },
                _ => out.push(OperandToken {
                    text,
                    kind: OperandKind::Immediate,
                    target: None,
                }),
            }
        } else if c == ',' {
            flush(&mut other, &mut out);
            out.push(OperandToken {
                text: ", ".into(),
                kind: OperandKind::Other,
                target: None,
            });
            i += 1;
            while i < chars.len() && chars[i] == ' ' {
                i += 1;
            }
        } else {
            other.push(c);
            i += 1;
        }
    }
    flush(&mut other, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_memory_operands() {
        let t = operands("qword ptr [RBP + -0x8],RDI", |_| None, |_| false);
        let kinds: Vec<(String, OperandKind)> =
            t.iter().map(|t| (t.text.clone(), t.kind)).collect();
        assert_eq!(
            kinds,
            vec![
                ("qword ptr [".into(), OperandKind::Other),
                ("RBP".into(), OperandKind::Register),
                (" + ".into(), OperandKind::Other),
                ("-0x8".into(), OperandKind::Immediate),
                ("]".into(), OperandKind::Other),
                (", ".into(), OperandKind::Other),
                ("RDI".into(), OperandKind::Register),
            ]
        );
    }

    #[test]
    fn call_targets_become_symbols() {
        let t = operands(
            "0x101030",
            |a| (a == 0x101030).then(|| "free".to_string()),
            |a| a >= 0x100000,
        );
        assert_eq!(t.len(), 1);
        assert_eq!(t[0].kind, OperandKind::Symbol);
        assert_eq!(t[0].text, "free");
        assert_eq!(t[0].target, Some(Locator::ram(0x101030)));
        let t = operands("0x102008", |_| None, |a| a >= 0x100000);
        assert_eq!(t[0].kind, OperandKind::Address);
        let t = operands("0x10", |_| None, |a| a >= 0x100000);
        assert_eq!(t[0].kind, OperandKind::Immediate);
    }
}
