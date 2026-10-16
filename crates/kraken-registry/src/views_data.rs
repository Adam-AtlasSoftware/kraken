//! Output types of the data commands: decompiler tokens, memory map, listing, references,
//! strings and symbols. Every binary-derived string is sanitised and wrapped in [`Untrusted`].

use kraken_proto::{
    DecompileResult, DisasmRow, FlowKind, FunctionRef, Hex64, Locator, MemoryBlock, MemoryKind,
    OperandKind, OperandToken, StringEncoding, StringEntry, SymbolEntry, SymbolKind, TokenKind,
    Untrusted, Xref, XrefKind, sanitize, sanitize_mapped,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::validate::{truncate_utf8, untrusted};

/// A span of the decompiled text with links to program entities. Offsets are UTF-8 byte offsets
/// into `DecompileView::text`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TokenView {
    /// Start byte offset (inclusive).
    pub start: u32,
    /// End byte offset (exclusive).
    pub end: u32,
    /// Syntactic category.
    pub kind: TokenKind,
    /// Address the token refers to (`ram` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Hex64>,
    /// The symbol the token names, only when it differs from the token's text
    /// (binary-derived); otherwise read it from the text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<Untrusted<String>>,
}

/// The ram offset of a locator, if it is one.
pub(crate) fn ram_offset(l: &Locator) -> Option<Hex64> {
    match l {
        Locator::Native { space, offset } if space == kraken_proto::DEFAULT_SPACE => Some(*offset),
        _ => None,
    }
}

/// The cleaned decompiler text of one function with its token spans.
pub(crate) struct CleanDecompile {
    /// Sanitised text, cut at the byte limit.
    pub text: String,
    /// Whether the text was cut.
    pub truncated: bool,
    /// Token spans valid for `text`.
    pub tokens: Vec<TokenView>,
    /// Set when the engine's spans were unusable and were dropped.
    pub token_warning: Option<&'static str>,
}

/// Sanitises decompiler text and maps its token spans onto the sanitised text, then cuts both at
/// `max_bytes`. Spans that sanitising empties are dropped; spans that cross the cut are clamped.
pub(crate) fn clean_decompile_text(r: &DecompileResult, max_bytes: usize) -> CleanDecompile {
    let (clean, map) = sanitize_mapped(&r.text);
    let (text, truncated) = truncate_utf8(clean, max_bytes);
    if r.validate_tokens().is_err() {
        return CleanDecompile {
            text,
            truncated,
            tokens: Vec::new(),
            token_warning: Some("token spans were invalid and were dropped"),
        };
    }
    let cut = text.len() as u32;
    let mut tokens = Vec::with_capacity(r.tokens.len());
    for t in &r.tokens {
        let start = map[t.start as usize];
        let end = map[t.end as usize].min(cut);
        if start >= end {
            continue;
        }
        let slice = text.get(start as usize..end as usize).unwrap_or("");
        let symbol = t
            .symbol
            .as_deref()
            .map(sanitize)
            .filter(|s| !s.is_empty() && s != slice);
        tokens.push(TokenView {
            start,
            end,
            kind: t.kind,
            target: t.target.as_ref().and_then(ram_offset),
            symbol: symbol.map(Untrusted),
        });
    }
    CleanDecompile {
        text,
        truncated,
        tokens,
        token_warning: None,
    }
}

fn space_if_not_ram(space: &str) -> Option<String> {
    (space != kraken_proto::DEFAULT_SPACE).then(|| sanitize(space))
}

/// One block of the program's memory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct MemoryBlockView {
    /// Block name such as `.text` (binary-derived).
    pub name: Untrusted<String>,
    /// Address space when it is not `ram`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub space: Option<String>,
    /// First address.
    pub start: Hex64,
    /// First address after the block.
    pub end: Hex64,
    /// Size in bytes.
    pub size: u64,
    /// Permissions as `rwx` with `-` for missing ones, such as `r-x`.
    pub perms: String,
    /// False for blocks without contents, such as `.bss`.
    pub initialized: bool,
    /// How the block is backed.
    pub kind: MemoryKind,
}

impl From<&MemoryBlock> for MemoryBlockView {
    fn from(b: &MemoryBlock) -> Self {
        MemoryBlockView {
            name: untrusted(&b.name),
            space: space_if_not_ram(&b.space),
            start: b.start,
            end: b.end,
            size: b.len(),
            perms: b
                .perms
                .chars()
                .filter(|c| matches!(c, 'r' | 'w' | 'x' | '-'))
                .take(3)
                .collect(),
            initialized: b.initialized,
            kind: b.kind,
        }
    }
}

/// One operand piece of an instruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct OperandView {
    /// Token category.
    pub kind: OperandKind,
    /// Text to show. For a `symbol` token this is the address; the name is in `symbol`.
    pub text: String,
    /// Symbol name for `symbol` tokens (binary-derived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<Untrusted<String>>,
    /// Address an `address` or `symbol` token refers to (`ram` only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Hex64>,
}

impl From<&OperandToken> for OperandView {
    fn from(t: &OperandToken) -> Self {
        let target = t.target.as_ref().and_then(ram_offset);
        if t.kind == OperandKind::Symbol {
            OperandView {
                kind: t.kind,
                text: target.map(|a| a.to_hex()).unwrap_or_default(),
                symbol: Some(untrusted(&t.text)),
                target,
            }
        } else {
            OperandView {
                kind: t.kind,
                text: sanitize(&t.text),
                symbol: None,
                target,
            }
        }
    }
}

/// One disassembled instruction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct InsnView {
    /// Address of the instruction.
    pub address: Hex64,
    /// Instruction bytes as contiguous lower-case hex.
    pub bytes: String,
    /// Mnemonic such as `mov`.
    pub mnemonic: String,
    /// Operands as tokens; join the `text` fields to render them.
    pub operands: Vec<OperandView>,
    /// Comment at the address (binary-derived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<Untrusted<String>>,
    /// Labels defined at the address (binary-derived).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<Untrusted<String>>,
    /// Control flow out of the instruction.
    pub flow: FlowKind,
}

impl From<&DisasmRow> for InsnView {
    fn from(r: &DisasmRow) -> Self {
        InsnView {
            address: r.address,
            bytes: r.bytes.chars().filter(char::is_ascii_hexdigit).collect(),
            mnemonic: sanitize(&r.mnemonic),
            operands: r.operands.iter().map(OperandView::from).collect(),
            comment: r.comment.as_deref().map(untrusted),
            labels: r.labels.iter().map(|l| untrusted(l)).collect(),
            flow: r.flow,
        }
    }
}

/// A function named by its entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct FunctionRefView {
    /// Entry address.
    pub address: Hex64,
    /// Function name (binary-derived).
    pub name: Untrusted<String>,
}

impl From<&FunctionRef> for FunctionRefView {
    fn from(f: &FunctionRef) -> Self {
        FunctionRefView {
            address: f.address,
            name: untrusted(&f.name),
        }
    }
}

/// A cross-reference.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct XrefView {
    /// Where the reference originates.
    pub from: Hex64,
    /// What it points to.
    pub to: Hex64,
    /// What the reference does.
    pub kind: XrefKind,
    /// The function containing `from`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_function: Option<FunctionRefView>,
    /// The function whose entry is `to`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_function: Option<FunctionRefView>,
}

impl From<&Xref> for XrefView {
    fn from(x: &Xref) -> Self {
        XrefView {
            from: x.from,
            to: x.to,
            kind: x.kind,
            from_function: x.from_function.as_ref().map(FunctionRefView::from),
            to_function: x.to_function.as_ref().map(FunctionRefView::from),
        }
    }
}

/// Longest string value returned, in characters.
pub const MAX_STRING_CHARS: usize = 1024;

/// A string found in memory.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct StringView {
    /// Address of the first byte.
    pub address: Hex64,
    /// Decoded text (binary-derived), cut at 1024 characters.
    pub value: Untrusted<String>,
    /// True when `value` was cut.
    pub truncated: bool,
    /// Encoding of the bytes.
    pub encoding: StringEncoding,
    /// Length in bytes in memory.
    pub length: u32,
}

impl From<&StringEntry> for StringView {
    fn from(s: &StringEntry) -> Self {
        let truncated = s.value.chars().count() > MAX_STRING_CHARS;
        let value: String = if truncated {
            s.value.chars().take(MAX_STRING_CHARS).collect()
        } else {
            s.value.clone()
        };
        StringView {
            address: s.address,
            value: untrusted(&value),
            truncated,
            encoding: s.encoding,
            length: s.length,
        }
    }
}

/// An imported or exported symbol.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SymbolView {
    /// Symbol name (binary-derived).
    pub name: Untrusted<String>,
    /// Definition (export) or stub (import) address, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<Hex64>,
    /// Library an import comes from (binary-derived).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub library: Option<Untrusted<String>>,
    /// What the symbol names.
    pub kind: SymbolKind,
}

impl From<&SymbolEntry> for SymbolView {
    fn from(s: &SymbolEntry) -> Self {
        SymbolView {
            name: untrusted(&s.name),
            address: s.address,
            library: s.library.as_deref().map(untrusted),
            kind: s.kind,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_proto::{Completeness, Token};

    fn token(start: u32, end: u32, symbol: Option<&str>) -> Token {
        Token {
            start,
            end,
            kind: TokenKind::Function,
            target: Some(Locator::ram(0x401000)),
            symbol: symbol.map(str::to_string),
            varnode: None,
        }
    }

    fn result(text: &str, tokens: Vec<Token>) -> DecompileResult {
        DecompileResult {
            function: Locator::ram(0x401000),
            language: "c".into(),
            text: text.into(),
            tokens,
            warnings: vec![],
            completeness: Completeness::Complete,
        }
    }

    fn slices(c: &CleanDecompile) -> Vec<&str> {
        c.tokens
            .iter()
            .map(|t| &c.text[t.start as usize..t.end as usize])
            .collect()
    }

    #[test]
    fn hostile_text_keeps_spans_on_their_tokens() {
        // an ANSI escape and a bidi override sit between and inside tokens
        let text = "\u{1b}[31mint\u{1b}[0m \u{202e}ma\u{7}in(\u{85}x); // é\u{202c}ok";
        let at = |needle: &str| text.find(needle).expect("present") as u32;
        let r = result(
            text,
            vec![
                token(at("int"), at("int") + 3, Some("int")),
                token(at("ma"), at("in(") + 2, Some("main")),
                token(at("x)"), at("x)") + 1, None),
                token(at("é"), at("é") + 2, None),
                token(at("ok"), at("ok") + 2, Some("ok")),
            ],
        );
        r.validate_tokens().expect("valid input spans");
        let c = clean_decompile_text(&r, 1 << 20);
        assert_eq!(c.text, "int main(x); // éok");
        assert_eq!(slices(&c), ["int", "main", "x", "é", "ok"]);
        assert!(
            c.tokens
                .iter()
                .all(|t| t.symbol.is_none() || t.start != t.end)
        );
        // "main" differs from nothing, but the symbol equals the cleaned slice: omitted
        assert_eq!(c.tokens[1].symbol, None);
        assert!(!c.text.chars().any(char::is_control));
    }

    #[test]
    fn tokens_inside_stripped_text_disappear() {
        let text = "a\u{1b}[31m\u{1b}[0mb";
        let r = result(text, vec![token(1, 9, None), token(0, 1, None)]);
        let c = clean_decompile_text(&r, 1 << 20);
        assert_eq!(c.text, "ab");
        assert_eq!(slices(&c), ["a"]);
    }

    #[test]
    fn truncation_keeps_spans_valid() {
        let text = "aé".repeat(100);
        let toks: Vec<Token> = (0..100)
            .map(|i| token(i * 3, i * 3 + 3, Some("x")))
            .collect();
        let r = result(&text, toks);
        for max in [0usize, 1, 2, 4, 5, 31, 32, 33, 299, 300, 301] {
            let c = clean_decompile_text(&r, max);
            assert!(c.text.len() <= max, "{max}");
            assert_eq!(c.truncated, max < text.len());
            for t in &c.tokens {
                assert!(
                    t.start < t.end && t.end as usize <= c.text.len(),
                    "{max}: {t:?}"
                );
                assert!(c.text.is_char_boundary(t.start as usize));
                assert!(c.text.is_char_boundary(t.end as usize));
            }
        }
        // a span across the cut is clamped to it
        let c = clean_decompile_text(&r, 4);
        assert_eq!(c.text, "aéa");
        assert_eq!(slices(&c), ["aé", "a"]);
    }

    #[test]
    fn invalid_engine_spans_are_dropped_with_a_reason() {
        let r = result("abc", vec![token(0, 99, None)]);
        let c = clean_decompile_text(&r, 100);
        assert!(c.tokens.is_empty() && c.token_warning.is_some());
        assert_eq!(c.text, "abc");
    }

    #[test]
    fn symbol_operands_split_text_from_the_untrusted_name() {
        let tok = OperandToken {
            text: "evil\u{1b}[31m".into(),
            kind: OperandKind::Symbol,
            target: Some(Locator::ram(0x401030)),
        };
        let v = OperandView::from(&tok);
        assert_eq!(v.text, "0x401030");
        assert_eq!(v.symbol, Some(Untrusted("evil".to_string())));
        let reg = OperandView::from(&OperandToken {
            text: "ea\u{202e}x".into(),
            kind: OperandKind::Register,
            target: None,
        });
        assert_eq!((reg.text.as_str(), reg.symbol), ("eax", None));
    }

    #[test]
    fn long_strings_are_cut_on_characters() {
        let s = StringEntry {
            address: Hex64(0x402000),
            value: "é".repeat(MAX_STRING_CHARS + 5),
            encoding: StringEncoding::Utf8,
            length: 9999,
        };
        let v = StringView::from(&s);
        assert!(v.truncated);
        assert_eq!(v.value.0.chars().count(), MAX_STRING_CHARS);
    }
}
