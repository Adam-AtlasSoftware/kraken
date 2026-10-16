//! Decompiler output: text plus a token map.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::{ErrorCode, ProtoError};
use crate::locator::Locator;
use crate::meta::Completeness;

/// Language tag for C output.
pub const LANGUAGE_C: &str = "c";

/// Language tag for C# output (managed-code engines).
pub const LANGUAGE_CSHARP: &str = "csharp";

fn default_language() -> String {
    LANGUAGE_C.to_string()
}

/// Syntactic category of a decompiler token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum TokenKind {
    /// Language keyword.
    Keyword,
    /// Local variable or parameter.
    Variable,
    /// Function name.
    Function,
    /// Type name.
    Type,
    /// Struct or union field.
    Field,
    /// Literal or named constant.
    Constant,
    /// Comment.
    Comment,
    /// Operator or punctuation.
    Op,
    /// Anything else.
    Other,
}

/// A span of the decompiled text with optional links to program entities.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct Token {
    /// Start byte offset into the text (inclusive).
    pub start: u32,
    /// End byte offset into the text (exclusive).
    pub end: u32,
    /// Syntactic category.
    pub kind: TokenKind,
    /// Program location the token refers to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<Locator>,
    /// Symbol name the token refers to, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbol: Option<String>,
    /// Engine-neutral varnode description such as `"unique:0x1f80:4"`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub varnode: Option<String>,
}

/// The decompilation of one function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DecompileResult {
    /// The decompiled function's entry.
    pub function: Locator,
    /// Output language tag; `"c"` by default.
    #[serde(default = "default_language")]
    pub language: String,
    /// Decompiled source text; binary-derived, so sanitise it at ingestion.
    pub text: String,
    /// Token spans into `text`, in increasing start order.
    pub tokens: Vec<Token>,
    /// Non-fatal problems the decompiler reported.
    pub warnings: Vec<String>,
    /// Analysis completeness behind this result.
    pub completeness: Completeness,
}

impl DecompileResult {
    /// Checks that every token span lies inside `text` on character boundaries with `start <= end`.
    pub fn validate_tokens(&self) -> Result<(), ProtoError> {
        for (i, t) in self.tokens.iter().enumerate() {
            let (s, e) = (t.start as usize, t.end as usize);
            let ok = s <= e
                && e <= self.text.len()
                && self.text.is_char_boundary(s)
                && self.text.is_char_boundary(e);
            if !ok {
                return Err(ProtoError::new(
                    ErrorCode::InvalidArgument,
                    format!("token {i} span {s}..{e} is not a valid span of the text"),
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DecompileResult {
        DecompileResult {
            function: Locator::ram(0x401000),
            language: LANGUAGE_C.into(),
            text: "int main(void) { return 0; }".into(),
            tokens: vec![
                Token {
                    start: 0,
                    end: 3,
                    kind: TokenKind::Type,
                    target: None,
                    symbol: Some("int".into()),
                    varnode: None,
                },
                Token {
                    start: 4,
                    end: 8,
                    kind: TokenKind::Function,
                    target: Some(Locator::ram(0x401000)),
                    symbol: Some("main".into()),
                    varnode: Some("ram:0x401000:1".into()),
                },
            ],
            warnings: vec!["w".into()],
            completeness: Completeness::Complete,
        }
    }

    #[test]
    fn round_trip() {
        let r = sample();
        let back: DecompileResult =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
        for k in [
            TokenKind::Keyword,
            TokenKind::Variable,
            TokenKind::Field,
            TokenKind::Constant,
            TokenKind::Comment,
            TokenKind::Op,
            TokenKind::Other,
        ] {
            let back: TokenKind =
                serde_json::from_str(&serde_json::to_string(&k).unwrap()).unwrap();
            assert_eq!(back, k);
        }
    }

    #[test]
    fn language_defaults_to_c() {
        let mut v = serde_json::to_value(sample()).unwrap();
        v.as_object_mut().unwrap().remove("language");
        let r: DecompileResult = serde_json::from_value(v).unwrap();
        assert_eq!(r.language, "c");
    }

    #[test]
    fn validates_spans() {
        let mut r = sample();
        assert!(r.validate_tokens().is_ok());
        r.tokens[0].end = 999;
        assert!(r.validate_tokens().is_err());
        r.tokens[0].end = 3;
        r.tokens[0].start = 4;
        assert!(r.validate_tokens().is_err());
        r.text = "é".into();
        r.tokens = vec![Token {
            start: 0,
            end: 1,
            kind: TokenKind::Other,
            target: None,
            symbol: None,
            varnode: None,
        }];
        assert!(r.validate_tokens().is_err());
    }
}
