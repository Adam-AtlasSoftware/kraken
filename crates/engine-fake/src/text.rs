//! Identifier-aware renaming inside decompiler output.

use kraken_proto::DecompileResult;

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Byte ranges of whole-word occurrences of `word` in `text`.
pub(crate) fn word_matches(text: &str, word: &str) -> Vec<(usize, usize)> {
    if word.is_empty() {
        return Vec::new();
    }
    text.match_indices(word)
        .filter(|(i, _)| {
            let before = text[..*i].chars().next_back();
            let after = text[i + word.len()..].chars().next();
            !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
        })
        .map(|(i, _)| (i, i + word.len()))
        .collect()
}

/// Replaces whole-word occurrences of `old` in `text`.
pub(crate) fn replace_word(text: &str, old: &str, new: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut at = 0;
    for (s, e) in word_matches(text, old) {
        out.push_str(&text[at..s]);
        out.push_str(new);
        at = e;
    }
    out.push_str(&text[at..]);
    out
}

/// Renames `old` to `new` in the text and token symbols of `r`, keeping token spans valid.
pub(crate) fn rename_in_result(r: &mut DecompileResult, old: &str, new: &str) {
    if old.is_empty() || old == new {
        return;
    }
    let occ = word_matches(&r.text, old);
    let delta = new.len() as i64 - old.len() as i64;
    let map = |p: u32| -> u32 {
        let n = occ.iter().filter(|(_, e)| *e <= p as usize).count() as i64;
        (i64::from(p) + delta * n).max(0) as u32
    };
    for t in &mut r.tokens {
        t.start = map(t.start);
        t.end = map(t.end);
        if t.symbol.as_deref() == Some(old) {
            t.symbol = Some(new.to_string());
        }
    }
    r.text = replace_word(&r.text, old, new);
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_proto::{Completeness, Locator, Token, TokenKind};

    #[test]
    fn whole_words_only() {
        assert_eq!(
            replace_word("foo foo_bar xfoo foo(", "foo", "q"),
            "q foo_bar xfoo q("
        );
    }

    #[test]
    fn rename_keeps_spans() {
        let text = "void f(void) { f(); }";
        let tok = |s: usize, e: usize, sym: Option<&str>| Token {
            start: s as u32,
            end: e as u32,
            kind: TokenKind::Function,
            target: Some(Locator::ram(0)),
            symbol: sym.map(str::to_string),
            varnode: None,
        };
        let mut r = DecompileResult {
            function: Locator::ram(0),
            language: "c".into(),
            text: text.into(),
            tokens: vec![
                tok(5, 6, Some("f")),
                tok(15, 16, Some("f")),
                tok(18, 19, None),
            ],
            warnings: vec![],
            completeness: Completeness::Complete,
        };
        rename_in_result(&mut r, "f", "long_name");
        assert_eq!(r.text, "void long_name(void) { long_name(); }");
        r.validate_tokens().unwrap();
        let spans: Vec<_> = r
            .tokens
            .iter()
            .map(|t| &r.text[t.start as usize..t.end as usize])
            .collect();
        assert_eq!(spans, ["long_name", "long_name", ";"]);
    }
}
