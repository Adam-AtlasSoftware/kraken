//! Decompiler token spans from the server.

use kraken_proto::{Locator, Token, TokenKind};

use super::wire::TokenWire;

/// Turns the registry's token spans into the tokens the decompiler widget draws.
///
/// The registry leaves `symbol` out when it equals the token text, so this fills it in for
/// anything that can be followed or highlighted: tokens with a target, function names and
/// variables. Spans that do not fit the text, or overlap the previous one, are dropped.
pub(crate) fn server_tokens(text: &str, wire: &[TokenWire]) -> Vec<Token> {
    let mut sorted: Vec<&TokenWire> = wire.iter().collect();
    sorted.sort_by_key(|t| (t.start, t.end));
    let mut out: Vec<Token> = Vec::with_capacity(sorted.len());
    let mut last_end = 0u32;
    for t in sorted {
        let Some(slice) = text.get(t.start as usize..t.end as usize) else {
            continue;
        };
        if t.start >= t.end || t.start < last_end {
            continue;
        }
        last_end = t.end;
        let target = t.target.map(|a| Locator::ram(a.0));
        let followable =
            target.is_some() || matches!(t.kind, TokenKind::Function | TokenKind::Variable);
        let symbol = t
            .symbol
            .as_ref()
            .map(|s| s.0.clone())
            .or_else(|| followable.then(|| slice.to_string()));
        out.push(Token {
            start: t.start,
            end: t.end,
            kind: t.kind,
            target,
            symbol,
            varnode: None,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_proto::{Hex64, Untrusted};

    fn w(
        start: u32,
        end: u32,
        kind: TokenKind,
        target: Option<u64>,
        sym: Option<&str>,
    ) -> TokenWire {
        TokenWire {
            start,
            end,
            kind,
            target: target.map(Hex64),
            symbol: sym.map(|s| Untrusted(s.to_string())),
        }
    }

    #[test]
    fn fills_symbols_and_drops_bad_spans() {
        let text = "int é(x) { return gv; }";
        let at = |n: &str| text.find(n).unwrap() as u32;
        let wire = vec![
            w(
                at("gv"),
                at("gv") + 2,
                TokenKind::Variable,
                Some(0x404000),
                None,
            ),
            w(at("int"), at("int") + 3, TokenKind::Type, None, None),
            w(
                at("é"),
                at("é") + 2,
                TokenKind::Function,
                Some(0x401000),
                Some("entry"),
            ),
            w(at("x"), at("x") + 1, TokenKind::Variable, None, None),
            // inside the "é" bytes: not a char boundary
            w(at("é") + 1, at("é") + 2, TokenKind::Op, None, None),
            // beyond the text
            w(500, 510, TokenKind::Op, None, None),
            // overlaps the previous accepted token
            w(at("gv") + 1, at("gv") + 2, TokenKind::Op, None, None),
        ];
        let t = server_tokens(text, &wire);
        let spans: Vec<&str> = t
            .iter()
            .map(|t| &text[t.start as usize..t.end as usize])
            .collect();
        assert_eq!(spans, ["int", "é", "x", "gv"]);
        assert_eq!(t[0].symbol, None);
        assert_eq!(t[1].symbol.as_deref(), Some("entry"));
        assert_eq!(t[2].symbol.as_deref(), Some("x"));
        assert_eq!(t[3].symbol.as_deref(), Some("gv"));
        assert_eq!(t[3].target, Some(Locator::ram(0x404000)));
    }
}
