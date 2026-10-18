//! Renames and comments for managed code. ILSpy has no database to write to, so the engine keeps
//! the annotations from KRAKEN's edit log in memory and applies them to what the sidecar returns:
//! identifiers that resolve to a renamed token are substituted in the C# text and its token spans,
//! and comments are added as `//` lines.

use std::collections::BTreeMap;

use kraken_proto::{
    CommentKind, DecompileResult, ErrorCode, FunctionSummary, Locator, ProtoError, Token, TokenKind,
};

/// Longest accepted identifier, in characters.
pub const MAX_IDENTIFIER_CHARS: usize = 200;

/// Metadata tables whose rows can be renamed: TypeDef, Field, MethodDef, Param, Event, Property.
const RENAMABLE_TABLES: [u8; 6] = [0x02, 0x04, 0x06, 0x08, 0x14, 0x17];

const KEYWORDS: &[&str] = &[
    "abstract",
    "as",
    "base",
    "bool",
    "break",
    "byte",
    "case",
    "catch",
    "char",
    "checked",
    "class",
    "const",
    "continue",
    "decimal",
    "default",
    "delegate",
    "do",
    "double",
    "else",
    "enum",
    "event",
    "explicit",
    "extern",
    "false",
    "finally",
    "fixed",
    "float",
    "for",
    "foreach",
    "goto",
    "if",
    "implicit",
    "in",
    "int",
    "interface",
    "internal",
    "is",
    "lock",
    "long",
    "namespace",
    "new",
    "null",
    "object",
    "operator",
    "out",
    "override",
    "params",
    "private",
    "protected",
    "public",
    "readonly",
    "ref",
    "return",
    "sbyte",
    "sealed",
    "short",
    "sizeof",
    "stackalloc",
    "static",
    "string",
    "struct",
    "switch",
    "this",
    "throw",
    "true",
    "try",
    "typeof",
    "uint",
    "ulong",
    "unchecked",
    "unsafe",
    "ushort",
    "using",
    "virtual",
    "void",
    "volatile",
    "while",
];

/// The metadata table of a token (its high byte).
pub fn table_of(token: u32) -> u8 {
    (token >> 24) as u8
}

/// Whether a token names something that can be renamed.
pub fn is_renamable(token: u32) -> bool {
    RENAMABLE_TABLES.contains(&table_of(token)) && token & 0x00ff_ffff != 0
}

/// Checks that `name` is usable as a C# identifier in the output.
pub fn validate_identifier(name: &str) -> Result<(), ProtoError> {
    let bad = |why: &str| ProtoError::new(ErrorCode::InvalidArgument, format!("`{name}`: {why}"));
    let mut chars = name.chars();
    let first = chars.next().ok_or_else(|| bad("the name is empty"))?;
    if !(first.is_alphabetic() || first == '_') {
        return Err(bad("a C# name starts with a letter or `_`"));
    }
    if !chars.all(|c| c.is_alphanumeric() || c == '_') {
        return Err(bad("a C# name has letters, digits and `_` only"));
    }
    if name.chars().count() > MAX_IDENTIFIER_CHARS {
        return Err(bad("the name is too long"));
    }
    if KEYWORDS.contains(&name) {
        return Err(bad("the name is a C# keyword"));
    }
    Ok(())
}

/// The method part of a listed name such as `Ns.Type.Method`.
pub fn ident_of(listed: &str) -> &str {
    listed.rsplit_once('.').map_or(listed, |(_, m)| m)
}

/// `listed` with its method part replaced by `ident`.
pub fn display_name(listed: &str, ident: &str) -> String {
    match listed.rsplit_once('.') {
        Some((prefix, _)) => format!("{prefix}.{ident}"),
        None => ident.to_string(),
    }
}

/// Constructors keep the name of their type.
pub fn is_constructor(listed: &str) -> bool {
    listed.ends_with("..ctor") || listed.ends_with("..cctor")
}

fn rank(kind: CommentKind) -> u8 {
    match kind {
        CommentKind::Plate => 0,
        CommentKind::Pre => 1,
        CommentKind::Repeatable => 2,
        CommentKind::Eol => 3,
        CommentKind::Post => 4,
    }
}

fn is_ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Replaces whole-identifier occurrences of `old` in `text`.
pub fn replace_ident(text: &str, old: &str, new: &str) -> String {
    if old.is_empty() {
        return text.to_string();
    }
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    let mut before: Option<char> = None;
    while let Some(i) = rest.find(old) {
        let prev = rest[..i].chars().next_back().or(before);
        let after = rest[i + old.len()..].chars().next();
        out.push_str(&rest[..i]);
        if prev.is_none_or(|c| !is_ident_char(c)) && after.is_none_or(|c| !is_ident_char(c)) {
            out.push_str(new);
        } else {
            out.push_str(old);
        }
        before = old.chars().next_back();
        rest = &rest[i + old.len()..];
    }
    out.push_str(rest);
    out
}

/// One comment line group as `//` lines. Line breaks of any kind split lines; other control
/// characters are dropped, so the text cannot end the comment.
fn comment_lines(text: &str) -> Vec<String> {
    let flat: String = text
        .chars()
        .map(|c| match c {
            '\u{85}' | '\u{2028}' | '\u{2029}' | '\r' => '\n',
            c => c,
        })
        .filter(|c| *c == '\n' || !c.is_control())
        .collect();
    flat.split('\n')
        .map(|l| {
            if l.trim().is_empty() {
                "//".to_string()
            } else {
                format!("// {}", l.trim_end())
            }
        })
        .collect()
}

/// The renames and comments of one open assembly, by metadata token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Annotations {
    names: BTreeMap<u32, String>,
    comments: BTreeMap<(u32, u8), (CommentKind, String)>,
}

impl Annotations {
    /// No annotations.
    pub fn new() -> Self {
        Self::default()
    }

    /// True when nothing is renamed or commented.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty() && self.comments.is_empty()
    }

    /// The name set for `token`, if renamed.
    pub fn name(&self, token: u32) -> Option<&str> {
        self.names.get(&token).map(String::as_str)
    }

    /// The comment text of `token` in slot `kind`.
    pub fn comment(&self, token: u32, kind: CommentKind) -> Option<&str> {
        self.comments
            .get(&(token, rank(kind)))
            .map(|(_, t)| t.as_str())
    }

    /// Sets the name of `token`; `None` clears it.
    pub fn set_name(&mut self, token: u32, name: Option<String>) {
        match name {
            Some(n) => {
                self.names.insert(token, n);
            }
            None => {
                self.names.remove(&token);
            }
        }
    }

    /// Sets the comment of `token` in slot `kind`; `None` or an empty text clears it.
    pub fn set_comment(&mut self, token: u32, kind: CommentKind, text: Option<String>) {
        match text.filter(|t| !t.trim().is_empty()) {
            Some(t) => {
                self.comments.insert((token, rank(kind)), (kind, t));
            }
            None => {
                self.comments.remove(&(token, rank(kind)));
            }
        }
    }

    /// `summary` with the method renamed, if it is. The listed name is `Namespace.Type.Method`;
    /// the rename replaces the method part.
    pub fn apply_summary(&self, mut f: FunctionSummary, mvid: &str) -> FunctionSummary {
        let Locator::Managed { module, token } = &f.locator else {
            return f;
        };
        if module != mvid {
            return f;
        }
        if let Some(new) = self.names.get(token) {
            let old = ident_of(&f.name).to_string();
            if let Some(sig) = &f.signature {
                f.signature = Some(replace_ident(sig, &old, new));
            }
            f.name = display_name(&f.name, new);
        }
        f
    }

    /// `r` with renamed identifiers substituted and comments added.
    pub fn apply_decompile(&self, mut r: DecompileResult, mvid: &str) -> DecompileResult {
        if self.is_empty() {
            return r;
        }
        self.rename_tokens(&mut r, mvid);
        if let Locator::Managed { module, token } = r.function.clone()
            && module == mvid
        {
            self.add_comments(&mut r, token);
        }
        r
    }

    fn rename_tokens(&self, r: &mut DecompileResult, mvid: &str) {
        if self.names.is_empty() {
            return;
        }
        let mut order: Vec<usize> = (0..r.tokens.len()).collect();
        order.sort_by_key(|&i| (r.tokens[i].start, r.tokens[i].end));
        let mut text = String::with_capacity(r.text.len());
        let mut copied = 0usize;
        let mut delta: i64 = 0;
        let mut moved: Vec<Token> = Vec::with_capacity(r.tokens.len());
        for i in order {
            let t = &r.tokens[i];
            let (start, end) = (t.start as usize, t.end as usize);
            let new = match &t.target {
                Some(Locator::Managed { module, token }) if module == mvid => self.names.get(token),
                _ => None,
            };
            let mut t = t.clone();
            // A token that overlaps the previous edit, or whose text is not the identifier, stays.
            let replace = new.filter(|_| {
                start >= copied
                    && t.symbol
                        .as_deref()
                        .is_some_and(|s| r.text.get(start..end) == Some(s))
            });
            t.start = shift(t.start, delta);
            if let Some(new) = replace {
                text.push_str(&r.text[copied..start]);
                text.push_str(new);
                copied = end;
                delta += new.len() as i64 - (end - start) as i64;
                t.symbol = Some(new.clone());
            }
            t.end = shift(t.end, delta);
            moved.push(t);
        }
        text.push_str(&r.text[copied..]);
        r.text = text;
        r.tokens = moved;
    }

    fn add_comments(&self, r: &mut DecompileResult, token: u32) {
        let slot = |k: CommentKind| self.comment(token, k).map(comment_lines);
        let mut header: Vec<String> = Vec::new();
        for k in [
            CommentKind::Plate,
            CommentKind::Pre,
            CommentKind::Repeatable,
        ] {
            header.extend(slot(k).unwrap_or_default());
        }
        let eol = slot(CommentKind::Eol).map(|lines| {
            let words: Vec<&str> = lines
                .iter()
                .map(|l| l.trim_start_matches('/').trim())
                .filter(|l| !l.is_empty())
                .collect();
            format!(" // {}", words.join(" "))
        });
        let post = slot(CommentKind::Post).unwrap_or_default();
        if header.is_empty() && eol.is_none() && post.is_empty() {
            return;
        }

        let mut spans: Vec<(usize, usize)> = Vec::new();
        let mut tokens = std::mem::take(&mut r.tokens);
        let mut body = std::mem::take(&mut r.text);

        // The end-of-line comment goes at the end of the first line; later tokens move right.
        let mut eol_span = None;
        if let Some(e) = &eol {
            let at = body.find('\n').unwrap_or(body.len());
            body.insert_str(at, e);
            for t in &mut tokens {
                if t.start as usize >= at {
                    t.start += e.len() as u32;
                }
                if t.end as usize > at {
                    t.end += e.len() as u32;
                }
            }
            eol_span = Some((at + 1, at + e.len()));
        }

        let mut text = String::new();
        for l in &header {
            spans.push((text.len(), text.len() + l.len()));
            text.push_str(l);
            text.push('\n');
        }
        let head_len = text.len();
        for t in &mut tokens {
            t.start += head_len as u32;
            t.end += head_len as u32;
        }
        if let Some((s, e)) = eol_span {
            spans.push((s + head_len, e + head_len));
        }
        text.push_str(&body);
        if !post.is_empty() {
            if !text.ends_with('\n') {
                text.push('\n');
            }
            for l in &post {
                spans.push((text.len(), text.len() + l.len()));
                text.push_str(l);
                text.push('\n');
            }
        }
        tokens.extend(spans.into_iter().map(|(s, e)| Token {
            start: s as u32,
            end: e as u32,
            kind: TokenKind::Comment,
            target: None,
            symbol: None,
            varnode: None,
        }));
        tokens.sort_by_key(|t| (t.start, t.end));
        r.text = text;
        r.tokens = tokens;
    }
}

fn shift(v: u32, delta: i64) -> u32 {
    u32::try_from(i64::from(v) + delta).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_proto::Completeness;

    const MVID: &str = "61a35c05-1940-4673-81a7-f2157a66b75c";
    const MAIN: u32 = 0x0600_0001;
    const GREET: u32 = 0x0600_0002;

    fn tok(start: u32, end: u32, kind: TokenKind, target: Option<u32>, sym: &str) -> Token {
        Token {
            start,
            end,
            kind,
            target: target.map(|t| Locator::managed(MVID, t)),
            symbol: Some(sym.into()),
            varnode: None,
        }
    }

    fn sample() -> DecompileResult {
        let text = "static void Main()\n{\n    Greet();\n}\n";
        let at = text.find("Greet").unwrap() as u32;
        DecompileResult {
            function: Locator::managed(MVID, MAIN),
            language: "csharp".into(),
            text: text.into(),
            tokens: vec![
                tok(12, 16, TokenKind::Function, Some(MAIN), "Main"),
                tok(at, at + 5, TokenKind::Function, Some(GREET), "Greet"),
                tok(at + 5, at + 6, TokenKind::Op, None, "("),
            ],
            warnings: vec![],
            completeness: Completeness::Complete,
        }
    }

    fn spans_ok(r: &DecompileResult) {
        r.validate_tokens().unwrap();
        let mut last = 0;
        for t in &r.tokens {
            assert!(
                t.start >= last,
                "tokens overlap or are unordered: {:?}",
                r.tokens
            );
            last = t.end;
        }
    }

    #[test]
    fn rename_substitutes_text_and_shifts_tokens() {
        let mut a = Annotations::new();
        a.set_name(GREET, Some("SayHello".into()));
        a.set_name(MAIN, Some("Run".into()));
        let r = a.apply_decompile(sample(), MVID);
        assert_eq!(r.text, "static void Run()\n{\n    SayHello();\n}\n");
        spans_ok(&r);
        for t in &r.tokens {
            if let Some(s) = &t.symbol {
                assert_eq!(&r.text[t.start as usize..t.end as usize], s);
            }
        }
        assert_eq!(r.tokens[1].symbol.as_deref(), Some("SayHello"));
    }

    #[test]
    fn other_module_and_mismatched_text_are_left_alone() {
        let mut a = Annotations::new();
        a.set_name(GREET, Some("SayHello".into()));
        let mut r = sample();
        r.tokens[1].target = Some(Locator::managed(
            "00000000-0000-0000-0000-000000000000",
            GREET,
        ));
        assert_eq!(a.apply_decompile(r.clone(), MVID).text, r.text);
        let mut r = sample();
        r.tokens[1].symbol = Some("Other".into());
        assert_eq!(a.apply_decompile(r.clone(), MVID).text, r.text);
    }

    #[test]
    fn comments_are_added_around_the_method() {
        let mut a = Annotations::new();
        a.set_comment(MAIN, CommentKind::Plate, Some("entry\nsecond".into()));
        a.set_comment(MAIN, CommentKind::Eol, Some("hi".into()));
        a.set_comment(MAIN, CommentKind::Post, Some("done".into()));
        a.set_name(GREET, Some("SayHello".into()));
        let r = a.apply_decompile(sample(), MVID);
        assert_eq!(
            r.text,
            "// entry\n// second\nstatic void Main() // hi\n{\n    SayHello();\n}\n// done\n"
        );
        spans_ok(&r);
        let comments: Vec<&str> = r
            .tokens
            .iter()
            .filter(|t| t.kind == TokenKind::Comment)
            .map(|t| &r.text[t.start as usize..t.end as usize])
            .collect();
        assert_eq!(comments, ["// entry", "// second", "// hi", "// done"]);
        for t in r.tokens.iter().filter(|t| t.kind == TokenKind::Function) {
            assert_eq!(
                &r.text[t.start as usize..t.end as usize],
                t.symbol.as_deref().unwrap()
            );
        }
    }

    #[test]
    fn comment_text_cannot_break_out_of_its_line() {
        let l = comment_lines("a\r\nb\u{2028}c\u{0}d");
        assert_eq!(l, ["// a", "//", "// b", "// cd"]);
    }

    #[test]
    fn summary_gets_the_new_name() {
        let mut a = Annotations::new();
        a.set_name(MAIN, Some("Run".into()));
        let f = FunctionSummary {
            locator: Locator::managed(MVID, MAIN),
            name: "App.Program.Main".into(),
            size: None,
            signature: Some("void Main(string[] args)".into()),
            fn_hash: None,
            completeness: Completeness::Complete,
            mangled: None,
        };
        let f = a.apply_summary(f, MVID);
        assert_eq!(f.name, "App.Program.Run");
        assert_eq!(f.signature.as_deref(), Some("void Run(string[] args)"));
    }

    #[test]
    fn listed_names_split_into_type_and_method() {
        assert_eq!(ident_of("A.B.Fib"), "Fib");
        assert_eq!(display_name("A.B.Fib", "F"), "A.B.F");
        assert_eq!(display_name("Fib", "F"), "F");
        assert!(is_constructor("A.B..ctor"));
        assert!(!is_constructor("A.B.Fib"));
    }

    #[test]
    fn replace_ident_respects_boundaries() {
        assert_eq!(
            replace_ident("Main MainX XMain Main", "Main", "R"),
            "R MainX XMain R"
        );
        assert_eq!(replace_ident("Main", "Main", "R"), "R");
    }

    #[test]
    fn identifiers_are_validated() {
        for ok in ["Run", "_x", "Größe", "a1"] {
            validate_identifier(ok).unwrap();
        }
        for bad in ["", "1a", "a b", "a.b", "class", "a;b", "x\n"] {
            assert!(validate_identifier(bad).is_err(), "{bad}");
        }
        assert!(validate_identifier(&"a".repeat(201)).is_err());
    }

    #[test]
    fn tables() {
        assert!(is_renamable(0x0600_0001));
        assert!(is_renamable(0x0200_0002));
        assert!(!is_renamable(0x0600_0000));
        assert!(!is_renamable(0x0100_0001));
    }
}
