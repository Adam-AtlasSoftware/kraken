//! Input validation and output sanitising shared by the commands (decision 61).

use kraken_model::AuthorKind;
use kraken_proto::{ErrorCode, ProtoError, Untrusted, sanitize};

/// Longest accepted symbol, type or convention name in characters.
pub const MAX_NAME_LEN: usize = 200;
/// Longest accepted comment in characters.
pub const MAX_COMMENT_LEN: usize = 4096;
/// Decompiler text above this many bytes is truncated in outputs.
pub const MAX_DECOMPILE_BYTES: usize = 64 * 1024;

fn invalid(msg: String) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

/// True for names matching `[A-Za-z_][A-Za-z0-9_:.$@<>~]*`.
pub fn is_conservative_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| {
        c.is_ascii_alphanumeric() || matches!(c, '_' | ':' | '.' | '$' | '@' | '<' | '>' | '~')
    })
}

/// Validates a name that will be written into the project (`what` names it in errors).
///
/// Every author: non-empty, at most [`MAX_NAME_LEN`] characters, unchanged by
/// [`sanitize`], no whitespace. Agents additionally must match the conservative identifier rule.
pub fn validate_name(what: &str, name: &str, author: AuthorKind) -> Result<String, ProtoError> {
    if name.is_empty() {
        return Err(invalid(format!("{what} must not be empty")));
    }
    if name.chars().count() > MAX_NAME_LEN {
        return Err(invalid(format!(
            "{what} is longer than {MAX_NAME_LEN} characters"
        )));
    }
    if sanitize(name) != name {
        return Err(invalid(format!(
            "{what} contains control, escape or bidirectional characters"
        )));
    }
    if name.chars().any(char::is_whitespace) {
        return Err(invalid(format!("{what} must not contain whitespace")));
    }
    if author == AuthorKind::Agent && !is_conservative_identifier(name) {
        return Err(invalid(format!(
            "{what} must match [A-Za-z_][A-Za-z0-9_:.$@<>~]*"
        )));
    }
    Ok(name.to_string())
}

/// Sanitises comment text and enforces [`MAX_COMMENT_LEN`].
pub fn clean_comment(text: &str) -> Result<String, ProtoError> {
    let clean = sanitize(text);
    if clean.chars().count() > MAX_COMMENT_LEN {
        return Err(invalid(format!(
            "comment is longer than {MAX_COMMENT_LEN} characters"
        )));
    }
    Ok(clean)
}

/// Sanitises engine-derived text and marks it untrusted.
pub fn untrusted(s: &str) -> Untrusted<String> {
    Untrusted::sanitized(s)
}

/// Cuts `s` to at most `max_bytes` bytes on a character boundary; the flag says whether it was cut.
pub fn truncate_utf8(mut s: String, max_bytes: usize) -> (String, bool) {
    if s.len() <= max_bytes {
        return (s, false);
    }
    let mut cut = max_bytes;
    while !s.is_char_boundary(cut) {
        cut -= 1;
    }
    s.truncate(cut);
    (s, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_rule() {
        for ok in ["main", "_x", "std::vec<int>", "a.b$c@d~", "A1"] {
            assert!(is_conservative_identifier(ok), "{ok}");
        }
        for bad in ["", "1a", "a b", "a-b", "a\u{202e}", "ünï", "a+b", "x()"] {
            assert!(!is_conservative_identifier(bad), "{bad}");
        }
    }

    #[test]
    fn names_by_author() {
        assert!(validate_name("name", "operator==", AuthorKind::User).is_ok());
        assert!(validate_name("name", "operator==", AuthorKind::Agent).is_err());
        assert!(validate_name("name", "a\u{1b}[31m", AuthorKind::User).is_err());
        assert!(validate_name("name", &"a".repeat(201), AuthorKind::User).is_err());
        assert!(validate_name("name", &"a".repeat(200), AuthorKind::Agent).is_ok());
        assert!(validate_name("name", "a b", AuthorKind::User).is_err());
    }

    #[test]
    fn truncation_respects_char_boundaries() {
        let (s, cut) = truncate_utf8("aé".repeat(10), 4);
        assert!(cut);
        assert_eq!(s, "aéa");
        assert_eq!(truncate_utf8("ab".into(), 4), ("ab".into(), false));
    }
}
