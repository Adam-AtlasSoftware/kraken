//! Rendering of a spec: the model writes Markdown with `[@0xADDR]` citations. The panel needs
//! headings, paragraphs, bullets, code blocks, bold, inline code and clickable citations, and
//! nothing else, so this is a small parser for exactly that (links, images and HTML stay text).

/// A piece of a line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Inline {
    /// Plain text.
    Text(String),
    /// `**bold**`.
    Bold(String),
    /// `` `code` ``.
    Code(String),
    /// `[@0x401240]`, a clickable address.
    Cite(u64),
}

/// A block of a spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpecBlock {
    /// `#`, `##`, ...
    Heading {
        /// 1 to 6.
        level: u8,
        /// Heading text.
        text: Vec<Inline>,
    },
    /// A paragraph (consecutive lines joined by spaces).
    Paragraph(Vec<Inline>),
    /// One `-` or `*` bullet.
    Bullet(Vec<Inline>),
    /// A fenced code block.
    Code(String),
}

/// Parses `markdown` into blocks.
pub fn parse_spec(markdown: &str) -> Vec<SpecBlock> {
    let mut out = Vec::new();
    let mut para: Vec<&str> = Vec::new();
    let mut code: Option<String> = None;
    let flush = |para: &mut Vec<&str>, out: &mut Vec<SpecBlock>| {
        if !para.is_empty() {
            out.push(SpecBlock::Paragraph(inline(&para.join(" "))));
            para.clear();
        }
    };
    for line in markdown.lines() {
        if let Some(buf) = code.as_mut() {
            if line.trim_start().starts_with("```") {
                out.push(SpecBlock::Code(std::mem::take(buf)));
                code = None;
            } else {
                if !buf.is_empty() {
                    buf.push('\n');
                }
                buf.push_str(line);
            }
            continue;
        }
        let t = line.trim();
        if t.starts_with("```") {
            flush(&mut para, &mut out);
            code = Some(String::new());
        } else if t.is_empty() {
            flush(&mut para, &mut out);
        } else if let Some((level, rest)) = heading(t) {
            flush(&mut para, &mut out);
            out.push(SpecBlock::Heading {
                level,
                text: inline(rest),
            });
        } else if let Some(rest) = t.strip_prefix("- ").or_else(|| t.strip_prefix("* ")) {
            flush(&mut para, &mut out);
            out.push(SpecBlock::Bullet(inline(rest)));
        } else {
            para.push(t);
        }
    }
    if let Some(buf) = code {
        out.push(SpecBlock::Code(buf));
    }
    flush(&mut para, &mut out);
    out
}

fn heading(t: &str) -> Option<(u8, &str)> {
    let n = t.bytes().take_while(|&b| b == b'#').count();
    if (1..=6).contains(&n) && t.as_bytes().get(n) == Some(&b' ') {
        Some((n as u8, t[n..].trim()))
    } else {
        None
    }
}

fn inline(s: &str) -> Vec<Inline> {
    let mut out = Vec::new();
    let mut text = String::new();
    let mut rest = s;
    let push_text = |text: &mut String, out: &mut Vec<Inline>| {
        if !text.is_empty() {
            out.push(Inline::Text(std::mem::take(text)));
        }
    };
    while let Some(c) = rest.chars().next() {
        if let Some((addr, len)) = cite(rest) {
            push_text(&mut text, &mut out);
            out.push(Inline::Cite(addr));
            rest = &rest[len..];
        } else if let Some(body) = rest.strip_prefix("**")
            && let Some(end) = body.find("**")
            && end > 0
        {
            push_text(&mut text, &mut out);
            out.push(Inline::Bold(body[..end].to_string()));
            rest = &body[end + 2..];
        } else if let Some(body) = rest.strip_prefix('`')
            && let Some(end) = body.find('`')
        {
            push_text(&mut text, &mut out);
            out.push(Inline::Code(body[..end].to_string()));
            rest = &body[end + 1..];
        } else {
            text.push(c);
            rest = &rest[c.len_utf8()..];
        }
    }
    push_text(&mut text, &mut out);
    out
}

/// `[@0x401240]` at the start of `s`: the address and the length of the citation.
fn cite(s: &str) -> Option<(u64, usize)> {
    let body = s.strip_prefix("[@0x")?;
    let digits = body.bytes().take_while(u8::is_ascii_hexdigit).count();
    if digits == 0 || digits > 16 || body.as_bytes().get(digits) != Some(&b']') {
        return None;
    }
    let addr = u64::from_str_radix(&body[..digits], 16).ok()?;
    Some((addr, 4 + digits + 1))
}

/// Every address cited in `blocks`, in order of first mention.
pub fn citations(blocks: &[SpecBlock]) -> Vec<u64> {
    let mut seen = Vec::new();
    for b in blocks {
        let parts = match b {
            SpecBlock::Heading { text, .. } => text,
            SpecBlock::Paragraph(t) | SpecBlock::Bullet(t) => t,
            SpecBlock::Code(_) => continue,
        };
        for p in parts {
            if let Inline::Cite(a) = p
                && !seen.contains(a)
            {
                seen.push(*a);
            }
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &str = "# Spec of checksum\n\n## Purpose\nHashes a buffer\nwith a rolling sum [@0x401240].\n\n## Inputs\n- `buf` bytes, read by [@0x401240] and [@0x4011a0]\n- **len** is the byte count\n\n```\nsum = sum * 33 + b\n```\n";

    #[test]
    fn parses_headings_paragraphs_bullets_and_code() {
        let b = parse_spec(SPEC);
        assert!(matches!(&b[0], SpecBlock::Heading { level: 1, .. }));
        assert!(matches!(&b[1], SpecBlock::Heading { level: 2, .. }));
        let SpecBlock::Paragraph(p) = &b[2] else {
            panic!("{b:?}")
        };
        assert_eq!(
            p,
            &[
                Inline::Text("Hashes a buffer with a rolling sum ".into()),
                Inline::Cite(0x401240),
                Inline::Text(".".into())
            ]
        );
        let SpecBlock::Bullet(first) = &b[4] else {
            panic!("{b:?}")
        };
        assert_eq!(first[0], Inline::Code("buf".into()));
        assert_eq!(first[2], Inline::Cite(0x401240));
        assert_eq!(first[4], Inline::Cite(0x4011a0));
        let SpecBlock::Bullet(second) = &b[5] else {
            panic!("{b:?}")
        };
        assert_eq!(second[0], Inline::Bold("len".into()));
        assert_eq!(b[6], SpecBlock::Code("sum = sum * 33 + b".into()));
    }

    #[test]
    fn lists_each_cited_address_once() {
        assert_eq!(citations(&parse_spec(SPEC)), vec![0x401240, 0x4011a0]);
    }

    #[test]
    fn malformed_citations_stay_text() {
        let b = parse_spec("see [@0x] and [@0xZZ] and [@0x12 and **open");
        let SpecBlock::Paragraph(p) = &b[0] else {
            panic!("{b:?}")
        };
        assert_eq!(p.len(), 1);
        assert!(citations(&b).is_empty());
    }
}
