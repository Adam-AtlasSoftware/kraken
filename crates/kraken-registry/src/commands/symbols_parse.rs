//! Parsers for the symbol files `symbols_import` reads: GNU ld and MSVC link maps, CSV, splat
//! `symbol_addrs.txt` and a subset of IDA scripts (IDC). Pure text in, records out.

use kraken_proto::CommentKind;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Longest line the parsers look at; longer lines are skipped.
pub const MAX_LINE_BYTES: usize = 4096;
/// Most records one file may yield.
pub const MAX_RECORDS: usize = 200_000;

/// The file formats `symbols_import` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SymbolFormat {
    /// Look at the text and pick one of the others.
    Auto,
    /// GNU ld link map (`-Map`): lines of `0xADDRESS  name` in the output sections.
    GnuMap,
    /// MSVC link map ("Publics by Value"), using the `Rva+Base` column.
    MsvcMap,
    /// `address,name[,size,comment]`, one per line, optional header.
    Csv,
    /// splat `symbol_addrs.txt`: `name = 0xADDRESS; // size:0x10`.
    Splat,
    /// IDA script subset: `set_name`, `MakeName`, `set_cmt`, `MakeComm`, `set_func_cmt`.
    Idc,
}

/// One symbol, label or comment read from a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymRecord {
    /// Address as written in the file (before rebasing).
    pub address: u64,
    /// New name, if the record names the address.
    pub name: Option<String>,
    /// Size in bytes, when the file says (informational).
    pub size: Option<u64>,
    /// Comment and its slot, if the record carries one.
    pub comment: Option<(CommentKind, String)>,
    /// 1-based line in the file.
    pub line: usize,
}

/// What a parse produced.
#[derive(Debug, Default)]
pub struct Parsed {
    /// Records in file order.
    pub records: Vec<SymRecord>,
    /// Lines that looked like they should have meant something but did not parse.
    pub ignored: usize,
    /// Notes for the caller (line too long, record limit).
    pub warnings: Vec<String>,
}

impl SymbolFormat {
    /// Short name for messages and the CLI.
    pub fn label(self) -> &'static str {
        match self {
            SymbolFormat::Auto => "auto",
            SymbolFormat::GnuMap => "gnu_map",
            SymbolFormat::MsvcMap => "msvc_map",
            SymbolFormat::Csv => "csv",
            SymbolFormat::Splat => "splat",
            SymbolFormat::Idc => "idc",
        }
    }
}

/// Picks a format from the text; CSV is the fallback.
pub fn detect(text: &str) -> SymbolFormat {
    let head: Vec<&str> = text.lines().take(4000).collect();
    if head
        .iter()
        .any(|l| l.contains("Publics by Value") || l.contains("Rva+Base"))
    {
        return SymbolFormat::MsvcMap;
    }
    if head.iter().any(|l| {
        l.starts_with("Linker script and memory map")
            || l.starts_with("Memory Configuration")
            || l.starts_with("Archive member included")
    }) {
        return SymbolFormat::GnuMap;
    }
    let idc_call = |l: &&str| {
        let t = l.trim_start();
        [
            "set_name(",
            "MakeName(",
            "set_cmt(",
            "MakeComm(",
            "set_func_cmt(",
            "MakeRptCmt(",
            "MakeFunction(",
        ]
        .iter()
        .any(|p| t.starts_with(p))
    };
    if head.iter().any(idc_call) {
        return SymbolFormat::Idc;
    }
    let splat = |l: &&str| {
        let t = l.trim();
        (t.ends_with(';') || t.contains("; //")) && (t.contains(" = 0x") || t.contains("=0x"))
    };
    if head.iter().any(splat) {
        return SymbolFormat::Splat;
    }
    SymbolFormat::Csv
}

enum Line {
    Rec(SymRecord),
    Skip,
    Bad,
}

/// Parses `text` as `format` (`Auto` detects) and returns the format used.
pub fn parse(text: &str, format: SymbolFormat) -> (SymbolFormat, Parsed) {
    let format = if format == SymbolFormat::Auto {
        detect(text)
    } else {
        format
    };
    let mut p = Parsed::default();
    let mut in_map = format != SymbolFormat::GnuMap;
    for (i, raw) in text.lines().enumerate() {
        let line_no = i + 1;
        if p.records.len() >= MAX_RECORDS {
            p.warnings.push(format!(
                "stopped at {MAX_RECORDS} records; the rest of the file was not read"
            ));
            break;
        }
        if raw.len() > MAX_LINE_BYTES {
            p.ignored += 1;
            if p.warnings.len() < 5 {
                p.warnings.push(format!(
                    "line {line_no} is over {MAX_LINE_BYTES} bytes and was skipped"
                ));
            }
            continue;
        }
        let line = raw.trim_end_matches('\r');
        let result = match format {
            SymbolFormat::GnuMap => {
                if !in_map {
                    in_map = line.starts_with("Linker script and memory map");
                    continue;
                }
                match gnu_map_line(line, line_no) {
                    Some(r) => Line::Rec(r),
                    None => Line::Skip,
                }
            }
            SymbolFormat::MsvcMap => match msvc_map_line(line, line_no) {
                Some(r) => Line::Rec(r),
                None => Line::Skip,
            },
            SymbolFormat::Csv => csv_line(line, line_no, p.records.is_empty() && i < 3),
            SymbolFormat::Splat => splat_line(line, line_no),
            SymbolFormat::Idc => idc_line(line, line_no),
            SymbolFormat::Auto => Line::Skip,
        };
        match result {
            Line::Rec(r) => p.records.push(r),
            Line::Skip => {}
            Line::Bad => p.ignored += 1,
        }
    }
    (format, p)
}

/// `0x...` hex, or bare hex digits (no sign); `None` otherwise.
pub fn parse_address(s: &str) -> Option<u64> {
    let s = s.trim();
    let digits = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if digits.is_empty() || digits.len() > 16 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(digits, 16).ok()
}

fn parse_number(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn record(address: u64, name: &str, line: usize) -> SymRecord {
    SymRecord {
        address,
        name: Some(name.to_string()),
        size: None,
        comment: None,
        line,
    }
}

fn gnu_map_line(line: &str, n: usize) -> Option<SymRecord> {
    let mut it = line.split_whitespace();
    let (a, name) = (it.next()?, it.next()?);
    if it.next().is_some() || !a.starts_with("0x") || name.starts_with(['.', '*']) {
        return None;
    }
    if name.contains(['=', '(', '/']) {
        return None;
    }
    Some(record(parse_address(a)?, name, n))
}

fn msvc_map_line(line: &str, n: usize) -> Option<SymRecord> {
    let toks: Vec<&str> = line.split_whitespace().collect();
    if toks.len() < 3 {
        return None;
    }
    let (s, o) = toks[0].split_once(':')?;
    let hex = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_hexdigit());
    if s.len() != 4 || !hex(s) || !hex(o) || toks[2].len() < 8 || !hex(toks[2]) {
        return None;
    }
    Some(record(u64::from_str_radix(toks[2], 16).ok()?, toks[1], n))
}

/// Splits one CSV line; double quotes group, `""` is a quote.
fn csv_fields(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    let mut chars = line.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' if quoted && chars.peek() == Some(&'"') => {
                cur.push('"');
                chars.next();
            }
            '"' => quoted = !quoted,
            ',' if !quoted => out.push(std::mem::take(&mut cur)),
            _ => cur.push(c),
        }
    }
    out.push(cur);
    out
}

fn csv_line(line: &str, n: usize, maybe_header: bool) -> Line {
    let t = line.trim();
    if t.is_empty() || t.starts_with('#') {
        return Line::Skip;
    }
    let f = csv_fields(t);
    let Some(addr) = parse_address(&f[0]) else {
        return if maybe_header { Line::Skip } else { Line::Bad };
    };
    let name = f.get(1).map(|s| s.trim()).filter(|s| !s.is_empty());
    let comment = f.get(3).map(|s| s.trim()).filter(|s| !s.is_empty());
    if name.is_none() && comment.is_none() {
        return Line::Bad;
    }
    Line::Rec(SymRecord {
        address: addr,
        name: name.map(str::to_string),
        size: f.get(2).and_then(|s| parse_number(s)),
        comment: comment.map(|c| (CommentKind::Plate, c.to_string())),
        line: n,
    })
}

fn splat_line(line: &str, n: usize) -> Line {
    let t = line.trim();
    if t.is_empty() || t.starts_with("//") || t.starts_with('#') {
        return Line::Skip;
    }
    let (code, attrs) = match t.split_once("//") {
        Some((c, a)) => (c.trim(), a.trim()),
        None => (t, ""),
    };
    let code = code.trim_end_matches(';').trim();
    let Some((name, addr)) = code.split_once('=') else {
        return Line::Bad;
    };
    let name = name.trim();
    let Some(addr) = parse_address(addr) else {
        return Line::Bad;
    };
    if name.is_empty() || name.contains(char::is_whitespace) {
        return Line::Bad;
    }
    let size = attrs
        .split_whitespace()
        .find_map(|a| a.strip_prefix("size:"))
        .and_then(parse_number);
    Line::Rec(SymRecord {
        address: addr,
        name: Some(name.to_string()),
        size,
        comment: None,
        line: n,
    })
}

/// Reads one C string literal at the start of `s`; returns it and the text after the closing quote.
fn c_string(s: &str) -> Option<(String, &str)> {
    let body = s.trim_start().strip_prefix('"')?;
    let mut out = String::new();
    let mut chars = body.char_indices();
    while let Some((i, c)) = chars.next() {
        match c {
            '"' => return Some((out, &body[i + 1..])),
            '\\' => match chars.next()?.1 {
                'n' => out.push('\n'),
                't' => out.push('\t'),
                'r' => {}
                'x' => {
                    let mut v = 0u32;
                    for _ in 0..2 {
                        let mut look = chars.clone();
                        match look.next().and_then(|(_, c)| c.to_digit(16)) {
                            Some(d) => {
                                v = v * 16 + d;
                                chars = look;
                            }
                            None => break,
                        }
                    }
                    if let Some(ch) = char::from_u32(v) {
                        out.push(ch);
                    }
                }
                other => out.push(other),
            },
            c => out.push(c),
        }
    }
    None
}

fn idc_line(line: &str, n: usize) -> Line {
    let t = line.trim();
    let Some(open) = t.find('(') else {
        return Line::Skip;
    };
    let call = &t[..open];
    if !matches!(
        call,
        "set_name" | "MakeName" | "set_cmt" | "MakeComm" | "set_func_cmt" | "MakeRptCmt"
    ) {
        return Line::Skip;
    }
    let Some((addr_text, rest)) = t[open + 1..].split_once(',') else {
        return Line::Bad;
    };
    let Some(addr) = parse_number(addr_text) else {
        return Line::Bad;
    };
    let Some((text, rest)) = c_string(rest) else {
        return Line::Bad;
    };
    let flag = rest
        .trim_start()
        .strip_prefix(',')
        .and_then(|r| r.split([',', ')']).next())
        .and_then(parse_number)
        .unwrap_or(0);
    let mut rec = SymRecord {
        address: addr,
        name: None,
        size: None,
        comment: None,
        line: n,
    };
    match call {
        "set_name" | "MakeName" => {
            if text.is_empty() {
                return Line::Skip;
            }
            rec.name = Some(text);
        }
        "set_cmt" | "MakeComm" => {
            let k = if flag != 0 && call == "set_cmt" {
                CommentKind::Repeatable
            } else {
                CommentKind::Eol
            };
            rec.comment = Some((k, text));
        }
        "MakeRptCmt" => rec.comment = Some((CommentKind::Repeatable, text)),
        _ => {
            let k = if flag != 0 {
                CommentKind::Repeatable
            } else {
                CommentKind::Plate
            };
            rec.comment = Some((k, text));
        }
    }
    Line::Rec(rec)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(p: &Parsed) -> Vec<(u64, String)> {
        p.records
            .iter()
            .filter_map(|r| r.name.clone().map(|n| (r.address, n)))
            .collect()
    }

    #[test]
    fn gnu_map_reads_symbol_lines_only() {
        let text = "Archive member included\n\nLinker script and memory map\n\n.text           0x0000000000001149      0x1d4\n *(.text)\n .text          0x0000000000001149       0x4e calc.o\n                0x0000000000001149                skip_ws\n                0x0000000000001197                parse_number\n                0x0000000000003000                PROVIDE (_end = .)\n                0x0000000000003010                _edata = .\n";
        let (f, p) = parse(text, SymbolFormat::Auto);
        assert_eq!(f, SymbolFormat::GnuMap);
        assert_eq!(
            names(&p),
            vec![
                (0x1149, "skip_ws".to_string()),
                (0x1197, "parse_number".to_string())
            ]
        );
    }

    #[test]
    fn msvc_map_uses_rva_plus_base() {
        let text = " Start         Length     Name                   Class\n\n  Address         Publics by Value              Rva+Base       Lib:Object\n\n 0001:00001000       _main                      00401000 f   main.obj\n 0001:00001050       ?helper@@YAXXZ             00401050 f i main.obj\n 0002:00000000       __imp__puts                00403000     libcmt:puts.obj\n entry point at        0001:00001000\n";
        let (f, p) = parse(text, SymbolFormat::Auto);
        assert_eq!(f, SymbolFormat::MsvcMap);
        assert_eq!(p.records.len(), 3);
        assert_eq!(p.records[0].address, 0x401000);
        assert_eq!(p.records[1].name.as_deref(), Some("?helper@@YAXXZ"));
    }

    #[test]
    fn csv_has_header_quotes_and_comments() {
        let text = "address,name,size,comment\n0x401000,main,0x40,\"entry, the first\"\n401050,helper\n0x401060,,,only a comment\nzzz,bad\n";
        let (f, p) = parse(text, SymbolFormat::Auto);
        assert_eq!(f, SymbolFormat::Csv);
        assert_eq!(p.records.len(), 3);
        assert_eq!(p.records[0].size, Some(0x40));
        assert_eq!(
            p.records[0].comment,
            Some((CommentKind::Plate, "entry, the first".to_string()))
        );
        assert_eq!(p.records[1].address, 0x401050);
        assert_eq!(p.records[2].name, None);
        assert_eq!(p.ignored, 1);
    }

    #[test]
    fn splat_reads_name_address_and_size() {
        let text = "// symbols\nfunc_80001000 = 0x80001000; // type:func size:0x20 rom:0x1000\ngMain=0x80002000;\nnot a line\n";
        let (f, p) = parse(text, SymbolFormat::Auto);
        assert_eq!(f, SymbolFormat::Splat);
        assert_eq!(p.records.len(), 2);
        assert_eq!(p.records[0].size, Some(0x20));
        assert_eq!(p.records[1].address, 0x8000_2000);
        assert_eq!(p.ignored, 1);
    }

    #[test]
    fn idc_names_and_comments() {
        let text = "#include <idc.idc>\nstatic main() {\n  set_name(0x401000, \"main\", SN_CHECK);\n  MakeName(4198480, \"helper\");\n  set_cmt(0x401004, \"say \\\"hi\\\"\\n\", 0);\n  MakeComm(0x401008, \"eol\");\n  set_func_cmt(0x401000, \"entry\", 1);\n  MakeFunction(0x401000, BADADDR);\n}\n";
        let (f, p) = parse(text, SymbolFormat::Auto);
        assert_eq!(f, SymbolFormat::Idc);
        assert_eq!(p.records.len(), 5);
        assert_eq!(p.records[1].address, 4_198_480);
        assert_eq!(
            p.records[2].comment,
            Some((CommentKind::Eol, "say \"hi\"\n".to_string()))
        );
        assert_eq!(
            p.records[4].comment.as_ref().map(|c| c.0),
            Some(CommentKind::Repeatable)
        );
    }

    #[test]
    fn long_lines_and_garbage_are_bounded() {
        let long = format!("0x401000,{}\n", "a".repeat(MAX_LINE_BYTES + 1));
        let (_, p) = parse(&long, SymbolFormat::Csv);
        assert!(p.records.is_empty());
        assert_eq!(p.ignored, 1);
        let (_, p) = parse("\u{0}\u{1}binary\n", SymbolFormat::Idc);
        assert!(p.records.is_empty());
    }
}
