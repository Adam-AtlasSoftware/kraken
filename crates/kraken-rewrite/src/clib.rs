//! Models of the few libc facts the oracle stubs need: a `printf` formatter for integer, string
//! and character conversions, and glibc's C-locale `ctype` table.

/// Formats `fmt` the way C `printf` would for the supported conversions
/// (`%d %i %u %x %X %o %c %s %p %%`, flags `-0+ #`, width, `.precision` for `%s`, length
/// modifiers `hh h l ll z j t`). Floating point is not supported and returns an error.
///
/// `next` yields the next variadic integer argument; `cstr` reads a NUL-terminated string.
pub fn format_printf(
    fmt: &[u8],
    next: &mut dyn FnMut() -> u64,
    cstr: &mut dyn FnMut(u64) -> Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < fmt.len() {
        let c = fmt[i];
        i += 1;
        if c != b'%' {
            out.push(c);
            continue;
        }
        let (mut left, mut zero, mut plus, mut space, mut alt) =
            (false, false, false, false, false);
        while let Some(&f) = fmt.get(i) {
            match f {
                b'-' => left = true,
                b'0' => zero = true,
                b'+' => plus = true,
                b' ' => space = true,
                b'#' => alt = true,
                _ => break,
            }
            i += 1;
        }
        let mut width = 0usize;
        if fmt.get(i) == Some(&b'*') {
            let w = next() as i32;
            if w < 0 {
                left = true;
            }
            width = w.unsigned_abs() as usize;
            i += 1;
        } else {
            while let Some(d) = fmt.get(i).filter(|d| d.is_ascii_digit()) {
                width = width
                    .saturating_mul(10)
                    .saturating_add(usize::from(d - b'0'));
                i += 1;
            }
        }
        let mut prec: Option<usize> = None;
        if fmt.get(i) == Some(&b'.') {
            i += 1;
            let mut p = 0usize;
            if fmt.get(i) == Some(&b'*') {
                p = usize::try_from(next() as i32).unwrap_or(0);
                i += 1;
            } else {
                while let Some(d) = fmt.get(i).filter(|d| d.is_ascii_digit()) {
                    p = p.saturating_mul(10).saturating_add(usize::from(d - b'0'));
                    i += 1;
                }
            }
            prec = Some(p);
        }
        let mut long = 0u8; // 0: int, 1: long (l, z, j, t), 2: short, 3: char
        loop {
            match fmt.get(i) {
                Some(b'l' | b'z' | b'j' | b't' | b'q') => long = 1,
                Some(b'h') => long = if long == 2 { 3 } else { 2 },
                _ => break,
            }
            i += 1;
        }
        let Some(&conv) = fmt.get(i) else {
            return Err("format ends inside a conversion".into());
        };
        i += 1;
        let signed_val = |raw: u64| -> i64 {
            match long {
                1 => raw as i64,
                2 => i64::from(raw as i16),
                3 => i64::from(raw as i8),
                _ => i64::from(raw as i32),
            }
        };
        let unsigned_val = |raw: u64| -> u64 {
            match long {
                1 => raw,
                2 => u64::from(raw as u16),
                3 => u64::from(raw as u8),
                _ => u64::from(raw as u32),
            }
        };
        let (mut sign, mut digits): (String, Vec<u8>) = match conv {
            b'%' => {
                out.push(b'%');
                continue;
            }
            b'd' | b'i' => {
                let v = signed_val(next());
                let s = if v < 0 {
                    "-"
                } else if plus {
                    "+"
                } else if space {
                    " "
                } else {
                    ""
                };
                (s.into(), v.unsigned_abs().to_string().into_bytes())
            }
            b'u' => (String::new(), unsigned_val(next()).to_string().into_bytes()),
            b'x' => {
                let v = unsigned_val(next());
                let p = if alt && v != 0 { "0x" } else { "" };
                (p.into(), format!("{v:x}").into_bytes())
            }
            b'X' => {
                let v = unsigned_val(next());
                let p = if alt && v != 0 { "0X" } else { "" };
                (p.into(), format!("{v:X}").into_bytes())
            }
            b'o' => (
                String::new(),
                format!("{:o}", unsigned_val(next())).into_bytes(),
            ),
            b'p' => {
                let v = next();
                if v == 0 {
                    (String::new(), b"(nil)".to_vec())
                } else {
                    ("0x".into(), format!("{v:x}").into_bytes())
                }
            }
            b'c' => {
                let v = next() as u8;
                pad(&mut out, &[v], width, left, false);
                continue;
            }
            b's' => {
                let addr = next();
                let mut s = if addr == 0 {
                    b"(null)".to_vec()
                } else {
                    cstr(addr).ok_or_else(|| format!("%s of unreadable pointer {addr:#x}"))?
                };
                if let Some(p) = prec {
                    s.truncate(p);
                }
                pad(&mut out, &s, width, left, false);
                continue;
            }
            b'f' | b'F' | b'e' | b'E' | b'g' | b'G' | b'a' | b'A' => {
                return Err("floating point conversions are not modelled".into());
            }
            other => return Err(format!("unsupported conversion %{}", other as char)),
        };
        if let Some(p) = prec
            && digits.len() < p
        {
            let mut z = vec![b'0'; p - digits.len()];
            z.extend_from_slice(&digits);
            digits = z;
        }
        if zero && !left && prec.is_none() {
            let used = sign.len() + digits.len();
            if used < width {
                let mut z = vec![b'0'; width - used];
                z.extend_from_slice(&digits);
                digits = z;
            }
        }
        let mut body = std::mem::take(&mut sign).into_bytes();
        body.extend_from_slice(&digits);
        pad(&mut out, &body, width, left, false);
    }
    Ok(out)
}

fn pad(out: &mut Vec<u8>, body: &[u8], width: usize, left: bool, _zero: bool) {
    let fill = width.saturating_sub(body.len());
    if !left {
        out.extend(std::iter::repeat_n(b' ', fill));
    }
    out.extend_from_slice(body);
    if left {
        out.extend(std::iter::repeat_n(b' ', fill));
    }
}

/// glibc's `__ctype_b` table for the C locale: 384 `u16` entries for characters -128..=255.
pub fn ctype_b_table() -> Vec<u8> {
    const UPPER: u16 = 0x100;
    const LOWER: u16 = 0x200;
    const ALPHA: u16 = 0x400;
    const DIGIT: u16 = 0x800;
    const XDIGIT: u16 = 0x1000;
    const SPACE: u16 = 0x2000;
    const PRINT: u16 = 0x4000;
    const GRAPH: u16 = 0x8000;
    const BLANK: u16 = 0x1;
    const CNTRL: u16 = 0x2;
    const PUNCT: u16 = 0x4;
    const ALNUM: u16 = 0x8;
    let mut out = Vec::with_capacity(384 * 2);
    for idx in 0..384i32 {
        let ch = idx - 128;
        let mut bits = 0u16;
        if (0..128).contains(&ch) {
            let c = ch as u8;
            if c.is_ascii_uppercase() {
                bits |= UPPER | ALPHA | ALNUM;
            }
            if c.is_ascii_lowercase() {
                bits |= LOWER | ALPHA | ALNUM;
            }
            if c.is_ascii_digit() {
                bits |= DIGIT | ALNUM;
            }
            if c.is_ascii_hexdigit() {
                bits |= XDIGIT;
            }
            if matches!(c, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
                bits |= SPACE;
            }
            if c == b' ' || c == b'\t' {
                bits |= BLANK;
            }
            if c.is_ascii_control() {
                bits |= CNTRL;
            }
            if c.is_ascii_punctuation() {
                bits |= PUNCT;
            }
            if c.is_ascii_graphic() {
                bits |= GRAPH | PRINT;
            }
            if c == b' ' {
                bits |= PRINT;
            }
        }
        out.extend_from_slice(&bits.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fmt(f: &str, args: &[u64]) -> String {
        let mut it = args.iter().copied();
        let mut next = move || it.next().unwrap_or(0);
        let mut cstr = |_a: u64| Some(b"str".to_vec());
        String::from_utf8(format_printf(f.as_bytes(), &mut next, &mut cstr).unwrap()).unwrap()
    }

    #[test]
    fn printf_basics() {
        assert_eq!(fmt("out: %d\n", &[(-5i32) as u32 as u64]), "out: -5\n");
        assert_eq!(fmt("%u %lu", &[7, 1 << 40]), "7 1099511627776");
        assert_eq!(
            fmt("%-18s=%ld", &[1, (-3i64) as u64]),
            "str               =-3"
        );
        assert_eq!(fmt("%05d|%x|%c|%%", &[42, 255, 65]), "00042|ff|A|%");
        assert_eq!(
            fmt("vm error at pc=%u: %s\n", &[3, 9]),
            "vm error at pc=3: str\n"
        );
    }
}
