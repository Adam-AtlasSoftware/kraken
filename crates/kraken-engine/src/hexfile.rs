//! Intel HEX and Motorola S-record text images: firmware as address-tagged records. Both give
//! blocks of bytes at their real addresses and, when the file has one, an entry address.
//! Hand-rolled (a few dozen lines each) so no dependency is added.

use kraken_proto::{ErrorCode, ProtoError};

/// Largest image mapped from a text record file.
const MAX_BYTES: usize = 256 << 20;

/// Which record format a file is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexKind {
    /// Intel HEX (`:LLAAAATT...CC`).
    Ihex,
    /// Motorola S-record (`S1LLAAAA...CC`).
    Srec,
}

impl HexKind {
    /// The `LoaderSpec::format` value for this kind.
    pub fn format(self) -> &'static str {
        match self {
            HexKind::Ihex => "ihex",
            HexKind::Srec => "srec",
        }
    }

    /// The kind a `LoaderSpec::format` value names.
    pub fn from_format(format: &str) -> Option<HexKind> {
        match format {
            "ihex" => Some(HexKind::Ihex),
            "srec" => Some(HexKind::Srec),
            _ => None,
        }
    }

    /// What to call it in a sentence.
    pub fn title(self) -> &'static str {
        match self {
            HexKind::Ihex => "Intel HEX",
            HexKind::Srec => "Motorola S-record",
        }
    }
}

/// A parsed record file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexImage {
    /// The format that was read.
    pub kind: HexKind,
    /// Contiguous byte runs at their addresses, ascending and non-overlapping.
    pub blocks: Vec<(u64, Vec<u8>)>,
    /// The start address the file records, when it has one.
    pub entry: Option<u64>,
}

/// Which record format `data` looks like, from its first line; `None` for anything else.
pub fn detect(data: &[u8]) -> Option<HexKind> {
    let head = &data[..data.len().min(64)];
    let head = head.strip_prefix(b"\xef\xbb\xbf").unwrap_or(head);
    let line = head.split(|b| matches!(b, b'\n' | b'\r')).next()?;
    let hex = |s: &[u8]| !s.is_empty() && s.iter().all(u8::is_ascii_hexdigit);
    if let Some(rest) = line.strip_prefix(b":")
        && rest.len() >= 10
        && hex(&rest[..10])
    {
        return Some(HexKind::Ihex);
    }
    if line.len() >= 10 && line[0] == b'S' && line[1].is_ascii_digit() && hex(&line[2..10]) {
        return Some(HexKind::Srec);
    }
    None
}

fn bad(line: usize, msg: &str) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, format!("line {line}: {msg}"))
}

fn bytes_of(text: &str, line: usize) -> Result<Vec<u8>, ProtoError> {
    if !text.len().is_multiple_of(2) || !text.is_ascii() {
        return Err(bad(line, "odd or non-hexadecimal record"));
    }
    (0..text.len() / 2)
        .map(|i| {
            u8::from_str_radix(&text[i * 2..i * 2 + 2], 16)
                .map_err(|_| bad(line, "non-hexadecimal digit"))
        })
        .collect()
}

#[derive(Default)]
struct Builder {
    runs: Vec<(u64, Vec<u8>)>,
    total: usize,
}

impl Builder {
    fn put(&mut self, addr: u64, data: &[u8], line: usize) -> Result<(), ProtoError> {
        if data.is_empty() {
            return Ok(());
        }
        self.total += data.len();
        if self.total > MAX_BYTES {
            return Err(bad(line, "the image is larger than 256 MiB"));
        }
        if let Some((start, run)) = self.runs.last_mut()
            && *start + run.len() as u64 == addr
        {
            run.extend_from_slice(data);
        } else {
            self.runs.push((addr, data.to_vec()));
        }
        Ok(())
    }

    fn finish(mut self) -> Result<Vec<(u64, Vec<u8>)>, ProtoError> {
        self.runs.sort_by_key(|r| r.0);
        let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
        for (addr, data) in self.runs {
            match out.last_mut() {
                Some((s, run)) if *s + run.len() as u64 > addr => {
                    return Err(ProtoError::new(
                        ErrorCode::InvalidArgument,
                        format!("records overlap at {addr:#x}"),
                    ));
                }
                Some((s, run)) if *s + run.len() as u64 == addr => run.extend(data),
                _ => out.push((addr, data)),
            }
        }
        if out.is_empty() {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                "the file has no data records",
            ));
        }
        Ok(out)
    }
}

/// Parses `data` as the record format `kind`, checking every checksum.
pub fn parse(data: &[u8], kind: HexKind) -> Result<HexImage, ProtoError> {
    let text = std::str::from_utf8(data)
        .map_err(|_| ProtoError::new(ErrorCode::InvalidArgument, "not a text file"))?;
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut b = Builder::default();
    let mut entry = None;
    let mut upper = 0u64;
    let mut done = false;
    for (n, raw) in text.lines().enumerate() {
        let n = n + 1;
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        match kind {
            HexKind::Ihex => {
                let body = line
                    .strip_prefix(':')
                    .ok_or_else(|| bad(n, "no ':' record mark"))?;
                let r = bytes_of(body, n)?;
                if r.len() < 5 || r.len() != r[0] as usize + 5 {
                    return Err(bad(n, "record length does not match"));
                }
                if r.iter().fold(0u8, |a, x| a.wrapping_add(*x)) != 0 {
                    return Err(bad(n, "checksum mismatch"));
                }
                let addr = u64::from(u16::from_be_bytes([r[1], r[2]]));
                let payload = &r[4..r.len() - 1];
                match r[3] {
                    0 => b.put(upper + addr, payload, n)?,
                    1 => {
                        done = true;
                        break;
                    }
                    2 | 4 if payload.len() == 2 => {
                        let v = u64::from(u16::from_be_bytes([payload[0], payload[1]]));
                        upper = if r[3] == 2 { v << 4 } else { v << 16 };
                    }
                    3 if payload.len() == 4 => {
                        let cs = u64::from(u16::from_be_bytes([payload[0], payload[1]]));
                        let ip = u64::from(u16::from_be_bytes([payload[2], payload[3]]));
                        entry = Some((cs << 4) + ip);
                    }
                    5 if payload.len() == 4 => {
                        entry = Some(u64::from(u32::from_be_bytes([
                            payload[0], payload[1], payload[2], payload[3],
                        ])));
                    }
                    t @ 2..=5 => return Err(bad(n, &format!("bad payload for record type {t}"))),
                    _ => return Err(bad(n, "unknown record type")),
                }
            }
            HexKind::Srec => {
                let body = line
                    .strip_prefix('S')
                    .ok_or_else(|| bad(n, "no 'S' record mark"))?;
                let ty = body
                    .as_bytes()
                    .first()
                    .copied()
                    .ok_or_else(|| bad(n, "short record"))?;
                let r = bytes_of(&body[1..], n)?;
                if r.len() < 2 || r.len() != r[0] as usize + 1 {
                    return Err(bad(n, "record length does not match"));
                }
                let sum = r[..r.len() - 1].iter().fold(0u8, |a, x| a.wrapping_add(*x));
                if !sum != r[r.len() - 1] {
                    return Err(bad(n, "checksum mismatch"));
                }
                let width = match ty {
                    b'0' | b'1' | b'9' => 2,
                    b'2' | b'8' => 3,
                    b'3' | b'7' => 4,
                    b'5' | b'6' => continue,
                    _ => return Err(bad(n, "unknown record type")),
                };
                let body = &r[1..r.len() - 1];
                if body.len() < width {
                    return Err(bad(n, "record too short for its address"));
                }
                let addr = body[..width]
                    .iter()
                    .fold(0u64, |a, x| a << 8 | u64::from(*x));
                match ty {
                    b'0' => {}
                    b'1'..=b'3' => b.put(addr, &body[width..], n)?,
                    _ => entry = Some(addr),
                }
            }
        }
    }
    if kind == HexKind::Ihex && !done {
        return Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            "Intel HEX file has no end-of-file record (truncated?)",
        ));
    }
    Ok(HexImage {
        kind,
        blocks: b.finish()?,
        entry,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ihex_rec(addr: u16, ty: u8, data: &[u8]) -> String {
        let mut r = vec![data.len() as u8, (addr >> 8) as u8, addr as u8, ty];
        r.extend(data);
        let sum = r.iter().fold(0u8, |a, x| a.wrapping_add(*x));
        r.push(sum.wrapping_neg());
        let hex: String = r.iter().map(|b| format!("{b:02X}")).collect();
        format!(":{hex}\n")
    }

    fn srec_rec(ty: char, addr: &[u8], data: &[u8]) -> String {
        let mut r = vec![(addr.len() + data.len() + 1) as u8];
        r.extend(addr);
        r.extend(data);
        let sum = r.iter().fold(0u8, |a, x| a.wrapping_add(*x));
        r.push(!sum);
        let hex: String = r.iter().map(|b| format!("{b:02X}")).collect();
        format!("S{ty}{hex}\n")
    }

    #[test]
    fn ihex_blocks_and_entry() {
        let t = ihex_rec(0, 4, &[0x08, 0x00])
            + &ihex_rec(0x10, 0, &[1, 2, 3])
            + &ihex_rec(0x13, 0, &[4])
            + &ihex_rec(0x100, 0, &[9])
            + &ihex_rec(0, 5, &[0x08, 0, 0, 0x11])
            + &ihex_rec(0, 1, &[]);
        assert_eq!(detect(t.as_bytes()), Some(HexKind::Ihex));
        let i = parse(t.as_bytes(), HexKind::Ihex).unwrap();
        assert_eq!(
            i.blocks,
            vec![(0x0800_0010, vec![1, 2, 3, 4]), (0x0800_0100, vec![9])]
        );
        assert_eq!(i.entry, Some(0x0800_0011));
    }

    #[test]
    fn ihex_errors() {
        let mut t = ihex_rec(0, 0, &[1, 2]);
        let e = parse(t.as_bytes(), HexKind::Ihex).unwrap_err();
        assert!(e.message.contains("end-of-file"), "{e:?}");
        t.push_str(&ihex_rec(0, 1, &[]));
        assert!(parse(t.as_bytes(), HexKind::Ihex).is_ok());
        let broken = t.replacen("0102", "0103", 1);
        let e = parse(broken.as_bytes(), HexKind::Ihex).unwrap_err();
        assert!(e.message.contains("checksum"), "{e:?}");
        let overlap = ihex_rec(0, 0, &[1, 2]) + &ihex_rec(1, 0, &[3]) + &ihex_rec(0, 1, &[]);
        let e = parse(overlap.as_bytes(), HexKind::Ihex).unwrap_err();
        assert!(e.message.contains("overlap"), "{e:?}");
    }

    #[test]
    fn srec_blocks_and_entry() {
        let t = srec_rec('0', &[0, 0], b"hdr")
            + &srec_rec('3', &[0x08, 0, 0, 0], &[1, 2])
            + &srec_rec('3', &[0x08, 0, 0, 0x02], &[3])
            + &srec_rec('1', &[0x10, 0], &[7])
            + &srec_rec('5', &[0, 3], &[])
            + &srec_rec('7', &[0x08, 0, 0, 1], &[]);
        assert_eq!(detect(t.as_bytes()), Some(HexKind::Srec));
        let i = parse(t.as_bytes(), HexKind::Srec).unwrap();
        assert_eq!(
            i.blocks,
            vec![(0x1000, vec![7]), (0x0800_0000, vec![1, 2, 3])]
        );
        assert_eq!(i.entry, Some(0x0800_0001));
        let broken = t.replacen("0102", "0103", 1);
        assert!(parse(broken.as_bytes(), HexKind::Srec).is_err());
    }

    #[test]
    fn other_files_are_not_detected() {
        assert_eq!(detect(b"\x7fELF"), None);
        assert_eq!(detect(b"hello world\n"), None);
        assert_eq!(detect(b""), None);
    }
}
