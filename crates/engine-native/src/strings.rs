//! Null-terminated strings in the initialized, non-executable memory blocks, found the way
//! Ghidra's string search finds them: ASCII and UTF-8 byte strings and UTF-16LE strings, each
//! terminated by a zero character and at least `min_len` characters long.

use engine_native_sys::Image;
use kraken_proto::{Hex64, MemoryBlock, StringEncoding, StringEntry};

/// Longest value reported, in characters (as the Ghidra sidecar caps them).
pub const MAX_CHARS: usize = 4096;

fn printable(c: char) -> bool {
    (c >= ' ' && c != '\u{7f}' && !c.is_control()) || matches!(c, '\t' | '\n' | '\r')
}

/// Every string of at least `min_len` characters, ordered by address. At an address the code
/// refers to (`referenced`), any zero-terminated run of 7-bit characters counts, control
/// characters included, the way Ghidra defines a string at a data reference; strings found
/// inside such a run are dropped.
pub fn scan(
    image: &Image,
    blocks: &[MemoryBlock],
    min_len: u32,
    referenced: &[u64],
) -> Vec<StringEntry> {
    let min = min_len.max(1) as usize;
    let mut out = scan_plain(image, blocks, min);
    let mut defined: Vec<StringEntry> = Vec::new();
    for at in referenced {
        let Some(b) = blocks.iter().find(|b| {
            b.space == "ram"
                && b.initialized
                && !b.perms.ends_with('x')
                && b.start.0 <= *at
                && *at < b.end.0
        }) else {
            continue;
        };
        let len = usize::try_from((b.end.0 - at).min(MAX_CHARS as u64 + 1)).unwrap_or(0);
        let mut bytes = vec![0u8; len];
        if !image.read(*at, &mut bytes) {
            continue;
        }
        let Some(n) = bytes.iter().position(|c| *c == 0) else {
            continue;
        };
        if n >= min && bytes[..n].iter().all(|c| (1..0x80).contains(c)) {
            defined.push(StringEntry {
                address: Hex64(*at),
                value: String::from_utf8_lossy(&bytes[..n]).into_owned(),
                encoding: StringEncoding::Ascii,
                length: (n + 1) as u32,
            });
        }
    }
    if !defined.is_empty() {
        out.retain(|s| {
            !defined.iter().any(|d| {
                d.address.0 <= s.address.0 && s.address.0 < d.address.0 + u64::from(d.length)
            })
        });
        out.extend(defined);
        out.sort_by_key(|s| s.address);
        out.dedup_by_key(|s| s.address);
    }
    out
}

fn scan_plain(image: &Image, blocks: &[MemoryBlock], min: usize) -> Vec<StringEntry> {
    let mut out = Vec::new();
    for b in blocks {
        if b.space != "ram" || !b.initialized || b.perms.ends_with('x') {
            continue;
        }
        let Ok(len) = usize::try_from(b.end.0 - b.start.0) else {
            continue;
        };
        let mut bytes = vec![0u8; len];
        if !image.read(b.start.0, &mut bytes) {
            continue;
        }
        // the dynamic string table is defined as UTF-8 strings by Ghidra's ELF loader
        let defined_utf8 = b.name == ".dynstr";
        scan_block(b.start.0, &bytes, min, defined_utf8, &mut out);
    }
    out.sort_by_key(|s| s.address);
    out
}

fn scan_block(base: u64, bytes: &[u8], min: usize, defined_utf8: bool, out: &mut Vec<StringEntry>) {
    let mut taken = vec![false; bytes.len()];
    // UTF-16LE first: two-byte aligned runs of (char, 0) pairs ending in a zero pair
    let mut i = (base % 2) as usize;
    while i + 1 < bytes.len() {
        let start = i;
        let mut units = Vec::new();
        while i + 1 < bytes.len() {
            let u = u16::from_le_bytes([bytes[i], bytes[i + 1]]);
            if u == 0 {
                break;
            }
            units.push(u);
            i += 2;
        }
        let terminated = i + 1 < bytes.len();
        let text = String::from_utf16(&units).ok();
        let ok = terminated
            && units.len() >= min.max(2)
            // mostly plain text, so ASCII byte strings are not read as UTF-16
            && units.iter().all(|u| (0x20..0x7f).contains(u) || matches!(u, 9 | 10 | 13))
            && text.as_deref().is_some_and(|t| t.chars().all(printable));
        if ok && let Some(t) = text {
            let end = i + 2;
            taken[start..end].iter_mut().for_each(|x| *x = true);
            out.push(StringEntry {
                address: Hex64(base + start as u64),
                value: t.chars().take(MAX_CHARS).collect(),
                encoding: StringEncoding::Utf16,
                length: (end - start) as u32,
            });
            i = end;
        } else {
            i = start + 2;
        }
    }
    // byte strings: runs of printable UTF-8 characters ending in a zero byte
    let mut i = 0;
    let mut start: Option<usize> = None;
    let mut chars = 0usize;
    while i < bytes.len() {
        if taken[i] {
            start = None;
            i += 1;
            continue;
        }
        if bytes[i] == 0 {
            if let Some(s) = start.take()
                && chars >= min
            {
                let raw = &bytes[s..i];
                let text = String::from_utf8_lossy(raw);
                out.push(StringEntry {
                    address: Hex64(base + s as u64),
                    value: text.chars().take(MAX_CHARS).collect(),
                    encoding: if defined_utf8 || !raw.is_ascii() {
                        StringEncoding::Utf8
                    } else {
                        StringEncoding::Ascii
                    },
                    length: (i + 1 - s) as u32,
                });
            }
            i += 1;
            continue;
        }
        let width = match bytes[i] {
            0x00..=0x7f => 1,
            0xc2..=0xdf => 2,
            0xe0..=0xef => 3,
            0xf0..=0xf4 => 4,
            _ => 0,
        };
        let c = (width > 0)
            .then(|| bytes.get(i..i + width))
            .flatten()
            .and_then(|s| std::str::from_utf8(s).ok())
            .and_then(|s| s.chars().next())
            .filter(|c| printable(*c));
        match c {
            Some(_) => {
                if start.is_none() {
                    start = Some(i);
                    chars = 0;
                }
                chars += 1;
                i += width;
            }
            None => {
                start = None;
                i += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn found(bytes: &[u8], min: usize) -> Vec<(u64, String, StringEncoding, u32)> {
        let mut out = Vec::new();
        scan_block(0x1000, bytes, min, false, &mut out);
        out.sort_by_key(|s| s.address);
        out.into_iter()
            .map(|s| (s.address.0, s.value, s.encoding, s.length))
            .collect()
    }

    #[test]
    fn byte_and_wide_strings() {
        let mut b = b"\x01\x02hello\0ab\0caf\xc3\xa9\0".to_vec();
        b.extend_from_slice(&[0, 0, 0]); // pad to an even offset
        assert_eq!(b.len() % 2, 0);
        let wide: Vec<u8> = "wide!"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let at = b.len() as u64;
        b.extend_from_slice(&wide);
        b.extend_from_slice(&[0, 0]);
        b.extend_from_slice(b"tail no nul");
        let got = found(&b, 4);
        assert_eq!(
            got,
            vec![
                (0x1002, "hello".into(), StringEncoding::Ascii, 6),
                (0x100b, "café".into(), StringEncoding::Utf8, 6),
                (0x1000 + at, "wide!".into(), StringEncoding::Utf16, 12),
            ]
        );
        assert!(
            found(b"\x01\x02\x03\0", 1).is_empty(),
            "control bytes are not text"
        );
    }
}
