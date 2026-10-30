//! Embedded-signature scan and entropy map for firmware and ROM images. Only header structure is
//! checked and nothing is decompressed, so the work is one pass over the bytes. Hits are
//! candidates: a magic number plus the plausibility checks the format allows.

use std::collections::BTreeMap;

/// Most signatures one scan reports.
pub const MAX_SIGNATURES: usize = 1000;
/// Bytes per entropy block.
pub const ENTROPY_BLOCK: usize = 4096;

/// One recognised structure inside an image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signature {
    pub offset: u64,
    /// Short id: `gzip`, `xz`, `lzma`, `bzip2`, `zstd`, `squashfs`, `cramfs`, `uimage`, `fit`,
    /// `dtb`, `elf`, `pe`, `ihex`, `uefi_fv`.
    pub kind: &'static str,
    pub name: &'static str,
    /// What the header says, in a few words.
    pub detail: String,
    /// The structure's own length, when its header gives one.
    pub size: Option<u64>,
}

/// A run of blocks of one kind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Region {
    pub offset: u64,
    pub length: u64,
    /// `padding` (one repeated byte, entropy under 0.5), `compressed_or_encrypted` (7.2 bits per
    /// byte or more) or `code_or_data`.
    pub kind: &'static str,
}

/// The result of [`scan`].
#[derive(Debug, Clone, PartialEq)]
pub struct Scan {
    pub signatures: Vec<Signature>,
    /// More than [`MAX_SIGNATURES`] were found; the rest are dropped.
    pub truncated: bool,
    /// Shannon entropy of each [`ENTROPY_BLOCK`] block in tenths of a bit per byte (0 to 80).
    pub entropy: Vec<u8>,
    pub regions: Vec<Region>,
}

fn be32(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_be_bytes(d.get(o..o + 4)?.try_into().ok()?))
}
fn le32(d: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(d.get(o..o + 4)?.try_into().ok()?))
}
fn le64(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(d.get(o..o + 8)?.try_into().ok()?))
}
fn be64(d: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_be_bytes(d.get(o..o + 8)?.try_into().ok()?))
}
fn le16(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(d.get(o..o + 2)?.try_into().ok()?))
}
fn be16(d: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_be_bytes(d.get(o..o + 2)?.try_into().ok()?))
}

fn c_string(d: &[u8]) -> String {
    let end = d.iter().position(|&b| b == 0).unwrap_or(d.len());
    d[..end]
        .iter()
        .filter(|b| b.is_ascii_graphic() || **b == b' ')
        .map(|&b| b as char)
        .collect()
}

fn machine(m: u16) -> String {
    match m {
        0x03 => "x86",
        0x08 => "MIPS",
        0x14 => "PowerPC",
        0x28 => "ARM",
        0x3e => "x86-64",
        0xb7 => "AArch64",
        0xf3 => "RISC-V",
        _ => return format!("machine {m:#x}"),
    }
    .into()
}

fn sig(
    offset: usize,
    kind: &'static str,
    name: &'static str,
    detail: String,
    size: Option<u64>,
) -> Signature {
    Signature {
        offset: offset as u64,
        kind,
        name,
        detail,
        size,
    }
}

fn hex_val(b: u8) -> Option<u8> {
    (b as char).to_digit(16).map(|v| v as u8)
}

/// The length of the Intel HEX line at `o` when its checksum holds.
fn ihex_line(d: &[u8], o: usize) -> Option<usize> {
    if d.get(o) != Some(&b':') {
        return None;
    }
    let byte = |i: usize| -> Option<u8> {
        Some(hex_val(*d.get(o + 1 + i * 2)?)? << 4 | hex_val(*d.get(o + 2 + i * 2)?)?)
    };
    let len = byte(0)? as usize;
    if byte(3)? > 5 {
        return None;
    }
    let mut sum = 0u8;
    for i in 0..len + 5 {
        sum = sum.wrapping_add(byte(i)?);
    }
    (sum == 0).then_some(1 + (len + 5) * 2)
}

fn check(d: &[u8], o: usize, hex_until: usize) -> Option<Signature> {
    let tail = &d[o..];
    match tail[0] {
        0x1f if tail.starts_with(&[0x1f, 0x8b, 0x08]) => {
            let flags = *tail.get(3)?;
            let xfl = *tail.get(8)?;
            let os = *tail.get(9)?;
            (flags & 0xe0 == 0 && matches!(xfl, 0 | 2 | 4) && (os <= 13 || os == 255))
                .then(|| sig(o, "gzip", "gzip stream", String::new(), None))
        }
        0xfd if tail.starts_with(&[0xfd, b'7', b'z', b'X', b'Z', 0]) => {
            Some(sig(o, "xz", "xz stream", String::new(), None))
        }
        0x5d if tail.starts_with(&[0x5d, 0, 0]) => {
            let dict = le32(tail, 1)?;
            let size = le64(tail, 5)?;
            (tail.get(13) == Some(&0)
                && tail
                    .get(14..22)
                    .is_some_and(|w| w.iter().filter(|b| **b == 0).count() <= 2)
                && dict.is_power_of_two()
                && (1 << 12..=1 << 26).contains(&dict)
                && (size == u64::MAX || size < 1 << 32))
                .then(|| {
                    sig(
                        o,
                        "lzma",
                        "LZMA stream",
                        format!("dictionary {} KiB", dict >> 10),
                        (size != u64::MAX).then_some(size),
                    )
                })
        }
        b'B' if tail.starts_with(b"BZh") => (matches!(tail.get(3)?, b'1'..=b'9')
            && tail.get(4..10)? == [0x31, 0x41, 0x59, 0x26, 0x53, 0x59])
        .then(|| sig(o, "bzip2", "bzip2 stream", String::new(), None)),
        0x28 if tail.starts_with(&[0x28, 0xb5, 0x2f, 0xfd]) => {
            Some(sig(o, "zstd", "Zstandard frame", String::new(), None))
        }
        0x28 if tail.starts_with(&[0x28, 0xcd, 0x3d, 0x45]) => Some(sig(
            o,
            "cramfs",
            "cramfs filesystem",
            "little-endian".into(),
            None,
        )),
        0x45 if be32(tail, 0) == Some(0x453d_cd28) => Some(sig(
            o,
            "cramfs",
            "cramfs filesystem",
            "big-endian".into(),
            None,
        )),
        b'h' | b's' if tail.starts_with(b"hsqs") || tail.starts_with(b"sqsh") => {
            let little = tail[0] == b'h';
            let rd16 = |i| if little { le16(tail, i) } else { be16(tail, i) };
            let major = rd16(28)?;
            let comp = rd16(20)?;
            if major != 4 || !(1..=6).contains(&comp) {
                return None;
            }
            let used = if little {
                le64(tail, 40)?
            } else {
                be64(tail, 40)?
            };
            let comp = ["gzip", "lzma", "lzo", "xz", "lz4", "zstd"][comp as usize - 1];
            Some(sig(
                o,
                "squashfs",
                "SquashFS filesystem",
                format!(
                    "version 4, {comp}, {}",
                    if little {
                        "little-endian"
                    } else {
                        "big-endian"
                    }
                ),
                Some(used),
            ))
        }
        0x27 if tail.starts_with(&[0x27, 0x05, 0x19, 0x56]) => {
            let os = *tail.get(28)?;
            let arch = *tail.get(29)?;
            let ty = *tail.get(30)?;
            let comp = *tail.get(31)?;
            if ty > 30 || comp > 6 {
                return None;
            }
            let arch = match arch {
                2 => "ARM",
                5 => "MIPS",
                7 => "PowerPC",
                22 => "RISC-V",
                24 => "AArch64",
                _ => "other CPU",
            };
            let os = match os {
                5 => "Linux",
                17 => "U-Boot standalone",
                _ => "other OS",
            };
            let ty = match ty {
                2 => "kernel",
                3 => "ramdisk",
                5 => "firmware",
                _ => "image",
            };
            let name = c_string(tail.get(32..64)?);
            Some(sig(
                o,
                "uimage",
                "U-Boot uImage",
                format!("{os} {arch} {ty} \"{name}\""),
                Some(64 + u64::from(be32(tail, 12)?)),
            ))
        }
        0xd0 if tail.starts_with(&[0xd0, 0x0d, 0xfe, 0xed]) => {
            let total = be32(tail, 4)? as usize;
            let version = be32(tail, 20)?;
            let last_comp = be32(tail, 24)?;
            if !(16..=17).contains(&version) || last_comp > version || total < 40 {
                return None;
            }
            let window = &tail[..total.min(tail.len()).min(1 << 20)];
            let fit = window.windows(7).any(|w| w == b"images\0");
            Some(sig(
                o,
                if fit { "fit" } else { "dtb" },
                if fit { "FIT image" } else { "device tree blob" },
                format!("version {version}"),
                Some(total as u64),
            ))
        }
        0x7f if tail.starts_with(b"\x7fELF") => {
            let (class, data, ver) = (*tail.get(4)?, *tail.get(5)?, *tail.get(6)?);
            if !matches!(class, 1 | 2) || !matches!(data, 1 | 2) || ver != 1 {
                return None;
            }
            let m = if data == 1 {
                le16(tail, 18)?
            } else {
                be16(tail, 18)?
            };
            Some(sig(
                o,
                "elf",
                "ELF file",
                format!("{}-bit {}", if class == 1 { 32 } else { 64 }, machine(m)),
                None,
            ))
        }
        b'M' if tail.starts_with(b"MZ") => {
            let pe = le32(tail, 0x3c)? as usize;
            if !(0x40..=0x1000).contains(&pe) || tail.get(pe..pe + 4)? != b"PE\0\0" {
                return None;
            }
            let m = le16(tail, pe + 4)?;
            let name = match m {
                0x14c => "x86".to_string(),
                0x8664 => "x86-64".into(),
                0x1c0 | 0x1c4 => "ARM".into(),
                0xaa64 => "AArch64".into(),
                _ => format!("machine {m:#x}"),
            };
            Some(sig(o, "pe", "Windows PE image", name, None))
        }
        b':' if o >= hex_until && (o == 0 || d[o - 1] == b'\n') => {
            ihex_line(d, o)?;
            let mut end = o;
            let mut lines = 0;
            while let Some(n) = ihex_line(d, end) {
                end += n;
                lines += 1;
                while matches!(d.get(end), Some(b'\r' | b'\n')) {
                    end += 1;
                }
            }
            Some(sig(
                o,
                "ihex",
                "Intel HEX records",
                format!("{lines} valid lines"),
                Some((end - o) as u64),
            ))
        }
        b'_' if o >= 40 && tail.starts_with(b"_FVH") => {
            // the volume header starts 40 bytes before the signature
            let h = &d[o - 40..];
            let len = le64(h, 32)?;
            let hdr = le16(h, 48)?;
            let rev = *h.get(55)?;
            ((1..=2).contains(&rev) && (0x38..=0x1000).contains(&hdr) && len >= u64::from(hdr))
                .then(|| {
                    sig(
                        o - 40,
                        "uefi_fv",
                        "UEFI firmware volume",
                        format!("revision {rev}"),
                        Some(len),
                    )
                })
        }
        _ => None,
    }
}

/// The first bytes of the magic numbers; every other byte is skipped without a call.
fn first_bytes() -> [bool; 256] {
    let mut t = [false; 256];
    for b in [
        0x1f, 0xfd, 0x5d, b'B', 0x28, b'h', b's', 0x45, 0x27, 0xd0, 0x7f, b'M', b':', b'_',
    ] {
        t[b as usize] = true;
    }
    t
}

fn entropy_tenths(block: &[u8]) -> u8 {
    let mut counts = [0u32; 256];
    for &b in block {
        counts[b as usize] += 1;
    }
    let n = block.len() as f64;
    let e: f64 = counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / n;
            -p * p.log2()
        })
        .sum();
    (e * 10.0).round().min(80.0) as u8
}

fn regions(entropy: &[u8], total: usize) -> Vec<Region> {
    let mut out: Vec<Region> = Vec::new();
    for (i, &e) in entropy.iter().enumerate() {
        let kind = if e < 5 {
            "padding"
        } else if e >= 72 {
            "compressed_or_encrypted"
        } else {
            "code_or_data"
        };
        let offset = (i * ENTROPY_BLOCK) as u64;
        let length = ENTROPY_BLOCK.min(total - i * ENTROPY_BLOCK) as u64;
        match out.last_mut() {
            Some(r) if r.kind == kind => r.length += length,
            _ => out.push(Region {
                offset,
                length,
                kind,
            }),
        }
    }
    out
}

/// Looks for embedded structures and measures entropy over `data`.
pub fn scan(data: &[u8]) -> Scan {
    let table = first_bytes();
    let mut found: BTreeMap<(u64, &'static str), Signature> = BTreeMap::new();
    let mut hex_until = 0usize;
    let mut truncated = false;
    for (o, b) in data.iter().enumerate() {
        if !table[*b as usize] {
            continue;
        }
        if let Some(s) = check(data, o, hex_until) {
            if s.kind == "ihex" {
                hex_until = o + s.size.unwrap_or(0) as usize;
            }
            if found.len() >= MAX_SIGNATURES {
                truncated = true;
                break;
            }
            found.insert((s.offset, s.kind), s);
        }
    }
    let entropy: Vec<u8> = data.chunks(ENTROPY_BLOCK).map(entropy_tenths).collect();
    let regions = regions(&entropy, data.len());
    Scan {
        signatures: found.into_values().collect(),
        truncated,
        entropy,
        regions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gzip() -> Vec<u8> {
        let mut v = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 3];
        v.extend((0..200u32).map(|i| (i * 7919 % 251) as u8));
        v
    }

    #[test]
    fn finds_gzip_and_elf_at_their_offsets() {
        let mut img = vec![0xffu8; 8192];
        img.extend(gzip());
        img.resize(img.len().div_ceil(4096) * 4096, 0);
        let elf_at = img.len();
        let mut elf = vec![0u8; 64];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = 2;
        elf[5] = 1;
        elf[6] = 1;
        elf[18] = 0x3e;
        img.extend(elf);
        let s = scan(&img);
        let kinds: Vec<_> = s.signatures.iter().map(|s| (s.offset, s.kind)).collect();
        assert_eq!(kinds, [(8192, "gzip"), (elf_at as u64, "elf")]);
        assert_eq!(s.signatures[1].detail, "64-bit x86-64");
        assert_eq!(s.regions[0].kind, "padding");
        assert_eq!(s.regions[0].length, 8192);
    }

    #[test]
    fn header_checks_reject_bad_candidates() {
        let mut d = vec![0u8; 64];
        d[..4].copy_from_slice(&[0x1f, 0x8b, 8, 0xe0]);
        assert!(scan(&d).signatures.is_empty());
    }

    #[test]
    fn recognises_ihex_squashfs_and_uimage() {
        let mut d = Vec::new();
        d.extend(b":0400000001020304F2\n:00000001FF\n");
        let hex_len = d.len() as u64;
        d.resize(512, 0);
        let mut sq = vec![0u8; 96];
        sq[..4].copy_from_slice(b"hsqs");
        sq[20] = 4;
        sq[28] = 4;
        let at = d.len();
        d.extend(sq);
        let mut ui = vec![0u8; 64];
        ui[..4].copy_from_slice(&[0x27, 0x05, 0x19, 0x56]);
        ui[12..16].copy_from_slice(&100u32.to_be_bytes());
        ui[28] = 5;
        ui[29] = 2;
        ui[30] = 2;
        ui[32..38].copy_from_slice(b"Linux!");
        let at2 = d.len();
        d.extend(ui);
        let s = scan(&d);
        let got: Vec<_> = s
            .signatures
            .iter()
            .map(|s| (s.offset, s.kind, s.size))
            .collect();
        assert_eq!(
            got,
            [
                (0, "ihex", Some(hex_len)),
                (at as u64, "squashfs", Some(0)),
                (at2 as u64, "uimage", Some(164)),
            ]
        );
        assert!(s.signatures[2].detail.contains("Linux ARM kernel"));
    }

    #[test]
    fn entropy_map_has_one_entry_per_block() {
        let d: Vec<u8> = (0..3 * 4096 + 10u64)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 7) as u8)
            .collect();
        let s = scan(&d);
        assert_eq!(s.entropy.len(), 4);
        assert!(s.entropy[0] >= 70, "{:?}", s.entropy);
    }
}
