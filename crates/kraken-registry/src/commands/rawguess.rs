//! Raw-image heuristics for `binary_probe`: what a file with no known container may be, by the
//! well-known layouts of firmware and ROM images. Pure functions over the file's bytes.

use kraken_proto::Hex64;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// One way to open an unrecognised file as a raw image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RawSuggestion {
    /// Value for `project_create`'s `language` (a short name such as `cortex-m`).
    pub language: String,
    /// Value for `base`: where the image is meant to live in memory.
    pub base: Hex64,
    /// Value for `offset` when a header comes first; absent when the image starts at byte 0.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<Hex64>,
    /// Value for `entry`, when the layout says where execution starts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<Hex64>,
    /// `high` (a structure that is hard to match by chance), `medium` or `low` (a guess).
    pub confidence: String,
    /// What was recognised, in a sentence.
    pub why: String,
}

/// The suggestions for `data`, most likely first; empty when nothing matches.
pub fn guess(data: &[u8]) -> Vec<RawSuggestion> {
    let mut out = Vec::new();
    out.extend(uimage(data));
    out.extend(arm64_image(data));
    out.extend(cortex_m(data));
    out.extend(x86_reset(data));
    out.sort_by_key(|s| match s.confidence.as_str() {
        "high" => 0,
        "medium" => 1,
        _ => 2,
    });
    out
}

/// The suggestions for the blocks of a firmware record file: the layouts are looked for in the
/// first block, and the base is where that block really is.
pub fn guess_blocks(blocks: &[(u64, Vec<u8>)]) -> Vec<RawSuggestion> {
    let Some((start, data)) = blocks.first() else {
        return Vec::new();
    };
    let mut out = guess(data);
    out.retain(|s| s.base.0 == *start || s.language == "cortex-m");
    for s in &mut out {
        s.base = Hex64(*start);
    }
    out
}

/// What a container with no loader is, when its magic number says (the person has to unpack or
/// convert it first).
pub fn container_hint(data: &[u8]) -> Option<&'static str> {
    let starts = |m: &[u8]| data.starts_with(m);
    Some(if starts(&[0x1f, 0x8b]) {
        "gzip-compressed data: unpack it (gunzip) and open what is inside"
    } else if starts(b"PK\x03\x04") {
        "a ZIP archive: unpack it and open what is inside"
    } else if starts(b"BZh") {
        "bzip2-compressed data: unpack it first"
    } else if starts(&[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        "xz-compressed data: unpack it first"
    } else if starts(b"7z\xbc\xaf\x27\x1c") {
        "a 7-Zip archive: unpack it first"
    } else if starts(b"hsqs") || starts(b"sqsh") {
        "a SquashFS file system: extract it (unsquashfs) and open the programs inside"
    } else if starts(&[0x45, 0x3d, 0xcd, 0x28]) {
        "a cramfs file system: extract it first"
    } else if starts(b"UBI#") {
        "a UBI flash image: extract its volumes first"
    } else if starts(&[0x85, 0x19]) || starts(&[0x19, 0x85]) {
        "a JFFS2 flash file system: extract it first"
    } else if starts(b":")
        && data
            .get(1..10)
            .is_some_and(|h| h.iter().all(|b| b.is_ascii_hexdigit()))
    {
        "Intel HEX text: convert it (objcopy -I ihex -O binary) and open the binary as raw"
    } else if starts(b"S0") || starts(b"S1") || starts(b"S3") {
        "Motorola S-record text: convert it (objcopy -I srec -O binary) and open the binary as raw"
    } else {
        return None;
    })
}

fn be32(d: &[u8], at: usize) -> Option<u32> {
    d.get(at..at + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn le32(d: &[u8], at: usize) -> Option<u32> {
    d.get(at..at + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

/// A U-Boot legacy image: a 64-byte header (big endian) with the load address, the entry point
/// and the CPU architecture.
fn uimage(d: &[u8]) -> Option<RawSuggestion> {
    if be32(d, 0)? != 0x2705_1956 || d.len() < 64 {
        return None;
    }
    let (load, entry) = (be32(d, 16)?, be32(d, 20)?);
    let language = match d[28] {
        2 => "arm",
        3 => "x86",
        5 => "mipsel",
        7 => "ppc",
        22 => "aarch64",
        26 => "riscv32",
        _ => return None,
    };
    // compressed payloads (compression type at byte 31) cannot be read as code
    if d[31] != 0 {
        return None;
    }
    Some(RawSuggestion {
        language: language.into(),
        base: Hex64(u64::from(load)),
        offset: Some(Hex64(64)),
        entry: Some(Hex64(u64::from(entry))),
        confidence: "high".into(),
        why: format!(
            "U-Boot uImage header: {language} code loaded at {load:#x}, entry {entry:#x}, \
             payload after the 64-byte header"
        ),
    })
}

/// The Linux arm64 `Image` header: `ARM\x64` at byte 56 and the load offset at byte 8.
fn arm64_image(d: &[u8]) -> Option<RawSuggestion> {
    if d.get(56..60)? != b"ARM\x64" {
        return None;
    }
    let text_offset = u64::from(le32(d, 8)?);
    Some(RawSuggestion {
        language: "aarch64".into(),
        base: Hex64(text_offset),
        offset: None,
        entry: Some(Hex64(text_offset)),
        confidence: "high".into(),
        why: "Linux arm64 Image header (`ARM\\x64` magic): AArch64 code from byte 0".into(),
    })
}

/// Bases real Cortex-M parts map their flash at, most common first.
const FLASH_BASES: [u64; 8] = [
    0x0800_0000, // STM32
    0x0000_0000, // NXP, Nordic, RP2040 boot ROM, remapped images
    0x1000_0000, // RP2040 XIP, Kinetis
    0x0001_0000,
    0x0000_8000,
    0x0200_0000,
    0x6000_0000,
    0x0c00_0000,
];

/// An ARM Cortex-M vector table at the start: an initial stack pointer in RAM and handlers with
/// the Thumb bit set that all point into the image.
fn cortex_m(d: &[u8]) -> Option<RawSuggestion> {
    if d.len() < 64 {
        return None;
    }
    let sp = le32(d, 0)?;
    let reset = le32(d, 4)?;
    if sp & 3 != 0 || !(0x1000_0000..0xE000_0000).contains(&sp) || reset & 1 == 0 {
        return None;
    }
    // exception vectors 1..16: handlers (odd) or reserved zeros; anything else is no table
    let mut handlers = Vec::new();
    for i in 1..16 {
        let v = le32(d, i * 4)?;
        match v {
            0 => {}
            v if v & 1 == 1 => handlers.push(u64::from(v & !1)),
            _ => return None,
        }
    }
    let size = d.len() as u64;
    let (lo, hi) = (*handlers.iter().min()?, *handlers.iter().max()?);
    let base = FLASH_BASES
        .iter()
        .copied()
        .find(|b| *b <= lo && hi < b + size)
        .or_else(|| (hi - lo < size).then_some(lo & !0xfff))?;
    let distinct = {
        let mut h = handlers.clone();
        h.sort_unstable();
        h.dedup();
        h.len()
    };
    let reset = u64::from(reset);
    // a reset handler past the vector table, inside the image
    if reset & !1 < base + 0x40 || reset & !1 >= base + size {
        return None;
    }
    Some(RawSuggestion {
        language: "cortex-m".into(),
        base: Hex64(base),
        offset: None,
        entry: Some(Hex64(reset)),
        confidence: if distinct >= 2 { "high" } else { "medium" }.into(),
        why: format!(
            "ARM Cortex-M vector table: initial stack pointer {sp:#x}, reset handler {reset:#x}, \
             {} exception handlers inside the image",
            handlers.len()
        ),
    })
}

/// A firmware or BIOS image whose last 16 bytes are the x86 reset vector: a jump (`EA` far,
/// `E9` or `EB` near) at 0xFFFFFFF0, or at 0xFFFF0 for a 1 MiB real-mode map.
fn x86_reset(d: &[u8]) -> Option<RawSuggestion> {
    let n = d.len();
    if n < 0x1000 || !n.is_power_of_two() && !n.is_multiple_of(0x1000) {
        return None;
    }
    let jump = *d.get(n - 16)?;
    if !(0xE9..=0xEB).contains(&jump) {
        return None;
    }
    // classic BIOS: far jump plus an `MM/DD/YY` build date at 0xFFFF5
    let date = &d[n - 11..n - 3];
    let has_date = date[2] == b'/'
        && date[5] == b'/'
        && date
            .iter()
            .enumerate()
            .all(|(i, b)| i == 2 || i == 5 || b.is_ascii_digit());
    if jump == 0xEA && has_date && n <= 0x10_0000 {
        let base = 0x10_0000 - n as u64;
        return Some(RawSuggestion {
            language: "x86-16".into(),
            base: Hex64(base),
            offset: None,
            entry: Some(Hex64(0x10_0000 - 16)),
            confidence: "high".into(),
            why: "BIOS image: a far jump at the reset vector (last 16 bytes) and a build date; \
                  real-mode x86 mapped to end at 1 MiB"
                .into(),
        });
    }
    if n >= 0x1_0000 && n.is_power_of_two() && n as u64 <= 1 << 32 {
        let base = (1u64 << 32) - n as u64;
        return Some(RawSuggestion {
            language: "x86".into(),
            base: Hex64(base),
            offset: None,
            entry: Some(Hex64((1u64 << 32) - 16)),
            confidence: "low".into(),
            why: "a power-of-two image with a jump at the x86 reset vector (last 16 bytes): \
                  firmware mapped to end at 4 GiB (32-bit protected mode; the reset code itself \
                  starts in real mode)"
                .into(),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cortex_blob() -> Vec<u8> {
        let mut b = Vec::new();
        for w in [
            0x2000_8000u32,
            0x0800_00ddu32,
            0x0800_008bu32,
            0x0800_008b,
            0x0800_008b,
        ] {
            b.extend(w.to_le_bytes());
        }
        b.resize(0x100, 0);
        b
    }

    #[test]
    fn cortex_m_vector_table_is_recognised() {
        let s = guess(&cortex_blob());
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].language, "cortex-m");
        assert_eq!(s[0].base, Hex64(0x0800_0000));
        assert_eq!(s[0].entry, Some(Hex64(0x0800_00dd)));
        assert_eq!(s[0].confidence, "high");
    }

    #[test]
    fn random_bytes_are_not_a_table() {
        assert!(guess(&[0x55u8; 256]).is_empty());
        assert!(guess(&[0u8; 256]).is_empty());
    }

    #[test]
    fn uimage_gives_load_address_and_offset() {
        let mut h = vec![0u8; 128];
        h[..4].copy_from_slice(&0x2705_1956u32.to_be_bytes());
        h[16..20].copy_from_slice(&0x8000_8000u32.to_be_bytes());
        h[20..24].copy_from_slice(&0x8000_8040u32.to_be_bytes());
        h[28] = 2;
        let s = guess(&h);
        assert_eq!(s[0].language, "arm");
        assert_eq!(s[0].base, Hex64(0x8000_8000));
        assert_eq!(s[0].offset, Some(Hex64(64)));
        assert_eq!(s[0].entry, Some(Hex64(0x8000_8040)));
    }

    #[test]
    fn bios_reset_vector_maps_the_image_to_the_end_of_1_mib() {
        let mut b = vec![0u8; 0x10000];
        let n = b.len();
        b[n - 16] = 0xEA;
        b[n - 11..n - 3].copy_from_slice(b"10/28/26");
        let s = guess(&b);
        assert_eq!(s[0].language, "x86-16");
        assert_eq!(s[0].base, Hex64(0xF0000));
        assert_eq!(s[0].entry, Some(Hex64(0xFFFF0)));
    }

    #[test]
    fn containers_are_named() {
        assert!(
            container_hint(&[0x1f, 0x8b, 8, 0])
                .unwrap()
                .contains("gzip")
        );
        assert!(
            container_hint(b":10010000214601360121470136007EFE09D2190140")
                .unwrap()
                .contains("Intel HEX")
        );
        assert!(container_hint(b"hello world").is_none());
    }
}
