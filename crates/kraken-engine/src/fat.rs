//! Universal (fat) Mach-O files: the table of slices at the start of the file, in plain words.
//! `binary_probe`, `project_create` and the native loader share it. Pure and bounded: the count
//! is capped and every slice must lie inside the file, so a damaged table is simply not a table.

use kraken_proto::{ErrorCode, ProtoError};
use serde::{Deserialize, Serialize};

/// `FAT_MAGIC`, also the magic of a Java class file; those have a major version of 45 or more
/// where the slice count is.
const FAT_MAGIC: u32 = 0xcafe_babe;
const FAT_MAGIC_64: u32 = 0xcafe_babf;
/// Java class files start at 45; no universal binary comes close.
const MAX_SLICES: usize = 44;

const CPU_X86: u32 = 7;
const CPU_X86_64: u32 = 0x0100_0007;
const CPU_ARM: u32 = 12;
const CPU_ARM64: u32 = 0x0100_000c;
const CPU_ARM64_32: u32 = 0x0200_000c;
const CPU_PPC: u32 = 18;
const CPU_PPC64: u32 = 0x0100_0012;
const SUBTYPE_MASK: u32 = 0x00ff_ffff;
const SUBTYPE_ARM64E: u32 = 2;

/// One architecture of a universal binary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FatSlice {
    /// The name `project_create` takes: `x86-64`, `arm64`, `arm64e`, ...
    pub arch: String,
    /// The same in plain words: `Intel 64-bit (x86-64)`.
    pub title: String,
    /// Where the slice starts in the file.
    pub offset: u64,
    /// Its size in bytes.
    pub size: u64,
    /// Whether the native engine opens this slice.
    pub supported: bool,
}

fn name_of(cpu: u32, subtype: u32) -> (String, String, bool) {
    let (arch, title, supported) = match (cpu, subtype & SUBTYPE_MASK) {
        (CPU_X86_64, _) => ("x86-64", "Intel 64-bit (x86-64)", true),
        (CPU_ARM64, SUBTYPE_ARM64E) => (
            "arm64e",
            "Apple silicon with pointer signing (arm64e)",
            true,
        ),
        (CPU_ARM64, _) => ("arm64", "Apple silicon (arm64)", true),
        (CPU_X86, _) => ("x86", "Intel 32-bit (x86)", false),
        (CPU_ARM, _) => ("arm", "32-bit ARM", false),
        (CPU_ARM64_32, _) => ("arm64_32", "Apple Watch (arm64_32)", false),
        (CPU_PPC, _) => ("ppc", "PowerPC", false),
        (CPU_PPC64, _) => ("ppc64", "64-bit PowerPC", false),
        _ => {
            return (
                format!("cpu-{cpu:#x}"),
                format!("processor {cpu:#x}"),
                false,
            );
        }
    };
    (arch.to_string(), title.to_string(), supported)
}

/// Whether a file starts like a universal binary; the first eight bytes say.
pub fn is_universal(head: &[u8]) -> bool {
    let word = |o: usize| {
        head.get(o..o + 4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    };
    matches!(word(0), Some(FAT_MAGIC | FAT_MAGIC_64))
        && word(4).is_some_and(|n| (1..=MAX_SLICES as u32).contains(&n))
}

/// The slices of a universal binary; `None` when `data` is not one.
pub fn slices(data: &[u8]) -> Option<Vec<FatSlice>> {
    slices_in(data, data.len() as u64)
}

/// [`slices`] from the start of a file (the table is in the first 4 KiB) of `file_len` bytes.
pub fn slices_in(data: &[u8], file_len: u64) -> Option<Vec<FatSlice>> {
    let word = |o: usize| {
        data.get(o..o + 4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    };
    let long = |o: usize| {
        data.get(o..o + 8)
            .map(|b| u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
    };
    if !is_universal(data) {
        return None;
    }
    let wide = word(0)? == FAT_MAGIC_64;
    let count = word(4)? as usize;
    let step = if wide { 32 } else { 20 };
    let mut out: Vec<FatSlice> = Vec::with_capacity(count);
    for i in 0..count {
        let at = 8 + i * step;
        let (cpu, subtype) = (word(at)?, word(at + 4)?);
        let (offset, size) = if wide {
            (long(at + 8)?, long(at + 16)?)
        } else {
            (u64::from(word(at + 8)?), u64::from(word(at + 12)?))
        };
        if offset.checked_add(size)? > file_len || size == 0 {
            return None;
        }
        let (arch, title, supported) = name_of(cpu, subtype);
        if out.iter().any(|s| s.arch == arch) {
            continue;
        }
        out.push(FatSlice {
            arch,
            title,
            offset,
            size,
            supported,
        });
    }
    Some(out)
}

/// The slice to open: `wanted`, or the only one the native engine opens. Several and no choice
/// is an error that names them, so a person or an agent knows what to pass.
pub fn pick<'a>(all: &'a [FatSlice], wanted: Option<&str>) -> Result<&'a FatSlice, ProtoError> {
    if let Some(w) = wanted {
        let Some(s) = all.iter().find(|s| s.arch.eq_ignore_ascii_case(w)) else {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                format!(
                    "this universal binary has no {w} slice; it holds {}",
                    list(all)
                ),
            ));
        };
        if !s.supported {
            return Err(ProtoError::new(
                ErrorCode::Unsupported,
                format!("KRAKEN does not open the {} slice yet", s.title),
            ));
        }
        return Ok(s);
    }
    let mut open = all.iter().filter(|s| s.supported);
    match (open.next(), open.next()) {
        (Some(s), None) => Ok(s),
        (None, _) => Err(ProtoError::new(
            ErrorCode::Unsupported,
            format!(
                "KRAKEN opens none of the slices of this universal binary: {}",
                list(all)
            ),
        )),
        _ => Err(ProtoError::new(
            ErrorCode::InvalidArgument,
            format!(
                "this universal binary holds {}; say which one with `slice` ({})",
                list(all),
                all.iter()
                    .filter(|s| s.supported)
                    .map(|s| s.arch.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

fn list(all: &[FatSlice]) -> String {
    all.iter()
        .map(|s| s.title.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table(entries: &[(u32, u32, u32, u32)], len: usize) -> Vec<u8> {
        let mut d = vec![0u8; len];
        d[..4].copy_from_slice(&FAT_MAGIC.to_be_bytes());
        d[4..8].copy_from_slice(&(entries.len() as u32).to_be_bytes());
        for (i, e) in entries.iter().enumerate() {
            let at = 8 + i * 20;
            d[at..at + 4].copy_from_slice(&e.0.to_be_bytes());
            d[at + 4..at + 8].copy_from_slice(&e.1.to_be_bytes());
            d[at + 8..at + 12].copy_from_slice(&e.2.to_be_bytes());
            d[at + 12..at + 16].copy_from_slice(&e.3.to_be_bytes());
        }
        d
    }

    #[test]
    fn reads_the_table_in_plain_words() {
        let d = table(
            &[(CPU_X86_64, 3, 0x100, 0x100), (CPU_ARM64, 0, 0x200, 0x100)],
            0x300,
        );
        let s = slices(&d).expect("fat");
        assert_eq!(s[0].arch, "x86-64");
        assert_eq!(s[1].title, "Apple silicon (arm64)");
        assert!(pick(&s, None).unwrap_err().message.contains("arm64"));
        assert_eq!(pick(&s, Some("ARM64")).expect("slice").offset, 0x200);
        assert_eq!(
            pick(&s, Some("ppc")).unwrap_err().code,
            ErrorCode::InvalidArgument
        );
    }

    #[test]
    fn one_supported_slice_needs_no_choice() {
        let d = table(
            &[(CPU_PPC, 0, 0x100, 0x100), (CPU_X86_64, 3, 0x200, 0x100)],
            0x300,
        );
        let s = slices(&d).expect("fat");
        assert_eq!(pick(&s, None).expect("slice").arch, "x86-64");
        assert_eq!(
            pick(&s, Some("ppc")).unwrap_err().code,
            ErrorCode::Unsupported
        );
    }

    #[test]
    fn java_classes_and_damaged_tables_are_not_universal_binaries() {
        // a class file: `cafebabe`, minor 0, major 65 reads as 65 slices
        let mut class = vec![0u8; 64];
        class[..8].copy_from_slice(&[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65]);
        assert!(slices(&class).is_none());
        assert!(slices(&table(&[(CPU_ARM64, 0, 0x100, u32::MAX)], 0x200)).is_none());
        assert!(slices(&[0xca, 0xfe, 0xba, 0xbe]).is_none());
        let count = table(&[(CPU_ARM64, 0, 0x100, 0x10)], 0x200);
        assert!(slices(&count[..12]).is_none());
    }
}
