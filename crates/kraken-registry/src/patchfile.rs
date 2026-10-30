//! Writing a project's byte patches into a copy of its binary.
//!
//! A patch names a virtual address, the bytes that were there (`original`) and the bytes to put
//! in their place (`replacement`). Exporting turns each address into a file offset through the
//! binary's own segments (ELF program headers, PE/Mach-O sections) and overwrites those bytes in
//! a fresh copy of the file; the original file is never touched. The recorded original bytes are
//! checked against the file before anything is written, so a patch that does not line up with the
//! file is refused rather than corrupting it.

use std::fmt;

use object::read::{Object, ObjectSegment};

/// Load base Ghidra and the native engine give a position-independent executable; tried when a
/// patch address does not sit at the file's own virtual addresses.
pub const PIE_BASE: u64 = 0x100000;
/// The native engine's load base for a position-independent 32-bit x86 executable.
pub const PIE_BASE_32: u64 = 0x10000;

/// A byte patch ready to write to a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilePatch {
    /// Virtual address of the first patched byte, as the engine reports it.
    pub address: u64,
    /// The bytes expected at `address`; checked before the patch is applied.
    pub original: Vec<u8>,
    /// The bytes to write there. Always the same length as `original`.
    pub replacement: Vec<u8>,
}

/// Where a patch landed in the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppliedPatch {
    /// The patched virtual address.
    pub address: u64,
    /// The file offset the address mapped to.
    pub file_offset: u64,
    /// Number of bytes written.
    pub len: usize,
}

/// Why a set of patches could not be written to a file.
#[derive(Debug)]
pub enum PatchError {
    /// The bytes are not an object file any segment mapping can be read from.
    NotAnObject(String),
    /// No load base lined every patch up with the file (unmapped address, or the bytes there did
    /// not match what the patch recorded).
    NoMapping(String),
}

impl fmt::Display for PatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PatchError::NotAnObject(m) => {
                write!(
                    f,
                    "the binary is not an object file patches can be mapped onto: {m}"
                )
            }
            PatchError::NoMapping(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for PatchError {}

/// A loadable segment of the file: its virtual address and the file bytes behind it.
struct Segment {
    vaddr: u64,
    file_off: u64,
    file_len: u64,
}

fn segments(image: &[u8]) -> Result<Vec<Segment>, PatchError> {
    let file = object::File::parse(image).map_err(|e| PatchError::NotAnObject(e.to_string()))?;
    let mut segs = Vec::new();
    for seg in file.segments() {
        let (file_off, file_len) = seg.file_range();
        if file_len > 0 {
            segs.push(Segment {
                vaddr: seg.address(),
                file_off,
                file_len,
            });
        }
    }
    Ok(segs)
}

/// The file offset a `[fv, fv+len)` run maps to, if one segment holds all of it on disk and the
/// bytes fit in `image`.
fn offset_of(segs: &[Segment], fv: u64, len: usize, image_len: usize) -> Option<u64> {
    let end = fv.checked_add(len as u64)?;
    for s in segs {
        let seg_end = s.vaddr.checked_add(s.file_len)?;
        if fv >= s.vaddr && end <= seg_end {
            let off = s.file_off.checked_add(fv - s.vaddr)?;
            if off.checked_add(len as u64)? <= image_len as u64 {
                return Some(off);
            }
        }
    }
    None
}

/// Resolves every patch to a file offset under load base `base`, checking the recorded original
/// bytes. `Ok` only when all patches map and match; otherwise a message about the first failure.
fn resolve(
    image: &[u8],
    segs: &[Segment],
    patches: &[FilePatch],
    base: u64,
) -> Result<Vec<AppliedPatch>, String> {
    let mut out = Vec::with_capacity(patches.len());
    for p in patches {
        let fv = p.address.checked_sub(base).ok_or_else(|| {
            format!(
                "address {:#x} is below the load base {:#x}",
                p.address, base
            )
        })?;
        let off = offset_of(segs, fv, p.replacement.len(), image.len()).ok_or_else(|| {
            format!(
                "address {:#x} is not in any part of the file that holds bytes",
                p.address
            )
        })?;
        let here = &image[off as usize..off as usize + p.original.len()];
        if here != p.original.as_slice() {
            return Err(format!(
                "the bytes at {:#x} are not what the patch recorded: expected {}, found {}",
                p.address,
                kraken_proto::hex_bytes(&p.original),
                kraken_proto::hex_bytes(here)
            ));
        }
        out.push(AppliedPatch {
            address: p.address,
            file_offset: off,
            len: p.replacement.len(),
        });
    }
    Ok(out)
}

/// Writes `patches` into a copy of `image` and returns the patched bytes with where each one
/// landed (ordered by address). The load base is found automatically: the file's own virtual
/// addresses first, then the engines' PIE bases.
pub fn patch_file_bytes(
    image: &[u8],
    patches: &[FilePatch],
) -> Result<(Vec<u8>, Vec<AppliedPatch>), PatchError> {
    patch_file_bytes_at(image, patches, None)
}

/// Reads the project's `binary` and applies the project's byte patches for a program the engine
/// loaded at `engine_base`. The one path both `patch_export` and the patched emulator copy use:
/// errors are already protocol errors (`not_found` for an unreadable binary, `unsupported` for a
/// file that is not an object, `invalid_argument` for a patch that does not line up).
pub fn apply_project_patches(
    binary: &std::path::Path,
    patches: &[kraken_model::Patch],
    engine_base: u64,
) -> Result<(Vec<u8>, Vec<AppliedPatch>), kraken_proto::ProtoError> {
    use kraken_proto::{ErrorCode, ProtoError};
    let image = std::fs::read(binary).map_err(|e| {
        ProtoError::new(
            ErrorCode::NotFound,
            format!("cannot read the project's binary {}: {e}", binary.display()),
        )
    })?;
    let file_patches: Vec<FilePatch> = patches
        .iter()
        .map(|p| FilePatch {
            address: p.address,
            original: p.original.clone(),
            replacement: p.replacement.clone(),
        })
        .collect();
    patch_file_bytes_at(&image, &file_patches, Some(engine_base)).map_err(|e| match e {
        PatchError::NotAnObject(_) => ProtoError::new(ErrorCode::Unsupported, e.to_string()),
        PatchError::NoMapping(_) => ProtoError::new(ErrorCode::InvalidArgument, e.to_string()),
    })
}

/// [`patch_file_bytes`] for a program the engine reports loaded at `engine_base` (its image
/// base): the shift from the file's lowest loaded address to it is tried first.
pub fn patch_file_bytes_at(
    image: &[u8],
    patches: &[FilePatch],
    engine_base: Option<u64>,
) -> Result<(Vec<u8>, Vec<AppliedPatch>), PatchError> {
    if patches.is_empty() {
        return Ok((image.to_vec(), Vec::new()));
    }
    let segs = segments(image)?;

    // The shift the engine reports, then the file's own addresses (base 0), then the engines'
    // usual PIE bases. The recorded original bytes have to match under the chosen base, which
    // rejects a wrong one.
    let lowest = segs.iter().map(|s| s.vaddr).min().unwrap_or(0);
    let mut bases: Vec<u64> = engine_base
        .and_then(|b| b.checked_sub(lowest))
        .into_iter()
        .collect();
    for b in [0, PIE_BASE_32, PIE_BASE] {
        if !bases.contains(&b) {
            bases.push(b);
        }
    }
    let mut first_err = None;
    let mut applied = None;
    for base in bases {
        match resolve(image, &segs, patches, base) {
            Ok(a) => {
                applied = Some(a);
                break;
            }
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }
    let mut applied = applied.ok_or_else(|| {
        PatchError::NoMapping(first_err.unwrap_or_else(|| "no patch could be mapped".into()))
    })?;

    let mut out = image.to_vec();
    for (p, a) in patches.iter().zip(&applied) {
        let off = a.file_offset as usize;
        out[off..off + p.replacement.len()].copy_from_slice(&p.replacement);
    }
    applied.sort_by_key(|a| a.address);
    if let Some(h) = pe_headers(&out) {
        let sum = pe_checksum_of(&out, h.checksum_off);
        out[h.checksum_off..h.checksum_off + 4].copy_from_slice(&sum.to_le_bytes());
    }
    Ok((out, applied))
}

fn le16(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// The parts of a PE file's headers the checksum and the lint need.
struct PeHeaders {
    /// File offset of the optional header's `CheckSum` field.
    checksum_off: usize,
    /// File offset of the data directory table.
    dirs_off: usize,
    /// Entries in it.
    dirs: usize,
    /// Sections as (virtual address, virtual size, raw offset, raw size).
    sections: Vec<(u32, u32, u32, u32)>,
}

fn pe_headers(image: &[u8]) -> Option<PeHeaders> {
    if image.get(..2)? != b"MZ" {
        return None;
    }
    let nt = le32(image, 0x3c)? as usize;
    if image.get(nt..nt + 4)? != b"PE\0\0" {
        return None;
    }
    let sections = le16(image, nt + 6)? as usize;
    let opt_size = le16(image, nt + 20)? as usize;
    let opt = nt + 24;
    let dirs_off = opt
        + match le16(image, opt)? {
            0x10b => 96,
            0x20b => 112,
            _ => return None,
        };
    let dirs = (le32(image, dirs_off - 4)? as usize).min(16);
    let mut table = Vec::new();
    for i in 0..sections {
        let at = opt + opt_size + i * 40;
        table.push((
            le32(image, at + 12)?,
            le32(image, at + 8)?,
            le32(image, at + 20)?,
            le32(image, at + 16)?,
        ));
    }
    Some(PeHeaders {
        checksum_off: opt + 64,
        dirs_off,
        dirs,
        sections: table,
    })
}

impl PeHeaders {
    fn dir(&self, image: &[u8], index: usize) -> Option<(u32, u32)> {
        if index >= self.dirs {
            return None;
        }
        let at = self.dirs_off + index * 8;
        Some((le32(image, at)?, le32(image, at + 4)?)).filter(|&(a, s)| a != 0 && s != 0)
    }

    fn rva_to_offset(&self, rva: u32) -> Option<u32> {
        self.sections.iter().find_map(|&(va, _, raw, rs)| {
            (rva >= va && rva - va < rs).then(|| raw.saturating_add(rva - va))
        })
    }
}

/// The PE checksum of `image` as the Windows loader computes it: the 16-bit words summed with
/// the carry folded back in, the `CheckSum` field counted as zero, plus the file length.
fn pe_checksum_of(image: &[u8], checksum_off: usize) -> u32 {
    let mut sum: u64 = 0;
    for (i, chunk) in image.chunks(2).enumerate() {
        let at = i * 2;
        if (checksum_off..checksum_off + 4).contains(&at) {
            continue;
        }
        let word = u64::from(chunk[0]) | chunk.get(1).map_or(0, |&b| u64::from(b) << 8);
        sum += word;
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = (sum & 0xffff) + (sum >> 16);
    (sum + image.len() as u64) as u32
}

/// The checksum a PE file should carry, or `None` when `image` is not a PE file.
pub fn pe_checksum(image: &[u8]) -> Option<u32> {
    pe_headers(image).map(|h| pe_checksum_of(image, h.checksum_off))
}

/// What a lint of the patched file found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageFinding {
    /// `relocation`, `pe_checksum` or `signature`.
    pub kind: &'static str,
    /// The patch (its address) the finding is about, when it is about one.
    pub address: Option<u64>,
    /// Plain-language description.
    pub message: String,
}

/// File ranges the loader rewrites at load time: PE base relocations and ELF dynamic
/// relocations, as (file offset, length, what it is).
fn relocation_slots(image: &[u8]) -> Vec<(u64, u64, String)> {
    use object::read::pe::RelocationBlockIterator;
    let mut out = Vec::new();
    if let Some(h) = pe_headers(image) {
        let Some((rva, size)) = h.dir(image, 5) else {
            return out;
        };
        let Some(off) = h.rva_to_offset(rva) else {
            return out;
        };
        let end = (off as usize)
            .saturating_add(size as usize)
            .min(image.len());
        let mut blocks = RelocationBlockIterator::new(&image[(off as usize).min(end)..end]);
        while let Ok(Some(block)) = blocks.next() {
            for r in block {
                let len = match r.typ.0 {
                    3 => 4,
                    10 => 8,
                    1 | 2 => 2,
                    _ => continue,
                };
                if let Some(at) = h.rva_to_offset(r.virtual_address) {
                    out.push((
                        u64::from(at),
                        len,
                        format!("a base relocation at RVA {:#x}", r.virtual_address),
                    ));
                }
            }
        }
        return out;
    }
    let (Ok(file), Ok(segs)) = (object::File::parse(image), segments(image)) else {
        return out;
    };
    if !matches!(file.format(), object::BinaryFormat::Elf) {
        return out;
    }
    let word = if file.is_64() { 8 } else { 4 };
    for (vaddr, rel) in file.dynamic_relocations().into_iter().flatten() {
        let len = match rel.size() {
            0 => word,
            bits => u64::from(bits) / 8,
        };
        if let Some(at) = offset_of(&segs, vaddr, len as usize, image.len()) {
            out.push((at, len, format!("a dynamic relocation at {vaddr:#x}")));
        }
    }
    out
}

/// Warnings about patches `applied` to `image` that the bytes alone show: patches over a slot
/// the loader rewrites, and for a PE file the checksum and any Authenticode signature.
pub fn image_findings(image: &[u8], applied: &[AppliedPatch]) -> Vec<ImageFinding> {
    let mut out = Vec::new();
    let slots = relocation_slots(image);
    for a in applied {
        let (lo, hi) = (a.file_offset, a.file_offset + a.len as u64);
        for (at, len, what) in &slots {
            if lo < at + len && *at < hi {
                out.push(ImageFinding {
                    kind: "relocation",
                    address: Some(a.address),
                    message: format!(
                        "the patch at {:#x} overlaps {what}: the loader overwrites those bytes \
                         at start-up, so the patch will not take effect there",
                        a.address
                    ),
                });
                break;
            }
        }
    }
    if let Some(h) = pe_headers(image)
        && !applied.is_empty()
    {
        if let Some(stored) = le32(image, h.checksum_off).filter(|&c| c != 0) {
            let right = pe_checksum_of(image, h.checksum_off);
            out.push(ImageFinding {
                kind: "pe_checksum",
                address: None,
                message: if stored == right {
                    format!(
                        "the PE checksum ({stored:#x}) is set and goes stale with any patch; \
                         patch_export recomputes it"
                    )
                } else {
                    format!(
                        "the PE checksum field ({stored:#x}) is set but already wrong \
                         (expected {right:#x}); patch_export writes the right one"
                    )
                },
            });
        }
        if h.dir(image, 4).is_some() {
            out.push(ImageFinding {
                kind: "signature",
                address: None,
                message: "the file carries an Authenticode signature; any patch invalidates it \
                          (it is left in place, not stripped)"
                    .into(),
            });
        }
    }
    out
}

/// The reverse of the export mapping: file offsets to the addresses the engine shows them at.
/// Used to bring patches from a patch file (which speaks in file offsets) into the project.
pub struct OffsetMap {
    segs: Vec<Segment>,
    shift: u64,
}

impl OffsetMap {
    /// Reads the segments of `image`; `engine_base` is the program's load base in the engine.
    pub fn new(image: &[u8], engine_base: u64) -> Result<OffsetMap, PatchError> {
        let segs = segments(image)?;
        let lowest = segs.iter().map(|s| s.vaddr).min().unwrap_or(0);
        let shift = engine_base.saturating_sub(lowest);
        Ok(OffsetMap { segs, shift })
    }

    /// The address of file offset `offset` and how many of the next `len` bytes lie in the same
    /// loaded segment (at least one), or `None` when the offset is not loaded memory.
    pub fn address(&self, offset: u64, len: u64) -> Option<(u64, u64)> {
        for s in &self.segs {
            let end = s.file_off.checked_add(s.file_len)?;
            if offset >= s.file_off && offset < end {
                let within = offset - s.file_off;
                let addr = s.vaddr.checked_add(within)?.checked_add(self.shift)?;
                return Some((addr, len.min(end - offset)));
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus_pe(name: &str) -> Vec<u8> {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/pe/bin")
            .join(name);
        std::fs::read(p).expect("corpus binary")
    }

    #[test]
    fn the_pe_checksum_matches_the_linkers_value_and_is_recomputed_on_export() {
        // Values from an independent implementation (the linker's own field, which agrees).
        let dll = corpus_pe("win_dll-x64-O0.dll");
        assert_eq!(pe_checksum(&dll), Some(0x12eb2));
        assert_eq!(pe_checksum(&corpus_pe("win_dll-x86-O0.dll")), Some(0x1297f));
        assert_eq!(
            pe_checksum(&corpus_pe("switch_vm-x64-O0.exe")),
            Some(0x1f087)
        );

        // Patching a code byte makes the stored value stale; export fixes it.
        let off = 0x400usize;
        let patch = FilePatch {
            address: 0x2ca150000 + 0x1000,
            original: dll[off..off + 1].to_vec(),
            replacement: vec![dll[off] ^ 0xff],
        };
        let (out, _) = patch_file_bytes(&dll, &[patch]).expect("patched");
        let h = pe_headers(&out).expect("pe");
        let stored = le32(&out, h.checksum_off).expect("field");
        assert_eq!(Some(stored), pe_checksum(&out));
        assert_ne!(stored, 0x12eb2, "the sum changed with the byte");
    }

    #[test]
    fn a_patch_on_a_base_relocation_slot_is_flagged_and_a_clean_one_is_not() {
        let dll = corpus_pe("win_dll-x64-O0.dll");
        let slot = AppliedPatch {
            address: 0x2ca153010,
            file_offset: 0x1a10,
            len: 4,
        };
        let f = image_findings(&dll, &[slot]);
        let rel: Vec<_> = f.iter().filter(|f| f.kind == "relocation").collect();
        assert_eq!(rel.len(), 1, "{f:?}");
        assert!(rel[0].message.contains("0x2ca153010"), "{f:?}");
        assert!(f.iter().any(|f| f.kind == "pe_checksum"), "{f:?}");
        assert!(!f.iter().any(|f| f.kind == "signature"), "{f:?}");

        let clean = AppliedPatch {
            address: 0x2ca151000,
            file_offset: 0x400,
            len: 2,
        };
        let f = image_findings(&dll, &[clean]);
        assert!(!f.iter().any(|f| f.kind == "relocation"), "{f:?}");
        let before = AppliedPatch {
            address: 0,
            file_offset: 0x1a0e,
            len: 2,
        };
        assert!(
            image_findings(&dll, &[before])
                .iter()
                .all(|f| f.kind != "relocation")
        );
    }

    #[test]
    fn an_elf_dynamic_relocation_slot_is_flagged() {
        let p = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../corpus/bin/stripped_calc-O0");
        let elf = std::fs::read(p).expect("corpus binary");
        // R_X86_64_RELATIVE at 0x3da0 (file offset 0x2da0) and a GLOB_DAT at 0x3fb8 (0x2fb8).
        for (off, flagged) in [
            (0x2da0u64, true),
            (0x2da4, true),
            (0x2fb8, true),
            (0x2da8, true),
            (0x1446, false),
        ] {
            let a = AppliedPatch {
                address: off + 0x400000,
                file_offset: off,
                len: 4,
            };
            let hit = image_findings(&elf, &[a])
                .iter()
                .any(|f| f.kind == "relocation");
            assert_eq!(hit, flagged, "offset {off:#x}");
        }
        // Just before the first slot of the table (0x2d98 is the previous 8-byte slot, 0x2d9c its
        // upper half), so 0x2d98..0x2d9c is covered too, but the bytes before it are not.
        let before = AppliedPatch {
            address: 0,
            file_offset: 0x2d88,
            len: 4,
        };
        assert!(
            image_findings(&elf, &[before])
                .iter()
                .all(|f| f.kind != "relocation")
        );
    }

    #[test]
    fn an_authenticode_directory_is_reported() {
        let mut dll = corpus_pe("win_dll-x64-O0.dll");
        let h = pe_headers(&dll).expect("pe");
        let at = h.dirs_off + 4 * 8;
        dll[at..at + 4].copy_from_slice(&0x1000u32.to_le_bytes());
        dll[at + 4..at + 8].copy_from_slice(&0x200u32.to_le_bytes());
        let p = AppliedPatch {
            address: 0x2ca151000,
            file_offset: 0x400,
            len: 1,
        };
        assert!(
            image_findings(&dll, &[p])
                .iter()
                .any(|f| f.kind == "signature")
        );
    }

    // A tiny ET_EXEC ELF64 with one PT_LOAD at vaddr 0x400000 covering the whole file.
    fn elf_exec() -> Vec<u8> {
        let mut e = vec![0u8; 0x200];
        e[..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
        e[4] = 2; // ELFCLASS64
        e[5] = 1; // little-endian
        e[6] = 1; // version
        let put16 =
            |e: &mut [u8], off: usize, v: u16| e[off..off + 2].copy_from_slice(&v.to_le_bytes());
        let put32 =
            |e: &mut [u8], off: usize, v: u32| e[off..off + 4].copy_from_slice(&v.to_le_bytes());
        let put64 =
            |e: &mut [u8], off: usize, v: u64| e[off..off + 8].copy_from_slice(&v.to_le_bytes());
        put16(&mut e, 16, 2); // e_type = ET_EXEC
        put16(&mut e, 18, 0x3e); // e_machine = x86-64
        put32(&mut e, 20, 1); // e_version
        put64(&mut e, 32, 0x40); // e_phoff
        put16(&mut e, 52, 64); // e_ehsize
        put16(&mut e, 54, 56); // e_phentsize
        put16(&mut e, 56, 1); // e_phnum
        // One program header at 0x40.
        let ph = 0x40;
        put32(&mut e, ph, 1); // PT_LOAD
        put32(&mut e, ph + 4, 5); // flags r-x
        put64(&mut e, ph + 8, 0); // p_offset
        put64(&mut e, ph + 16, 0x400000); // p_vaddr
        put64(&mut e, ph + 24, 0x400000); // p_paddr
        put64(&mut e, ph + 32, 0x200); // p_filesz
        put64(&mut e, ph + 40, 0x200); // p_memsz
        // Some code bytes to patch at offset 0x100 (vaddr 0x400100).
        e[0x100..0x104].copy_from_slice(&[0x74, 0x10, 0x90, 0x90]);
        e
    }

    /// [`elf_exec`] as a position-independent file: ET_DYN loaded at vaddr 0.
    fn elf_pie() -> Vec<u8> {
        let mut e = elf_exec();
        e[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        e[0x40 + 16..0x40 + 24].copy_from_slice(&0u64.to_le_bytes()); // p_vaddr
        e[0x40 + 24..0x40 + 32].copy_from_slice(&0u64.to_le_bytes()); // p_paddr
        e
    }

    #[test]
    fn a_pie_maps_at_either_engine_base_or_the_one_reported() {
        let image = elf_pie();
        for base in [PIE_BASE_32, PIE_BASE, 0x5555_0000] {
            let patches = vec![FilePatch {
                address: base + 0x100,
                original: vec![0x74, 0x10],
                replacement: vec![0xeb, 0x10],
            }];
            let hint = (base == 0x5555_0000).then_some(base);
            let (out, applied) = patch_file_bytes_at(&image, &patches, hint)
                .unwrap_or_else(|e| panic!("{base:#x}: {e}"));
            assert_eq!(applied[0].file_offset, 0x100, "{base:#x}");
            assert_eq!(&out[0x100..0x102], &[0xeb, 0x10]);
        }
        // An unusual base needs the hint.
        let far = vec![FilePatch {
            address: 0x5555_0100,
            original: vec![0x74, 0x10],
            replacement: vec![0xeb, 0x10],
        }];
        assert!(patch_file_bytes(&image, &far).is_err());
    }

    #[test]
    fn maps_address_to_offset_and_writes() {
        let image = elf_exec();
        let patches = vec![FilePatch {
            address: 0x400100,
            original: vec![0x74, 0x10],
            replacement: vec![0xeb, 0x10],
        }];
        let (out, applied) = patch_file_bytes(&image, &patches).expect("apply");
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].file_offset, 0x100);
        assert_eq!(&out[0x100..0x104], &[0xeb, 0x10, 0x90, 0x90]);
        // The original file is untouched.
        assert_eq!(&image[0x100..0x102], &[0x74, 0x10]);
    }

    #[test]
    fn wrong_original_is_refused() {
        let image = elf_exec();
        let patches = vec![FilePatch {
            address: 0x400100,
            original: vec![0x00, 0x00], // not what is there
            replacement: vec![0xeb, 0x10],
        }];
        let err = patch_file_bytes(&image, &patches).expect_err("mismatch");
        assert!(matches!(err, PatchError::NoMapping(_)), "{err}");
    }

    #[test]
    fn unmapped_address_is_refused() {
        let image = elf_exec();
        let patches = vec![FilePatch {
            address: 0x900000,
            original: vec![0x00],
            replacement: vec![0x01],
        }];
        let err = patch_file_bytes(&image, &patches).expect_err("unmapped");
        assert!(matches!(err, PatchError::NoMapping(_)), "{err}");
    }

    #[test]
    fn pie_base_fallback() {
        // Same file read as if the engine loaded it at the PIE base: the patch address carries
        // the 0x10000 base on top of the file's own 0x400100.
        let image = elf_exec();
        let patches = vec![FilePatch {
            address: 0x400100 + PIE_BASE_32,
            original: vec![0x74, 0x10],
            replacement: vec![0x90, 0x90],
        }];
        let (out, applied) = patch_file_bytes(&image, &patches).expect("apply at pie base");
        assert_eq!(applied[0].file_offset, 0x100);
        assert_eq!(&out[0x100..0x102], &[0x90, 0x90]);
    }

    #[test]
    fn empty_is_a_plain_copy() {
        let image = elf_exec();
        let (out, applied) = patch_file_bytes(&image, &[]).expect("copy");
        assert_eq!(out, image);
        assert!(applied.is_empty());
    }

    #[test]
    fn not_an_object_is_reported() {
        let err = patch_file_bytes(
            b"not an elf at all",
            &[FilePatch {
                address: 0,
                original: vec![0],
                replacement: vec![1],
            }],
        )
        .expect_err("garbage");
        assert!(matches!(err, PatchError::NotAnObject(_)), "{err}");
    }
}
