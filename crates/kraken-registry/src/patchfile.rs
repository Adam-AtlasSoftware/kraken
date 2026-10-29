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
    Ok((out, applied))
}

#[cfg(test)]
mod tests {
    use super::*;

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
