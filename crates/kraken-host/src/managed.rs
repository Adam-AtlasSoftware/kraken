//! Telling .NET assemblies from native binaries: a PE file whose CLR runtime header data
//! directory is set (ECMA-335 II.25.3.3) is a managed assembly.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

/// Index of the CLR runtime header in the PE data directories.
const CLR_DIRECTORY: u64 = 14;
const MAGIC_PE32: u16 = 0x10b;
const MAGIC_PE32_PLUS: u16 = 0x20b;

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

/// True when `head` (the start of a file; 4 KiB is enough for sane images, the PE header may sit
/// anywhere below that) is a PE image with a CLI header. `read_at` fetches more bytes when the
/// PE header lies beyond `head`.
fn parse(head: &[u8], read_at: &mut dyn FnMut(u64, usize) -> io::Result<Vec<u8>>) -> bool {
    if head.get(..2) != Some(b"MZ") {
        return false;
    }
    let Some(pe_off) = u32_at(head, 0x3c).map(u64::from) else {
        return false;
    };
    // Signature (4) + COFF header (20) + the optional header up to the data directories.
    const NEEDED: usize = 4 + 20 + 112 + 16 * 8;
    let Ok(hdr) = read_at(pe_off, NEEDED) else {
        return false;
    };
    if hdr.get(..4) != Some(b"PE\0\0") {
        return false;
    }
    let opt = 4 + 20;
    let (dirs, count_at) = match u16_at(&hdr, opt) {
        Some(MAGIC_PE32) => (opt + 96, opt + 92),
        Some(MAGIC_PE32_PLUS) => (opt + 112, opt + 108),
        _ => return false,
    };
    let size_of_opt = u16_at(&hdr, 4 + 16).map_or(0, usize::from);
    let count = u32_at(&hdr, count_at).map_or(0, u64::from);
    if count <= CLR_DIRECTORY || size_of_opt < (dirs - opt) + (CLR_DIRECTORY as usize + 1) * 8 {
        return false;
    }
    let at = dirs + CLR_DIRECTORY as usize * 8;
    matches!((u32_at(&hdr, at), u32_at(&hdr, at + 4)), (Some(rva), Some(size)) if rva != 0 && size != 0)
}

/// True when the file at `path` is a .NET assembly (a PE image with a CLI header). Unreadable
/// and non-PE files are not; the engine reports those itself.
pub fn is_managed_assembly(path: &Path) -> bool {
    let Ok(mut f) = File::open(path) else {
        return false;
    };
    let mut head = vec![0u8; 0x40];
    let n = f.read(&mut head).unwrap_or(0);
    head.truncate(n);
    parse(&head, &mut |off, len| {
        f.seek(SeekFrom::Start(off))?;
        let mut buf = Vec::new();
        f.by_ref().take(len as u64).read_to_end(&mut buf)?;
        Ok(buf)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal PE image; `clr` is the (rva, size) of the CLR directory.
    fn pe(plus: bool, dirs: u32, clr: (u32, u32)) -> Vec<u8> {
        let pe_off = 0x80usize;
        let opt_len = if plus { 112 } else { 96 } + 16 * 8;
        let mut b = vec![0u8; pe_off + 24 + opt_len];
        b[..2].copy_from_slice(b"MZ");
        b[0x3c..0x40].copy_from_slice(&(pe_off as u32).to_le_bytes());
        b[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
        b[pe_off + 20..pe_off + 22].copy_from_slice(&(opt_len as u16).to_le_bytes());
        let opt = pe_off + 24;
        let magic = if plus { MAGIC_PE32_PLUS } else { MAGIC_PE32 };
        b[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
        let (count_at, dir_at) = if plus {
            (opt + 108, opt + 112)
        } else {
            (opt + 92, opt + 96)
        };
        b[count_at..count_at + 4].copy_from_slice(&dirs.to_le_bytes());
        let at = dir_at + 14 * 8;
        b[at..at + 4].copy_from_slice(&clr.0.to_le_bytes());
        b[at + 4..at + 8].copy_from_slice(&clr.1.to_le_bytes());
        b
    }

    fn check(bytes: &[u8]) -> bool {
        let dir = tempfile::tempdir().expect("tempdir");
        let p = dir.path().join("x.bin");
        std::fs::write(&p, bytes).expect("write");
        is_managed_assembly(&p)
    }

    #[test]
    fn a_pe_with_a_clr_directory_is_managed() {
        assert!(check(&pe(false, 16, (0x2008, 0x48))));
        assert!(check(&pe(true, 16, (0x2008, 0x48))));
    }

    #[test]
    fn native_pes_and_other_files_are_not() {
        assert!(!check(&pe(false, 16, (0, 0))));
        assert!(!check(&pe(true, 14, (0x2008, 0x48))));
        assert!(!check(b"\x7fELF\x02\x01\x01"));
        assert!(!check(b"MZ"));
        assert!(!check(&[]));
        let mut bad_sig = pe(true, 16, (1, 1));
        bad_sig[0x80] = b'X';
        assert!(!check(&bad_sig));
        let mut huge_offset = pe(true, 16, (1, 1));
        huge_offset[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(!check(&huge_offset));
        assert!(!is_managed_assembly(Path::new("/nonexistent/kraken/x.dll")));
    }

    #[test]
    fn the_dotnet_corpus_assembly_is_managed() {
        let dll =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/dotnet/bin/kraken-corpus.dll");
        assert!(is_managed_assembly(&dll));
    }
}
