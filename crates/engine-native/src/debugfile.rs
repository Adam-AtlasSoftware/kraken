//! Separate debug files of ELF programs: the file a stripped program names with
//! `.gnu_debuglink` (and its CRC-32), or the one its GNU build-id selects, looked for where GDB
//! looks: next to the program, in its `.debug/` directory, under `/usr/lib/debug` (by directory
//! and by build-id). A candidate counts only when it proves to be the program's own: the same
//! build-id, or the CRC the link names. A PE image names its PDB in the CodeView record of its
//! debug directory; [`find`] looks for it beside the image (under that name, then under the
//! image's own) and accepts it when its GUID is the image's.

use std::path::{Path, PathBuf};

use object::Object;

/// Where distributions install debug packages.
const SYSTEM_DEBUG_DIR: &str = "/usr/lib/debug";
/// A debug file larger than this is not read.
const MAX_DEBUG_FILE: u64 = 2 << 30;

/// What a program says about its separate debug file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    /// The GNU build-id, when the program has one.
    pub build_id: Option<Vec<u8>>,
    /// The `.gnu_debuglink` file name and CRC-32.
    pub link: Option<(String, u32)>,
}

/// What `data` (an ELF program) wants; `None` when it carries its own DWARF or names nothing.
pub fn wanted(data: &[u8]) -> Option<Wanted> {
    let file = object::File::parse(data).ok()?;
    if file.format() != object::BinaryFormat::Elf || file.section_by_name(".debug_info").is_some() {
        return None;
    }
    let build_id = file.build_id().ok().flatten().map(<[u8]>::to_vec);
    let link = file
        .gnu_debuglink()
        .ok()
        .flatten()
        .map(|(n, crc)| (String::from_utf8_lossy(n).into_owned(), crc));
    (build_id.is_some() || link.is_some()).then_some(Wanted { build_id, link })
}

/// The places a debug file may be, best first.
pub fn candidates(binary: &Path, w: &Wanted) -> Vec<PathBuf> {
    candidates_in(binary, w, Path::new(SYSTEM_DEBUG_DIR))
}

fn candidates_in(binary: &Path, w: &Wanted, system: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let dir = binary.parent().map(Path::to_path_buf).unwrap_or_default();
    if let Some(id) = &w.build_id
        && id.len() > 1
    {
        let hex: String = id.iter().map(|b| format!("{b:02x}")).collect();
        let rel = format!(".build-id/{}/{}.debug", &hex[..2], &hex[2..]);
        out.push(dir.join(&rel));
        out.push(system.join(&rel));
    }
    if let Some((name, _)) = &w.link
        && !name.is_empty()
        && !name.contains('/')
    {
        out.push(dir.join(name));
        out.push(dir.join(".debug").join(name));
        // /usr/lib/debug/<directory of the program>/<name>
        let abs = dir.canonicalize().unwrap_or(dir);
        out.push(
            system
                .join(abs.strip_prefix("/").unwrap_or(&abs))
                .join(name),
        );
    }
    out
}

/// The separate debug file of the program at `binary` with contents `data`, if one is installed.
pub fn find(binary: &Path, data: &[u8]) -> Option<PathBuf> {
    if let Some(pdb) = find_pdb(binary, data) {
        return Some(pdb);
    }
    let w = wanted(data)?;
    find_wanted(binary, &w, Path::new(SYSTEM_DEBUG_DIR))
}

/// The PDB beside the PE image `data` at `binary`: the CodeView name, then `<stem>.pdb`.
pub fn find_pdb(binary: &Path, data: &[u8]) -> Option<PathBuf> {
    let file = object::File::parse(data).ok()?;
    if file.format() != object::BinaryFormat::Pe {
        return None;
    }
    let info = file.pdb_info().ok().flatten()?;
    let guid = info.guid();
    let dir = binary.parent().map(Path::to_path_buf).unwrap_or_default();
    let named = String::from_utf8_lossy(info.path());
    let named = named
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .to_string();
    let mut names = Vec::new();
    if !named.is_empty() && !named.contains("..") {
        names.push(named);
    }
    if let Some(stem) = binary.file_stem() {
        let mut n = stem.to_os_string();
        n.push(".pdb");
        names.push(n.to_string_lossy().into_owned());
    }
    for name in names {
        let path = dir.join(name);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.len() > crate::pdbinfo::MAX_PDB_BYTES {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if crate::pdbinfo::identity(&bytes).is_some_and(|(g, age)| g == guid && age >= info.age()) {
            return Some(path);
        }
    }
    None
}

fn find_wanted(binary: &Path, w: &Wanted, system: &Path) -> Option<PathBuf> {
    for path in candidates_in(binary, w, system) {
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if !meta.is_file() || meta.len() > MAX_DEBUG_FILE {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        if matches_wanted(&bytes, w) {
            return Some(path);
        }
    }
    None
}

/// Whether `candidate` is the debug file `w` asks for.
fn matches_wanted(candidate: &[u8], w: &Wanted) -> bool {
    let Ok(file) = object::File::parse(candidate) else {
        return false;
    };
    if let Some(id) = &w.build_id
        && let Ok(Some(theirs)) = file.build_id()
    {
        return theirs == id.as_slice();
    }
    match &w.link {
        Some((_, crc)) => crc32(candidate) == *crc,
        None => false,
    }
}

/// CRC-32 (IEEE, as `.gnu_debuglink` stores it).
pub fn crc32(data: &[u8]) -> u32 {
    let mut table = [0u32; 256];
    for (i, slot) in table.iter_mut().enumerate() {
        let mut c = i as u32;
        for _ in 0..8 {
            c = if c & 1 != 0 {
                0xedb8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
        }
        *slot = c;
    }
    !data.iter().fold(!0u32, |c, b| {
        table[((c ^ u32::from(*b)) & 0xff) as usize] ^ (c >> 8)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_the_standard_check_value() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn candidates_follow_gdb_order() {
        let w = Wanted {
            build_id: Some(vec![0xab, 0xcd, 0xef]),
            link: Some(("prog.debug".into(), 1)),
        };
        let c = candidates_in(
            Path::new("/opt/app/bin/prog"),
            &w,
            Path::new("/usr/lib/debug"),
        );
        let c: Vec<String> = c.iter().map(|p| p.display().to_string()).collect();
        assert_eq!(c[0], "/opt/app/bin/.build-id/ab/cdef.debug");
        assert_eq!(c[1], "/usr/lib/debug/.build-id/ab/cdef.debug");
        assert_eq!(c[2], "/opt/app/bin/prog.debug");
        assert_eq!(c[3], "/opt/app/bin/.debug/prog.debug");
        assert!(c[4].ends_with("opt/app/bin/prog.debug") && c[4].starts_with("/usr/lib/debug/"));
        // a link name with a slash is not followed
        let w = Wanted {
            build_id: None,
            link: Some(("../x".into(), 1)),
        };
        assert!(candidates_in(Path::new("/a/b"), &w, Path::new("/d")).is_empty());
    }
}
