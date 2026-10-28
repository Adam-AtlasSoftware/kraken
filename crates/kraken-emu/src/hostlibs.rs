//! A private sysroot made from this computer's own libraries, for a dynamically linked program
//! built for the host when no extracted sysroot exists. Only the program's interpreter and the
//! shared libraries it names (and the ones those name, transitively) are copied into a fresh
//! directory; the guest sees that directory as `/` and nothing else of the host. Libraries a
//! program opens by name at run time (`dlopen`, NSS modules, gconv) are not there.

use std::collections::{BTreeSet, VecDeque};
use std::path::{Path, PathBuf};

use object::Endianness;
use object::elf;
use object::read::elf::{Dyn as _, FileHeader, ProgramHeader as _};

use crate::arch::Arch;
use crate::error::EmuError;

/// Most libraries copied for one program.
const MAX_LIBRARIES: usize = 512;
/// Most bytes copied for one program.
const MAX_BYTES: u64 = 1 << 30;

/// What [`private_sysroot`] copied.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostLibs {
    /// Sonames of the libraries copied.
    pub libraries: Vec<String>,
    /// Sonames the program needs that this computer does not have for its architecture.
    pub missing: Vec<String>,
}

/// The directories the dynamic loader searches by default for `arch`, across distributions
/// (Arch and Fedora style, Debian multiarch). Each copied library is placed in all of them, so
/// the host loader finds it whichever its built-in list is.
fn search_dirs(arch: Arch) -> &'static [&'static str] {
    match arch {
        Arch::X86_64 => &[
            "/lib64",
            "/usr/lib64",
            "/lib/x86_64-linux-gnu",
            "/usr/lib/x86_64-linux-gnu",
            "/lib",
            "/usr/lib",
        ],
        Arch::X86 => &[
            "/lib32",
            "/usr/lib32",
            "/lib/i386-linux-gnu",
            "/usr/lib/i386-linux-gnu",
            "/lib",
            "/usr/lib",
        ],
        _ => &[],
    }
}

/// Builds the private sysroot for `program` (interpreter `interp`, architecture `arch`) in
/// `dest`, which should be an empty directory.
pub fn private_sysroot(
    program: &Path,
    interp: &str,
    arch: Arch,
    dest: &Path,
) -> Result<HostLibs, EmuError> {
    let io = |what: &Path, e: std::io::Error| EmuError::Io(format!("{}: {e}", what.display()));
    if !interp.starts_with('/') {
        return Err(EmuError::Unsupported(format!(
            "the program's interpreter {interp} is not an absolute path"
        )));
    }
    let mut budget = MAX_BYTES;
    let host_interp = std::fs::canonicalize(interp).map_err(|e| io(Path::new(interp), e))?;
    copy_into(&host_interp, &guest_path(dest, interp), &mut budget)?;

    let data = std::fs::read(program).map_err(|e| io(program, e))?;
    let mut queue: VecDeque<String> = needed(&data).into();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut out = HostLibs::default();
    while let Some(name) = queue.pop_front() {
        if !seen.insert(name.clone()) {
            continue;
        }
        if name.contains('/') || name.is_empty() {
            out.missing.push(name);
            continue;
        }
        if out.libraries.len() >= MAX_LIBRARIES {
            return Err(EmuError::Unsupported(format!(
                "the program needs more than {MAX_LIBRARIES} shared libraries"
            )));
        }
        let Some(host) = find(&name, arch) else {
            out.missing.push(name);
            continue;
        };
        let lib = std::fs::read(&host).map_err(|e| io(&host, e))?;
        let dirs = search_dirs(arch);
        let first = guest_path(dest, &format!("{}/{name}", dirs[0]));
        copy_into(&host, &first, &mut budget)?;
        for d in &dirs[1..] {
            let p = guest_path(dest, &format!("{d}/{name}"));
            if let Some(parent) = p.parent() {
                std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
            }
            if std::fs::hard_link(&first, &p).is_err() {
                copy_into(&host, &p, &mut budget)?;
            }
        }
        queue.extend(needed(&lib));
        out.libraries.push(name);
    }
    Ok(out)
}

fn guest_path(dest: &Path, guest: &str) -> PathBuf {
    dest.join(guest.trim_start_matches('/'))
}

fn copy_into(host: &Path, to: &Path, budget: &mut u64) -> Result<(), EmuError> {
    let len = std::fs::metadata(host)
        .map_err(|e| EmuError::Io(format!("{}: {e}", host.display())))?
        .len();
    *budget = budget.checked_sub(len).ok_or_else(|| {
        EmuError::Unsupported("the program's shared libraries are larger than 1 GiB".into())
    })?;
    if let Some(parent) = to.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| EmuError::Io(format!("{}: {e}", parent.display())))?;
    }
    std::fs::copy(host, to).map_err(|e| EmuError::Io(format!("{}: {e}", host.display())))?;
    Ok(())
}

/// The host file of library `name` for `arch`, if one of the search directories has it.
fn find(name: &str, arch: Arch) -> Option<PathBuf> {
    search_dirs(arch).iter().find_map(|d| {
        let p = Path::new(d).join(name);
        let head = read_head(&p)?;
        (Arch::from_elf(&head).ok()? == arch).then(|| std::fs::canonicalize(&p).ok())?
    })
}

fn read_head(p: &Path) -> Option<Vec<u8>> {
    use std::io::Read;
    let mut f = std::fs::File::open(p).ok()?;
    if !f.metadata().ok()?.is_file() {
        return None;
    }
    let mut b = vec![0u8; 64];
    let n = f.read(&mut b).ok()?;
    b.truncate(n);
    Some(b)
}

/// The `DT_NEEDED` sonames of an ELF file (empty for a static or unreadable one).
pub fn needed(data: &[u8]) -> Vec<String> {
    match data.get(4) {
        Some(2) => needed_of::<elf::FileHeader64<Endianness>>(data),
        Some(1) => needed_of::<elf::FileHeader32<Endianness>>(data),
        _ => None,
    }
    .unwrap_or_default()
}

fn needed_of<H: FileHeader<Endian = Endianness>>(data: &[u8]) -> Option<Vec<String>> {
    let h = H::parse(data).ok()?;
    let e = h.endian().ok()?;
    let mut dynamic = None;
    let mut loads: Vec<(u64, u64, u64)> = Vec::new();
    for ph in h.program_headers(e, data).ok()? {
        match ph.p_type(e) {
            elf::PT_DYNAMIC => dynamic = ph.dynamic(e, data).ok().flatten(),
            elf::PT_LOAD => loads.push((
                ph.p_vaddr(e).into(),
                ph.p_offset(e).into(),
                ph.p_filesz(e).into(),
            )),
            _ => {}
        }
    }
    let file_offset = |addr: u64| {
        loads
            .iter()
            .find_map(|&(va, off, sz)| (addr >= va && addr - va < sz).then(|| off + (addr - va)))
    };
    let mut strtab = None;
    let mut names = Vec::new();
    for d in dynamic? {
        let tag: u64 = d.d_tag(e).into();
        let val: u64 = d.d_val(e).into();
        match tag as u32 {
            elf::DT_NULL => break,
            elf::DT_STRTAB => strtab = file_offset(val),
            elf::DT_NEEDED => names.push(val),
            _ => {}
        }
    }
    let base = usize::try_from(strtab?).ok()?;
    Some(
        names
            .into_iter()
            .filter_map(|o| {
                let start = base.checked_add(usize::try_from(o).ok()?)?;
                let rest = data.get(start..)?;
                let end = rest.iter().position(|b| *b == 0)?;
                Some(String::from_utf8_lossy(&rest[..end]).into_owned())
            })
            .collect(),
    )
}

#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
mod tests {
    use super::*;

    #[test]
    fn only_the_programs_libraries_are_copied() {
        let exe = std::env::current_exe().unwrap();
        let data = std::fs::read(&exe).unwrap();
        let Some(interp) = crate::loader::parse_elf(&data).unwrap().interp else {
            eprintln!("skipping: the test binary is statically linked");
            return;
        };
        let names = needed(&data);
        assert!(names.iter().any(|n| n.starts_with("libc.so")), "{names:?}");

        let dest = tempfile::tempdir().unwrap();
        let libs = private_sysroot(&exe, &interp, Arch::X86_64, dest.path()).unwrap();
        assert!(libs.libraries.iter().any(|n| n.starts_with("libc.so")));
        assert!(guest_path(dest.path(), &interp).is_file());
        for d in search_dirs(Arch::X86_64) {
            assert!(guest_path(dest.path(), &format!("{d}/libc.so.6")).is_file());
        }
        assert!(!dest.path().join("etc").exists());
        assert!(!dest.path().join("home").exists());
    }

    #[test]
    fn a_static_file_needs_nothing() {
        assert!(needed(b"\x7fELF\x02\x01\x01").is_empty());
        assert!(needed(b"not an elf").is_empty());
    }
}
