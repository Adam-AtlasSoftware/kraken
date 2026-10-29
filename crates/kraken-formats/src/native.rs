//! Windows and DOS executables, Mach-O, Java classes.

use crate::{Identified, Loader, rd};

fn pe_machine(m: u16) -> Option<(&'static str, u8, Option<&'static str>, Option<&'static str>)> {
    // name, bits, engine, language
    Some(match m {
        0x14c => ("x86", 32, Some("native"), Some("x86:LE:32:default")),
        0x8664 => ("x86-64", 64, Some("native"), Some("x86:LE:64:default")),
        0x1c0 | 0x1c4 => ("ARM", 32, Some("ghidra"), Some("ARM:LE:32:v8")),
        0xaa64 => ("AArch64", 64, Some("ghidra"), Some("AARCH64:LE:64:v8A")),
        0x200 => ("Itanium", 64, Some("ghidra"), None),
        0x5064 => ("RISC-V", 64, Some("ghidra"), None),
        0x166 => ("MIPS", 32, Some("ghidra"), None),
        0x1f0 | 0x1f1 => ("PowerPC", 32, Some("ghidra"), None),
        _ => return None,
    })
}

pub fn mz(d: &[u8]) -> Option<Identified> {
    if !rd::at(d, 0, b"MZ") {
        return None;
    }
    let dos = || {
        Identified::new("mz", "DOS MZ executable", "dos", "MS-DOS", "executable")
            .cpu("x86", 16, false)
            .loader(Loader::Program)
            .language("x86:LE:16:Real Mode")
    };
    let lfanew = match rd::u32le(d, 0x3c) {
        Some(o) if o >= 0x40 => o as usize,
        _ => return Some(dos()),
    };
    if rd::at(d, lfanew, b"PE\0\0") {
        let machine = rd::u16le(d, lfanew + 4)?;
        let chars = rd::u16le(d, lfanew + 4 + 18).unwrap_or(0);
        let opt = lfanew + 24;
        let magic = rd::u16le(d, opt);
        let subsystem = rd::u16le(d, opt + 68).unwrap_or(0);
        let (name, bits, engine, lang) =
            pe_machine(machine).unwrap_or(("unknown processor", 32, None, None));
        let clr_dir = match magic {
            Some(0x10b) => opt + 96 + 14 * 8,
            Some(0x20b) => opt + 112 + 14 * 8,
            _ => usize::MAX,
        };
        let managed = clr_dir != usize::MAX && rd::u32le(d, clr_dir).is_some_and(|rva| rva != 0);
        let kind = if chars & 0x2000 != 0 {
            "library"
        } else {
            "executable"
        };
        if managed {
            let mut id = Identified::new("dotnet", ".NET assembly", "dotnet", ".NET", kind)
                .cpu(name, bits, false)
                .loader(Loader::Program);
            id.engine = Some("dotnet");
            id.emulators = vec!["wine"];
            return Some(id);
        }
        if (10..=13).contains(&subsystem) {
            let mut id = Identified::new("pe-efi", "UEFI PE image", "uefi", "UEFI firmware", kind)
                .cpu(name, bits, false)
                .loader(Loader::Program)
                .detail("EFI application, driver or runtime driver");
            id.engine = engine;
            id.language = lang;
            return Some(id);
        }
        let mut id = Identified::new("pe", "Windows PE", "windows", "Windows", kind)
            .cpu(name, bits, false)
            .loader(Loader::Program);
        id.engine = engine;
        id.language = lang;
        if matches!(machine, 0x14c | 0x8664) {
            id.emulators = vec!["wine"];
        }
        return Some(id);
    }
    if rd::at(d, lfanew, b"NE") {
        let os = rd::u8(d, lfanew + 0x36).unwrap_or(0);
        let (p, pn) = match os {
            2 => ("windows", "Windows 3.x (16-bit)"),
            1 => ("os2", "OS/2 1.x"),
            _ => ("dos", "MS-DOS / 16-bit"),
        };
        return Some(
            Identified::new("ne", "NE executable", p, pn, "executable")
                .cpu("x86", 16, false)
                .language("x86:LE:16:Protected Mode")
                .loader(Loader::Program),
        );
    }
    if rd::at(d, lfanew, b"LE") || rd::at(d, lfanew, b"LX") {
        return Some(
            Identified::new(
                "le",
                "LE/LX executable",
                "dos",
                "DOS extender or OS/2",
                "executable",
            )
            .cpu("x86", 32, false),
        );
    }
    Some(dos())
}

pub fn macho(d: &[u8]) -> Option<Identified> {
    let magic = rd::u32be(d, 0)?;
    let (bits, big) = match magic {
        0xfeed_face => (32, true),
        0xfeed_facf => (64, true),
        0xcefa_edfe => (32, false),
        0xcffa_edfe => (64, false),
        0xcafe_babe | 0xcafe_babf if rd::u32be(d, 4).is_some_and(|n| (1..45).contains(&n)) => {
            return fat(d, magic == 0xcafe_babf);
        }
        _ => return None,
    };
    let r32 = |o| {
        if big {
            rd::u32be(d, o)
        } else {
            rd::u32le(d, o)
        }
    };
    let cpu = r32(4)?;
    let filetype = r32(12)?;
    let kind = match filetype {
        1 => "object",
        2 => "executable",
        6 | 8 => "library",
        10 => "debug companion",
        11 => "kernel extension",
        _ => "executable",
    };
    let (name, engine) = cpu_name(cpu);
    let mut id = Identified::new("macho", "Mach-O", "macos", "macOS / iOS", kind)
        .cpu(name, bits, big)
        .loader(Loader::Program);
    id.engine = engine;
    Some(id)
}

fn cpu_name(cpu: u32) -> (&'static str, Option<&'static str>) {
    match cpu {
        7 => ("x86", Some("native")),
        0x0100_0007 => ("x86-64", Some("native")),
        12 => ("ARM", Some("native")),
        0x0100_000c => ("AArch64", Some("native")),
        18 => ("PowerPC", Some("ghidra")),
        0x0100_0012 => ("PowerPC 64", Some("ghidra")),
        _ => ("unknown processor", None),
    }
}

fn fat(d: &[u8], wide: bool) -> Option<Identified> {
    let n = rd::u32be(d, 4)? as usize;
    let step = if wide { 32 } else { 20 };
    let mut names = Vec::new();
    for i in 0..n {
        let cpu = rd::u32be(d, 8 + i * step)?;
        names.push(cpu_name(cpu).0);
    }
    let mut id = Identified::new(
        "macho-fat",
        "Mach-O universal binary",
        "macos",
        "macOS / iOS",
        "executable",
    )
    .loader(Loader::Program)
    .detail(format!("{n} slices: {}", names.join(", ")));
    id.engine = Some("native");
    Some(id)
}

pub fn java_class(d: &[u8]) -> Option<Identified> {
    if !rd::at(d, 0, &[0xca, 0xfe, 0xba, 0xbe]) {
        return None;
    }
    let major = rd::u16be(d, 6)?;
    if !(45..=100).contains(&major) {
        return None;
    }
    Some(
        Identified::new(
            "java-class",
            "Java class file",
            "java",
            "Java VM",
            "bytecode",
        )
        .detail(format!(
            "Java {} bytecode (class version {major})",
            major - 44
        )),
    )
}
