//! ELF files, and the console variants that wear an ELF header.

use crate::{Identified, Loader, rd};

const SCE_TYPES: u16 = 0xFE00;

/// Processor name and the engine that reads it.
fn machine_name(m: u16) -> (&'static str, Option<&'static str>) {
    match m {
        3 => ("x86", Some("native")),
        62 => ("x86-64", Some("native")),
        40 => ("ARM", Some("native")),
        183 => ("AArch64", Some("native")),
        243 => ("RISC-V", Some("native")),
        8 => ("MIPS", Some("ghidra")),
        20 => ("PowerPC", Some("ghidra")),
        21 => ("PowerPC 64", Some("ghidra")),
        2 => ("SPARC", Some("ghidra")),
        43 => ("SPARC V9", Some("ghidra")),
        22 => ("s390", Some("ghidra")),
        4 => ("Motorola 68000", Some("ghidra")),
        42 => ("SuperH", Some("ghidra")),
        94 => ("Xtensa", Some("ghidra")),
        164 => ("Hexagon", Some("ghidra")),
        258 => ("LoongArch", Some("ghidra")),
        247 => ("BPF", None),
        _ => ("unknown processor", None),
    }
}

fn language_for(machine: u16, bits: u8, big: bool) -> Option<&'static str> {
    Some(match (machine, bits, big) {
        (62, 64, false) => "x86:LE:64:default",
        (3, 32, false) => "x86:LE:32:default",
        (183, 64, false) => "AARCH64:LE:64:v8A",
        (40, 32, false) => "ARM:LE:32:v8",
        (243, 64, false) => "RISCV:LE:64:RV64IC",
        (8, 32, false) => "MIPS:LE:32:default",
        (8, 32, true) => "MIPS:BE:32:default",
        (20, 32, true) => "PowerPC:BE:32:default",
        (21, 64, true) => "PowerPC:BE:64:default",
        _ => return None,
    })
}

pub fn elf(d: &[u8]) -> Option<Identified> {
    if !rd::at(d, 0, b"\x7fELF") {
        return None;
    }
    let bits: u8 = match rd::u8(d, 4)? {
        1 => 32,
        2 => 64,
        _ => return None,
    };
    let big = match rd::u8(d, 5)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let osabi = rd::u8(d, 7)?;
    let r16 = |o| {
        if big {
            rd::u16be(d, o)
        } else {
            rd::u16le(d, o)
        }
    };
    let r32 = |o| {
        if big {
            rd::u32be(d, o)
        } else {
            rd::u32le(d, o)
        }
    };
    let e_type = r16(16)?;
    let machine = r16(18)?;
    let flags = r32(if bits == 32 { 36 } else { 48 })?;
    let (name, engine) = machine_name(machine);

    let mk = |format, format_name, platform, platform_name, kind| {
        Identified::new(format, format_name, platform, platform_name, kind).cpu(name, bits, big)
    };

    // consoles first: their ELF headers carry vendor markers
    if osabi == 0xCA && machine == 20 {
        return Some(
            mk(
                "rpx",
                "Wii U RPX/RPL",
                "wiiu",
                "Nintendo Wii U",
                "executable",
            )
            .run_with(&["cemu"])
            .detail("sections are zlib-compressed; Cemu runs it"),
        );
    }
    if machine == 62 && e_type >= SCE_TYPES {
        let kind = match e_type {
            0xFE10 | 0xFE00 => "executable",
            0xFE18 => "library",
            _ => "module",
        };
        let mut id = mk("sce-elf", "SCE ELF", "ps4", "PlayStation 4/5", kind)
            .run_with(&["shadps4"])
            .loader(Loader::Program)
            .language("x86:LE:64:default")
            .detail(format!("SCE type {e_type:#x}"));
        id.engine = Some("native");
        return Some(id);
    }
    if machine == 40 && e_type >= SCE_TYPES {
        return Some(
            mk(
                "sce-elf",
                "SCE ELF",
                "vita",
                "PlayStation Vita",
                "executable",
            )
            .loader(Loader::Program)
            .language("ARM:LE:32:v7")
            .detail(format!("SCE type {e_type:#x}")),
        );
    }
    if machine == 21 && osabi == 0x66 {
        return Some(
            mk("elf", "PS3 ELF", "ps3", "PlayStation 3", "executable")
                .run_with(&["rpcs3"])
                .loader(Loader::Program)
                .language("PowerPC:BE:64:default"),
        );
    }
    if machine == 8 && bits == 32 && !big {
        if flags & 0x00FF_0000 == 0x0092_0000 {
            return Some(
                mk("elf", "PS2 ELF", "ps2", "PlayStation 2", "executable")
                    .run_with(&["pcsx2"])
                    .loader(Loader::Program)
                    .detail("Emotion Engine (R5900) code"),
            );
        }
        if (0xFF80..=0xFF9F).contains(&e_type) {
            let what = if e_type == 0xFF80 {
                "IOP module"
            } else {
                "EE module"
            };
            return Some(
                mk("irx", "PS2 IRX", "ps2", "PlayStation 2", "module")
                    .run_with(&["pcsx2"])
                    .loader(Loader::Program)
                    .detail(what),
            );
        }
        if e_type == 0xFFA0 {
            return Some(
                mk("prx", "PSP PRX", "psp", "PlayStation Portable", "module")
                    .run_with(&["ppsspp"])
                    .loader(Loader::Program)
                    .language("MIPS:LE:32:default"),
            );
        }
    }

    let (platform, platform_name) = match osabi {
        0 | 3 => ("linux", "Linux / Unix"),
        9 => ("freebsd", "FreeBSD"),
        12 => ("openbsd", "OpenBSD"),
        2 => ("netbsd", "NetBSD"),
        6 => ("solaris", "Solaris"),
        _ => ("elf", "ELF system"),
    };
    // e_type 3 is both PIE programs and shared libraries; `binary_probe` tells them apart
    let kind = match e_type {
        1 => "object",
        4 => "core",
        _ => "executable",
    };
    let mut id = mk("elf", "ELF", platform, platform_name, kind).loader(Loader::Program);
    id.language = language_for(machine, bits, big);
    id.engine = engine;
    let qemu = match (machine, bits) {
        (62, 64) => Some("qemu-user-x86-64"),
        (183, 64) => Some("qemu-user-aarch64"),
        (40, 32) => Some("qemu-user-arm"),
        (243, 64) => Some("qemu-user-riscv64"),
        _ => None,
    };
    if let Some(q) = qemu
        && platform == "linux"
        && kind == "executable"
    {
        id.emulators.push(q);
    }
    Some(id)
}
