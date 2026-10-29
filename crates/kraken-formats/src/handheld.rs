//! Console executables and cartridge ROMs.

use crate::{Confidence, Identified, Loader, kib, rd};

const SNES_EMU: &[&str] = &["ares", "mame"];

pub fn xbe(d: &[u8]) -> Option<Identified> {
    if !rd::at(d, 0, b"XBEH") {
        return None;
    }
    let base = rd::u32le(d, 0x104)?;
    let sections = rd::u32le(d, 0x11c).unwrap_or(0);
    Some(
        Identified::new("xbe", "XBE", "xbox", "Original Xbox", "executable")
            .cpu("x86", 32, false)
            .language("x86:LE:32:default")
            .run_with(&["xemu"])
            .detail(format!(
                "base {base:#x}, {sections} sections; the entry point is obfuscated"
            )),
    )
}

pub fn xex(d: &[u8]) -> Option<Identified> {
    let v = if rd::at(d, 0, b"XEX2") {
        2
    } else if rd::at(d, 0, b"XEX1") {
        1
    } else {
        return None;
    };
    let mut enc = None;
    let mut comp = None;
    let count = rd::u32be(d, 0x14).unwrap_or(0).min(256) as usize;
    for i in 0..count {
        let o = 0x18 + i * 8;
        if rd::u32be(d, o) == Some(0x3ff)
            && let Some(info) = rd::u32be(d, o + 4)
        {
            let info = info as usize;
            enc = rd::u16be(d, info.saturating_add(4));
            comp = rd::u16be(d, info.saturating_add(6));
        }
    }
    let comp_name = match comp {
        Some(0) => "uncompressed",
        Some(1) => "basic compression",
        Some(2) => "LZX compression",
        Some(3) => "delta compression",
        _ => "compression unknown",
    };
    let mut id = Identified::new(
        if v == 2 { "xex2" } else { "xex1" },
        if v == 2 { "XEX2" } else { "XEX1" },
        "xbox360",
        "Xbox 360",
        "executable",
    )
    .cpu("PowerPC (Xenon)", 64, true)
    .run_with(&["xenia-canary"])
    .detail(comp_name);
    if enc.is_some_and(|e| e != 0) {
        id = id.encrypted();
    }
    Some(id)
}

pub fn sce(d: &[u8]) -> Option<Identified> {
    if rd::at(d, 0, &[0x4f, 0x15, 0x3d, 0x1d]) {
        return Some(
            Identified::new("self", "PS4 SELF", "ps4", "PlayStation 4", "executable")
                .cpu("x86-64", 64, false)
                .run_with(&["shadps4"])
                .encrypted()
                .detail("signed container around an ELF; open the decrypted ELF instead"),
        );
    }
    if rd::at(d, 0, &[0x54, 0x14, 0xf5, 0xee]) {
        return Some(
            Identified::new("self", "PS5 SELF", "ps5", "PlayStation 5", "executable")
                .cpu("x86-64", 64, false)
                .encrypted()
                .detail("signed and encrypted"),
        );
    }
    if rd::at(d, 0, b"SCE\0") {
        let ver = rd::u32be(d, 4)?;
        return Some(match ver {
            2 => Identified::new("self", "PS3 SELF", "ps3", "PlayStation 3", "executable")
                .cpu("PowerPC 64", 64, true)
                .run_with(&["rpcs3"])
                .encrypted()
                .detail("signed container around an ELF; open the decrypted ELF instead"),
            3 => Identified::new(
                "self",
                "Vita SELF",
                "vita",
                "PlayStation Vita",
                "executable",
            )
            .cpu("ARM", 32, false)
            .encrypted()
            .detail("signed and encrypted"),
            _ => Identified::new("self", "SCE SELF", "sony", "PlayStation", "executable")
                .encrypted()
                .detail(format!("SCE header version {ver}")),
        });
    }
    if rd::at(d, 0, b"~PSP") {
        return Some(
            Identified::new(
                "prx",
                "PSP PRX (encrypted)",
                "psp",
                "PlayStation Portable",
                "module",
            )
            .cpu("MIPS (Allegrex)", 32, false)
            .run_with(&["ppsspp"])
            .encrypted(),
        );
    }
    None
}

pub fn pbp(d: &[u8]) -> Option<Identified> {
    if !rd::at(d, 0, b"\0PBP") {
        return None;
    }
    let data_psp = rd::u32le(d, 0x20)? as usize;
    let enc = rd::at(d, data_psp, b"~PSP");
    let elf = rd::at(d, data_psp, b"\x7fELF");
    let mut id = Identified::new(
        "pbp",
        "PSP EBOOT.PBP",
        "psp",
        "PlayStation Portable",
        "container",
    )
    .cpu("MIPS (Allegrex)", 32, false)
    .run_with(&["ppsspp"]);
    if enc {
        id = id.encrypted().detail("DATA.PSP is an encrypted PRX");
    } else if elf {
        id = id.detail("DATA.PSP is a plain ELF");
    }
    Some(id)
}

pub fn psx_exe(d: &[u8]) -> Option<Identified> {
    if !rd::at(d, 0, b"PS-X EXE") {
        return None;
    }
    let pc = rd::u32le(d, 0x10)?;
    let addr = rd::u32le(d, 0x18)?;
    let size = rd::u32le(d, 0x1c)?;
    Some(
        Identified::new("ps-exe", "PS-X EXE", "ps1", "PlayStation", "executable")
            .cpu("MIPS R3000", 32, false)
            .language("MIPS:LE:32:default")
            .loader(Loader::Raw)
            .run_with(&["duckstation", "ares"])
            .detail(format!(
                "entry {pc:#x}, text {} at {addr:#x} (header is 0x800 bytes)",
                kib(size as u64)
            )),
    )
}

pub fn nes(d: &[u8]) -> Option<Identified> {
    if !rd::at(d, 0, b"NES\x1a") {
        return None;
    }
    let (b4, b5, b6, b7) = (rd::u8(d, 4)?, rd::u8(d, 5)?, rd::u8(d, 6)?, rd::u8(d, 7)?);
    let v2 = b7 & 0x0c == 0x08;
    let mut mapper = (b6 >> 4) as u32 | (b7 & 0xf0) as u32;
    let (mut prg, mut chr) = (b4 as u64 * 16384, b5 as u64 * 8192);
    if v2 {
        let b8 = rd::u8(d, 8).unwrap_or(0);
        let b9 = rd::u8(d, 9).unwrap_or(0);
        mapper |= ((b8 & 0x0f) as u32) << 8;
        if b9 & 0x0f != 0x0f {
            prg = ((b9 & 0x0f) as u64) << 8 | b4 as u64;
            prg *= 16384;
        }
        if b9 >> 4 != 0x0f {
            chr = ((b9 >> 4) as u64) << 8 | b5 as u64;
            chr *= 8192;
        }
    }
    Some(
        Identified::new(
            if v2 { "nes2" } else { "ines" },
            if v2 { "NES 2.0 ROM" } else { "iNES ROM" },
            "nes",
            "Nintendo Entertainment System",
            "rom",
        )
        .cpu("MOS 6502 (2A03)", 8, false)
        .language("6502:LE:16:default")
        .run_with(SNES_EMU)
        .detail(format!(
            "mapper {mapper}, PRG {}, CHR {}",
            kib(prg),
            if chr == 0 {
                "RAM".to_string()
            } else {
                kib(chr)
            }
        )),
    )
}

pub fn switch(d: &[u8]) -> Option<Identified> {
    let mk = |f, n, k| {
        Identified::new(f, n, "switch", "Nintendo Switch", k)
            .cpu("AArch64", 64, false)
            .run_with(&["ryubing"])
    };
    if rd::at(d, 0, b"NSO0") {
        return Some(mk("nso", "NSO", "executable").detail("segments are LZ4-compressed"));
    }
    if rd::at(d, 0x10, b"NRO0") {
        return Some(mk("nro", "NRO", "executable"));
    }
    if rd::at(d, 0, b"KIP1") {
        return Some(mk("kip", "KIP (kernel initial process)", "module"));
    }
    if rd::at(d, 0, b"PFS0") {
        return Some(mk("nsp", "NSP (PFS0 archive)", "container").detail("holds NCA files"));
    }
    if rd::at(d, 0x100, b"HEAD") && d.len() >= 0x200 {
        return Some(mk("xci", "XCI game card image", "container"));
    }
    if rd::at(d, 0x200, b"NCA2") || rd::at(d, 0x200, b"NCA3") {
        return Some(mk("nca", "NCA (decrypted header)", "container").encrypted());
    }
    None
}

const GBA_LOGO: [u8; 12] = [
    0x24, 0xff, 0xae, 0x51, 0x69, 0x9a, 0xa2, 0x21, 0x3d, 0x84, 0x82, 0x0a,
];

pub fn gba(d: &[u8]) -> Option<Identified> {
    if d.len() < 0xc0 || !rd::at(d, 4, &GBA_LOGO) || rd::u8(d, 0xb2)? != 0x96 {
        return None;
    }
    let sum = d
        .get(0xa0..0xbd)?
        .iter()
        .fold(0u8, |a, &b| a.wrapping_sub(b));
    let ok = sum.wrapping_sub(0x19) == rd::u8(d, 0xbd)?;
    let title = rd::ascii(d, 0xa0, 12).unwrap_or_default();
    let code = rd::ascii(d, 0xac, 4)
        .filter(|c| !c.is_empty())
        .map(|c| format!(" {c}"))
        .unwrap_or_default();
    Some(
        Identified::new("gba", "GBA ROM", "gba", "Game Boy Advance", "rom")
            .cpu("ARM7TDMI", 32, false)
            .language("ARM:LE:32:v4t")
            .loader(Loader::Raw)
            .run_with(&["mgba", "ares"])
            .detail(format!(
                "\"{title}\"{code}, loads at 0x08000000{}",
                if ok { "" } else { " (header checksum off)" }
            )),
    )
}

pub fn nds(d: &[u8]) -> Option<Identified> {
    if d.len() < 0x200 || rd::u16le(d, 0x15c)? != 0xcf56 {
        return None;
    }
    let arm9 = rd::u32le(d, 0x20)?;
    let entry9 = rd::u32le(d, 0x24)?;
    let ram9 = rd::u32le(d, 0x28)?;
    let unit = rd::u8(d, 0x12)?;
    let title = rd::ascii(d, 0, 12).unwrap_or_default();
    Some(
        Identified::new("nds", "NDS ROM", "nds", "Nintendo DS", "rom")
            .cpu("ARM946E-S + ARM7TDMI", 32, false)
            .language("ARM:LE:32:v5t")
            .loader(Loader::Raw)
            .run_with(&["melonds"])
            .detail(format!(
                "\"{title}\"{}, ARM9 at file {arm9:#x} loads {ram9:#x}, entry {entry9:#x}",
                if unit & 2 != 0 { ", DSi-enhanced" } else { "" }
            )),
    )
}

pub fn gameboy(d: &[u8]) -> Option<Identified> {
    if !rd::at(d, 0x104, &[0xce, 0xed, 0x66, 0x66, 0xcc, 0x0d, 0x00, 0x0b]) {
        return None;
    }
    let sum = d
        .get(0x134..0x14d)?
        .iter()
        .fold(0u8, |a, &b| a.wrapping_sub(b).wrapping_sub(1));
    let cgb = matches!(rd::u8(d, 0x143)?, 0x80 | 0xc0);
    let title = rd::ascii(d, 0x134, 11).unwrap_or_default();
    let mut id = Identified::new(
        if cgb { "gbc" } else { "gb" },
        if cgb {
            "Game Boy Color ROM"
        } else {
            "Game Boy ROM"
        },
        "gb",
        "Game Boy",
        "rom",
    )
    .cpu("Sharp SM83", 8, false)
    .run_with(&["mgba", "ares"])
    .detail(format!("\"{title}\""));
    if sum != rd::u8(d, 0x14d)? {
        id = id.confidence(Confidence::Medium);
    }
    Some(id)
}

pub fn n64(d: &[u8]) -> Option<Identified> {
    let head: [u8; 4] = rd::bytes(d, 0)?;
    let (fmt, name, order) = match head {
        [0x80, 0x37, 0x12, 0x40] => ("z64", "N64 ROM (z64, big endian)", 0),
        [0x37, 0x80, 0x40, 0x12] => ("v64", "N64 ROM (v64, byte-swapped)", 1),
        [0x40, 0x12, 0x37, 0x80] => ("n64", "N64 ROM (n64, little endian)", 2),
        _ => return None,
    };
    // the title sits at 0x20 in z64 order
    let title = (|| {
        let raw = d.get(0x20..0x34)?;
        let mut t = Vec::with_capacity(20);
        for c in raw.chunks(4) {
            let w: [u8; 4] = c.try_into().ok()?;
            let w = match order {
                0 => w,
                1 => [w[1], w[0], w[3], w[2]],
                _ => [w[3], w[2], w[1], w[0]],
            };
            t.extend_from_slice(&w);
        }
        let end = t
            .iter()
            .rposition(|&b| b != 0 && b != b' ')
            .map_or(0, |i| i + 1);
        t.truncate(end);
        t.iter()
            .all(|b| (0x20..0x7f).contains(b))
            .then(|| String::from_utf8_lossy(&t).into_owned())
    })()
    .unwrap_or_default();
    Some(
        Identified::new(fmt, name, "n64", "Nintendo 64", "rom")
            .cpu("MIPS VR4300", 64, true)
            .language("MIPS:BE:64:64-32addr")
            .run_with(SNES_EMU)
            .detail(format!("\"{title}\"; swap to z64 order before loading")),
    )
}

pub fn snes(d: &[u8]) -> Option<Identified> {
    let copier = if d.len() % 1024 == 512 { 512 } else { 0 };
    for (off, name, hi) in [
        (0x7fc0usize, "LoROM", false),
        (0xffc0, "HiROM", true),
        (0x40ffc0, "ExHiROM", true),
    ] {
        let b = copier + off;
        let (Some(map), Some(cs), Some(inv), Some(reset)) = (
            rd::u8(d, b + 0x15),
            rd::u16le(d, b + 0x1e),
            rd::u16le(d, b + 0x1c),
            rd::u16le(d, b + 0x3c),
        ) else {
            continue;
        };
        let Some(title) = rd::ascii(d, b, 21) else {
            continue;
        };
        if cs ^ inv == 0xffff
            && map & 0xe0 == 0x20
            && (map & 1 == 1) == hi
            && reset >= 0x8000
            && !title.is_empty()
        {
            return Some(
                Identified::new("snes", "SNES ROM", "snes", "Super Nintendo", "rom")
                    .cpu("WDC 65816", 16, false)
                    .run_with(SNES_EMU)
                    .confidence(Confidence::Medium)
                    .detail(format!(
                        "\"{title}\", {name}{}",
                        if copier != 0 { ", copier header" } else { "" }
                    )),
            );
        }
    }
    None
}

const MEM: std::ops::Range<u32> = 0x8000_0000..0x8180_0000;
const MEM2: std::ops::Range<u32> = 0x9000_0000..0x9400_0000;

pub fn dol(d: &[u8]) -> Option<Identified> {
    if d.len() < 0x100 {
        return None;
    }
    let mut text_hit = false;
    let entry = rd::u32be(d, 0xe0)?;
    let mut any = false;
    for i in 0..18 {
        let off = rd::u32be(d, i * 4)?;
        let addr = rd::u32be(d, 0x48 + i * 4)?;
        let size = rd::u32be(d, 0x90 + i * 4)?;
        if size == 0 {
            if off != 0 || addr != 0 {
                return None;
            }
            continue;
        }
        any = true;
        let end = (off as u64).checked_add(size as u64)?;
        if off < 0x100 || end > d.len() as u64 || size > 0x0200_0000 {
            return None;
        }
        if !MEM.contains(&addr) && !MEM2.contains(&addr) {
            return None;
        }
        if i < 7 && entry >= addr && (entry as u64) < addr as u64 + size as u64 {
            text_hit = true;
        }
    }
    if !any || !text_hit || entry & 3 != 0 {
        return None;
    }
    Some(
        Identified::new("dol", "DOL", "gamecube-wii", "GameCube / Wii", "executable")
            .cpu("PowerPC (Gekko/Broadway)", 32, true)
            .language("PowerPC:BE:32:default")
            .loader(Loader::Raw)
            .run_with(&["dolphin"])
            .confidence(Confidence::Medium)
            .detail(format!("entry {entry:#x}")),
    )
}

pub fn rel(d: &[u8]) -> Option<Identified> {
    let num = rd::u32be(d, 0x0c)?;
    let table = rd::u32be(d, 0x10)? as u64;
    let version = rd::u32be(d, 0x1c)?;
    if rd::u32be(d, 4)? != 0
        || rd::u32be(d, 8)? != 0
        || !(1..=3).contains(&version)
        || !(1..=0x100).contains(&num)
        || table < 0x40
        || table + num as u64 * 8 > d.len() as u64
    {
        return None;
    }
    // section table entries: offset (low bit is the executable flag) and length; offsets in file
    for i in 0..num as usize {
        let o = rd::u32be(d, table as usize + i * 8)? & !3;
        let l = rd::u32be(d, table as usize + i * 8 + 4)? as u64;
        if o as u64 + l > d.len() as u64 {
            return None;
        }
    }
    Some(
        Identified::new("rel", "REL", "gamecube-wii", "GameCube / Wii", "module")
            .cpu("PowerPC (Gekko/Broadway)", 32, true)
            .language("PowerPC:BE:32:default")
            .run_with(&["dolphin"])
            .confidence(Confidence::Medium)
            .detail(format!(
                "module id {}, {num} sections, version {version}",
                rd::u32be(d, 0)?
            )),
    )
}
