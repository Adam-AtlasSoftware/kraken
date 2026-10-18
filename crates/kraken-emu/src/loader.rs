//! ELF loading for both uses of the layer: a program image mapped for a Linux run (segments with
//! their permissions, the interpreter, what the auxiliary vector needs), and a program image with
//! its dynamic relocations applied for function calls (every import slot pointed wherever the
//! caller wants, usually at a stub address the host handles).
//!
//! Only little-endian ELF files of the emulated architectures; the program header is checked
//! before anything is allocated (a hostile header must not make the host allocate gigabytes).

use std::collections::BTreeMap;

use object::read::elf::{FileHeader, ProgramHeader as _};
use object::{Object, ObjectSymbol, RelocationFlags, RelocationTarget, elf};

use crate::arch::Arch;
use crate::error::EmuError;
use crate::machine::{Machine, Perm};

/// Page size of every emulated architecture.
pub const PAGE: u64 = 0x1000;
/// Most memory the loadable segments of one file may take.
pub const MAX_IMAGE_BYTES: u64 = 256 << 20;
/// Most dynamic relocations processed.
const MAX_RELOCATIONS: usize = 1 << 20;

pub(crate) fn align_down(v: u64) -> u64 {
    v & !(PAGE - 1)
}

pub(crate) fn align_up(v: u64) -> Option<u64> {
    Some(v.checked_add(PAGE - 1)? & !(PAGE - 1))
}

fn bad(m: impl Into<String>) -> EmuError {
    EmuError::Image(m.into())
}

/// One `PT_LOAD` segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// Link-time virtual address.
    pub vaddr: u64,
    /// File offset.
    pub offset: u64,
    /// Bytes in the file.
    pub filesz: u64,
    /// Bytes in memory.
    pub memsz: u64,
    /// `PF_*` flags.
    pub flags: u32,
}

/// What the loader needs from an ELF header and its program headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfInfo {
    /// The architecture.
    pub arch: Arch,
    /// `ET_DYN` (a position-independent executable or a shared object).
    pub is_dyn: bool,
    /// Entry point (link-time).
    pub entry: u64,
    /// Program header table offset, entry size and count.
    pub phoff: u64,
    /// Size of one program header.
    pub phentsize: u64,
    /// Number of program headers.
    pub phnum: u64,
    /// `PT_INTERP`, when the program is dynamically linked.
    pub interp: Option<String>,
    /// The loadable segments, sorted by address.
    pub segments: Vec<Segment>,
}

impl ElfInfo {
    /// Lowest and highest (page aligned, exclusive) link-time address of the loadable segments.
    pub fn span(&self) -> (u64, u64) {
        let lo = self
            .segments
            .iter()
            .map(|s| align_down(s.vaddr))
            .min()
            .unwrap_or(0);
        let hi = self
            .segments
            .iter()
            .filter_map(|s| align_up(s.vaddr + s.memsz))
            .max()
            .unwrap_or(0);
        (lo, hi)
    }

    /// The link-time address of the program header table (inside a loaded segment), if any.
    pub fn phdr_vaddr(&self) -> Option<u64> {
        let end = self.phoff + self.phentsize * self.phnum;
        self.segments
            .iter()
            .find(|s| s.offset <= self.phoff && end <= s.offset + s.filesz)
            .map(|s| self.phoff - s.offset + s.vaddr)
    }
}

/// Parses and checks the header and program headers of an ELF of an emulated architecture.
pub fn parse_elf(data: &[u8]) -> Result<ElfInfo, EmuError> {
    let arch = Arch::from_elf(data)?;
    if arch.bits() == 64 {
        parse_with::<elf::FileHeader64<object::Endianness>>(data, arch)
    } else {
        parse_with::<elf::FileHeader32<object::Endianness>>(data, arch)
    }
}

fn parse_with<H: FileHeader<Endian = object::Endianness>>(
    data: &[u8],
    arch: Arch,
) -> Result<ElfInfo, EmuError> {
    let header = H::parse(data).map_err(|e| bad(e.to_string()))?;
    let endian = header.endian().map_err(|e| bad(e.to_string()))?;
    let e_type = header.e_type(endian);
    if e_type != elf::ET_EXEC && e_type != elf::ET_DYN {
        return Err(bad("not an executable or shared object"));
    }
    let phdrs = header
        .program_headers(endian, data)
        .map_err(|e| bad(e.to_string()))?;
    let max_addr: u64 = if arch.bits() == 64 { 1 << 48 } else { 1 << 32 };
    let mut segments = Vec::new();
    let mut interp = None;
    for ph in phdrs {
        let p_type = ph.p_type(endian);
        if p_type == elf::PT_INTERP {
            let bytes = ph
                .data(endian, data)
                .map_err(|_| bad("PT_INTERP beyond end of file"))?;
            let s = bytes.split(|b| *b == 0).next().unwrap_or_default();
            interp = Some(String::from_utf8_lossy(s).into_owned());
        }
        if p_type != elf::PT_LOAD {
            continue;
        }
        let seg = Segment {
            vaddr: ph.p_vaddr(endian).into(),
            offset: ph.p_offset(endian).into(),
            filesz: ph.p_filesz(endian).into(),
            memsz: ph.p_memsz(endian).into(),
            flags: ph.p_flags(endian),
        };
        if seg.filesz > seg.memsz {
            return Err(bad("segment file size exceeds its memory size"));
        }
        if seg
            .offset
            .checked_add(seg.filesz)
            .is_none_or(|e| e > data.len() as u64)
        {
            return Err(bad("segment beyond end of file"));
        }
        let end = seg
            .vaddr
            .checked_add(seg.memsz)
            .and_then(align_up)
            .ok_or_else(|| bad("segment address range overflows"))?;
        if end > max_addr {
            return Err(bad("segment lies beyond the address space"));
        }
        segments.push(seg);
    }
    if segments.is_empty() {
        return Err(bad("no PT_LOAD segments"));
    }
    segments.sort_by_key(|s| s.vaddr);
    let info = ElfInfo {
        arch,
        is_dyn: e_type == elf::ET_DYN,
        entry: header.e_entry(endian).into(),
        phoff: header.e_phoff(endian).into(),
        phentsize: u64::from(header.e_phentsize(endian)),
        phnum: u64::from(header.e_phnum(endian)),
        interp,
        segments,
    };
    let (lo, hi) = info.span();
    if hi.saturating_sub(lo) > MAX_IMAGE_BYTES {
        return Err(bad("the loadable segments span more than 256 MiB"));
    }
    Ok(info)
}

/// Where a file ended up in guest memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapped {
    /// Load bias (0 for a fixed-address executable).
    pub bias: u64,
    /// Entry point (biased; with the Thumb bit as the ELF has it).
    pub entry: u64,
    /// Address of the program header table, or 0.
    pub phdr: u64,
    /// First mapped byte.
    pub start: u64,
    /// End of the mapped image (page aligned).
    pub end: u64,
}

/// Maps the loadable segments of `data` at `bias` with their permissions (pages shared by two
/// segments get both). Returns where everything went.
pub fn map_segments(
    m: &mut Machine,
    data: &[u8],
    info: &ElfInfo,
    bias: u64,
) -> Result<Mapped, EmuError> {
    // Page ranges with merged permissions.
    let mut pages: Vec<(u64, u64, Perm)> = Vec::new();
    for s in &info.segments {
        let (start, end) = (
            align_down(s.vaddr),
            align_up(s.vaddr + s.memsz).ok_or_else(|| bad("segment overflows"))?,
        );
        let p = Perm::from_elf_flags(s.flags);
        match pages.last_mut() {
            Some(last) if start < last.1 => {
                last.1 = last.1.max(end);
                last.2 = Perm {
                    read: last.2.read | p.read,
                    write: last.2.write | p.write,
                    exec: last.2.exec | p.exec,
                };
            }
            _ => pages.push((start, end, p)),
        }
    }
    for &(start, end, p) in &pages {
        m.map(bias.wrapping_add(start), end - start, p)?;
    }
    for s in &info.segments {
        let lo = usize::try_from(s.offset).map_err(|_| bad("segment offset"))?;
        let hi = usize::try_from(s.offset + s.filesz).map_err(|_| bad("segment size"))?;
        let bytes = data
            .get(lo..hi)
            .ok_or_else(|| bad("segment beyond end of file"))?;
        m.write_mem(bias.wrapping_add(s.vaddr), bytes)?;
    }
    let (lo, hi) = info.span();
    Ok(Mapped {
        bias,
        entry: bias.wrapping_add(info.entry),
        phdr: info.phdr_vaddr().map_or(0, |v| bias.wrapping_add(v)),
        start: bias.wrapping_add(lo),
        end: bias.wrapping_add(hi),
    })
}

/// How a relocated slot refers to a symbol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    /// A PLT slot (`JUMP_SLOT`): a function the code calls.
    JumpSlot,
    /// A GOT entry (`GLOB_DAT`): the address of a function or a variable.
    GlobDat,
    /// An absolute word (`R_*_32`/`R_*_64`) naming a symbol.
    Absolute,
    /// A copy relocation: the program has its own copy of a library variable at this address.
    Copy,
}

/// The dynamic relocation classes of one architecture.
fn reloc_class(arch: Arch, r: u32) -> Option<RelocClass> {
    use RelocClass::*;
    Some(match (arch, r) {
        (Arch::X86_64, elf::R_X86_64_RELATIVE) => Relative,
        (Arch::X86_64, elf::R_X86_64_JUMP_SLOT) => Symbol(SlotKind::JumpSlot),
        (Arch::X86_64, elf::R_X86_64_GLOB_DAT) => Symbol(SlotKind::GlobDat),
        (Arch::X86_64, elf::R_X86_64_64) => Symbol(SlotKind::Absolute),
        (Arch::X86_64, elf::R_X86_64_COPY) => Symbol(SlotKind::Copy),
        (Arch::X86, elf::R_386_RELATIVE) => Relative,
        (Arch::X86, elf::R_386_JMP_SLOT) => Symbol(SlotKind::JumpSlot),
        (Arch::X86, elf::R_386_GLOB_DAT) => Symbol(SlotKind::GlobDat),
        (Arch::X86, elf::R_386_32) => Symbol(SlotKind::Absolute),
        (Arch::X86, elf::R_386_COPY) => Symbol(SlotKind::Copy),
        (Arch::Arm, elf::R_ARM_RELATIVE) => Relative,
        (Arch::Arm, elf::R_ARM_JUMP_SLOT) => Symbol(SlotKind::JumpSlot),
        (Arch::Arm, elf::R_ARM_GLOB_DAT) => Symbol(SlotKind::GlobDat),
        (Arch::Arm, elf::R_ARM_ABS32) => Symbol(SlotKind::Absolute),
        (Arch::Arm, elf::R_ARM_COPY) => Symbol(SlotKind::Copy),
        (Arch::Aarch64, elf::R_AARCH64_RELATIVE) => Relative,
        (Arch::Aarch64, elf::R_AARCH64_JUMP_SLOT) => Symbol(SlotKind::JumpSlot),
        (Arch::Aarch64, elf::R_AARCH64_GLOB_DAT) => Symbol(SlotKind::GlobDat),
        (Arch::Aarch64, elf::R_AARCH64_ABS64) => Symbol(SlotKind::Absolute),
        (Arch::Aarch64, elf::R_AARCH64_COPY) => Symbol(SlotKind::Copy),
        (Arch::Riscv32 | Arch::Riscv64, elf::R_RISCV_RELATIVE) => Relative,
        (Arch::Riscv32 | Arch::Riscv64, elf::R_RISCV_JUMP_SLOT) => Symbol(SlotKind::JumpSlot),
        (Arch::Riscv32, elf::R_RISCV_32) | (Arch::Riscv64, elf::R_RISCV_64) => {
            Symbol(SlotKind::Absolute)
        }
        (Arch::Riscv32 | Arch::Riscv64, elf::R_RISCV_COPY) => Symbol(SlotKind::Copy),
        _ => return None,
    })
}

enum RelocClass {
    Relative,
    Symbol(SlotKind),
}

/// One region of a relocated image: runtime address, initial contents, writable.
#[derive(Debug, Clone)]
pub struct Region {
    /// Runtime address of the first byte (page aligned).
    pub addr: u64,
    /// Contents after relocation.
    pub bytes: Vec<u8>,
    /// Some segment in it is writable.
    pub writable: bool,
    /// Some segment in it is executable.
    pub exec: bool,
}

/// A program image with its relocations applied, ready to be written into a [`Machine`] for
/// function calls (no loader, no libc: the caller decides what every import slot holds).
#[derive(Debug, Clone)]
pub struct Image {
    /// Architecture.
    pub arch: Arch,
    /// Position independent (loaded at `bias`).
    pub is_pie: bool,
    /// Load bias.
    pub bias: u64,
    /// Page regions in address order.
    pub regions: Vec<Region>,
    /// Symbols by name: ELF values (link-time, before the bias; Thumb functions keep bit 0).
    pub symbols: BTreeMap<String, u64>,
}

impl Image {
    /// Builds the image of `data` at `pie_bias` (ignored for a fixed-address executable). Every
    /// symbolic relocation asks `resolve(name, kind, runtime slot address)` for the value the
    /// slot gets; `None` leaves the slot as the file has it.
    pub fn load(
        data: &[u8],
        pie_bias: u64,
        mut resolve: impl FnMut(&str, SlotKind, u64) -> Option<u64>,
    ) -> Result<Image, EmuError> {
        let info = parse_elf(data)?;
        let arch = info.arch;
        let bias = if info.is_dyn { pie_bias } else { 0 };
        if info
            .span()
            .1
            .checked_add(bias)
            .is_none_or(|e| e > arch.ptr_mask())
        {
            return Err(bad("the image does not fit the address space at this bias"));
        }
        let mut ranges: Vec<(u64, u64, bool, bool)> = Vec::new();
        for s in &info.segments {
            let (st, en) = (
                align_down(s.vaddr),
                align_up(s.vaddr + s.memsz).ok_or_else(|| bad("segment overflows"))?,
            );
            let (w, x) = (s.flags & elf::PF_W != 0, s.flags & elf::PF_X != 0);
            match ranges.last_mut() {
                Some(last) if st <= last.1 => {
                    last.1 = last.1.max(en);
                    last.2 |= w;
                    last.3 |= x;
                }
                _ => ranges.push((st, en, w, x)),
            }
        }
        let mut regions = Vec::with_capacity(ranges.len());
        for &(st, en, w, x) in &ranges {
            let len = usize::try_from(en - st).map_err(|_| bad("segment too large"))?;
            let mut bytes = Vec::new();
            bytes
                .try_reserve_exact(len)
                .map_err(|_| bad("cannot allocate the segment"))?;
            bytes.resize(len, 0);
            regions.push(Region {
                addr: bias + st,
                bytes,
                writable: w,
                exec: x,
            });
        }
        for s in &info.segments {
            let r = regions
                .iter_mut()
                .find(|r| {
                    r.addr <= bias + s.vaddr && bias + s.vaddr < r.addr + r.bytes.len() as u64
                })
                .ok_or_else(|| bad("segment outside its range"))?;
            let start = usize::try_from(bias + s.vaddr - r.addr).map_err(|_| bad("offset"))?;
            let (lo, hi) = (
                usize::try_from(s.offset).map_err(|_| bad("offset"))?,
                usize::try_from(s.offset + s.filesz).map_err(|_| bad("size"))?,
            );
            let src = data
                .get(lo..hi)
                .ok_or_else(|| bad("segment beyond end of file"))?;
            r.bytes
                .get_mut(start..start + src.len())
                .ok_or_else(|| bad("segment data does not fit its range"))?
                .copy_from_slice(src);
        }

        let file = object::File::parse(data).map_err(|e| bad(e.to_string()))?;
        let mut symbols = BTreeMap::new();
        for s in file.symbols().chain(file.dynamic_symbols()) {
            if let Ok(name) = s.name()
                && !name.is_empty()
                && s.address() != 0
                && !name.starts_with('$')
            {
                symbols.entry(name.to_string()).or_insert(s.address());
            }
        }

        let ptr = arch.ptr_size();
        let mut image = Image {
            arch,
            is_pie: info.is_dyn,
            bias,
            regions,
            symbols,
        };
        let dyn_names: std::collections::HashMap<_, String> = file
            .dynamic_symbols()
            .filter_map(|s| s.name().ok().map(|n| (s.index(), n.to_string())))
            .collect();
        let mut patches: Vec<(u64, u64)> = Vec::new();
        if let Some(relocs) = file.dynamic_relocations() {
            for (offset, rel) in relocs {
                if patches.len() >= MAX_RELOCATIONS {
                    return Err(bad("too many relocations"));
                }
                let RelocationFlags::Elf { r_type } = rel.flags() else {
                    continue;
                };
                let Some(class) = reloc_class(arch, r_type) else {
                    continue;
                };
                let slot = bias.wrapping_add(offset);
                let addend = if rel.has_implicit_addend() {
                    image.read_word(slot).unwrap_or(0) as i64
                } else {
                    rel.addend()
                };
                match class {
                    RelocClass::Relative => {
                        patches.push((slot, bias.wrapping_add(addend as u64) & arch.ptr_mask()));
                    }
                    RelocClass::Symbol(kind) => {
                        let name = match rel.target() {
                            RelocationTarget::Symbol(idx) => {
                                dyn_names.get(&idx).cloned().unwrap_or_default()
                            }
                            _ => String::new(),
                        };
                        if name.is_empty() {
                            continue;
                        }
                        if let Some(v) = resolve(&name, kind, slot) {
                            patches.push((slot, v & arch.ptr_mask()));
                        }
                    }
                }
            }
        }
        for (slot, v) in patches {
            image.write_word(slot, v, ptr)?;
        }
        Ok(image)
    }

    fn region_of(&self, addr: u64, len: u64) -> Option<(usize, usize)> {
        self.regions.iter().enumerate().find_map(|(i, r)| {
            let end = addr.checked_add(len)?;
            (r.addr <= addr && end <= r.addr + r.bytes.len() as u64)
                .then(|| (i, (addr - r.addr) as usize))
        })
    }

    fn read_word(&self, addr: u64) -> Option<u64> {
        let n = self.arch.ptr_size();
        let (i, off) = self.region_of(addr, n as u64)?;
        let mut b = [0u8; 8];
        b[..n].copy_from_slice(&self.regions[i].bytes[off..off + n]);
        Some(u64::from_le_bytes(b))
    }

    fn write_word(&mut self, addr: u64, v: u64, n: usize) -> Result<(), EmuError> {
        let (i, off) = self
            .region_of(addr, n as u64)
            .ok_or_else(|| bad(format!("relocation at {addr:#x} unmapped")))?;
        self.regions[i].bytes[off..off + n].copy_from_slice(&v.to_le_bytes()[..n]);
        Ok(())
    }

    /// Maps every region into `m` (read, write and execute: the function oracle does not model
    /// page permissions of the image).
    pub fn map_into(&self, m: &mut Machine) -> Result<(), EmuError> {
        for r in &self.regions {
            m.map(r.addr, r.bytes.len() as u64, Perm::RWX)?;
        }
        self.reset(m)
    }

    /// Writes the initial contents of every region back.
    pub fn reset(&self, m: &mut Machine) -> Result<(), EmuError> {
        for r in &self.regions {
            m.write_mem(r.addr, &r.bytes)?;
        }
        Ok(())
    }

    /// The runtime address of a symbol.
    pub fn symbol_addr(&self, name: &str) -> Option<u64> {
        self.symbols.get(name).map(|v| v.wrapping_add(self.bias))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf64_with_load(vaddr: u64, off: u64, filesz: u64, memsz: u64) -> Vec<u8> {
        let mut b = vec![0u8; 64 + 56 + 16];
        b[0..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[6] = 1;
        b[16..18].copy_from_slice(&2u16.to_le_bytes());
        b[18..20].copy_from_slice(&183u16.to_le_bytes()); // AArch64
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes());
        b[52..54].copy_from_slice(&64u16.to_le_bytes());
        b[54..56].copy_from_slice(&56u16.to_le_bytes());
        b[56..58].copy_from_slice(&1u16.to_le_bytes());
        let ph = 64;
        b[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes());
        b[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes());
        b[ph + 8..ph + 16].copy_from_slice(&off.to_le_bytes());
        b[ph + 16..ph + 24].copy_from_slice(&vaddr.to_le_bytes());
        b[ph + 24..ph + 32].copy_from_slice(&vaddr.to_le_bytes());
        b[ph + 32..ph + 40].copy_from_slice(&filesz.to_le_bytes());
        b[ph + 40..ph + 48].copy_from_slice(&memsz.to_le_bytes());
        b[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
        b
    }

    fn refused(vaddr: u64, off: u64, filesz: u64, memsz: u64) -> String {
        match parse_elf(&elf64_with_load(vaddr, off, filesz, memsz)) {
            Err(EmuError::Image(m)) => m,
            other => panic!("hostile ELF not refused as an image error: {other:?}"),
        }
    }

    #[test]
    fn hostile_program_headers_are_refused_before_allocation() {
        assert!(refused(0x1000, 0, 16, 1 << 46).contains("256 MiB"));
        assert!(refused(0x1000, 0, 16, 1 << 50).contains("address space"));
        assert!(refused(u64::MAX - 8, 0, 0, 0x2000).contains("overflow"));
        assert!(refused(0x1000, 0, 64, 16).contains("exceeds"));
        assert!(refused(0x1000, 100, 1 << 20, 1 << 20).contains("beyond end of file"));
        assert!(refused(0x1000, u64::MAX - 4, 16, 16).contains("beyond end of file"));
    }

    #[test]
    fn a_small_header_parses() {
        let i = parse_elf(&elf64_with_load(0x400000, 0, 0x88, 0x2000)).expect("parse");
        assert_eq!(i.arch, Arch::Aarch64);
        assert_eq!(i.span(), (0x400000, 0x402000));
        assert!(i.interp.is_none());
    }
}
