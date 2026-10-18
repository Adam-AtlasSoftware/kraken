//! The program image: the original program's loadable data, for translations that use globals.
//!
//! A translated function reads and writes the original's globals (and its constant tables) at
//! the addresses KRAKEN shows, through `rt::g(address)`. The bytes behind those addresses are the
//! program's own `PT_LOAD` segments (file contents, zeroed `.bss`), relocated like the loader
//! would: a pointer stored in the data (`R_X86_64_RELATIVE`) points into the same image, the
//! program's copies of `stdin`, `stdout` and `stderr` hold the runtime shim's streams. Every
//! translation of a program shares this one image, so state written by one function is seen by
//! the next, exactly as in the original.
//!
//! The image is used twice: the program crate embeds it (`src/image.bin`, `src/image.rs`) and
//! installs it before `main`; the native runner of a function-level test installs it at the
//! address the emulator gives the same bytes, so pointers in the data have the same values on
//! both sides and the runner can report the writes to globals the oracle reports
//! ([`crate::abi::GlobalWrite`]).

use std::collections::BTreeMap;
use std::path::Path;

use object::elf;
use object::read::elf::{ElfFile64, ProgramHeader};
use object::{Object, ObjectSymbol, RelocationFlags, RelocationTarget};

use crate::error::RewriteError;

/// Largest image that is embedded (the span of the loadable segments).
pub const MAX_IMAGE_BYTES: u64 = 64 << 20;
/// Without a symbol to say where a table ends: how far after an address a function refers to a
/// stored function pointer still belongs to the same table.
pub const TABLE_REACH: u64 = 0x200;
const PAGE: u64 = 0x1000;

/// A stream variable of the C library that the program has a copy of or a pointer to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// `stdin`.
    Stdin,
    /// `stdout`.
    Stdout,
    /// `stderr`.
    Stderr,
}

impl Stream {
    fn of(name: &str) -> Option<Stream> {
        match name {
            "stdin" | "_IO_2_1_stdin_" => Some(Stream::Stdin),
            "stdout" | "_IO_2_1_stdout_" => Some(Stream::Stdout),
            "stderr" | "_IO_2_1_stderr_" => Some(Stream::Stderr),
            _ => None,
        }
    }

    /// The number the generated code and the shim use (0, 1, 2).
    pub fn index(self) -> u8 {
        match self {
            Stream::Stdin => 0,
            Stream::Stdout => 1,
            Stream::Stderr => 2,
        }
    }
}

/// A named object of the program's data, for the prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataSymbol {
    /// The name, demangled (`loop()::tick`).
    pub name: String,
    /// Address as KRAKEN shows it.
    pub address: u64,
    /// Size in bytes (0 when the symbol table does not say).
    pub size: u64,
    /// In a writable segment.
    pub writable: bool,
}

/// The loadable data of a program, relocated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramImage {
    /// The address KRAKEN shows for byte 0 (the ELF address plus the image base of a PIE).
    pub low: u64,
    /// The ELF virtual address of byte 0.
    pub low_vaddr: u64,
    /// The bytes: segment contents, zeros elsewhere.
    pub bytes: Vec<u8>,
    /// Pointers inside the data: the 8 bytes at offset `.0` hold the address of offset `.1`.
    pub relative: Vec<(u32, u32)>,
    /// The program's own copies of C library streams (copy relocations): the 8 bytes at the
    /// offset hold that stream.
    pub copies: Vec<(u32, Stream)>,
    /// Slots that point to a C library stream variable (`GLOB_DAT`).
    pub refs: Vec<(u32, Stream)>,
    /// The ranges the emulator compares after a call to find writes to globals (offset, length):
    /// whole pages, merged where segments touch, writable when any segment in them is.
    pub writable: Vec<(u32, u32)>,
    /// Whether the program is position independent.
    pub is_pie: bool,
    /// Named data objects (functions excluded), by address.
    pub symbols: Vec<DataSymbol>,
    /// The functions of `.init_array` in order (static constructors run before `main`), as
    /// addresses KRAKEN shows.
    pub init: Vec<u64>,
}

fn bad(m: impl Into<String>) -> RewriteError {
    RewriteError::Image(m.into())
}

fn demangle(name: &str) -> String {
    if name.starts_with("_Z")
        && let Ok(sym) = cpp_demangle::Symbol::new(name)
        && let Ok(text) = sym.demangle()
    {
        return text;
    }
    name.to_string()
}

impl ProgramImage {
    /// Reads the image of the ELF at `path`, which KRAKEN loaded at `image_base`.
    pub fn load(path: &Path, image_base: u64) -> Result<Self, RewriteError> {
        let data = std::fs::read(path).map_err(|e| bad(format!("{}: {e}", path.display())))?;
        Self::from_bytes(&data, image_base)
    }

    /// [`ProgramImage::load`] from memory.
    pub fn from_bytes(data: &[u8], image_base: u64) -> Result<Self, RewriteError> {
        let file = ElfFile64::<object::Endianness>::parse(data).map_err(|e| bad(e.to_string()))?;
        let endian = file.endian();
        if file.elf_header().e_machine.get(endian) != elf::EM_X86_64 {
            return Err(bad("not an x86-64 ELF"));
        }
        let is_pie = file.elf_header().e_type.get(endian) == elf::ET_DYN;
        let bias = if is_pie { image_base } else { 0 };
        let mut loads: Vec<(u64, u64, u64, u64, bool)> = Vec::new();
        for ph in file.elf_program_headers() {
            if ph.p_type(endian) == elf::PT_LOAD {
                loads.push((
                    ph.p_vaddr(endian),
                    ph.p_offset(endian),
                    ph.p_filesz(endian),
                    ph.p_memsz(endian),
                    ph.p_flags(endian) & elf::PF_W != 0,
                ));
            }
        }
        if loads.is_empty() {
            return Err(bad("no PT_LOAD segments"));
        }
        loads.sort_by_key(|l| l.0);
        let low_vaddr = loads[0].0 & !(PAGE - 1);
        let mut high = 0u64;
        let mut ranges: Vec<(u64, u64, bool)> = Vec::new();
        for &(vaddr, off, filesz, memsz, w) in &loads {
            if filesz > memsz
                || off
                    .checked_add(filesz)
                    .is_none_or(|e| e > data.len() as u64)
            {
                return Err(bad("a segment lies outside the file"));
            }
            let end = vaddr
                .checked_add(memsz)
                .and_then(|e| e.checked_add(PAGE - 1))
                .map(|e| e & !(PAGE - 1))
                .ok_or_else(|| bad("segment address range overflows"))?;
            high = high.max(end);
            let s = vaddr & !(PAGE - 1);
            match ranges.last_mut() {
                Some(last) if s <= last.1 => {
                    last.1 = last.1.max(end);
                    last.2 |= w;
                }
                _ => ranges.push((s, end, w)),
            }
        }
        let span = high - low_vaddr;
        if span > MAX_IMAGE_BYTES {
            return Err(bad(format!(
                "the loadable segments span {span} bytes, more than the {MAX_IMAGE_BYTES} an \
                 image may have"
            )));
        }
        let mut bytes = vec![0u8; span as usize];
        for &(vaddr, off, filesz, _, _) in &loads {
            let at = (vaddr - low_vaddr) as usize;
            let src = &data[off as usize..(off + filesz) as usize];
            bytes[at..at + src.len()].copy_from_slice(src);
        }
        let in_image = |v: u64| v >= low_vaddr && v + 8 <= high;
        let mut relative = Vec::new();
        let mut copies = Vec::new();
        let mut refs = Vec::new();
        let dyn_names: std::collections::HashMap<_, String> = file
            .dynamic_symbols()
            .filter_map(|s| s.name().ok().map(|n| (s.index(), n.to_string())))
            .collect();
        if let Some(relocs) = file.dynamic_relocations() {
            for (offset, rel) in relocs {
                let RelocationFlags::Elf { r_type } = rel.flags() else {
                    continue;
                };
                if !in_image(offset) {
                    continue;
                }
                let slot = (offset - low_vaddr) as u32;
                let name = match rel.target() {
                    RelocationTarget::Symbol(idx) => {
                        dyn_names.get(&idx).cloned().unwrap_or_default()
                    }
                    _ => String::new(),
                };
                match r_type {
                    elf::R_X86_64_RELATIVE => {
                        let target = rel.addend() as u64;
                        if target >= low_vaddr && target < high {
                            relative.push((slot, (target - low_vaddr) as u32));
                        }
                    }
                    elf::R_X86_64_COPY => {
                        if let Some(s) = Stream::of(&name) {
                            copies.push((slot, s));
                        }
                    }
                    elf::R_X86_64_GLOB_DAT | elf::R_X86_64_64 => {
                        if let Some(s) = Stream::of(&name) {
                            refs.push((slot, s));
                        }
                    }
                    _ => {}
                }
            }
        }
        let writable = ranges
            .iter()
            .filter(|r| r.2)
            .map(|r| ((r.0 - low_vaddr) as u32, (r.1 - r.0) as u32))
            .collect();
        let writable_at = |v: u64| loads.iter().any(|l| l.4 && v >= l.0 && v < l.0 + l.3);
        let mut by_addr: BTreeMap<u64, DataSymbol> = BTreeMap::new();
        for s in file.symbols() {
            if s.kind() != object::SymbolKind::Data || s.address() == 0 {
                continue;
            }
            let Ok(name) = s.name() else { continue };
            if name.is_empty() || !(s.address() >= low_vaddr && s.address() < high) {
                continue;
            }
            by_addr.entry(s.address()).or_insert(DataSymbol {
                name: demangle(name),
                address: s.address() + bias,
                size: s.size(),
                writable: writable_at(s.address()),
            });
        }
        let mut init = Vec::new();
        if let Some(sec) = file.section_by_name(".init_array") {
            use object::ObjectSection;
            let targets: BTreeMap<u32, u32> = relative.iter().copied().collect();
            let (start, size) = (sec.address(), sec.size());
            let mut v = start;
            while v + 8 <= start + size && in_image(v) {
                let slot = (v - low_vaddr) as u32;
                let raw = match targets.get(&slot) {
                    Some(t) => Some(low_vaddr + u64::from(*t)),
                    None if !is_pie => bytes
                        .get(slot as usize..slot as usize + 8)
                        .and_then(|b| b.try_into().ok())
                        .map(u64::from_le_bytes),
                    None => None,
                };
                if let Some(t) = raw.filter(|t| *t != 0 && *t != u64::MAX) {
                    init.push(t + bias);
                }
                v += 8;
            }
        }
        Ok(ProgramImage {
            init,
            low: low_vaddr + bias,
            low_vaddr,
            bytes,
            relative,
            copies,
            refs,
            writable,
            is_pie,
            symbols: by_addr.into_values().collect(),
        })
    }

    /// The address KRAKEN shows for offset `off`.
    pub fn address(&self, off: u32) -> u64 {
        self.low + u64::from(off)
    }

    /// Whether KRAKEN address `a` is inside the image.
    pub fn contains(&self, a: u64) -> bool {
        a >= self.low && a < self.low + self.bytes.len() as u64
    }

    /// The data symbol that holds address `a`, if any.
    pub fn symbol_at(&self, a: u64) -> Option<&DataSymbol> {
        let i = self.symbols.partition_point(|s| s.address <= a);
        let s = self.symbols.get(i.checked_sub(1)?)?;
        (a < s.address + s.size.max(1)).then_some(s)
    }

    /// Whether a reference to `address` reaches the pointer stored at `slot`: both lie in the same
    /// named data object (a vtable, a table of callbacks), or, without a symbol, the slot is at
    /// most [`TABLE_REACH`] bytes after the address.
    pub fn same_table(&self, address: u64, slot: u64) -> bool {
        match (self.symbol_at(address), self.symbol_at(slot)) {
            (Some(a), Some(b)) => a.address == b.address,
            (None, None) => address <= slot && slot < address.saturating_add(TABLE_REACH),
            _ => false,
        }
    }

    /// Pointers stored in the data whose target is in `entries` (function entries, as KRAKEN
    /// addresses): `(slot address, target address)`. The program crate writes the Rust function
    /// into each such slot, so a table of callbacks or a vtable calls the translations.
    pub fn function_pointers(&self, entries: &std::collections::BTreeSet<u64>) -> Vec<(u64, u64)> {
        self.relative
            .iter()
            .map(|(slot, target)| (self.address(*slot), self.address(*target)))
            .filter(|(_, t)| entries.contains(t))
            .collect()
    }

    /// `image.rs` of the program crate (and of the function-level runner): the tables
    /// [`crate::rt`] needs to install the image whose bytes are in `image.bin` next to it.
    pub fn module_source(&self, fn_pointers: &[(u64, String)]) -> String {
        let list = |v: &[(u32, u32)]| -> String {
            v.iter()
                .map(|(a, b)| format!("({a:#x}, {b:#x}),"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let streams = |v: &[(u32, Stream)]| -> String {
            v.iter()
                .map(|(a, s)| format!("({a:#x}, {}),", s.index()))
                .collect::<Vec<_>>()
                .join(" ")
        };
        let fns: String = fn_pointers
            .iter()
            .map(|(slot, path)| {
                format!("    unsafe {{ rt::image_put({slot:#x}, {path} as usize) }};\n")
            })
            .collect();
        format!(
            "//! The original program's loadable data (`image.bin`) and how to relocate it, \
             generated by KRAKEN.\n\
             #![allow(warnings)]\n\
             use super::rt;\n\n\
             pub static IMAGE: rt::Image = rt::Image {{\n    \
             bytes: include_bytes!(\"image.bin\"),\n    \
             low: {low:#x},\n    \
             relative: &[{rel}],\n    \
             copies: &[{copies}],\n    \
             refs: &[{refs}],\n    \
             writable: &[{wr}],\n\
             }};\n\n\
             /// Installs the image (at `at` when given, else in fresh memory) and points the \
             tables of function pointers at the translations.\n\
             pub fn install(at: *mut u8) {{\n    \
             unsafe {{ rt::image_install(&IMAGE, at) }};\n{fns}}}\n",
            low = self.low,
            rel = list(&self.relative),
            copies = streams(&self.copies),
            refs = streams(&self.refs),
            wr = list(&self.writable),
        )
    }

    /// Prompt text: how to reach the program's data, and the named objects among `addresses`
    /// (data a function refers to).
    pub fn prompt_notes(&self, addresses: &[u64]) -> String {
        let mut seen = std::collections::BTreeSet::new();
        let mut rows = Vec::new();
        let mut loose = Vec::new();
        for a in addresses {
            if !self.contains(*a) {
                continue;
            }
            match self.symbol_at(*a) {
                Some(s) => {
                    if seen.insert(s.address) {
                        rows.push(format!(
                            "- `{}` at {:#x}, {} bytes{}",
                            s.name.replace('`', "'"),
                            s.address,
                            s.size,
                            if s.writable { "" } else { ", read-only" }
                        ));
                    }
                }
                None => {
                    if seen.insert(*a) {
                        loose.push(format!("{a:#x}"));
                    }
                }
            }
        }
        let mut text = format!(
            "{IMAGE_PROMPT} The image spans {:#x} to {:#x}.",
            self.low,
            self.low + self.bytes.len() as u64
        );
        if !rows.is_empty() {
            text.push_str(&format!(
                "\nProgram data this function refers to:\n{}",
                rows.join("\n")
            ));
        }
        if !loose.is_empty() {
            text.push_str(&format!(
                "\nOther data addresses it refers to: {}.",
                loose.join(", ")
            ));
        }
        text
    }
}

/// The program's function symbols as the linker knows them (mangled), by the address KRAKEN
/// shows (`0x...`). Empty when the file cannot be read.
pub fn function_symbols(path: &Path, image_base: u64) -> BTreeMap<String, String> {
    let Ok(data) = std::fs::read(path) else {
        return BTreeMap::new();
    };
    let Ok(file) = ElfFile64::<object::Endianness>::parse(&*data) else {
        return BTreeMap::new();
    };
    let bias = if file.elf_header().e_type.get(file.endian()) == elf::ET_DYN {
        image_base
    } else {
        0
    };
    let mut out = BTreeMap::new();
    for s in file.symbols().chain(file.dynamic_symbols()) {
        if s.kind() != object::SymbolKind::Text || s.address() == 0 || !s.is_definition() {
            continue;
        }
        if let Ok(name) = s.name()
            && !name.is_empty()
        {
            out.entry(format!("{:#x}", s.address() + bias))
                .or_insert_with(|| name.to_string());
        }
    }
    out
}

/// What a program-mode prompt says about globals (trusted operator text).
pub const IMAGE_PROMPT: &str = "\
Globals. The original program's data (globals, static locals, constant tables, string \
literals) is loaded into one shared memory image at the addresses the decompile shows, and \
every translated function of the program uses that same image. Reach program data only through \
`rt::g(address)`, which takes the address as any integer type (write `rt::g(addr)`, never \
`rt::g(addr as _)`) and returns a `*mut u8` to the byte at that address: for example \
`*(rt::g(0x150400) as *mut i32) = 5;` or `let p = rt::g(0x10a020) as *mut Voice;`. A global \
named in the decompile (`gLead`, `DAT_00150400`, `loop()::tick`) is at the address listed below \
(a `DAT_`, `PTR_` or `_DAT_` name ends in its address in hex). A number in the decompile that \
lies inside the image is the address of program data: pass `rt::g(that number)` where the \
decompile passes the number. Never declare a `static` or `static mut` for program state, and \
never copy a global's initial value into the code: read it from the image. Pointers stored in \
the image are real pointers (they point into the image, or at translated functions). The C \
library streams are `rt::stdin()`, `rt::stdout()` and `rt::stderr()`; the program's own \
`stdout` variable in the image holds the same value.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_demangled_with_their_scope() {
        assert_eq!(demangle("_ZZ4loopvE4tick"), "loop()::tick");
        assert_eq!(demangle("gLead"), "gLead");
    }
}
