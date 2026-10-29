//! Raw binary images: firmware, ROMs and boot code with no container format. The person says
//! which processor the bytes are for, where they live (base address) and optionally which part
//! of the file to map and where execution starts; one block holds the bytes.
//!
//! ARM Cortex-M images start with a vector table (initial stack pointer, then the exception
//! vectors with the Thumb bit set); its entries become named function seeds, so a bare
//! `objcopy -O binary` blob opens with `Reset_Handler` and the interrupt handlers found.

use std::collections::BTreeMap;

use engine_native_sys::{ContextRange, Image, Segment};
use kraken_engine::LoaderSpec;
use kraken_proto::{ErrorCode, MemoryBlock, MemoryKind, ProtoError};

use crate::elf::{Language, Loaded};

/// One processor a raw image can be loaded for.
struct Processor {
    id: &'static str,
    /// The Sleigh `.sla` file the language needs: (processor directory, file).
    sla: (&'static str, &'static str),
    pointer_size: u32,
    /// Compiler specs in Ghidra's order; the first is the default.
    compilers: &'static [&'static str],
    /// What to call it in a description.
    title: &'static str,
}

const PROCESSORS: &[Processor] = &[
    Processor {
        id: "x86:LE:64:default",
        sla: ("x86", "x86-64.sla"),
        pointer_size: 8,
        compilers: &["gcc", "windows"],
        title: "x86-64",
    },
    Processor {
        id: "x86:LE:32:default",
        sla: ("x86", "x86.sla"),
        pointer_size: 4,
        compilers: &["gcc", "windows", "borland"],
        title: "32-bit x86",
    },
    Processor {
        id: "ARM:LE:32:Cortex",
        sla: ("ARM", "ARM7_le.sla"),
        pointer_size: 4,
        compilers: &["default", "apcs"],
        title: "ARM Cortex-M (Thumb)",
    },
    Processor {
        id: "ARM:LE:32:v8",
        sla: ("ARM", "ARM8_le.sla"),
        pointer_size: 4,
        compilers: &["default", "apcs"],
        title: "ARM (A32 and Thumb)",
    },
    Processor {
        id: "ARM:LE:32:v7",
        sla: ("ARM", "ARM7_le.sla"),
        pointer_size: 4,
        compilers: &["default", "apcs"],
        title: "ARMv7 (A32 and Thumb)",
    },
    Processor {
        id: "AARCH64:LE:64:v8A",
        sla: ("AARCH64", "AARCH64.sla"),
        pointer_size: 8,
        compilers: &["default"],
        title: "AArch64",
    },
    Processor {
        id: "RISCV:LE:32:default",
        sla: ("RISCV", "riscv.ilp32d.sla"),
        pointer_size: 4,
        compilers: &["gcc"],
        title: "RISC-V 32",
    },
    Processor {
        id: "RISCV:LE:64:default",
        sla: ("RISCV", "riscv.lp64d.sla"),
        pointer_size: 8,
        compilers: &["gcc"],
        title: "RISC-V 64",
    },
];

fn processor(name: &str) -> Option<&'static Processor> {
    let id = kraken_engine::language_id(name);
    PROCESSORS.iter().find(|p| p.id.eq_ignore_ascii_case(&id))
}

/// The language ids the native engine loads raw images for.
pub fn languages() -> Vec<&'static str> {
    PROCESSORS.iter().map(|p| p.id).collect()
}

/// The language id for `name` (an id or a short name such as `cortex-m`), or `None` when the
/// native engine has no raw loader for it.
pub fn resolve(name: &str) -> Option<&'static str> {
    processor(name).map(|p| p.id)
}

/// The processor directory and Sleigh file the language `name` needs.
pub fn sla_file(name: &str) -> Option<(&'static str, &'static str)> {
    processor(name).map(|p| p.sla)
}

fn bad(msg: impl Into<String>) -> ProtoError {
    ProtoError::new(ErrorCode::InvalidArgument, msg)
}

const VECTOR_NAMES: [(usize, &str); 10] = [
    (1, "Reset_Handler"),
    (2, "NMI_Handler"),
    (3, "HardFault_Handler"),
    (4, "MemManage_Handler"),
    (5, "BusFault_Handler"),
    (6, "UsageFault_Handler"),
    (11, "SVC_Handler"),
    (12, "DebugMon_Handler"),
    (14, "PendSV_Handler"),
    (15, "SysTick_Handler"),
];

fn vector_name(i: usize) -> String {
    VECTOR_NAMES
        .iter()
        .find(|(n, _)| *n == i)
        .map(|(_, s)| (*s).to_string())
        .unwrap_or_else(|| format!("IRQ{}_Handler", i.saturating_sub(16)))
}

/// A Cortex-M vector table at the start of `bytes` (mapped at `base`): the initial stack
/// pointer, then handlers with the Thumb bit set that point into the image. Returns the
/// handlers as (index, even address); empty when the start does not look like a table.
pub fn cortex_vectors(bytes: &[u8], base: u64) -> Vec<(usize, u64)> {
    let word = |i: usize| {
        bytes
            .get(i * 4..i * 4 + 4)
            .map(|b| u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])))
    };
    let inside = |v: u64| v & 1 == 1 && (base..base + bytes.len() as u64).contains(&(v & !1));
    let (Some(sp), Some(reset)) = (word(0), word(1)) else {
        return Vec::new();
    };
    // the stack pointer is word aligned and points into RAM or a vector table's CCM, not code
    if sp & 3 != 0
        || sp < 0x1000
        || !inside(reset)
        || (base..base + bytes.len() as u64).contains(&sp)
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    for i in 1..bytes.len() / 4 {
        match word(i) {
            Some(v) if inside(v) => out.push((i, v & !1)),
            // reserved slots, and the table may continue after a few unused interrupts
            Some(0) if i < 16 => {}
            Some(0) if i < 256 => {}
            _ => break,
        }
    }
    out
}

/// Loads `data` as a raw image as `spec` says (`spec.arch` is required).
pub fn load(data: &[u8], spec: &LoaderSpec) -> Result<Loaded, ProtoError> {
    let Some(arch) = spec.arch.as_deref().filter(|a| !a.trim().is_empty()) else {
        return Err(bad(format!(
            "a raw binary needs a processor (language); the native engine knows: {}",
            languages().join(", ")
        )));
    };
    let p = processor(arch).ok_or_else(|| {
        ProtoError::new(
            ErrorCode::Unsupported,
            format!(
                "the native engine has no raw loader for language {arch:?}; use `--engine ghidra` \
                 for other processors"
            ),
        )
    })?;
    let compiler = match spec.compiler.as_deref().map(str::trim) {
        None | Some("") => p.compilers[0],
        Some(c) => p
            .compilers
            .iter()
            .copied()
            .find(|k| k.eq_ignore_ascii_case(c))
            .ok_or_else(|| {
                bad(format!(
                    "compiler {c:?} is not known for {}; use one of {}",
                    p.id,
                    p.compilers.join(", ")
                ))
            })?,
    };
    let language = Language {
        id: p.id,
        compiler,
        pointer_size: p.pointer_size,
    };

    let offset = spec.offset.map_or(0, |o| o.0);
    if offset >= data.len() as u64 {
        return Err(bad(format!(
            "file offset {offset:#x} is past the end of the file ({} bytes)",
            data.len()
        )));
    }
    let available = data.len() as u64 - offset;
    let length = spec.length.map_or(available, |l| l.0);
    if length == 0 || length > available {
        return Err(bad(format!(
            "length {length:#x} does not fit: {available:#x} bytes follow offset {offset:#x}"
        )));
    }
    let bytes = &data[offset as usize..(offset + length) as usize];
    let base = spec.base.map_or(0, |b| b.0);
    let end = base
        .checked_add(length)
        .filter(|e| p.pointer_size == 8 || *e <= 1 << 32)
        .ok_or_else(|| bad("the image does not fit in the address space at that base"))?;

    let cortex = p.id == "ARM:LE:32:Cortex";
    let arm = p.id.starts_with("ARM:");
    let vectors = if cortex {
        cortex_vectors(bytes, base)
    } else {
        Vec::new()
    };
    let in_image = |a: u64| (base..end).contains(&a);
    let entry = match spec.entry {
        Some(e) => {
            let e = e.0;
            let at = if arm { e & !1 } else { e };
            if !in_image(at) {
                return Err(bad(format!(
                    "entry point {e:#x} is outside the image ({base:#x}..{end:#x})"
                )));
            }
            e
        }
        None => match vectors.iter().find(|(i, _)| *i == 1) {
            Some((_, reset)) => *reset | 1,
            None => base,
        },
    };

    let image = Image {
        segments: vec![Segment {
            start: base,
            data: bytes.to_vec(),
            mem_size: length,
            readonly: false,
        }],
        context: Vec::new(),
    };
    let mut loaded_image = image;
    if cortex {
        loaded_image.context = vec![ContextRange {
            name: crate::arm::TMODE.into(),
            start: base,
            end,
            value: 1,
        }];
    } else if arm {
        let exec = vec![(base, end)];
        let mut seeds = vec![crate::arm::Seed {
            rank: crate::arm::rank::SYMBOL,
            addr: entry & !1,
            thumb: entry & 1 == 1,
        }];
        // an A32 image has no hint besides the entry, so also try the start
        if entry & !1 != base {
            seeds.push(crate::arm::Seed {
                rank: crate::arm::rank::WEAK,
                addr: base,
                thumb: false,
            });
        }
        let walked =
            crate::arm::Modes::new(&loaded_image, exec.clone(), Default::default()).walk(seeds);
        loaded_image.context = crate::arm::paint(&walked, &exec);
    }

    let mut functions = BTreeMap::new();
    let mut code_symbols: BTreeMap<u64, Vec<String>> = BTreeMap::new();
    for (i, addr) in &vectors {
        // one handler in many slots is the catch-all
        let shared = vectors.iter().filter(|(_, a)| a == addr).count() > 1;
        let name = if shared {
            "Default_Handler".to_string()
        } else {
            vector_name(*i)
        };
        functions.entry(*addr).or_insert_with(|| name.clone());
        let names = code_symbols.entry(*addr).or_default();
        if !names.contains(&name) {
            names.push(name);
        }
    }
    let entry_addr = if arm { entry & !1 } else { entry };
    let description = format!(
        "Raw binary image for {} ({} bytes at {base:#x}{})",
        p.title,
        length,
        if vectors.is_empty() {
            String::new()
        } else {
            format!(", {} vector table entries", vectors.len())
        }
    );
    Ok(Loaded {
        format: "raw",
        container: "raw",
        description,
        members: Vec::new(),
        language,
        base,
        image: loaded_image,
        blocks: vec![MemoryBlock {
            name: "image".into(),
            space: "ram".into(),
            start: base.into(),
            end: end.into(),
            perms: "rwx".into(),
            initialized: true,
            kind: MemoryKind::Default,
        }],
        functions,
        code_symbols,
        debug: crate::dwarf::Debug::default(),
        plt: BTreeMap::new(),
        import_slots: BTreeMap::new(),
        externals: BTreeMap::new(),
        pdata_starts: Vec::new(),
        pic_base: None,
        conventions: BTreeMap::new(),
        entry: Some(entry_addr),
        init_pointers: Vec::new(),
        data_pointers: Vec::new(),
        pointer_slots: Vec::new(),
        imports: Vec::new(),
        exports: BTreeMap::new(),
        fde_starts: Vec::new(),
        landing_pads: BTreeMap::new(),
        got_code: Vec::new(),
        default_names: BTreeMap::new(),
        global_pointer: None,
        data_symbols: BTreeMap::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_proto::Hex64;

    fn vector_blob() -> Vec<u8> {
        // SP, Reset (0x0800_0041), NMI, HardFault
        let mut b = Vec::new();
        for w in [0x2000_8000u32, 0x0800_0041, 0x0800_0051, 0x0800_0061] {
            b.extend(w.to_le_bytes());
        }
        b.resize(0x100, 0);
        b
    }

    #[test]
    fn names_resolve() {
        assert_eq!(resolve("Cortex-M"), Some("ARM:LE:32:Cortex"));
        assert_eq!(resolve("x86_64"), Some("x86:LE:64:default"));
        assert_eq!(resolve("ARM:LE:32:v8"), Some("ARM:LE:32:v8"));
        assert_eq!(resolve("z80"), None);
    }

    #[test]
    fn cortex_vector_table_is_read() {
        let v = cortex_vectors(&vector_blob(), 0x0800_0000);
        assert_eq!(
            v,
            vec![(1, 0x0800_0040), (2, 0x0800_0050), (3, 0x0800_0060)]
        );
        // not a table: SP inside the image
        assert!(cortex_vectors(&vector_blob(), 0x2000_7f00).is_empty());
        assert!(cortex_vectors(&[0u8; 64], 0).is_empty());
    }

    #[test]
    fn cortex_image_is_loaded_with_reset_as_entry() {
        let spec = LoaderSpec {
            format: Some("raw".into()),
            arch: Some("cortex-m".into()),
            base: Some(Hex64(0x0800_0000)),
            ..LoaderSpec::default()
        };
        let l = load(&vector_blob(), &spec).unwrap();
        assert_eq!(l.entry, Some(0x0800_0040));
        assert_eq!(l.functions[&0x0800_0040], "Reset_Handler");
        assert_eq!(l.functions[&0x0800_0060], "HardFault_Handler");
        assert!(l.is_code(0x0800_0040));
        assert!(l.is_thumb(0x0800_0040));
        assert_eq!(l.blocks[0].start.0, 0x0800_0000);
    }

    #[test]
    fn offset_length_and_entry_are_checked() {
        let data = vec![0x90u8; 0x100];
        let mk = |offset: u64, length: Option<u64>, entry: Option<u64>| LoaderSpec {
            format: Some("raw".into()),
            arch: Some("x86-32".into()),
            base: Some(Hex64(0x1000)),
            offset: Some(Hex64(offset)),
            length: length.map(Hex64),
            entry: entry.map(Hex64),
            ..LoaderSpec::default()
        };
        let l = load(&data, &mk(0x10, Some(0x20), Some(0x1008))).unwrap();
        assert_eq!((l.blocks[0].start.0, l.blocks[0].end.0), (0x1000, 0x1020));
        assert_eq!(l.entry, Some(0x1008));
        assert!(load(&data, &mk(0x100, None, None)).is_err());
        assert!(load(&data, &mk(0x10, Some(0x1000), None)).is_err());
        assert!(load(&data, &mk(0, None, Some(0x2000))).is_err());
        let none = LoaderSpec {
            format: Some("raw".into()),
            ..LoaderSpec::default()
        };
        assert!(
            load(&data, &none)
                .unwrap_err()
                .message
                .contains("processor")
        );
    }
}
