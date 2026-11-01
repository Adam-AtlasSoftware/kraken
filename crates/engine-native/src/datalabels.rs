//! Ghidra's automatic labels for data the code refers to, so the decompiler prints `DAT_00104020`
//! and `PTR_s_by_id_00103da0` where it would print `cRam0000000000104020`: `DAT_<addr>` for plain
//! data, `PTR_<what it points at>_<addr>` for a pointer, and `s_<text>_<addr>` for a string (a
//! string is only named inside a pointer's label: the decompiler prints the text itself).

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::Instruction;
use kraken_proto::{StringEncoding, StringEntry};

use crate::elf::Loaded;
use crate::refs::RefIndex;

/// Longest text of a string label, in characters.
const LABEL_TEXT: usize = 32;

/// One label for the decompiler's global scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataLabel {
    pub addr: u64,
    pub name: String,
    /// Declaration giving the type (`void *p`); empty leaves it to the decompiler.
    pub decl: String,
    pub size: u32,
}

/// The text of a string label as Ghidra writes it: whitespace and control characters become `_`,
/// the rest of the 7-bit characters stay, leading and trailing blanks go.
pub fn string_label_text(value: &str) -> String {
    let mapped: String = value
        .chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '_' })
        .collect();
    let trimmed = mapped.trim_matches('_');
    let mut out: String = trimmed.chars().take(LABEL_TEXT).collect();
    if trimmed.chars().count() > LABEL_TEXT {
        out = out.trim_end_matches('_').to_string();
    }
    out
}

/// A label without its address: `FUN_00101090` is `FUN`, `s_abc_00102004` is `s_abc`, and a name
/// of the symbol table stays whole.
fn without_address(name: &str) -> &str {
    if let Some((head, tail)) = name.rsplit_once('_')
        && tail.len() >= 8
        && tail.bytes().all(|b| b.is_ascii_hexdigit())
        && ["FUN", "LAB", "DAT", "LOOP", "UNK"].contains(&head)
    {
        return head;
    }
    name
}

/// The width in bytes of the memory operand an instruction reads or writes: from the operand size
/// keyword, else from the register on the other side.
fn access_width(i: &Instruction) -> u32 {
    let b = i.body.to_ascii_lowercase();
    for (kw, w) in [
        ("xmmword ptr", 8),
        ("qword ptr", 8),
        ("dword ptr", 4),
        ("word ptr", 2),
        ("byte ptr", 1),
    ] {
        if b.contains(kw) {
            return w;
        }
    }
    let mnemonic = i.mnemonic.to_ascii_lowercase();
    if mnemonic == "lea" {
        return 1;
    }
    let outside = b.split('[').next().unwrap_or("");
    let outside = if outside.trim().is_empty() {
        b.rsplit(']').next().unwrap_or("")
    } else {
        outside
    };
    for reg in outside.split(|c: char| !c.is_ascii_alphanumeric()) {
        let w = match reg {
            "rax" | "rbx" | "rcx" | "rdx" | "rsi" | "rdi" | "rbp" | "rsp" => 8,
            "eax" | "ebx" | "ecx" | "edx" | "esi" | "edi" | "ebp" | "esp" => 4,
            "ax" | "bx" | "cx" | "dx" | "si" | "di" | "bp" => 2,
            "al" | "bl" | "cl" | "dl" | "sil" | "dil" | "ah" | "bh" | "ch" | "dh" => 1,
            r if r.starts_with('r') && r.len() >= 2 => {
                let digits = r[1..].trim_end_matches(['d', 'w', 'b']);
                if digits.is_empty() || !digits.bytes().all(|c| c.is_ascii_digit()) {
                    continue;
                }
                match r.as_bytes()[r.len() - 1] {
                    b'd' => 4,
                    b'w' => 2,
                    b'b' => 1,
                    _ => 8,
                }
            }
            _ => continue,
        };
        return w;
    }
    if b.contains("xmm") { 8 } else { 4 }
}

/// The width of what the code reads or writes through a register loaded by `lea reg, [data]`:
/// the widest `[reg]` access among the next few instructions (the register may be overwritten
/// later; a wrong guess only widens a label).
fn width_through_lea(insns: &BTreeMap<u64, Instruction>, lea: &Instruction) -> Option<u32> {
    let body = lea.body.to_ascii_lowercase();
    let reg = body.split(',').next()?.trim().to_string();
    if reg.is_empty() || !reg.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let needle = format!("[{reg}]");
    insns
        .range(lea.addr + 1..)
        .take(48)
        .filter(|(_, i)| i.body.to_ascii_lowercase().contains(&needle))
        .map(|(_, i)| access_width(i))
        .max()
}

/// Whether the symbol table's name for the data at `addr` is left out, as Ghidra leaves it out: a
/// COFF symbol at the very start of a section is taken for the section's own.
pub fn symbol_ignored(loaded: &Loaded, addr: u64) -> bool {
    loaded.container == "pe"
        && !loaded.debug.globals.contains_key(&addr)
        && loaded.blocks.iter().any(|b| b.start.0 == addr)
}

/// The labels that type the strings the code points at (`targets`) as `char[n]`, so a constant
/// pointer prints as the literal. Only 8-bit text: a UTF-16 string typed `char[]` would print as
/// its first character. `eligible` leaves out code, named data and fields of typed variables.
fn string_labels(
    strings: &[StringEntry],
    targets: &[u64],
    eligible: &dyn Fn(u64) -> bool,
) -> Vec<DataLabel> {
    let at: BTreeMap<u64, &StringEntry> = strings
        .iter()
        .filter(|s| matches!(s.encoding, StringEncoding::Ascii | StringEncoding::Utf8))
        .map(|s| (s.address.0, s))
        .collect();
    targets
        .iter()
        .filter_map(|a| at.get(a).filter(|_| eligible(*a)).map(|s| (*a, *s)))
        .map(|(a, s)| {
            let len = s.length.max(1);
            DataLabel {
                addr: a,
                name: format!("s_{}_{a:08x}", string_label_text(&s.value)),
                decl: format!("char s[{len}]"),
                size: len,
            }
        })
        .collect()
}

/// The bytes a `DAT_` label at `a` may cover: up to the next label, the end of its block or the
/// next typed string (`strings`: start to end). `None` when `a` lies inside a typed string.
fn room_at(
    a: u64,
    next: Option<u64>,
    block_end: Option<u64>,
    strings: &BTreeMap<u64, u64>,
) -> Option<u64> {
    if strings
        .range(..=a)
        .next_back()
        .is_some_and(|(_, end)| a < *end)
    {
        return None;
    }
    let next_string = strings.range(a + 1..).next().map(|(s, _)| *s);
    Some(
        next.into_iter()
            .chain(block_end)
            .chain(next_string)
            .min()
            .map_or(1, |e| e - a),
    )
}

/// The labels for the data the references touch. `function_name` gives the name of the function
/// starting at an address; `strings` are the strings found (those at referenced addresses).
/// Addresses the symbol table or DWARF names, code, imports and the stand-ins for them are left
/// out.
pub fn compute(
    loaded: &Loaded,
    refs: &RefIndex,
    insns: &BTreeMap<u64, Instruction>,
    function_name: &dyn Fn(u64) -> Option<String>,
    strings: &[StringEntry],
) -> Vec<DataLabel> {
    let ptr = loaded.pointer_size() as u64;
    let text: BTreeMap<u64, &str> = strings
        .iter()
        .map(|s| (s.address.0, s.value.as_str()))
        .collect();
    let block_of = |a: u64| loaded.blocks.iter().find(|b| b.start.0 <= a && a < b.end.0);
    let is_code = |a: u64| loaded.is_code(a);
    let taken = |a: u64| {
        (loaded.data_symbols.contains_key(&a) && !symbol_ignored(loaded, a))
            || loaded.debug.globals.contains_key(&a)
            || loaded.import_slots.contains_key(&a)
            || loaded.externals.contains_key(&a)
            || loaded.plt.contains_key(&a)
            // the Mach-O header: Ghidra's markup of it leaves no labels to code
            || block_of(a).is_some_and(|b| b.name == "__TEXT")
    };
    // a field or an element of a variable DWARF types: the typed variable prints it
    let inside_typed = |a: u64| {
        loaded
            .data_symbols
            .range(..=a)
            .next_back()
            .is_some_and(|(s, d)| a < s + d.size && loaded.debug.globals.contains_key(s))
    };
    // the decompiler prints a string in read-only data as the text
    let min_string = if loaded.container == "pe" { 5 } else { 1 };
    let readonly_string = |a: u64| {
        // a relocated pointer in RELRO data can look like a short string (`2c 20 00`)
        if loaded
            .pointer_slots
            .binary_search_by_key(&a, |(s, _)| *s)
            .is_ok()
        {
            return false;
        }
        let Some(b) = block_of(a).filter(|b| b.initialized && !b.perms.contains('w')) else {
            return false;
        };
        let len = usize::try_from((b.end.0 - a).min(256)).unwrap_or(0);
        let mut bytes = vec![0u8; len];
        loaded.image.read(a, &mut bytes)
            && bytes.iter().position(|c| *c == 0).is_some_and(|n| {
                n >= min_string
                    && bytes[..n]
                        .iter()
                        .all(|c| (0x20..0x7f).contains(c) || matches!(c, b'\t' | b'\n' | b'\r'))
            })
    };
    let wanted: BTreeSet<u64> = refs
        .touched_targets()
        .into_iter()
        .filter(|a| {
            block_of(*a).is_some_and(|b| b.space == "ram")
                && !is_code(*a)
                && function_name(*a).is_none()
                && !taken(*a)
                && !inside_typed(*a)
                && !readonly_string(*a)
        })
        .collect();
    // what the label of a target says about it
    let target_label = |from: u64, v: u64| -> Option<String> {
        if v == from {
            return Some("LOOP".to_string());
        }
        block_of(v)?;
        if let Some(n) = function_name(v) {
            return Some(without_address(&n).to_string());
        }
        if is_code(v) {
            return Some("LAB".to_string());
        }
        if let Some(t) = text.get(&v) {
            return Some(format!("s_{}", string_label_text(t)));
        }
        if let Some(s) = loaded.data_symbols.get(&v) {
            return Some(s.name.clone());
        }
        if let Some(g) = loaded.debug.globals.get(&v) {
            return Some(g.name.clone());
        }
        wanted.contains(&v).then(|| "DAT".to_string())
    };
    let mut out = string_labels(strings, &refs.touched_targets(), &|a| {
        block_of(a).is_some_and(|b| b.space == "ram")
            && !is_code(a)
            && !taken(a)
            && !inside_typed(a)
    });
    let typed_strings: BTreeMap<u64, u64> = out
        .iter()
        .map(|l| (l.addr, l.addr + u64::from(l.size)))
        .collect();
    let all: Vec<u64> = wanted.iter().copied().collect();
    for (k, a) in all.iter().enumerate() {
        if text.contains_key(a) {
            continue;
        }
        let block = block_of(*a);
        let Some(room) = room_at(
            *a,
            all.get(k + 1).copied(),
            block.map(|b| b.end.0),
            &typed_strings,
        ) else {
            // inside a string typed above: the string prints it
            continue;
        };
        if block.is_some_and(|b| b.name == ".got") {
            // slots the loader fills: imports, which the decompiler names itself
            continue;
        }
        let slot = loaded
            .pointer_slots
            .binary_search_by_key(a, |(s, _)| *s)
            .ok()
            .map(|i| loaded.pointer_slots[i].1);
        let stored = slot.or_else(|| {
            if !block.is_some_and(|b| b.initialized) || a % ptr != 0 {
                return None;
            }
            let mut bytes = vec![0u8; ptr as usize];
            loaded.image.read(*a, &mut bytes).then(|| {
                bytes
                    .iter()
                    .enumerate()
                    .fold(0u64, |v, (i, b)| v | (u64::from(*b) << (8 * i)))
            })
        });
        let pointer = stored.filter(|v| *v != 0).and_then(|v| target_label(*a, v));
        if let Some(t) = pointer {
            out.push(DataLabel {
                addr: *a,
                name: format!("PTR_{t}_{a:08x}"),
                decl: "void *p".to_string(),
                size: ptr as u32,
            });
            continue;
        }
        let width = refs
            .to(*a)
            .iter()
            .filter_map(|r| {
                let Some(i) = insns.get(&r.from) else {
                    // a pointer slot (`.refptr`): what is read through the register it is
                    // loaded into
                    return refs
                        .to(r.from)
                        .iter()
                        .filter_map(|s| insns.get(&s.from))
                        .filter_map(|l| width_through_lea(insns, l))
                        .max();
                };
                if i.mnemonic.eq_ignore_ascii_case("lea") {
                    Some(width_through_lea(insns, i).unwrap_or(1))
                } else {
                    Some(access_width(i))
                }
            })
            .max()
            .unwrap_or(4);
        let mut size = width.min(8).min(u32::try_from(room).unwrap_or(8)).max(1);
        while size > 1 && (!size.is_power_of_two() || a % u64::from(size) != 0) {
            size -= 1;
        }
        out.push(DataLabel {
            addr: *a,
            name: format!("DAT_{a:08x}"),
            decl: String::new(),
            size,
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_text_as_ghidra() {
        assert_eq!(string_label_text("1 + 2 * 3"), "1_+_2_*_3");
        assert_eq!(string_label_text("%-18s : error\n"), "%-18s_:_error");
        assert_eq!(
            string_label_text("apply_all=%d secret=%d version=%s\n"),
            "apply_all=%d_secret=%d_version=%"
        );
    }

    fn entry(addr: u64, value: &str, encoding: StringEncoding, length: u32) -> StringEntry {
        StringEntry {
            address: kraken_proto::Hex64(addr),
            value: value.into(),
            encoding,
            length,
        }
    }

    #[test]
    fn only_8_bit_strings_the_caller_allows_are_typed() {
        let strings = [
            entry(0x100, "Hello", StringEncoding::Ascii, 6),
            entry(0x200, "Wide", StringEncoding::Utf16, 10),
            entry(0x300, "name", StringEncoding::Utf8, 5),
        ];
        // 0x300 is a field of a typed global, so the caller leaves it out
        let labels = string_labels(&strings, &[0x100, 0x200, 0x300, 0x400], &|a| a != 0x300);
        assert_eq!(
            labels,
            vec![DataLabel {
                addr: 0x100,
                name: "s_Hello_00000100".into(),
                decl: "char s[6]".into(),
                size: 6,
            }]
        );
    }

    #[test]
    fn data_labels_stop_at_typed_strings() {
        let strings = BTreeMap::from([(0x108, 0x110)]);
        // the string bounds the label before it
        assert_eq!(room_at(0x100, Some(0x200), Some(0x1000), &strings), Some(8));
        // a label inside the string is left to it
        assert_eq!(room_at(0x10c, Some(0x200), Some(0x1000), &strings), None);
        // past the string, the next label and the block end count as before
        assert_eq!(room_at(0x110, Some(0x118), Some(0x1000), &strings), Some(8));
        assert_eq!(room_at(0x110, None, None, &strings), Some(1));
    }

    #[test]
    fn labels_lose_their_address() {
        assert_eq!(without_address("FUN_00101090"), "FUN");
        assert_eq!(without_address("op_sub"), "op_sub");
    }
}
