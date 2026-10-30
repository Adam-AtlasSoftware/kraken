//! Ghidra's automatic labels for data the code refers to, so the decompiler prints `DAT_00104020`
//! and `PTR_s_by_id_00103da0` where it would print `cRam0000000000104020`: `DAT_<addr>` for plain
//! data, `PTR_<what it points at>_<addr>` for a pointer, and `s_<text>_<addr>` for a string (a
//! string is only named inside a pointer's label: the decompiler prints the text itself).

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::Instruction;
use kraken_proto::StringEntry;

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

/// Whether the symbol table's name for the data at `addr` is left out, as Ghidra leaves it out: a
/// COFF symbol at the very start of a section is taken for the section's own.
pub fn symbol_ignored(loaded: &Loaded, addr: u64) -> bool {
    loaded.container == "pe"
        && !loaded.debug.globals.contains_key(&addr)
        && loaded.blocks.iter().any(|b| b.start.0 == addr)
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
    let mut out = Vec::new();
    let all: Vec<u64> = wanted.iter().copied().collect();
    for (k, a) in all.iter().enumerate() {
        if text.contains_key(a) {
            continue;
        }
        let block = block_of(*a);
        let room = all
            .get(k + 1)
            .copied()
            .into_iter()
            .chain(block.map(|b| b.end.0))
            .min()
            .map_or(1, |e| e - a);
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
            .filter_map(|r| insns.get(&r.from).map(access_width))
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

    #[test]
    fn labels_lose_their_address() {
        assert_eq!(without_address("FUN_00101090"), "FUN");
        assert_eq!(without_address("op_sub"), "op_sub");
    }
}
