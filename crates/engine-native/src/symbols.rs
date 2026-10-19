//! Imports and exports in the shape of Ghidra's external symbols and external entry points:
//! an import's address is its PLT stub, and the exports are the global and weak definitions plus
//! the entry point and the init/fini array functions, one per address. C++ names are shown
//! demangled as Ghidra shows them (an export with DWARF takes the function's DWARF name), with the
//! mangled name kept in `mangled`.

use std::collections::BTreeMap;

use kraken_proto::{Hex64, SymbolEntry, SymbolKind};

use crate::demangle::{display_name, mangled};
use crate::discover::Func;
use crate::elf::Loaded;

/// The name a function or export at `addr` with symbol `raw` gets: its DWARF name, else the
/// demangled name, else `raw` (a placeholder `FUN_` name in the program's spelling, see
/// [`Loaded::default_prefix`]).
pub fn default_name(loaded: &Loaded, addr: u64, raw: &str) -> String {
    match loaded.debug.functions.get(&addr) {
        Some(f) => f.name.clone(),
        None if raw == crate::discover::default_name(addr) => {
            format!("{}{addr:08x}", loaded.default_prefix())
        }
        None => display_name(raw),
    }
}

/// Imported symbols ordered by (address, name), addressless ones last.
pub fn imports(loaded: &Loaded) -> Vec<SymbolEntry> {
    let stubs: BTreeMap<&str, u64> = loaded.plt.iter().map(|(a, n)| (n.as_str(), *a)).collect();
    let mut out: Vec<SymbolEntry> = loaded
        .imports
        .iter()
        .map(|i| SymbolEntry {
            name: display_name(&i.name),
            address: stubs.get(i.name.as_str()).map(|a| Hex64(*a)),
            library: i.library.clone(),
            kind: i.kind,
            mangled: mangled(&i.name),
        })
        .collect();
    out.sort_by(|a, b| {
        (a.address.is_none(), a.address, &a.name).cmp(&(b.address.is_none(), b.address, &b.name))
    });
    out
}

/// Exported symbols ordered by (address, name). Names come from the symbol table (see
/// [`default_name`]), else from the function at the address; `renamed` gives the name of a
/// function the user renamed, which the export follows (it is the same symbol).
pub fn exports(
    loaded: &Loaded,
    functions: &BTreeMap<u64, Func>,
    renamed: &dyn Fn(u64) -> Option<String>,
) -> Vec<SymbolEntry> {
    let mut at: BTreeMap<u64, SymbolEntry> = BTreeMap::new();
    for (a, e) in &loaded.exports {
        let kind = if functions.contains_key(a) {
            SymbolKind::Function
        } else {
            e.kind
        };
        let name = renamed(*a).unwrap_or_else(|| default_name(loaded, *a, &e.name));
        at.insert(
            *a,
            SymbolEntry {
                name,
                address: Some(Hex64(*a)),
                library: e.member.clone(),
                kind,
                mangled: mangled(&e.name),
            },
        );
    }
    let extra = loaded
        .entry
        .into_iter()
        .chain(loaded.init_pointers.iter().copied())
        .filter(|a| !loaded.in_plt(*a));
    for a in extra {
        at.entry(a).or_insert_with(|| SymbolEntry {
            name: functions
                .get(&a)
                .map(|f| f.name.clone())
                .unwrap_or_else(|| format!("entry_{a:x}")),
            address: Some(Hex64(a)),
            library: None,
            kind: if functions.contains_key(&a) {
                SymbolKind::Function
            } else {
                SymbolKind::Other
            },
            mangled: None,
        });
    }
    at.into_values().collect()
}
