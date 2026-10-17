//! Imports and exports in the shape of Ghidra's external symbols and external entry points:
//! an import's address is its PLT stub, and the exports are the global and weak definitions plus
//! the entry point and the init/fini array functions, one per address.

use std::collections::BTreeMap;

use kraken_proto::{Hex64, SymbolEntry, SymbolKind};

use crate::discover::Func;
use crate::elf::Loaded;

/// Imported symbols ordered by (address, name), addressless ones last.
pub fn imports(loaded: &Loaded) -> Vec<SymbolEntry> {
    let stubs: BTreeMap<&str, u64> = loaded.plt.iter().map(|(a, n)| (n.as_str(), *a)).collect();
    let mut out: Vec<SymbolEntry> = loaded
        .imports
        .iter()
        .map(|i| SymbolEntry {
            name: i.name.clone(),
            address: stubs.get(i.name.as_str()).map(|a| Hex64(*a)),
            library: None,
            kind: i.kind,
        })
        .collect();
    out.sort_by(|a, b| {
        (a.address.is_none(), a.address, &a.name).cmp(&(b.address.is_none(), b.address, &b.name))
    });
    out
}

/// Exported symbols ordered by (address, name). Names come from the symbol table, else from
/// the function at the address.
pub fn exports(loaded: &Loaded, functions: &BTreeMap<u64, Func>) -> Vec<SymbolEntry> {
    let mut at: BTreeMap<u64, SymbolEntry> = BTreeMap::new();
    for (a, e) in &loaded.exports {
        let kind = if functions.contains_key(a) {
            SymbolKind::Function
        } else {
            e.kind
        };
        at.insert(
            *a,
            SymbolEntry {
                name: e.name.clone(),
                address: Some(Hex64(*a)),
                library: None,
                kind,
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
        });
    }
    at.into_values().collect()
}
