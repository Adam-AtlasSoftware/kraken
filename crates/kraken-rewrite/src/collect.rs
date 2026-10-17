//! Reads the call graph of a project through [`Lift`] and classifies what it finds: program
//! functions, import thunks (the program's external calls) and compiler glue.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use kraken_proto::XrefKind;
use kraken_registry::{CallContext, Session};

use crate::error::RewriteError;
use crate::lift::{Block, Lift, OutRef};
use crate::plan::{Collected, FnNode, RUNTIME_GLUE, is_linker_block, is_thunk_block};

/// What a call target is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// A function of the program.
    Program,
    /// A thunk for an imported library function, with the import's name.
    Import(String),
    /// Compiler or loader glue.
    Glue,
}

/// Facts about the program that classify addresses.
#[derive(Debug, Clone, Default)]
pub struct ProgramFacts {
    import_addrs: BTreeSet<u64>,
    import_names: BTreeSet<String>,
    blocks: Vec<Block>,
    /// Addresses of the program's own copies of `stdout` and `stderr` (copy relocations): the
    /// oracle models these streams, so touching them is not a global the test cannot control.
    stdio_cells: BTreeSet<u64>,
}

/// Where a PIE or fixed-address ELF keeps its copy-relocated `stdout` / `stderr`, as addresses of
/// the loaded program (ELF address plus `image_base` for a PIE).
fn stdio_cells(path: &Path, image_base: u64) -> BTreeSet<u64> {
    use object::read::elf::ElfFile64;
    use object::{Object, ObjectSymbol, RelocationFlags, RelocationTarget, elf};
    let Ok(data) = std::fs::read(path) else {
        return BTreeSet::new();
    };
    let Ok(file) = ElfFile64::<object::Endianness>::parse(&*data) else {
        return BTreeSet::new();
    };
    let endian = file.endian();
    let bias = if file.elf_header().e_type.get(endian) == elf::ET_DYN {
        image_base
    } else {
        0
    };
    let mut out = BTreeSet::new();
    if let Some(relocs) = file.dynamic_relocations() {
        for (offset, rel) in relocs {
            let RelocationFlags::Elf { r_type } = rel.flags() else {
                continue;
            };
            if r_type != elf::R_X86_64_COPY {
                continue;
            }
            let RelocationTarget::Symbol(idx) = rel.target() else {
                continue;
            };
            let name = file
                .dynamic_symbols()
                .find(|s| s.index() == idx)
                .and_then(|s| s.name().ok());
            if matches!(name, Some("stdout" | "stderr")) {
                out.insert(bias + offset);
            }
        }
    }
    out
}

impl ProgramFacts {
    /// Reads the import table, the memory map and the binary's stdio copy relocations.
    pub async fn load(lift: &Lift<'_>) -> Result<Self, RewriteError> {
        let imports = lift.imports().await?;
        let (binary, image_base) = lift.binary()?;
        Ok(ProgramFacts {
            import_addrs: imports.iter().filter_map(|(a, _)| *a).collect(),
            import_names: imports.into_iter().map(|(_, n)| n).collect(),
            blocks: lift.blocks().await?,
            stdio_cells: stdio_cells(&binary, image_base),
        })
    }

    fn block_of(&self, address: u64) -> Option<&Block> {
        self.blocks
            .iter()
            .find(|b| b.start <= address && address < b.end)
    }

    /// Classifies the function `name` at `address`.
    pub fn classify(&self, address: u64, name: &str) -> Target {
        let in_thunk = self
            .block_of(address)
            .is_some_and(|b| is_thunk_block(&b.name));
        if self.import_addrs.contains(&address) || (in_thunk && self.import_names.contains(name)) {
            Target::Import(name.to_string())
        } else if in_thunk || RUNTIME_GLUE.contains(&name) {
            Target::Glue
        } else {
            Target::Program
        }
    }

    /// True when `address` is in a block that can hold a table of function pointers: `.data*`
    /// and `.rodata*` (not code, unwind tables or the dynamic-linking sections).
    pub fn is_pointer_table_block(&self, address: u64) -> bool {
        self.block_of(address)
            .is_some_and(|b| b.name.starts_with(".data") || b.name.starts_with(".rodata"))
    }

    /// True when both addresses are in the same memory block.
    pub fn same_block(&self, a: u64, b: u64) -> bool {
        match (self.block_of(a), self.block_of(b)) {
            (Some(x), Some(y)) => x.start == y.start,
            _ => false,
        }
    }

    /// True when `address` is in a writable data block that holds program globals.
    pub fn is_global(&self, address: u64) -> bool {
        !self.stdio_cells.contains(&address)
            && self
                .block_of(address)
                .is_some_and(|b| b.writable && !is_linker_block(&b.name))
    }

    /// True when any of `refs` is a data reference to a program global.
    pub fn touches_globals(&self, refs: &[OutRef]) -> bool {
        refs.iter().any(|r| {
            matches!(r.kind, XrefKind::Read | XrefKind::Write | XrefKind::Data)
                && self.is_global(r.to)
        })
    }
}

/// A function's direct calls, split by what they call.
#[derive(Debug, Clone, Default)]
pub struct Calls {
    /// Program functions called (entry, name).
    pub program: BTreeMap<u64, String>,
    /// Imports called.
    pub imports: BTreeSet<String>,
    /// Calls to glue.
    pub glue: u64,
}

/// Splits the calls the function containing `address` makes.
pub async fn calls_of(
    lift: &Lift<'_>,
    facts: &ProgramFacts,
    address: u64,
) -> Result<Calls, RewriteError> {
    let mut out = Calls::default();
    for r in lift.callees(address).await? {
        let Some((target, name)) = r.to_function else {
            continue;
        };
        match facts.classify(target, &name) {
            Target::Program => {
                out.program.insert(target, name);
            }
            Target::Import(n) => {
                out.imports.insert(n);
            }
            Target::Glue => out.glue += 1,
        }
    }
    Ok(out)
}

/// Reads the call graph of the whole program (up to `cap` functions).
pub async fn collect(
    s: &Session,
    ctx: &CallContext,
    cap: usize,
) -> Result<Collected, RewriteError> {
    let lift = Lift::new(s, ctx);
    let (functions, truncated) = lift.functions(cap).await?;
    let facts = ProgramFacts::load(&lift).await?;
    let mut out = Collected {
        functions_total: functions.len() as u64,
        truncated,
        ..Collected::default()
    };
    let mut program: BTreeMap<u64, String> = BTreeMap::new();
    for f in &functions {
        match facts.classify(f.address, &f.name) {
            Target::Program => {
                program.insert(f.address, f.name.clone());
            }
            Target::Import(_) => out.skipped_imports += 1,
            Target::Glue => out.skipped_runtime += 1,
        }
    }
    for (addr, name) in &program {
        let calls = calls_of(&lift, &facts, *addr).await?;
        let globals = facts.touches_globals(&lift.data_refs(*addr).await?);
        out.nodes.push(FnNode {
            address: *addr,
            name: name.clone(),
            callees: calls
                .program
                .keys()
                .copied()
                .filter(|c| program.contains_key(c))
                .collect(),
            imports: calls.imports,
            globals,
            syscalls: false,
        });
    }
    Ok(out)
}

/// How far past a data address a function takes (a table it indexes) a pointer stored in the
/// table still counts as taken by that function.
const TABLE_REACH: u64 = 0x80;

/// The functions whose address each program function takes: `F -> {G}` when `F` stores `G`'s
/// entry (a data reference to the entry from `F`), or when `G`'s entry sits in a data table that
/// `F` references (the pointer is stored at a location with no function, within
/// [`TABLE_REACH`] bytes after an address `F` refers to). This is how functions that are only
/// ever called through a pointer, as `qsort` callbacks and dispatch tables are, join the call
/// graph.
pub async fn address_taken(
    lift: &Lift<'_>,
    facts: &ProgramFacts,
    program: &BTreeMap<u64, String>,
) -> Result<BTreeMap<u64, BTreeSet<u64>>, RewriteError> {
    // What each function refers to (read, written or address-taken data).
    let mut data_to: BTreeMap<u64, Vec<u64>> = BTreeMap::new();
    let mut taken: BTreeMap<u64, BTreeSet<u64>> = BTreeMap::new();
    for f in program.keys() {
        let refs = lift.data_refs(*f).await?;
        for r in &refs {
            if let Some((g, _)) = &r.to_function
                && program.contains_key(g)
                && g != f
            {
                taken.entry(*f).or_default().insert(*g);
            }
        }
        data_to.insert(*f, refs.iter().map(|r| r.to).collect());
    }
    for g in program.keys() {
        for (from, in_function) in lift.data_refs_to(*g).await? {
            // A table of pointers lives in a data block; the unwind tables and the like next to
            // it also point at every function entry and are not uses.
            if in_function.is_some() || !facts.is_pointer_table_block(from) {
                continue;
            }
            for (f, targets) in &data_to {
                if f != g
                    && targets.iter().any(|d| {
                        *d <= from
                            && from < d.saturating_add(TABLE_REACH)
                            && facts.same_block(*d, from)
                    })
                {
                    taken.entry(*f).or_default().insert(*g);
                }
            }
        }
    }
    Ok(taken)
}

/// [`collect`] for a whole-program rewrite: the call graph plus the functions whose address a
/// function takes (see [`address_taken`]) as edges, so they are translated before the function
/// that passes them on and the program run reaches them. The second value says which edges
/// those are.
pub async fn collect_program(
    s: &Session,
    ctx: &CallContext,
    cap: usize,
) -> Result<(Collected, BTreeMap<u64, BTreeSet<u64>>), RewriteError> {
    let mut out = collect(s, ctx, cap).await?;
    let lift = Lift::new(s, ctx);
    let program: BTreeMap<u64, String> = out
        .nodes
        .iter()
        .map(|n| (n.address, n.name.clone()))
        .collect();
    let facts = ProgramFacts::load(&lift).await?;
    let taken = address_taken(&lift, &facts, &program).await?;
    for n in &mut out.nodes {
        if let Some(gs) = taken.get(&n.address) {
            n.callees.extend(gs.iter().copied());
        }
    }
    Ok((out, taken))
}

/// Reads the part of the call graph reachable from `entry` (callees, transitively; at most `cap`
/// functions). Returns it with the entry address of the function that contains `entry`.
pub async fn collect_closure(
    s: &Session,
    ctx: &CallContext,
    entry: u64,
    cap: usize,
) -> Result<(Collected, u64), RewriteError> {
    let lift = Lift::new(s, ctx);
    let root = lift.listed(entry).await?;
    let facts = ProgramFacts::load(&lift).await?;
    let mut out = Collected::default();
    let mut names: BTreeMap<u64, String> = BTreeMap::new();
    names.insert(root.address, root.name.clone());
    let mut todo = vec![root.address];
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    while let Some(addr) = todo.pop() {
        if !seen.insert(addr) {
            continue;
        }
        if seen.len() > cap {
            out.truncated = true;
            break;
        }
        let calls = calls_of(&lift, &facts, addr).await?;
        out.skipped_imports += calls.imports.len() as u64;
        out.skipped_runtime += calls.glue;
        for (target, name) in &calls.program {
            names.entry(*target).or_insert_with(|| name.clone());
            todo.push(*target);
        }
        let globals = facts.touches_globals(&lift.data_refs(addr).await?);
        out.nodes.push(FnNode {
            address: addr,
            name: names.get(&addr).cloned().unwrap_or_default(),
            callees: calls.program.keys().copied().collect(),
            imports: calls.imports,
            globals,
            syscalls: false,
        });
    }
    out.functions_total = out.nodes.len() as u64;
    // Calls to functions beyond the cap are not nodes; the ordering drops those edges.
    Ok((out, root.address))
}
