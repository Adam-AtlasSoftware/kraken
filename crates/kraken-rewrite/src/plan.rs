//! The rewrite plan: functions in dependency order, callees first, recursive groups together,
//! with the ones the differential test cannot fully cover flagged.
//!
//! [`order_functions`] is the pure algorithm over a call graph (Tarjan's strongly connected
//! components, which come out callee-first); [`crate::collect`] reads the graph from a project through
//! [`crate::lift::Lift`].

use std::collections::{BTreeMap, BTreeSet};

use kraken_registry::commands::PlanFlag;

use crate::oracle::STUBBED_IMPORTS;
use crate::store::{PlannedFunction, StoredPlan};

/// Names of compiler and loader glue that is not part of the program's own code.
pub(crate) const RUNTIME_GLUE: &[&str] = &[
    "_init",
    "_fini",
    "_start",
    "entry",
    "deregister_tm_clones",
    "register_tm_clones",
    "__do_global_dtors_aux",
    "frame_dummy",
    "__libc_csu_init",
    "__libc_csu_fini",
    "__cxa_finalize",
    "__gmon_start__",
    "_DT_INIT",
    "_DT_FINI",
];

/// Names of import-section memory blocks whose functions are thunks, not code.
pub(crate) fn is_thunk_block(name: &str) -> bool {
    name.starts_with(".plt")
        || name == ".init"
        || name == ".fini"
        || name.starts_with(".stubs")
        || name == "EXTERNAL"
}

/// Data blocks that hold dynamic-linking bookkeeping rather than program globals.
pub(crate) fn is_linker_block(name: &str) -> bool {
    name.starts_with(".got")
        || name.starts_with(".dyn")
        || name.starts_with(".init_array")
        || name.starts_with(".fini_array")
        || name == ".data.rel.ro"
        || name == ".tm_clone_table"
}

/// One function of the call graph.
#[derive(Debug, Clone, Default)]
pub struct FnNode {
    /// Entry address.
    pub address: u64,
    /// Name.
    pub name: String,
    /// Entries of the program functions it calls (nodes of the graph).
    pub callees: BTreeSet<u64>,
    /// Imports it calls directly.
    pub imports: BTreeSet<String>,
    /// References global data.
    pub globals: bool,
    /// Calls `syscall`.
    pub syscalls: bool,
}

/// The result of ordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ordered {
    /// Functions in rewrite order.
    pub entries: Vec<PlannedFunction>,
    /// Number of groups.
    pub groups: u32,
}

/// True for imports the oracle has no stub for.
pub fn needs_stub(import: &str) -> bool {
    !STUBBED_IMPORTS.contains(&import)
}

fn is_syscall(import: &str) -> bool {
    matches!(import, "syscall" | "__syscall" | "__libc_syscall")
}

/// Orders `nodes` leaves first. Within a group and among independent functions the order is by
/// address, so the result is deterministic.
pub fn order_functions(nodes: &[FnNode]) -> Ordered {
    let by_addr: BTreeMap<u64, usize> = {
        let mut idx: Vec<usize> = (0..nodes.len()).collect();
        idx.sort_by_key(|&i| nodes[i].address);
        idx.into_iter().map(|i| (nodes[i].address, i)).collect()
    };
    let addrs: Vec<u64> = by_addr.keys().copied().collect();
    let n = addrs.len();
    let node_of = |slot: usize| &nodes[by_addr[&addrs[slot]]];
    let slot_of: BTreeMap<u64, usize> = addrs.iter().enumerate().map(|(s, a)| (*a, s)).collect();
    let edges: Vec<Vec<usize>> = (0..n)
        .map(|s| {
            node_of(s)
                .callees
                .iter()
                .filter_map(|c| slot_of.get(c).copied())
                .collect()
        })
        .collect();

    // Iterative Tarjan. SCCs are emitted callee-first.
    const UNSEEN: usize = usize::MAX;
    let mut index = vec![UNSEEN; n];
    let mut low = vec![0usize; n];
    let mut on_stack = vec![false; n];
    let mut stack: Vec<usize> = Vec::new();
    let mut next_index = 0usize;
    let mut sccs: Vec<Vec<usize>> = Vec::new();
    for root in 0..n {
        if index[root] != UNSEEN {
            continue;
        }
        let mut work: Vec<(usize, usize)> = vec![(root, 0)];
        while let Some(&(v, i)) = work.last() {
            if i == 0 {
                index[v] = next_index;
                low[v] = next_index;
                next_index += 1;
                stack.push(v);
                on_stack[v] = true;
            }
            if let Some(&w) = edges[v].get(i) {
                if let Some(top) = work.last_mut() {
                    top.1 += 1;
                }
                if index[w] == UNSEEN {
                    work.push((w, 0));
                } else if on_stack[w] {
                    low[v] = low[v].min(index[w]);
                }
            } else {
                if low[v] == index[v] {
                    let mut comp = Vec::new();
                    while let Some(w) = stack.pop() {
                        on_stack[w] = false;
                        comp.push(w);
                        if w == v {
                            break;
                        }
                    }
                    comp.sort_unstable();
                    sccs.push(comp);
                }
                work.pop();
                if let Some(&(parent, _)) = work.last() {
                    low[parent] = low[parent].min(low[v]);
                }
            }
        }
    }

    // Per SCC, in emission order, accumulate what its functions (and everything below) need.
    let mut scc_of = vec![0usize; n];
    for (c, comp) in sccs.iter().enumerate() {
        for &s in comp {
            scc_of[s] = c;
        }
    }
    let mut stubs: Vec<BTreeSet<String>> = Vec::with_capacity(sccs.len());
    let mut globals = vec![false; sccs.len()];
    let mut syscalls = vec![false; sccs.len()];
    for (c, comp) in sccs.iter().enumerate() {
        let mut set = BTreeSet::new();
        for &s in comp {
            let node = node_of(s);
            set.extend(node.imports.iter().filter(|i| needs_stub(i)).cloned());
            globals[c] |= node.globals;
            syscalls[c] |= node.syscalls || node.imports.iter().any(|i| is_syscall(i));
            for &w in &edges[s] {
                let d = scc_of[w];
                if d != c {
                    set.extend(stubs[d].iter().cloned());
                    globals[c] |= globals[d];
                    syscalls[c] |= syscalls[d];
                }
            }
        }
        stubs.push(set);
    }

    let mut entries = Vec::with_capacity(n);
    for (c, comp) in sccs.iter().enumerate() {
        for &s in comp {
            let node = node_of(s);
            let recursive = comp.len() > 1 || edges[s].contains(&s);
            let mut flags = Vec::new();
            if !stubs[c].is_empty() {
                flags.push(PlanFlag::NeedsStubs);
            }
            if globals[c] {
                flags.push(PlanFlag::UsesGlobals);
            }
            if syscalls[c] {
                flags.push(PlanFlag::UsesSyscalls);
            }
            if recursive {
                flags.push(PlanFlag::Recursive);
            }
            entries.push(PlannedFunction {
                order: u32::try_from(entries.len()).unwrap_or(u32::MAX),
                address: node.address,
                name: node.name.clone(),
                group: u32::try_from(c).unwrap_or(u32::MAX),
                group_size: u32::try_from(comp.len()).unwrap_or(u32::MAX),
                callees: edges[s].iter().map(|&w| addrs[w]).collect(),
                imports: node.imports.iter().cloned().collect(),
                needs_stubs: stubs[c].iter().cloned().collect(),
                flags,
            });
        }
    }
    Ordered {
        entries,
        groups: u32::try_from(sccs.len()).unwrap_or(u32::MAX),
    }
}

/// The graph read from a project.
#[derive(Debug, Clone, Default)]
pub struct Collected {
    /// Functions to plan.
    pub nodes: Vec<FnNode>,
    /// Functions the engine listed (up to the cap).
    pub functions_total: u64,
    /// Import thunks left out.
    pub skipped_imports: u64,
    /// Runtime glue left out.
    pub skipped_runtime: u64,
    /// True when the cap cut the listing.
    pub truncated: bool,
}

/// The entries of a plan as indices, grouped into levels that can be translated at the same
/// time: a function is one level above its deepest callee outside its own recursive group, so
/// every callee is in an earlier level. Within a level the indices are in plan order.
pub fn levels(entries: &[PlannedFunction]) -> Vec<Vec<usize>> {
    let group_of: BTreeMap<u64, u32> = entries.iter().map(|e| (e.address, e.group)).collect();
    let mut level_of_group: BTreeMap<u32, usize> = BTreeMap::new();
    // Callees come first in plan order, so a callee's group level is final when it is read.
    for e in entries {
        let mut level = level_of_group.get(&e.group).copied().unwrap_or(0);
        for c in &e.callees {
            if let Some(g) = group_of.get(c).filter(|g| **g != e.group) {
                level = level.max(level_of_group.get(g).copied().unwrap_or(0) + 1);
            }
        }
        level_of_group.insert(e.group, level);
    }
    let mut out: Vec<Vec<usize>> = Vec::new();
    for (i, e) in entries.iter().enumerate() {
        let l = level_of_group[&e.group];
        if out.len() <= l {
            out.resize_with(l + 1, Vec::new);
        }
        out[l].push(i);
    }
    out
}

/// Assembles the stored form from a collection.
pub fn to_plan(c: &Collected) -> StoredPlan {
    let ordered = order_functions(&c.nodes);
    StoredPlan {
        functions_total: c.functions_total,
        skipped_imports: c.skipped_imports,
        skipped_runtime: c.skipped_runtime,
        groups: ordered.groups,
        truncated: c.truncated,
        entries: ordered.entries,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(address: u64, name: &str, callees: &[u64], imports: &[&str]) -> FnNode {
        FnNode {
            address,
            name: name.into(),
            callees: callees.iter().copied().collect(),
            imports: imports.iter().map(|s| s.to_string()).collect(),
            ..FnNode::default()
        }
    }

    fn names(o: &Ordered) -> Vec<&str> {
        o.entries.iter().map(|e| e.name.as_str()).collect()
    }

    #[test]
    fn callees_come_before_callers_and_the_order_is_stable() {
        // main -> run -> {push, pop} -> fail; main -> name
        let nodes = vec![
            node(0x10, "main", &[0x40, 0x30], &[]),
            node(0x20, "fail", &[], &["fprintf", "exit"]),
            node(0x30, "name", &[], &[]),
            node(0x40, "run", &[0x50, 0x60, 0x20], &[]),
            node(0x50, "push", &[0x20], &[]),
            node(0x60, "pop", &[0x20], &[]),
        ];
        let o = order_functions(&nodes);
        assert_eq!(names(&o), ["name", "fail", "push", "pop", "run", "main"]);
        assert_eq!(o.groups, 6);
        // Shuffled input gives the same result.
        let mut shuffled = nodes.clone();
        shuffled.reverse();
        assert_eq!(order_functions(&shuffled), o);
        for e in &o.entries {
            assert!(e.flags.is_empty(), "{e:?}");
            assert_eq!(e.group_size, 1);
        }
        let main = &o.entries[5];
        assert_eq!(main.callees, vec![0x30, 0x40]);
    }

    #[test]
    fn levels_put_every_callee_in_an_earlier_level() {
        let nodes = vec![
            node(0x10, "main", &[0x40, 0x30], &[]),
            node(0x20, "fail", &[], &[]),
            node(0x30, "name", &[], &[]),
            node(0x40, "run", &[0x50, 0x60, 0x20], &[]),
            node(0x50, "push", &[0x20], &[]),
            node(0x60, "pop", &[0x20], &[]),
        ];
        let o = order_functions(&nodes);
        let lv = levels(&o.entries);
        let named =
            |l: &[usize]| -> Vec<&str> { l.iter().map(|i| o.entries[*i].name.as_str()).collect() };
        assert_eq!(lv.len(), 4);
        assert_eq!(named(&lv[0]), ["name", "fail"]);
        assert_eq!(named(&lv[1]), ["push", "pop"]);
        assert_eq!(named(&lv[2]), ["run"]);
        assert_eq!(named(&lv[3]), ["main"]);
        assert_eq!(lv.iter().map(Vec::len).sum::<usize>(), o.entries.len());
    }

    #[test]
    fn a_recursive_group_is_one_level() {
        let nodes = vec![
            node(1, "top", &[2, 4], &[]),
            node(2, "even", &[3], &[]),
            node(3, "odd", &[2], &[]),
            node(4, "fact", &[4], &[]),
        ];
        let o = order_functions(&nodes);
        let lv = levels(&o.entries);
        assert_eq!(lv.len(), 2);
        assert_eq!(lv[0].len(), 3);
        assert_eq!(lv[1].len(), 1);
    }

    #[test]
    fn recursive_groups_stay_together_and_are_flagged() {
        // even <-> odd, both called by top; fact calls itself.
        let nodes = vec![
            node(1, "top", &[2, 4], &[]),
            node(2, "even", &[3], &[]),
            node(3, "odd", &[2], &[]),
            node(4, "fact", &[4], &[]),
        ];
        let o = order_functions(&nodes);
        assert_eq!(names(&o), ["even", "odd", "fact", "top"]);
        assert_eq!(o.groups, 3);
        assert_eq!(o.entries[0].group, o.entries[1].group);
        assert_eq!(o.entries[0].group_size, 2);
        assert!(o.entries[0].flags.contains(&PlanFlag::Recursive));
        assert!(o.entries[2].flags.contains(&PlanFlag::Recursive));
        assert!(!o.entries[3].flags.contains(&PlanFlag::Recursive));
    }

    #[test]
    fn functions_that_need_stubs_are_flagged_through_their_callers() {
        let nodes = vec![
            node(1, "leaf_alloc", &[], &["realloc", "printf"]),
            node(2, "uses_leaf", &[1], &[]),
            node(3, "pure", &[], &["strlen"]),
            FnNode {
                globals: true,
                ..node(4, "counter", &[], &[])
            },
            node(5, "sys", &[], &["syscall"]),
            node(6, "top", &[2, 4, 5], &[]),
        ];
        let o = order_functions(&nodes);
        let by = |n: &str| o.entries.iter().find(|e| e.name == n).expect("entry");
        assert_eq!(by("leaf_alloc").needs_stubs, vec!["realloc"]);
        assert!(by("leaf_alloc").flags.contains(&PlanFlag::NeedsStubs));
        assert_eq!(by("uses_leaf").needs_stubs, vec!["realloc"]);
        assert!(by("pure").flags.is_empty());
        assert!(by("counter").flags.contains(&PlanFlag::UsesGlobals));
        assert!(by("sys").flags.contains(&PlanFlag::UsesSyscalls));
        // The top function inherits all three through its callees.
        let top = by("top");
        assert!(top.flags.contains(&PlanFlag::NeedsStubs));
        assert!(top.flags.contains(&PlanFlag::UsesGlobals));
        assert!(top.flags.contains(&PlanFlag::UsesSyscalls));
        // A syscall wrapper also needs a stub: `syscall` is not modelled.
        assert!(by("sys").needs_stubs.contains(&"syscall".to_string()));
    }

    #[test]
    fn dangling_edges_are_ignored_and_an_empty_graph_is_empty() {
        let o = order_functions(&[node(1, "a", &[99], &[])]);
        assert_eq!(names(&o), ["a"]);
        assert!(o.entries[0].callees.is_empty());
        assert!(order_functions(&[]).entries.is_empty());
    }

    #[test]
    fn deep_chains_do_not_overflow_the_stack() {
        let n = 50_000u64;
        let nodes: Vec<FnNode> = (0..n)
            .map(|i| {
                let callees: Vec<u64> = if i + 1 < n { vec![i + 1] } else { vec![] };
                node(i, "f", &callees, &[])
            })
            .collect();
        let o = order_functions(&nodes);
        assert_eq!(o.entries.len(), n as usize);
        assert_eq!(o.entries[0].address, n - 1);
    }
}
