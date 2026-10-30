//! The program-data capabilities: cross-references, CFGs, strings, imports and exports, types.

use async_trait::async_trait;
use kraken_engine::{
    EngineResult, FlowGraph, JumpTables, StringLister, StringsRequest, SymbolLister, TypeStore,
    XrefProvider, XrefRequest,
};
use kraken_proto::{
    Cfg, ErrorCode, FunctionRef, Hex64, JumpTable, Locator, Page, PageRequest, ProtoError,
    StringEntry, SymbolEntry, TypeDef, Xref, XrefDirection,
};
use tokio_util::sync::CancellationToken;

use crate::engine::{
    Funcs, InProcessEngine, Program, blocking, check, check_cursor, page_of, ram_offset,
};
use crate::mutate::Journaled;
use crate::refs::Ref;

fn xref(funcs: &Funcs, r: &Ref, from_function: Option<u64>) -> Xref {
    let fref = |entry: u64| {
        funcs.get(entry).map(|f| FunctionRef {
            address: Hex64(f.entry),
            name: f.name.clone(),
        })
    };
    let from_function = match from_function {
        Some(e) => fref(e),
        None => funcs.containing(r.from).and_then(|f| fref(f.entry)),
    };
    Xref {
        from: Hex64(r.from),
        to: Hex64(r.to),
        kind: r.kind,
        from_function,
        to_function: fref(r.to),
    }
}

/// Defines a type (blocking) and journals it, so a reopened engine has it again.
pub(crate) fn define(p: &Program, def: TypeDef) -> EngineResult<()> {
    p.touch();
    let r = define_inner(p, def);
    p.touch();
    r
}

fn define_inner(p: &Program, def: TypeDef) -> EngineResult<()> {
    let applied = {
        let mut types = p.types();
        let mut session = p.session();
        types.define(def.clone(), &mut session, &|n| p.named(n))?
    };
    {
        let mut sigs = p.signatures();
        let mut locked = p.locked();
        for (at, text) in applied {
            locked.insert(at, text.clone());
            sigs.insert(at, text);
        }
    }
    p.edits().journal.push(Journaled::TypeDef(def));
    Ok(())
}

/// Forgets the type named `name` (`not_found` if there is none) and journals the removal.
pub(crate) fn remove(p: &Program, name: &str) -> EngineResult<()> {
    p.touch();
    let removed = p.types().remove(name);
    p.touch();
    if !removed {
        return Err(ProtoError::new(
            ErrorCode::NotFound,
            format!("no type named {name}"),
        ));
    }
    p.edits()
        .journal
        .push(Journaled::RemoveType(name.to_string()));
    Ok(())
}

#[async_trait]
impl XrefProvider for InProcessEngine {
    async fn xrefs(
        &self,
        req: &XrefRequest,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<Xref>> {
        check(cancel)?;
        check_cursor(page)?;
        let p = self.program()?;
        let at = req.address.0;
        let funcs = p.funcs();
        let refs = p.refs();
        let keep = |r: &&Ref| req.kind.is_none_or(|k| r.kind == k);
        let list: Vec<Xref> = match req.direction {
            XrefDirection::To => refs
                .to(at)
                .iter()
                .filter(keep)
                .map(|r| xref(&funcs, r, None))
                .collect(),
            XrefDirection::From if req.whole_function => {
                let f = funcs.containing(at).ok_or_else(|| {
                    ProtoError::new(ErrorCode::NotFound, format!("no function contains {at:#x}"))
                })?;
                f.insns
                    .iter()
                    .flat_map(|a| refs.from(*a))
                    .filter(keep)
                    .map(|r| xref(&funcs, r, Some(f.entry)))
                    .collect()
            }
            XrefDirection::From => refs
                .from(at)
                .iter()
                .filter(keep)
                .map(|r| xref(&funcs, r, None))
                .collect(),
        };
        page_of(&list, page)
    }
}

#[async_trait]
impl FlowGraph for InProcessEngine {
    async fn cfg(&self, function: &Locator, cancel: &CancellationToken) -> EngineResult<Cfg> {
        check(cancel)?;
        let p = self.program()?;
        let at = ram_offset(function)?;
        let funcs = p.funcs();
        let f = funcs.containing(at).ok_or_else(|| {
            ProtoError::new(ErrorCode::NotFound, format!("no function contains {at:#x}"))
        })?;
        let pads = p
            .loaded
            .landing_pads
            .get(&f.entry)
            .cloned()
            .unwrap_or_default();
        let noreturn = p.noreturn();
        let insns = p.insns.lock().unwrap_or_else(|e| e.into_inner());
        Ok(crate::cfg::build(f, &insns, &pads, &|t| {
            noreturn.contains(&t)
        }))
    }
}

#[async_trait]
impl JumpTables for InProcessEngine {
    async fn list_jump_tables(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<JumpTable>> {
        check(cancel)?;
        check_cursor(page)?;
        let p = self.program()?;
        let funcs = p.funcs();
        let mut all: Vec<JumpTable> = funcs
            .map
            .values()
            .flat_map(|f| {
                f.switches
                    .iter()
                    .filter(|(_, t)| !t.is_empty())
                    .map(|(jump, targets)| {
                        let mut t = targets.clone();
                        t.sort_unstable();
                        t.dedup();
                        JumpTable {
                            function: Hex64(f.entry),
                            jump: Hex64(*jump),
                            targets: t.into_iter().map(Hex64).collect(),
                        }
                    })
            })
            .collect();
        all.sort_by_key(|t| t.jump.0);
        all.dedup_by_key(|t| t.jump.0);
        page_of(&all, page)
    }
}

#[async_trait]
impl StringLister for InProcessEngine {
    async fn strings(
        &self,
        req: &StringsRequest,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<StringEntry>> {
        check(cancel)?;
        check_cursor(page)?;
        let p = self.program()?;
        let min = req.min_len.max(1);
        let all = blocking(move || Ok(p.strings(min))).await?;
        check(cancel)?;
        match req.filter.as_deref().filter(|f| !f.is_empty()) {
            None => page_of(&all, page),
            Some(f) => {
                let needle = f.to_lowercase();
                let hits: Vec<StringEntry> = all
                    .iter()
                    .filter(|s| s.value.to_lowercase().contains(&needle))
                    .cloned()
                    .collect();
                page_of(&hits, page)
            }
        }
    }
}

#[async_trait]
impl SymbolLister for InProcessEngine {
    async fn imports(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<SymbolEntry>> {
        check(cancel)?;
        page_of(&self.program()?.imports, page)
    }

    async fn exports(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<SymbolEntry>> {
        check(cancel)?;
        page_of(&self.program()?.exports(), page)
    }
}

#[async_trait]
impl TypeStore for InProcessEngine {
    async fn get_type(&self, name: &str, cancel: &CancellationToken) -> EngineResult<TypeDef> {
        check(cancel)?;
        let p = self.program()?;
        let t = p.types();
        t.get_shown(name)
            .ok_or_else(|| ProtoError::new(ErrorCode::NotFound, format!("no type named {name}")))
    }

    async fn define_type(&self, def: TypeDef, cancel: &CancellationToken) -> EngineResult<()> {
        check(cancel)?;
        let p = self.program()?;
        blocking(move || define(&p, def)).await
    }

    async fn remove_type(&self, name: &str, cancel: &CancellationToken) -> EngineResult<()> {
        check(cancel)?;
        let p = self.program()?;
        let name = name.to_string();
        blocking(move || remove(&p, &name)).await
    }

    async fn list_types(
        &self,
        page: &PageRequest,
        cancel: &CancellationToken,
    ) -> EngineResult<Page<TypeDef>> {
        check(cancel)?;
        check_cursor(page)?;
        let all = self.program()?.types().all();
        page_of(&all, page)
    }
}
