//! The program-data capabilities: cross-references, CFGs, strings, imports and exports, types.

use async_trait::async_trait;
use kraken_engine::{
    EngineResult, FlowGraph, StringLister, StringsRequest, SymbolLister, TypeStore, XrefProvider,
    XrefRequest,
};
use kraken_proto::{
    Cfg, ErrorCode, FunctionRef, Hex64, Locator, Page, PageRequest, ProtoError, StringEntry,
    SymbolEntry, TypeDef, Xref, XrefDirection,
};
use tokio_util::sync::CancellationToken;

use crate::engine::{InProcessEngine, Program, blocking, check, check_cursor, page_of, ram_offset};
use crate::refs::Ref;

fn xref(p: &Program, r: &Ref, from_function: Option<u64>) -> Xref {
    let fref = |entry: u64| {
        p.functions.get(&entry).map(|f| FunctionRef {
            address: Hex64(f.entry),
            name: f.name.clone(),
        })
    };
    let from_function = match from_function {
        Some(e) => fref(e),
        None => p.function_containing(r.from).and_then(|f| fref(f.entry)),
    };
    Xref {
        from: Hex64(r.from),
        to: Hex64(r.to),
        kind: r.kind,
        from_function,
        to_function: fref(r.to),
    }
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
        let keep = |r: &&Ref| req.kind.is_none_or(|k| r.kind == k);
        let list: Vec<Xref> = match req.direction {
            XrefDirection::To => p
                .refs
                .to(at)
                .iter()
                .filter(keep)
                .map(|r| xref(&p, r, None))
                .collect(),
            XrefDirection::From if req.whole_function => {
                let f = p.function_containing(at).ok_or_else(|| {
                    ProtoError::new(ErrorCode::NotFound, format!("no function contains {at:#x}"))
                })?;
                f.insns
                    .iter()
                    .flat_map(|a| p.refs.from(*a))
                    .filter(keep)
                    .map(|r| xref(&p, r, Some(f.entry)))
                    .collect()
            }
            XrefDirection::From => p
                .refs
                .from(at)
                .iter()
                .filter(keep)
                .map(|r| xref(&p, r, None))
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
        let f = p.function_containing(at).ok_or_else(|| {
            ProtoError::new(ErrorCode::NotFound, format!("no function contains {at:#x}"))
        })?;
        let pads = p
            .loaded
            .landing_pads
            .get(&f.entry)
            .cloned()
            .unwrap_or_default();
        let insns = p.insns.lock().unwrap_or_else(|e| e.into_inner());
        Ok(crate::cfg::build(f, &insns, &pads, &|t| {
            p.noreturn.contains(&t)
        }))
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
        page_of(&self.program()?.exports, page)
    }
}

#[async_trait]
impl TypeStore for InProcessEngine {
    async fn get_type(&self, name: &str, cancel: &CancellationToken) -> EngineResult<TypeDef> {
        check(cancel)?;
        let p = self.program()?;
        let t = p.types();
        t.get(name)
            .cloned()
            .ok_or_else(|| ProtoError::new(ErrorCode::NotFound, format!("no type named {name}")))
    }

    async fn define_type(&self, def: TypeDef, cancel: &CancellationToken) -> EngineResult<()> {
        check(cancel)?;
        let p = self.program()?;
        blocking(move || {
            let applied = {
                let mut types = p.types();
                let mut session = p.session();
                types.define(def, &mut session, &|n| p.named(n))?
            };
            let mut sigs = p.signatures();
            for (at, text) in applied {
                sigs.insert(at, text);
            }
            Ok(())
        })
        .await
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
