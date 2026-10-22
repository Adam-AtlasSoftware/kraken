//! Reading what the pipeline needs from the open project, through the registry's own commands
//! (so engine capability checks, size caps and sanitising apply as for any other client).

use kraken_proto::{Hex64, Page, ProtoError, XrefDirection, XrefKind};
use kraken_registry::commands::{
    CallGraphArgs, Callees, DecompileArgs, GetFunction, GetFunctionArgs, Imports, ListFunctions,
    ListFunctionsArgs, MemoryMap, NoArgs, SymbolsArgs, Xrefs, XrefsArgs,
};
use kraken_registry::{CallContext, Command, Session};

use crate::error::RewriteError;
use crate::fetch::FunctionContext;
use crate::unit::sha256_hex;

/// Most pages read for one function's references.
const MAX_REF_PAGES: usize = 10;

/// A function in the program's listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListedFunction {
    /// Entry address.
    pub address: u64,
    /// Name.
    pub name: String,
    /// Rendered signature, if known.
    pub signature: Option<String>,
}

/// A memory block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// Name such as `.data`.
    pub name: String,
    /// First address.
    pub start: u64,
    /// First address after it.
    pub end: u64,
    /// Whether the block is writable.
    pub writable: bool,
}

/// A call or data reference out of a function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutRef {
    /// What it points to.
    pub to: u64,
    /// The function whose entry is the target, if any.
    pub to_function: Option<(u64, String)>,
    /// The kind.
    pub kind: XrefKind,
}

/// Typed reads over a session.
pub struct Lift<'a> {
    s: &'a Session,
    ctx: &'a CallContext,
}

fn cmd(e: ProtoError) -> RewriteError {
    RewriteError::Command(e)
}

impl<'a> Lift<'a> {
    /// Reads through `s` as `ctx`.
    pub fn new(s: &'a Session, ctx: &'a CallContext) -> Self {
        Lift { s, ctx }
    }

    /// The session read through.
    pub fn session(&self) -> &'a Session {
        self.s
    }

    /// SHA-256 of the analysed binary and its image base.
    pub fn program(&self) -> Result<(String, u64), RewriteError> {
        let p = self.s.project().map_err(cmd)?.program();
        Ok((p.sha256.clone(), p.base.0))
    }

    /// The analysed binary's path and the image base the engine loaded it at.
    pub fn binary(&self) -> Result<(std::path::PathBuf, u64), RewriteError> {
        let project = self.s.project().map_err(cmd)?;
        Ok((
            std::path::PathBuf::from(project.meta().binary_path),
            project.program().base.0,
        ))
    }

    /// The function containing `address`, with its decompile.
    pub async fn function(&self, address: u64) -> Result<FunctionContext, RewriteError> {
        let detail = GetFunction
            .run(
                self.s,
                self.ctx,
                GetFunctionArgs {
                    address: Hex64(address),
                    module: None,
                },
            )
            .await
            .map_err(cmd)?;
        let entry = detail.function.address.0;
        let d = kraken_registry::commands::Decompile
            .run(
                self.s,
                self.ctx,
                DecompileArgs {
                    address: Hex64(entry),
                    module: None,
                },
            )
            .await
            .map_err(cmd)?;
        let decompile = d.text.0;
        let (program_sha256, image_base) = self.program()?;
        Ok(FunctionContext {
            name: detail.function.name.0,
            address: entry,
            signature: detail.function.signature.map(|s| s.0),
            decompile_hash: sha256_hex(&decompile),
            decompile,
            program_sha256,
            image_base,
        })
    }

    /// The function at `address` without decompiling it.
    pub async fn listed(&self, address: u64) -> Result<ListedFunction, RewriteError> {
        let detail = GetFunction
            .run(
                self.s,
                self.ctx,
                GetFunctionArgs {
                    address: Hex64(address),
                    module: None,
                },
            )
            .await
            .map_err(cmd)?;
        Ok(ListedFunction {
            address: detail.function.address.0,
            name: detail.function.name.0,
            signature: detail.function.signature.map(|s| s.0),
        })
    }

    /// Up to `cap` functions in address order, and whether more exist.
    pub async fn functions(&self, cap: usize) -> Result<(Vec<ListedFunction>, bool), RewriteError> {
        let mut out = Vec::new();
        let mut cursor = None;
        loop {
            let page = ListFunctions
                .run(
                    self.s,
                    self.ctx,
                    ListFunctionsArgs {
                        cursor: cursor.clone(),
                        limit: Some(200),
                        name_filter: None,
                    },
                )
                .await
                .map_err(cmd)?;
            for f in page.items {
                if out.len() >= cap {
                    return Ok((out, true));
                }
                out.push(ListedFunction {
                    address: f.address.0,
                    name: f.name.0,
                    signature: f.signature.map(|s| s.0),
                });
            }
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => return Ok((out, false)),
            }
        }
    }

    /// Imported symbols with their stub addresses: `(address, name)`.
    pub async fn imports(&self) -> Result<Vec<(Option<u64>, String)>, RewriteError> {
        let mut out = Vec::new();
        let mut cursor = None;
        loop {
            let page = Imports
                .run(
                    self.s,
                    self.ctx,
                    SymbolsArgs {
                        cursor: cursor.clone(),
                        limit: Some(200),
                    },
                )
                .await
                .map_err(cmd)?;
            out.extend(
                page.items
                    .into_iter()
                    .map(|i| (i.address.map(|a| a.0), i.name.0)),
            );
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => return Ok(out),
            }
        }
    }

    /// The memory blocks.
    pub async fn blocks(&self) -> Result<Vec<Block>, RewriteError> {
        let m = MemoryMap
            .run(self.s, self.ctx, NoArgs {})
            .await
            .map_err(cmd)?;
        Ok(m.blocks
            .into_iter()
            .map(|b| Block {
                name: b.name.0,
                start: b.start.0,
                end: b.end.0,
                writable: b.perms.chars().nth(1) == Some('w'),
            })
            .collect())
    }

    fn convert(page: Page<kraken_registry::views_data::XrefView>) -> (Vec<OutRef>, Option<String>) {
        let refs = page
            .items
            .into_iter()
            .map(|x| OutRef {
                to: x.to.0,
                to_function: x.to_function.map(|f| (f.address.0, f.name.0)),
                kind: x.kind,
            })
            .collect();
        (refs, page.next_cursor)
    }

    /// Calls made by the function containing `address`.
    pub async fn callees(&self, address: u64) -> Result<Vec<OutRef>, RewriteError> {
        let mut out = Vec::new();
        let mut cursor = None;
        for _ in 0..MAX_REF_PAGES {
            let page = Callees
                .run(
                    self.s,
                    self.ctx,
                    CallGraphArgs {
                        address: Hex64(address),
                        cursor: cursor.clone(),
                        limit: Some(200),
                    },
                )
                .await
                .map_err(cmd)?;
            let (refs, next) = Self::convert(page);
            out.extend(refs);
            match next {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        Ok(out)
    }

    /// Data-like references (reads, addresses taken, other) that point at `address`, with the
    /// function each one sits in, if any: `(from, from_function entry)`.
    pub async fn data_refs_to(
        &self,
        address: u64,
    ) -> Result<Vec<(u64, Option<u64>)>, RewriteError> {
        let mut out = Vec::new();
        let mut cursor = None;
        for _ in 0..MAX_REF_PAGES {
            let page = Xrefs
                .run(
                    self.s,
                    self.ctx,
                    XrefsArgs {
                        address: Hex64(address),
                        direction: XrefDirection::To,
                        kind: None,
                        whole_function: false,
                        cursor: cursor.clone(),
                        limit: Some(200),
                    },
                )
                .await
                .map_err(cmd)?;
            for x in page.items {
                if matches!(x.kind, XrefKind::Read | XrefKind::Data | XrefKind::Other) {
                    out.push((x.from.0, x.from_function.map(|f| f.address.0)));
                }
            }
            match page.next_cursor {
                Some(c) => cursor = Some(c),
                None => break,
            }
        }
        Ok(out)
    }

    /// Data references (reads, writes, addresses taken) out of the function containing `address`.
    pub async fn data_refs(&self, address: u64) -> Result<Vec<OutRef>, RewriteError> {
        let mut out = Vec::new();
        for kind in [XrefKind::Read, XrefKind::Write, XrefKind::Data] {
            let mut cursor = None;
            for _ in 0..MAX_REF_PAGES {
                let page = Xrefs
                    .run(
                        self.s,
                        self.ctx,
                        XrefsArgs {
                            address: Hex64(address),
                            direction: XrefDirection::From,
                            kind: Some(kind),
                            whole_function: true,
                            cursor: cursor.clone(),
                            limit: Some(200),
                        },
                    )
                    .await
                    .map_err(cmd)?;
                let (refs, next) = Self::convert(page);
                out.extend(refs);
                match next {
                    Some(c) => cursor = Some(c),
                    None => break,
                }
            }
        }
        Ok(out)
    }
}
