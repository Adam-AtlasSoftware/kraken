//! The mutator (ADR 0014, phase 4): edit-log operations applied to the open program.
//!
//! The engine keeps no program database. Function edits (rename, create, delete, bounds) change
//! the function table and the decompiler's symbol; everything else is kept here and fed to the
//! decompiler and the listing when they run:
//!
//! - labels (a rename at an address that is not a function entry) show in the listing and in
//!   operands,
//! - comments show in the listing (end-of-line, else pre, else repeatable, as Ghidra lists them)
//!   and in decompiled C (plate in the header; pre, end-of-line and post at the statement),
//! - a function prototype set with `set_type` is locked onto the function in the decompiler,
//!   so its own output and its callers use it, and becomes the listed signature,
//! - a calling convention selects the decompiler's prototype model,
//! - code and data definitions: code must decode; a data item shows as one row of the linear
//!   listing with its type.
//!
//! When a function symbol is rebuilt (renames and cleared prototypes create a fresh decompiler
//! function), its prototype, convention and noreturn mark are applied again. Every applied op,
//! and every type defined through the type store, is kept in a journal: [`Edits::watermark`]
//! names it, and with a state directory the engine writes it there on `save` and replays it when
//! the same binary is opened again.

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::{CommentSlot, NativeError, UserComment};
use kraken_engine::EngineRejected;
use kraken_proto::{
    AddressRange, Anchor, CodeData, CommentKind, ErrorCode, FunctionPrototype, LogOp, TypeDef,
    TypeRef, VersionedLogOp,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::discover::{Func, walk_function};
use crate::engine::{Funcs, Program};

/// File in the state directory that holds the journal and the analysed signatures.
pub(crate) const STATE_FILE: &str = "native-state.json";
/// Version of the state file layout.
pub(crate) const STATE_FORMAT: u32 = 1;

/// The type name the edit log uses for "no type" (undoing a `set_type`).
const UNDEFINED: &str = "undefined";
/// Name the prototype carries when it is handed to the decompiler's C grammar; the printed
/// name comes from the function symbol, so renames with characters C does not allow still work.
pub(crate) const PROTO_NAME: &str = "kraken_fn";
/// Longest accepted name.
const MAX_NAME: usize = 2000;
/// Largest data item in the listing.
const MAX_DATA: u64 = 1 << 20;

/// A comment slot in listing order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Slot {
    Plate,
    Pre,
    Eol,
    Post,
    Repeatable,
}

impl From<CommentKind> for Slot {
    fn from(k: CommentKind) -> Slot {
        match k {
            CommentKind::Plate => Slot::Plate,
            CommentKind::Pre => Slot::Pre,
            CommentKind::Eol => Slot::Eol,
            CommentKind::Post => Slot::Post,
            CommentKind::Repeatable => Slot::Repeatable,
        }
    }
}

/// What the mutator defined an address as.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Defined {
    /// Code (the address decodes).
    Code,
    /// A data item of `len` bytes.
    Data { ty: Option<TypeRef>, len: u64 },
}

/// Everything the mutator applied that is not in the function table.
#[derive(Debug, Default)]
pub(crate) struct Edits {
    pub(crate) labels: BTreeMap<u64, String>,
    pub(crate) comments: BTreeMap<(u64, Slot), String>,
    pub(crate) protos: BTreeMap<u64, FunctionPrototype>,
    pub(crate) conventions: BTreeMap<u64, String>,
    pub(crate) defined: BTreeMap<u64, Defined>,
    /// Hashes the anchors of `create_function` carried, accepted by later edits of the function.
    created_hash: BTreeMap<u64, String>,
    /// Applied ops and type definitions in order.
    pub(crate) journal: Vec<Journaled>,
}

/// One journal entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Journaled {
    /// An edit-log op the mutator applied.
    Op(VersionedLogOp),
    /// A type defined through the type store.
    TypeDef(TypeDef),
}

impl Edits {
    /// The comment the listing shows at `addr`: end-of-line, else pre, else repeatable.
    pub(crate) fn listing_comment(&self, addr: u64) -> Option<String> {
        [Slot::Eol, Slot::Pre, Slot::Repeatable]
            .into_iter()
            .find_map(|s| self.comments.get(&(addr, s)).cloned())
    }

    /// The comments the decompiler prints for `f`: those at its entry or in its body.
    pub(crate) fn decompiler_comments(&self, f: &Func) -> Vec<UserComment> {
        self.comments
            .iter()
            .filter(|((a, _), _)| *a == f.entry || f.contains(*a))
            .filter_map(|((a, s), text)| {
                let slot = match s {
                    Slot::Plate => CommentSlot::Header,
                    Slot::Pre => CommentSlot::Pre,
                    Slot::Eol => CommentSlot::Eol,
                    Slot::Post => CommentSlot::Post,
                    Slot::Repeatable => return None,
                };
                Some(UserComment {
                    addr: *a,
                    slot,
                    text: text.clone(),
                })
            })
            .collect()
    }

    /// Names the journal: the number of ops and a hash over them.
    pub(crate) fn watermark(&self) -> String {
        let mut h = Sha256::new();
        for op in &self.journal {
            h.update(serde_json::to_vec(op).unwrap_or_default());
            h.update(b"\n");
        }
        let digest = h.finalize();
        let hex: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        format!("native:{}:{hex}", self.journal.len())
    }
}

/// Where the parameter list of `sig` (`ret name(params)`) opens: the parenthesis matching the
/// last one, so names with parentheses (`operator()`) stay in the head.
fn parameters_open(sig: &str) -> Option<usize> {
    let close = sig.rfind(')')?;
    let mut depth = 0i32;
    for (i, c) in sig[..=close].char_indices().rev() {
        match c {
            ')' => depth += 1,
            '(' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

/// `sig` with its function name, one of `old` (the names it may have been made with), replaced
/// by `name`; other signatures go through [`with_name`].
pub(crate) fn renamed_signature(sig: &str, old: &[&str], name: &str) -> String {
    if let Some(open) = parameters_open(sig) {
        let head = &sig[..open];
        for o in old.iter().filter(|o| !o.is_empty()) {
            if let Some(prefix) = head.strip_suffix(o)
                && (prefix.is_empty() || prefix.ends_with([' ', '*', '&']))
            {
                return format!("{prefix}{name}{}", &sig[open..]);
            }
        }
    }
    with_name(sig, name)
}

/// `sig` (a C declaration `ret name(params)`) with the function name replaced by `name`.
pub(crate) fn with_name(sig: &str, name: &str) -> String {
    let Some(open) = parameters_open(sig) else {
        return sig.to_string();
    };
    let head = &sig[..open];
    let is_name = |c: char| c.is_alphanumeric() || "_:.$@<>~".contains(c);
    let start = head
        .char_indices()
        .rev()
        .find(|(_, c)| !is_name(*c))
        .map_or(0, |(i, c)| i + c.len_utf8());
    if &head[start..] == name {
        return sig.to_string();
    }
    format!("{}{name}{}", &head[..start], &sig[open..])
}

fn reject(code: ErrorCode, msg: impl Into<String>) -> EngineRejected {
    EngineRejected::new(code, msg)
}

fn not_found(msg: impl Into<String>) -> EngineRejected {
    reject(ErrorCode::NotFound, msg)
}

fn invalid(msg: impl Into<String>) -> EngineRejected {
    reject(ErrorCode::InvalidArgument, msg)
}

fn native_rejected(e: NativeError) -> EngineRejected {
    match e {
        NativeError::Native(m) => invalid(m),
        other => crate::engine::native(other).into(),
    }
}

fn anchor_of(op: &LogOp) -> &Anchor {
    match op {
        LogOp::Rename { anchor, .. }
        | LogOp::SetType { anchor, .. }
        | LogOp::SetComment { anchor, .. }
        | LogOp::CreateFunction { anchor, .. }
        | LogOp::DeleteFunction { anchor, .. }
        | LogOp::SetFunctionBounds { anchor, .. }
        | LogOp::SetCodeData { anchor, .. }
        | LogOp::SetCallingConvention { anchor, .. } => anchor,
    }
}

fn check_name(name: &str) -> Result<(), EngineRejected> {
    if name.len() > MAX_NAME || name.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid(format!("{name:?} is not a valid symbol name")));
    }
    Ok(())
}

/// One edit of the function table at a time: a mutable copy of the current table.
struct Table<'a> {
    p: &'a Program,
    funcs: Funcs,
}

impl<'a> Table<'a> {
    fn new(p: &'a Program) -> Table<'a> {
        Table {
            p,
            funcs: (*p.funcs()).clone(),
        }
    }

    fn commit(self) {
        let map = self.funcs.map;
        self.p.set_funcs(Funcs::new(map));
    }
}

/// Applies one op (blocking: it may call into the decompiler). Structural edits (function
/// create, delete and bounds, code and data, renames) rebuild the references, exports and
/// noreturn set afterwards.
pub(crate) fn apply(p: &Program, op: &VersionedLogOp) -> Result<(), EngineRejected> {
    apply_op(p, op)?;
    if is_structural(&op.op) {
        p.reindex();
    }
    Ok(())
}

/// [`apply`] without the rebuild, for replaying many ops; the caller rebuilds once at the end.
pub(crate) fn apply_deferred(p: &Program, op: &VersionedLogOp) -> Result<(), EngineRejected> {
    apply_op(p, op)
}

/// Whether `op` changes what the reference index, the exports or the noreturn set derive from.
fn is_structural(op: &LogOp) -> bool {
    matches!(
        op,
        LogOp::Rename { .. }
            | LogOp::CreateFunction { .. }
            | LogOp::DeleteFunction { .. }
            | LogOp::SetFunctionBounds { .. }
            | LogOp::SetCodeData { .. }
            | LogOp::SetType { .. }
    )
}

fn apply_op(p: &Program, op: &VersionedLogOp) -> Result<(), EngineRejected> {
    op.check_version()?;
    let (space, offset, _, hash) = anchor_of(&op.op).native()?;
    if space != "ram" {
        return Err(not_found(format!("no address space {space}")));
    }
    let at = offset.0;
    let mut edits = p.edits();
    let e = &mut *edits;
    match &op.op {
        LogOp::Rename {
            old_name, new_name, ..
        } => rename(p, e, at, hash, old_name.as_deref(), new_name)?,
        LogOp::SetType { new, .. } => set_type(p, e, at, hash, new)?,
        LogOp::SetComment {
            comment_kind, new, ..
        } => {
            if !p.mapped(at) {
                return Err(not_found(format!("{at:#x} is not mapped")));
            }
            let key = (at, Slot::from(*comment_kind));
            match new.as_deref().filter(|t| !t.is_empty()) {
                Some(t) => {
                    e.comments.insert(key, t.to_string());
                }
                None => {
                    e.comments.remove(&key);
                }
            }
        }
        LogOp::CreateFunction { name, body, .. } => {
            create(p, e, at, hash, name.as_deref(), body.as_ref())?
        }
        LogOp::DeleteFunction { .. } => {
            let mut t = Table::new(p);
            let f = t
                .funcs
                .get(at)
                .ok_or_else(|| not_found(format!("no function at {at:#x}")))?;
            check_hash(p, e, f, hash)?;
            t.funcs.map.remove(&at);
            p.session().remove_function(at).map_err(native_rejected)?;
            e.protos.remove(&at);
            e.conventions.remove(&at);
            e.created_hash.remove(&at);
            t.commit();
        }
        LogOp::SetFunctionBounds { new, .. } => set_bounds(p, e, at, hash, new)?,
        LogOp::SetCodeData { new, length, .. } => {
            set_code_data(p, e, at, new, length.map(|l| l.0))?
        }
        LogOp::SetCallingConvention { new, .. } => {
            let f = function(p, at)?;
            check_hash(p, e, &f, hash)?;
            let before = e.conventions.get(&at).cloned();
            if new.is_empty() {
                e.conventions.remove(&at);
            } else {
                e.conventions.insert(at, new.clone());
            }
            if let Err(err) = refresh(p, e, &f) {
                put(&mut e.conventions, at, before);
                let _ = refresh(p, e, &f);
                return Err(err);
            }
        }
    }
    e.journal.push(Journaled::Op(op.clone()));
    Ok(())
}

/// Sets `map[at]` to `value`, or removes the entry for `None`.
fn put<V>(map: &mut BTreeMap<u64, V>, at: u64, value: Option<V>) {
    match value {
        Some(v) => {
            map.insert(at, v);
        }
        None => {
            map.remove(&at);
        }
    }
}

fn function(p: &Program, at: u64) -> Result<Func, EngineRejected> {
    p.funcs()
        .get(at)
        .cloned()
        .ok_or_else(|| not_found(format!("no function at {at:#x}")))
}

/// An anchor hash names the function's body as the edit saw it: the current one, the one
/// discovery found (edits recorded before a bounds change), or the one a create recorded.
fn check_hash(p: &Program, e: &Edits, f: &Func, hash: &str) -> Result<(), EngineRejected> {
    if hash.is_empty() || e.created_hash.get(&f.entry).is_some_and(|h| h == hash) {
        return Ok(());
    }
    if p.fn_hash(f) == hash
        || p.discovered
            .get(f.entry)
            .is_some_and(|d| p.fn_hash(d) == hash)
    {
        return Ok(());
    }
    Err(reject(
        ErrorCode::ConflictStaleRead,
        format!(
            "the function at {:#x} changed since the edit was made (hash {hash})",
            f.entry
        ),
    ))
}

/// Rebuilds the decompiler's function at `f.entry` (name, prototype, convention, noreturn).
fn refresh(p: &Program, e: &Edits, f: &Func) -> Result<(), EngineRejected> {
    let at = f.entry;
    let user = e.protos.get(&at);
    let decl = match user {
        Some(proto) => {
            let types = p.types();
            Some(types.prototype_text(proto, PROTO_NAME))
        }
        None => p.locked().get(&at).cloned(),
    };
    let convention = e.conventions.get(&at).cloned().or_else(|| {
        user.map(|u| u.calling_convention.clone())
            .filter(|c| !c.is_empty())
    });
    let noreturn = p.noreturn().contains(&at) || user.is_some_and(|u| u.noreturn);
    let mut s = p.session();
    s.remove_function(at).map_err(native_rejected)?;
    s.add_function(at, &f.name).map_err(native_rejected)?;
    if let Some(d) = decl {
        s.set_prototype(at, &d).map_err(native_rejected)?;
    }
    if let Some(c) = convention {
        s.set_convention(at, &c).map_err(native_rejected)?;
    }
    if noreturn {
        s.set_noreturn(at, true).map_err(native_rejected)?;
    }
    Ok(())
}

fn rename(
    p: &Program,
    e: &mut Edits,
    at: u64,
    hash: &str,
    old: Option<&str>,
    new: &str,
) -> Result<(), EngineRejected> {
    check_name(new)?;
    let mut t = Table::new(p);
    if let Some(f) = t.funcs.map.get_mut(&at) {
        let target = if new.is_empty() {
            p.base_name(at)
        } else {
            new.to_string()
        };
        if f.name == target {
            return Ok(());
        }
        if let Some(o) = old
            && o != f.name
        {
            return Err(reject(
                ErrorCode::ConflictStaleRead,
                format!("the function at {at:#x} is named {}, not {o}", f.name),
            ));
        }
        let snapshot = f.clone();
        check_hash(p, e, &snapshot, hash)?;
        f.name = target;
        let renamed = f.clone();
        refresh(p, e, &renamed)?;
        t.commit();
        return Ok(());
    }
    if !p.mapped(at) {
        return Err(not_found(format!("{at:#x} is not mapped")));
    }
    let current = e.labels.get(&at).cloned();
    if current.as_deref().unwrap_or("") == new {
        return Ok(());
    }
    if let (Some(o), Some(c)) = (old, current.as_deref())
        && o != c
    {
        return Err(reject(
            ErrorCode::ConflictStaleRead,
            format!("the label at {at:#x} is {c}, not {o}"),
        ));
    }
    if new.is_empty() {
        e.labels.remove(&at);
    } else {
        e.labels.insert(at, new.to_string());
    }
    Ok(())
}

/// Size in bytes of `ty` as far as the type store knows it.
fn type_size(p: &Program, ty: &TypeRef, depth: usize) -> Option<u64> {
    if depth > 16 {
        return None;
    }
    match ty {
        TypeRef::Primitive(pr) => Some(u64::from(pr.size)),
        TypeRef::Pointer { size, .. } => Some(u64::from(*size)),
        TypeRef::Array { element, count } => {
            type_size(p, element, depth + 1).map(|s| s.saturating_mul(*count))
        }
        TypeRef::Function(_) => None,
        TypeRef::Named { name } => {
            let def = p.types().get(name).cloned()?;
            match def {
                TypeDef::Struct(c) | TypeDef::Union(c) => Some(c.size),
                TypeDef::Enum(en) => Some(u64::from(en.size)),
                TypeDef::Typedef(td) => type_size(p, &td.target, depth + 1),
                TypeDef::Function(_) => None,
            }
        }
    }
}

fn set_type(
    p: &Program,
    e: &mut Edits,
    at: u64,
    hash: &str,
    new: &TypeRef,
) -> Result<(), EngineRejected> {
    let funcs = p.funcs();
    if let Some(f) = funcs.get(at) {
        check_hash(p, e, f, hash)?;
        let proto = match new {
            TypeRef::Named { name } if name == UNDEFINED => None,
            TypeRef::Function(proto) => Some((**proto).clone()),
            TypeRef::Named { name } => match p.types().get(name) {
                Some(TypeDef::Function(proto)) => Some(proto.clone()),
                _ => {
                    return Err(invalid(format!(
                        "{name} is not a function prototype; a function's type must be one"
                    )));
                }
            },
            _ => {
                return Err(invalid("a function's type must be a function prototype"));
            }
        };
        let before = e.protos.get(&at).cloned();
        put(&mut e.protos, at, proto);
        if let Err(err) = refresh(p, e, f) {
            put(&mut e.protos, at, before);
            let _ = refresh(p, e, f);
            return Err(err);
        }
        return Ok(());
    }
    if let Some(f) = funcs.containing(at) {
        return Err(EngineRejected::rejected(format!(
            "{at:#x} lies inside the body of {}; only functions and data take a type",
            f.name
        )));
    }
    if !p.mapped(at) {
        return Err(not_found(format!("{at:#x} is not mapped")));
    }
    if matches!(new, TypeRef::Named { name } if name == UNDEFINED) {
        e.defined.remove(&at);
        return Ok(());
    }
    let len = type_size(p, new, 0)
        .ok_or_else(|| invalid("the type has no known size"))?
        .clamp(1, MAX_DATA);
    e.defined.insert(
        at,
        Defined::Data {
            ty: Some(new.clone()),
            len,
        },
    );
    Ok(())
}

/// A function whose body is the given range, decoded linearly.
fn linear_func(
    p: &Program,
    entry: u64,
    name: String,
    body: &AddressRange,
) -> Result<Func, EngineRejected> {
    let (start, end) = (body.start.0, body.end.0);
    if body.space != "ram" || end <= start || !(start..end).contains(&entry) {
        return Err(invalid(format!(
            "the body {start:#x}..{end:#x} must contain the entry {entry:#x}"
        )));
    }
    if end - start > MAX_DATA {
        return Err(invalid("the body is larger than 1 MiB"));
    }
    let mut insns = Vec::new();
    let mut returns = false;
    let mut pc = start;
    {
        let mut cache = p.insns.lock().unwrap_or_else(|e| e.into_inner());
        let mut s = p.session();
        'outer: while pc < end {
            let run = s.decode(pc, 64).map_err(native_rejected)?;
            if run.is_empty() {
                break;
            }
            for i in run {
                if i.addr >= end {
                    break 'outer;
                }
                pc = i.addr + u64::from(i.length);
                insns.push(i.addr);
                returns |= matches!(
                    i.flow,
                    engine_native_sys::Flow::Return | engine_native_sys::Flow::IndirectJump
                );
                cache.entry(i.addr).or_insert(i);
            }
        }
    }
    Ok(Func {
        entry,
        name,
        insns,
        ranges: vec![(start, end)],
        switches: BTreeMap::new(),
        tail_calls: Vec::new(),
        noreturn: p.noreturn().contains(&entry),
        returns,
    })
}

/// A function found by recursive descent from `entry`.
fn walked_func(
    p: &Program,
    funcs: &Funcs,
    entry: u64,
    name: String,
) -> Result<Func, EngineRejected> {
    if !p.loaded.is_code(entry) {
        return Err(EngineRejected::rejected(format!(
            "{entry:#x} is not in executable memory; give the body to create a function there"
        )));
    }
    let names: BTreeMap<u64, String> = funcs
        .map
        .values()
        .map(|f| (f.entry, f.name.clone()))
        .collect();
    let noreturn: BTreeSet<u64> = p.noreturn().iter().copied().collect();
    let mut cache = p.insns.lock().unwrap_or_else(|e| e.into_inner());
    let mut s = p.session();
    let mut f = walk_function(&p.loaded, &mut s, names, noreturn, &mut cache, entry)
        .map_err(native_rejected)?;
    if f.insns.is_empty() {
        return Err(EngineRejected::rejected(format!(
            "no code can be disassembled at {entry:#x}"
        )));
    }
    f.name = name;
    Ok(f)
}

fn create(
    p: &Program,
    e: &mut Edits,
    at: u64,
    hash: &str,
    name: Option<&str>,
    body: Option<&AddressRange>,
) -> Result<(), EngineRejected> {
    if let Some(n) = name {
        check_name(n)?;
    }
    let mut t = Table::new(p);
    if let Some(f) = t.funcs.get(at) {
        return if name.is_none_or(|n| n == f.name) {
            Ok(())
        } else {
            Err(EngineRejected::rejected(format!(
                "a function already exists at {at:#x}"
            )))
        };
    }
    if !p.mapped(at) {
        return Err(not_found(format!("{at:#x} is not mapped")));
    }
    let name = name
        .filter(|n| !n.is_empty())
        .map_or_else(|| p.base_name(at), str::to_string);
    // the body discovery found, when the log asks for it back (undoing a delete)
    let found = p.discovered.get(at).filter(|d| {
        body.is_none_or(|b| b.start.0 == at && b.end.0.saturating_sub(b.start.0) == d.size())
    });
    let mut f = match (found, body) {
        (Some(d), _) => d.clone(),
        (None, Some(b)) => linear_func(p, at, name.clone(), b)?,
        (None, None) => walked_func(p, &t.funcs, at, name.clone())?,
    };
    f.name = name;
    refresh(p, e, &f)?;
    if !hash.is_empty() {
        e.created_hash.insert(at, hash.to_string());
    }
    t.funcs.map.insert(at, f);
    t.commit();
    Ok(())
}

fn set_bounds(
    p: &Program,
    e: &mut Edits,
    at: u64,
    hash: &str,
    new: &AddressRange,
) -> Result<(), EngineRejected> {
    let mut t = Table::new(p);
    let f = t
        .funcs
        .get(at)
        .cloned()
        .ok_or_else(|| not_found(format!("no function at {at:#x}")))?;
    check_hash(p, e, &f, hash)?;
    let mut g = if new.start.0 == 0 && new.end.0 == 0 {
        // the log's "no bounds recorded" marker (undoing a bounds change): the found body
        match p.discovered.get(at) {
            Some(d) => d.clone(),
            None => walked_func(p, &t.funcs, at, f.name.clone())?,
        }
    } else {
        if new.start.0 != at {
            return Err(EngineRejected::rejected(
                "the entry point cannot move; use delete and create",
            ));
        }
        linear_func(p, at, f.name.clone(), new)?
    };
    g.name = f.name.clone();
    t.funcs.map.insert(at, g);
    t.commit();
    Ok(())
}

fn set_code_data(
    p: &Program,
    e: &mut Edits,
    at: u64,
    new: &CodeData,
    length: Option<u64>,
) -> Result<(), EngineRejected> {
    if !p.mapped(at) {
        return Err(not_found(format!("{at:#x} is not mapped")));
    }
    match new {
        CodeData::Undefined => {
            e.defined.remove(&at);
        }
        CodeData::Code => {
            let run = p.session().decode(at, 1).map_err(native_rejected)?;
            let Some(i) = run.into_iter().find(|i| i.addr == at) else {
                return Err(EngineRejected::rejected(format!(
                    "no instruction decodes at {at:#x}"
                )));
            };
            p.insns
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .entry(at)
                .or_insert(i);
            e.defined.insert(at, Defined::Code);
        }
        CodeData::Data { data_type } => {
            if let Some(f) = p.funcs().containing(at) {
                return Err(EngineRejected::rejected(format!(
                    "{at:#x} lies inside the body of {}; data cannot be defined over its code",
                    f.name
                )));
            }
            let len = length
                .or_else(|| data_type.as_ref().and_then(|t| type_size(p, t, 0)))
                .unwrap_or(1)
                .clamp(1, MAX_DATA);
            e.defined.insert(
                at,
                Defined::Data {
                    ty: data_type.clone(),
                    len,
                },
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_take_the_current_name() {
        assert_eq!(
            with_name("int FUN_00101189(int *param_1)", "cmp_id"),
            "int cmp_id(int *param_1)"
        );
        assert_eq!(with_name("char *f(void)", "g"), "char *g(void)");
        assert_eq!(with_name("void ns::f(void)", "h"), "void h(void)");
        assert_eq!(with_name("no parens", "x"), "no parens");
        assert_eq!(
            renamed_signature("ulong operator()(void *this)", &["operator()"], "call"),
            "ulong call(void *this)"
        );
        assert_eq!(
            renamed_signature("void *operator.new(ulong size)", &["operator.new"], "alloc"),
            "void *alloc(ulong size)"
        );
        assert_eq!(
            renamed_signature("int f(code *cb)", &["g"], "h"),
            "int h(code *cb)"
        );
    }

    #[test]
    fn listing_comment_prefers_eol_then_pre_then_repeatable() {
        let mut e = Edits::default();
        e.comments.insert((0x10, Slot::Repeatable), "r".into());
        assert_eq!(e.listing_comment(0x10).as_deref(), Some("r"));
        e.comments.insert((0x10, Slot::Pre), "p".into());
        assert_eq!(e.listing_comment(0x10).as_deref(), Some("p"));
        e.comments.insert((0x10, Slot::Eol), "e".into());
        assert_eq!(e.listing_comment(0x10).as_deref(), Some("e"));
        assert_eq!(e.listing_comment(0x11), None);
    }

    #[test]
    fn watermarks_follow_the_journal() {
        let mut e = Edits::default();
        let empty = e.watermark();
        e.journal.push(Journaled::Op(VersionedLogOp::new(
            LogOp::SetCallingConvention {
                anchor: Anchor::Native {
                    space: "ram".into(),
                    offset: kraken_proto::Hex64(1),
                    fn_entry: kraken_proto::Hex64(1),
                    fn_hash: String::new(),
                },
                old: None,
                new: "MSABI".into(),
            },
        )));
        let one = e.watermark();
        assert_ne!(empty, one);
        assert!(one.starts_with("native:1:"));
        assert_eq!(one, e.watermark());
    }
}
