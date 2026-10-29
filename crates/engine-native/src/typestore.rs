//! The engine's type store: definitions in the neutral model, mirrored into the decompiler's
//! type factory as C declarations and onto functions as locked prototypes.
//!
//! Definitions the decompiler cannot take yet (one naming a type that is not defined yet) wait
//! in a pending set and are retried after every successful definition. A pointer to a type the
//! decompiler does not know becomes `void *`, so recursive structs still go in. Redefining a
//! composite that the decompiler already has changes the stored definition only. Prototypes set
//! on single functions through the mutator (`set_type`) are kept by the mutator, not here.
//!
//! The decompiler's C grammar renames the type a typedef names (`typedef record rec_t;` turns
//! `record` into `rec_t`), so a typedef of another named type is not declared there: it becomes
//! an alias, and declarations and prototypes handed to the decompiler use the aliased name.
//! Only typedefs of primitives, pointers, arrays and functions are declared.

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::Session;
use kraken_engine::type_def_name;
use kraken_proto::{ErrorCode, FunctionPrototype, ProtoError, TypeDef, TypeRef};

use crate::ctypes::{DataModel, declaration, prototype, valid_name};

/// Core type names of the decompiler (see the shim's `buildCoreTypes`).
const CORE: &[&str] = &[
    "void",
    "bool",
    "byte",
    "ushort",
    "uint",
    "ulong",
    "sbyte",
    "short",
    "int",
    "long",
    "float",
    "double",
    "float10",
    "float16",
    "undefined",
    "undefined2",
    "undefined4",
    "undefined8",
    "code",
    "char",
    "wchar16",
    "wchar32",
    "longlong",
    "ulonglong",
];

/// Whether `name` is one of the decompiler's core type names.
pub fn is_core(name: &str) -> bool {
    CORE.contains(&name)
}

/// Named definitions plus what the decompiler has accepted.
#[derive(Debug, Default)]
pub struct TypeModel {
    /// The sizes of `long` and pointers, which decide the spelling of 8-byte integers.
    model: DataModel,
    defs: BTreeMap<String, TypeDef>,
    declared: BTreeSet<String>,
    pending: BTreeSet<String>,
    /// Typedefs of named types: typedef name -> the name the decompiler knows the type by.
    aliases: BTreeMap<String, String>,
}

/// `ty` with every named type replaced through `rename`.
fn renamed(ty: &TypeRef, rename: &dyn Fn(&str) -> String) -> TypeRef {
    match ty {
        TypeRef::Named { name } => TypeRef::Named { name: rename(name) },
        TypeRef::Pointer { target, size } => TypeRef::Pointer {
            target: Box::new(renamed(target, rename)),
            size: *size,
        },
        TypeRef::Array { element, count } => TypeRef::Array {
            element: Box::new(renamed(element, rename)),
            count: *count,
        },
        TypeRef::Function(p) => TypeRef::Function(Box::new(renamed_proto(p, rename))),
        TypeRef::Primitive(_) => ty.clone(),
    }
}

pub(crate) fn renamed_proto(
    p: &FunctionPrototype,
    rename: &dyn Fn(&str) -> String,
) -> FunctionPrototype {
    let mut out = p.clone();
    out.return_type = Box::new(renamed(&p.return_type, rename));
    for param in &mut out.params {
        param.ty = renamed(&param.ty, rename);
    }
    out
}

fn renamed_def(def: &TypeDef, rename: &dyn Fn(&str) -> String) -> TypeDef {
    let mut out = def.clone();
    match &mut out {
        TypeDef::Struct(c) | TypeDef::Union(c) => {
            for f in &mut c.fields {
                f.ty = renamed(&f.ty, rename);
            }
        }
        TypeDef::Typedef(t) => t.target = renamed(&t.target, rename),
        TypeDef::Function(p) => *p = renamed_proto(p, rename),
        TypeDef::Enum(_) => {}
    }
    out
}

/// A prototype that reached a function: its entry and the C text.
pub type Applied = (u64, String);

impl TypeModel {
    /// An empty store for programs of `model`.
    pub fn new(model: DataModel) -> TypeModel {
        TypeModel {
            model,
            ..TypeModel::default()
        }
    }

    /// The data model of the program.
    pub fn model(&self) -> DataModel {
        self.model
    }

    /// The definition named `name`.
    pub fn get(&self, name: &str) -> Option<&TypeDef> {
        self.defs.get(name)
    }

    /// Definitions ordered by name.
    pub fn all(&self) -> Vec<TypeDef> {
        self.defs.values().cloned().collect()
    }

    /// Whether the decompiler knows the type named `name` (a core type or an accepted
    /// definition).
    pub fn knows(&self, name: &str) -> bool {
        CORE.contains(&name) || self.declared.contains(name)
    }

    /// The name the decompiler knows `name` by (itself, or what an alias resolves to).
    pub fn decompiler_name(&self, name: &str) -> String {
        let mut at = name;
        for _ in 0..32 {
            match self.aliases.get(at) {
                Some(next) => at = next,
                None => break,
            }
        }
        at.to_string()
    }

    /// The C prototype of `p` named `name`, in the names the decompiler knows (for
    /// `set_prototype`).
    pub fn prototype_text(&self, p: &FunctionPrototype, name: &str) -> String {
        let p = renamed_proto(p, &|n| self.decompiler_name(n));
        self.model.spell(&prototype(&p, name, &|n| self.knows(n)))
    }

    /// The C declaration of a variable `name` of type `ty` (for `set_global`).
    pub fn global_decl(&self, ty: &TypeRef, name: &str) -> String {
        let ty = renamed(ty, &|n| self.decompiler_name(n));
        self.model
            .spell(&crate::ctypes::declarator(&ty, name, &|n| self.knows(n)))
    }

    /// Names that are stored but not in the decompiler yet.
    pub fn pending(&self) -> impl Iterator<Item = &str> {
        self.pending.iter().map(String::as_str)
    }

    /// Stores `def` and pushes it (and anything it unblocks) into the decompiler. `named`
    /// gives the entries of the functions called `name`, which receive a prototype. Returns the
    /// prototypes that reached functions.
    pub fn define(
        &mut self,
        def: TypeDef,
        session: &mut Session,
        named: &dyn Fn(&str) -> Vec<u64>,
    ) -> Result<Vec<Applied>, ProtoError> {
        let name = type_def_name(&def)
            .ok_or_else(|| {
                ProtoError::new(
                    ErrorCode::InvalidArgument,
                    "an anonymous prototype cannot be defined",
                )
            })?
            .to_string();
        if !valid_name(&name) {
            return Err(ProtoError::new(
                ErrorCode::InvalidArgument,
                format!("{name:?} is not a C identifier"),
            ));
        }
        self.defs.insert(name.clone(), def);
        self.pending.insert(name);
        let mut applied = Vec::new();
        loop {
            let mut progress = false;
            for n in self.pending.clone() {
                if let Some(a) = self.apply(&n, session, named) {
                    self.pending.remove(&n);
                    applied.extend(a);
                    progress = true;
                }
            }
            if !progress {
                return Ok(applied);
            }
        }
    }

    /// Pushes one stored definition; `None` when the decompiler refused it for now.
    fn apply(
        &mut self,
        name: &str,
        session: &mut Session,
        named: &dyn Fn(&str) -> Vec<u64>,
    ) -> Option<Vec<Applied>> {
        let def = self.defs.get(name)?.clone();
        // a typedef of a named type is an alias (declaring it would rename that type)
        if let TypeDef::Typedef(t) = &def
            && let TypeRef::Named { name: target } = &t.target
            && !CORE.contains(&target.as_str())
        {
            if self.declared.contains(name) {
                return Some(Vec::new());
            }
            let resolved = self.decompiler_name(target);
            if resolved == name || !self.knows(&resolved) {
                return None;
            }
            self.aliases.insert(name.to_string(), resolved);
            self.declared.insert(name.to_string());
            return Some(Vec::new());
        }
        let def = renamed_def(&def, &|n| self.decompiler_name(n));
        let declared = &self.declared;
        let known = |n: &str| CORE.contains(&n) || declared.contains(n);
        match &def {
            TypeDef::Function(p) => {
                let text = self.model.spell(&prototype(p, name, &known));
                let mut out = Vec::new();
                for at in named(name) {
                    session.set_prototype(at, &text).ok()?;
                    // a convention the compiler spec does not have leaves the default
                    if !p.calling_convention.is_empty() {
                        let _ = session.set_convention(at, &p.calling_convention);
                    }
                    if p.noreturn {
                        session.set_noreturn(at, true).ok()?;
                    }
                    out.push((at, text.clone()));
                }
                Some(out)
            }
            other => {
                if self.declared.contains(name) {
                    return Some(Vec::new());
                }
                let text = self.model.spell(&declaration(other, &known)?);
                session.declare_type(&text).ok()?;
                self.declared.insert(name.to_string());
                Some(Vec::new())
            }
        }
    }
}
