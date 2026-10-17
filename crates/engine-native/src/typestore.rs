//! The engine's type store: definitions in the neutral model, mirrored into the decompiler's
//! type factory as C declarations and onto functions as locked prototypes.
//!
//! Definitions the decompiler cannot take yet (one naming a type that is not defined yet) wait
//! in a pending set and are retried after every successful definition. A pointer to a type the
//! decompiler does not know becomes `void *`, so recursive structs still go in. Redefining a
//! composite that the decompiler already has changes the stored definition only. Prototypes set
//! on single functions through the mutator (`set_type`) are kept by the mutator, not here.

use std::collections::{BTreeMap, BTreeSet};

use engine_native_sys::Session;
use kraken_engine::type_def_name;
use kraken_proto::{ErrorCode, ProtoError, TypeDef};

use crate::ctypes::{declaration, prototype, valid_name};

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
];

/// Named definitions plus what the decompiler has accepted.
#[derive(Debug, Default)]
pub struct TypeModel {
    defs: BTreeMap<String, TypeDef>,
    declared: BTreeSet<String>,
    pending: BTreeSet<String>,
}

/// A prototype that reached a function: its entry and the C text.
pub type Applied = (u64, String);

impl TypeModel {
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
        let declared = &self.declared;
        let known = |n: &str| CORE.contains(&n) || declared.contains(n);
        match &def {
            TypeDef::Function(p) => {
                let text = prototype(p, name, &known);
                let mut out = Vec::new();
                for at in named(name) {
                    session.set_prototype(at, &text).ok()?;
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
                let text = declaration(other, &known)?;
                session.declare_type(&text).ok()?;
                self.declared.insert(name.to_string());
                Some(Vec::new())
            }
        }
    }
}
