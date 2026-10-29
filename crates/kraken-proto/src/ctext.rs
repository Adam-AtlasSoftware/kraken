//! C declarations of the neutral type model, for people and agents to read.
//!
//! References to named types print by name, as C does; a struct's fields carry their byte offsets
//! in comments (`/* +0x8 */`), which is what reverse engineers read a layout for.

use crate::types::{
    Composite, EnumDef, FunctionPrototype, Primitive, PrimitiveClass, TypeDef, TypeRef, TypedefDef,
};

impl TypeDef {
    /// The type's name, if it has one.
    pub fn name(&self) -> Option<&str> {
        match self {
            TypeDef::Struct(c) | TypeDef::Union(c) => Some(&c.name),
            TypeDef::Enum(e) => Some(&e.name),
            TypeDef::Typedef(t) => Some(&t.name),
            TypeDef::Function(f) => f.name.as_deref(),
        }
    }

    /// `struct`, `union`, `enum`, `typedef` or `function`.
    pub fn kind_name(&self) -> &'static str {
        match self {
            TypeDef::Struct(_) => "struct",
            TypeDef::Union(_) => "union",
            TypeDef::Enum(_) => "enum",
            TypeDef::Typedef(_) => "typedef",
            TypeDef::Function(_) => "function",
        }
    }

    /// Size in bytes where the definition has one (structs, unions, enums).
    pub fn size(&self) -> Option<u64> {
        match self {
            TypeDef::Struct(c) | TypeDef::Union(c) => Some(c.size),
            TypeDef::Enum(e) => Some(u64::from(e.size)),
            _ => None,
        }
    }

    /// The names of the types this definition refers to, in order, without repeats.
    pub fn references(&self) -> Vec<String> {
        let mut out = Vec::new();
        match self {
            TypeDef::Struct(c) | TypeDef::Union(c) => {
                for f in &c.fields {
                    f.ty.collect_names(&mut out);
                }
            }
            TypeDef::Enum(_) => {}
            TypeDef::Typedef(t) => t.target.collect_names(&mut out),
            TypeDef::Function(p) => proto_names(p, &mut out),
        }
        out
    }

    /// The C declaration, ending in a newline.
    pub fn to_c(&self) -> String {
        match self {
            TypeDef::Struct(c) => composite("struct", c),
            TypeDef::Union(c) => composite("union", c),
            TypeDef::Enum(e) => enumeration(e),
            TypeDef::Typedef(TypedefDef { name, target }) => {
                format!("typedef {};\n", target.declare(name))
            }
            TypeDef::Function(p) => {
                let name = p.name.as_deref().unwrap_or("");
                let decl = declare_function(p, name);
                let note = if p.noreturn { " /* noreturn */" } else { "" };
                format!("{decl};{note}\n")
            }
        }
    }
}

impl TypeRef {
    /// The C spelling of the type with no declared name (`char *`, `int [4]`).
    pub fn to_c(&self) -> String {
        self.declare("")
    }

    /// `declarator` declared with this type (`int *p`, `void (*cb)(int)`).
    pub fn declare(&self, declarator: &str) -> String {
        match self {
            TypeRef::Named { name } => join(name, declarator),
            TypeRef::Primitive(p) => join(&primitive_name(p), declarator),
            TypeRef::Pointer { target, .. } => {
                let inner = match **target {
                    TypeRef::Array { .. } | TypeRef::Function(_) => format!("(*{declarator})"),
                    _ => format!("*{declarator}"),
                };
                target.declare(&inner)
            }
            TypeRef::Array { element, count } => element.declare(&format!("{declarator}[{count}]")),
            TypeRef::Function(p) => declare_function(p, declarator),
        }
    }

    fn collect_names(&self, out: &mut Vec<String>) {
        match self {
            TypeRef::Named { name } => {
                if !out.contains(name) {
                    out.push(name.clone());
                }
            }
            TypeRef::Primitive(_) => {}
            TypeRef::Pointer { target, .. } => target.collect_names(out),
            TypeRef::Array { element, .. } => element.collect_names(out),
            TypeRef::Function(p) => proto_names(p, out),
        }
    }
}

fn proto_names(p: &FunctionPrototype, out: &mut Vec<String>) {
    p.return_type.collect_names(out);
    for param in &p.params {
        param.ty.collect_names(out);
    }
}

fn join(base: &str, declarator: &str) -> String {
    if declarator.is_empty() {
        base.to_string()
    } else {
        format!("{base} {declarator}")
    }
}

fn primitive_name(p: &Primitive) -> String {
    let Primitive {
        class,
        size,
        signed,
    } = *p;
    match class {
        PrimitiveClass::Void => "void".into(),
        PrimitiveClass::Bool => "bool".into(),
        PrimitiveClass::Char => match (size, signed) {
            (1, _) => "char".into(),
            (2, _) => "char16_t".into(),
            _ => "wchar_t".into(),
        },
        PrimitiveClass::Float => match size {
            4 => "float".into(),
            8 => "double".into(),
            _ => "long double".into(),
        },
        PrimitiveClass::Int => {
            let u = if signed { "" } else { "u" };
            format!("{u}int{}_t", u64::from(size) * 8)
        }
        PrimitiveClass::Undefined => format!("undefined{size}"),
    }
}

fn declare_function(p: &FunctionPrototype, declarator: &str) -> String {
    let mut params: Vec<String> = p
        .params
        .iter()
        .map(|a| a.ty.declare(a.name.as_deref().unwrap_or("")))
        .collect();
    if p.varargs {
        params.push("...".into());
    }
    let list = if params.is_empty() {
        "void".to_string()
    } else {
        params.join(", ")
    };
    let cc = if p.calling_convention.is_empty() {
        String::new()
    } else {
        format!("{} ", p.calling_convention)
    };
    // the calling convention sits between the return type and the name, as compilers spell it
    let inner = if let Some(rest) = declarator.strip_prefix('(') {
        format!("({cc}{rest}")
    } else {
        format!("{cc}{declarator}")
    };
    p.return_type.declare(&format!("{inner}({list})"))
}

fn composite(keyword: &str, c: &Composite) -> String {
    let mut out = format!("{keyword} {} {{\n", c.name);
    for f in &c.fields {
        let decl = f.ty.declare(&f.name);
        match f.bitfield {
            Some(b) => out.push_str(&format!(
                "    {decl} : {}; /* +{:#x} bit {} */\n",
                b.bit_size, f.offset, b.bit_offset
            )),
            None => out.push_str(&format!("    {decl}; /* +{:#x} */\n", f.offset)),
        }
    }
    out.push_str(&format!(
        "}}; /* size {:#x}, align {} */\n",
        c.size, c.align
    ));
    out
}

fn enumeration(e: &EnumDef) -> String {
    let mut out = format!("enum {} {{\n", e.name);
    for v in &e.variants {
        out.push_str(&format!("    {} = {},\n", v.name, v.value));
    }
    out.push_str(&format!("}}; /* size {} */\n", e.size));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Bitfield, EnumVariant, Field, Param};

    fn int(size: u32, signed: bool) -> TypeRef {
        TypeRef::Primitive(Primitive {
            class: PrimitiveClass::Int,
            size,
            signed,
        })
    }

    fn named(n: &str) -> TypeRef {
        TypeRef::Named { name: n.into() }
    }

    fn ptr(t: TypeRef) -> TypeRef {
        TypeRef::Pointer {
            target: Box::new(t),
            size: 8,
        }
    }

    #[test]
    fn declarators_follow_c_precedence() {
        assert_eq!(ptr(int(4, true)).declare("p"), "int32_t *p");
        assert_eq!(ptr(ptr(named("Node"))).declare("pp"), "Node **pp");
        let arr = TypeRef::Array {
            element: Box::new(int(1, false)),
            count: 16,
        };
        assert_eq!(arr.declare("buf"), "uint8_t buf[16]");
        assert_eq!(ptr(arr.clone()).declare("p"), "uint8_t (*p)[16]");
        let cb = FunctionPrototype {
            name: None,
            return_type: Box::new(int(4, true)),
            params: vec![
                Param {
                    name: Some("ctx".into()),
                    ty: ptr(named("Ctx")),
                    storage: None,
                },
                Param {
                    name: None,
                    ty: int(8, false),
                    storage: None,
                },
            ],
            calling_convention: String::new(),
            varargs: true,
            noreturn: false,
        };
        let fp = ptr(TypeRef::Function(Box::new(cb)));
        assert_eq!(fp.declare("cb"), "int32_t (*cb)(Ctx *ctx, uint64_t, ...)");
        assert_eq!(ptr(int(1, true)).to_c(), "int8_t *");
    }

    #[test]
    fn definitions_print_as_c() {
        let node = TypeDef::Struct(Composite {
            name: "Node".into(),
            size: 16,
            align: 8,
            fields: vec![
                Field {
                    name: "next".into(),
                    offset: 0,
                    ty: ptr(named("Node")),
                    bitfield: None,
                },
                Field {
                    name: "flags".into(),
                    offset: 8,
                    ty: int(4, false),
                    bitfield: Some(Bitfield {
                        bit_offset: 2,
                        bit_size: 3,
                    }),
                },
            ],
        });
        assert_eq!(
            node.to_c(),
            "struct Node {\n    Node *next; /* +0x0 */\n    uint32_t flags : 3; /* +0x8 bit 2 */\n}; /* size 0x10, align 8 */\n"
        );
        assert_eq!(node.references(), vec!["Node".to_string()]);
        let e = TypeDef::Enum(EnumDef {
            name: "Color".into(),
            size: 4,
            variants: vec![EnumVariant {
                name: "RED".into(),
                value: -1,
            }],
        });
        assert_eq!(e.to_c(), "enum Color {\n    RED = -1,\n}; /* size 4 */\n");
        let t = TypeDef::Typedef(TypedefDef {
            name: "NodePtr".into(),
            target: ptr(named("Node")),
        });
        assert_eq!(t.to_c(), "typedef Node *NodePtr;\n");
        assert_eq!((t.kind_name(), t.name()), ("typedef", Some("NodePtr")));
    }

    #[test]
    fn named_prototypes_print_with_their_convention() {
        let f = TypeDef::Function(FunctionPrototype {
            name: Some("run".into()),
            return_type: Box::new(TypeRef::Primitive(Primitive {
                class: PrimitiveClass::Void,
                size: 0,
                signed: false,
            })),
            params: vec![],
            calling_convention: "__stdcall".into(),
            varargs: false,
            noreturn: true,
        });
        assert_eq!(f.to_c(), "void __stdcall run(void); /* noreturn */\n");
    }
}
