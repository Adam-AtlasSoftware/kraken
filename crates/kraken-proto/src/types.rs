//! Neutral C-like type model.
//!
//! References (`TypeRef`) point at named definitions (`TypeDef`) by name, so recursive types such
//! as linked-list nodes need no cycles in the data. Sizes and counts are plain JSON numbers;
//! enum values are `i64`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Class of a primitive type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PrimitiveClass {
    /// No value (`void`); size is 0.
    Void,
    /// Boolean.
    Bool,
    /// Integer.
    Int,
    /// Floating point.
    Float,
    /// Character.
    Char,
    /// Opaque bytes of known size and unknown meaning.
    Undefined,
}

/// A primitive type with explicit size and signedness.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Primitive {
    /// What kind of primitive this is.
    pub class: PrimitiveClass,
    /// Size in bytes.
    pub size: u32,
    /// Whether the type is signed (meaningful for `int`, `char` and `float`).
    pub signed: bool,
}

/// A use of a type: either a named definition or an anonymous composition of references.
///
/// Serialized with `"kind"` as the tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypeRef {
    /// A reference to a [`TypeDef`] by its name.
    Named {
        /// Name of the referenced definition.
        name: String,
    },
    /// A primitive type.
    Primitive(Primitive),
    /// A pointer with an explicit size in bytes.
    Pointer {
        /// The pointed-to type.
        target: Box<TypeRef>,
        /// Pointer size in bytes.
        size: u32,
    },
    /// A fixed-size array.
    Array {
        /// Element type.
        element: Box<TypeRef>,
        /// Number of elements.
        count: u64,
    },
    /// An anonymous function prototype (for function pointers).
    Function(Box<FunctionPrototype>),
}

/// A named type definition.
///
/// Serialized with `"kind"` as the tag.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TypeDef {
    /// A struct.
    Struct(Composite),
    /// A union.
    Union(Composite),
    /// An enum.
    Enum(EnumDef),
    /// A typedef.
    Typedef(TypedefDef),
    /// A named function prototype.
    Function(FunctionPrototype),
}

/// Layout of a struct or union.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Composite {
    /// Type name.
    pub name: String,
    /// Total size in bytes.
    pub size: u64,
    /// Alignment in bytes.
    pub align: u32,
    /// Fields in declaration order.
    pub fields: Vec<Field>,
}

/// One field of a struct or union.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Field {
    /// Field name.
    pub name: String,
    /// Byte offset from the start of the composite.
    pub offset: u64,
    /// Field type.
    #[serde(rename = "type")]
    pub ty: TypeRef,
    /// Bit position and width when the field is a bitfield.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bitfield: Option<Bitfield>,
}

/// Position of a bitfield within its storage unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Bitfield {
    /// Bit offset from the least significant bit of the storage unit at the field offset.
    pub bit_offset: u32,
    /// Width in bits.
    pub bit_size: u32,
}

/// An enum definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct EnumDef {
    /// Type name.
    pub name: String,
    /// Size in bytes.
    pub size: u32,
    /// Enumerators in declaration order.
    pub variants: Vec<EnumVariant>,
}

/// One enumerator.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct EnumVariant {
    /// Enumerator name.
    pub name: String,
    /// Enumerator value.
    pub value: i64,
}

/// A typedef definition.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct TypedefDef {
    /// The new name.
    pub name: String,
    /// The aliased type.
    pub target: TypeRef,
}

/// A function prototype.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct FunctionPrototype {
    /// Prototype name; absent for anonymous prototypes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Return type.
    pub return_type: Box<TypeRef>,
    /// Parameters in order.
    pub params: Vec<Param>,
    /// Calling convention name, such as `"__cdecl"`; empty for the engine default.
    pub calling_convention: String,
    /// Whether the function takes variable arguments.
    pub varargs: bool,
    /// Whether the function never returns.
    pub noreturn: bool,
}

/// One parameter of a function prototype.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct Param {
    /// Parameter name, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Parameter type.
    #[serde(rename = "type")]
    pub ty: TypeRef,
    /// Storage description such as `"RDI"` or `"stack+8"`, if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<String>,
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn int(size: u32, signed: bool) -> TypeRef {
        TypeRef::Primitive(Primitive {
            class: PrimitiveClass::Int,
            size,
            signed,
        })
    }

    pub(crate) fn sample_proto() -> FunctionPrototype {
        FunctionPrototype {
            name: Some("cb".into()),
            return_type: Box::new(int(4, true)),
            params: vec![
                Param {
                    name: Some("ctx".into()),
                    ty: TypeRef::Pointer {
                        target: Box::new(TypeRef::Named {
                            name: "node".into(),
                        }),
                        size: 8,
                    },
                    storage: Some("RDI".into()),
                },
                Param {
                    name: None,
                    ty: int(8, false),
                    storage: None,
                },
            ],
            calling_convention: "__stdcall".into(),
            varargs: true,
            noreturn: false,
        }
    }

    fn rt<T: Serialize + for<'a> Deserialize<'a> + PartialEq + std::fmt::Debug>(v: &T) {
        let back: T = serde_json::from_str(&serde_json::to_string(v).unwrap()).unwrap();
        assert_eq!(&back, v);
    }

    #[test]
    fn type_ref_round_trip() {
        let proto = sample_proto();
        for t in [
            TypeRef::Named {
                name: "node".into(),
            },
            int(1, false),
            TypeRef::Primitive(Primitive {
                class: PrimitiveClass::Void,
                size: 0,
                signed: false,
            }),
            TypeRef::Pointer {
                target: Box::new(int(1, true)),
                size: 8,
            },
            TypeRef::Array {
                element: Box::new(int(4, true)),
                count: 16,
            },
            TypeRef::Function(Box::new(proto)),
        ] {
            rt(&t);
        }
        for class in [
            PrimitiveClass::Bool,
            PrimitiveClass::Float,
            PrimitiveClass::Char,
            PrimitiveClass::Undefined,
        ] {
            rt(&class);
        }
    }

    #[test]
    fn type_def_round_trip_with_recursion() {
        let node = Composite {
            name: "node".into(),
            size: 16,
            align: 8,
            fields: vec![
                Field {
                    name: "next".into(),
                    offset: 0,
                    ty: TypeRef::Pointer {
                        target: Box::new(TypeRef::Named {
                            name: "node".into(),
                        }),
                        size: 8,
                    },
                    bitfield: None,
                },
                Field {
                    name: "flags".into(),
                    offset: 8,
                    ty: int(4, false),
                    bitfield: Some(Bitfield {
                        bit_offset: 3,
                        bit_size: 5,
                    }),
                },
            ],
        };
        for d in [
            TypeDef::Struct(node.clone()),
            TypeDef::Union(node),
            TypeDef::Enum(EnumDef {
                name: "color".into(),
                size: 4,
                variants: vec![
                    EnumVariant {
                        name: "RED".into(),
                        value: -1,
                    },
                    EnumVariant {
                        name: "BLUE".into(),
                        value: 7,
                    },
                ],
            }),
            TypeDef::Typedef(TypedefDef {
                name: "size_t".into(),
                target: int(8, false),
            }),
            TypeDef::Function(sample_proto()),
        ] {
            rt(&d);
        }
    }

    #[test]
    fn field_uses_type_key_and_kind_tag() {
        let json = serde_json::to_value(TypeDef::Typedef(TypedefDef {
            name: "t".into(),
            target: int(4, true),
        }))
        .unwrap();
        assert_eq!(json["kind"], "typedef");
        assert_eq!(json["target"]["kind"], "primitive");
        let f = serde_json::to_value(Field {
            name: "a".into(),
            offset: 0,
            ty: int(4, true),
            bitfield: None,
        })
        .unwrap();
        assert!(f.get("type").is_some() && f.get("bitfield").is_none());
    }
}
