package kraken.ghidra;

import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.BitFieldDataType;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.BuiltInDataTypeManager;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.ParameterDefinitionImpl;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.SignedCharDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.TypedefDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.UnionDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.WideChar16DataType;
import ghidra.program.model.data.WideChar32DataType;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import kraken.ghidra.Proto.Bitfield;
import kraken.ghidra.Proto.EnumDef;
import kraken.ghidra.Proto.EnumVariant;
import kraken.ghidra.Proto.Field;
import kraken.ghidra.Proto.FunctionPrototype;
import kraken.ghidra.Proto.Param;
import kraken.ghidra.Proto.TypeDef;
import kraken.ghidra.Proto.TypeRef;
import kraken.ghidra.Proto.TypedefDef;

/** Conversion between the neutral kraken-proto type model and Ghidra DataTypes. */
final class TypeConv {
    private final DataTypeManager dtm;

    TypeConv(DataTypeManager dtm) {
        this.dtm = dtm;
    }

    // ---- neutral -> Ghidra ----------------------------------------------------------------

    DataType toGhidra(TypeRef ref) {
        return switch (ref) {
            case TypeRef.Named n -> lookup(n.name());
            case TypeRef.Primitive p -> primitive(p);
            case TypeRef.Pointer p -> {
                DataType target = toGhidra(p.target());
                yield new PointerDataType(target, p.size(), dtm);
            }
            case TypeRef.Array a -> {
                DataType el = toGhidra(a.element());
                if (el.getLength() <= 0) {
                    throw KrakenError.invalid("array element type has no size");
                }
                if (a.count() <= 0 || a.count() > Integer.MAX_VALUE) {
                    throw KrakenError.invalid("bad array count " + a.count());
                }
                yield new ArrayDataType(el, (int) a.count(), el.getLength(), dtm);
            }
            case TypeRef.Function f -> functionDefinition(f.proto(), "anon_fn_" + anonCounter++);
        };
    }

    private int anonCounter;

    private DataType primitive(TypeRef.Primitive p) {
        DataType dt =
            switch (p.cls()) {
                case "void" -> VoidDataType.dataType;
                case "bool" -> BooleanDataType.dataType;
                case "int" ->
                    p.signed()
                        ? AbstractIntegerDataType.getSignedDataType(p.size(), dtm)
                        : AbstractIntegerDataType.getUnsignedDataType(p.size(), dtm);
                case "float" -> AbstractFloatDataType.getFloatDataType(p.size(), dtm);
                case "char" ->
                    switch (p.size()) {
                        case 1 -> p.signed() ? SignedCharDataType.dataType : UnsignedCharDataType.dataType;
                        case 2 -> WideChar16DataType.dataType;
                        case 4 -> WideChar32DataType.dataType;
                        default -> null;
                    };
                case "undefined" -> p.size() > 0 ? Undefined.getUndefinedDataType(p.size()) : null;
                default -> null;
            };
        if (dt == null || (!p.cls().equals("void") && dt.getLength() != p.size())) {
            throw KrakenError.unsupported(
                "no Ghidra type for primitive " + p.cls() + " size " + p.size());
        }
        return dt;
    }

    /** Removes the program's own type `name` from the root category; false when there is none. */
    boolean remove(String name) {
        DataType dt = dtm.getDataType(CategoryPath.ROOT, name);
        return dt != null && dtm.remove(dt, ghidra.util.task.TaskMonitor.DUMMY);
    }

    /** Find a named type: program types first, then built-ins. */
    DataType lookup(String name) {
        DataType dt = dtm.getDataType(CategoryPath.ROOT, name);
        if (dt != null) {
            return dt;
        }
        List<DataType> found = new ArrayList<>();
        dtm.findDataTypes(name, found);
        if (found.isEmpty()) {
            BuiltInDataTypeManager.getDataTypeManager().findDataTypes(name, found);
        }
        for (DataType d : found) {
            if (d.getName().equals(name)) {
                return d;
            }
        }
        throw KrakenError.notFound("unknown type `" + name + "`");
    }

    private FunctionDefinitionDataType functionDefinition(FunctionPrototype p, String fallbackName) {
        String name = p.name() != null && !p.name().isEmpty() ? p.name() : fallbackName;
        FunctionDefinitionDataType fd = new FunctionDefinitionDataType(CategoryPath.ROOT, name);
        fd.setReturnType(toGhidra(p.returnType()));
        ParameterDefinition[] params = new ParameterDefinition[p.params().size()];
        for (int i = 0; i < params.length; i++) {
            Param pa = p.params().get(i);
            params[i] = new ParameterDefinitionImpl(pa.name(), toGhidra(pa.type()), null);
        }
        fd.setArguments(params);
        fd.setVarArgs(p.varargs());
        fd.setNoReturn(p.noreturn());
        String cc = p.callingConvention();
        if (cc != null && !cc.isEmpty()) {
            try {
                fd.setCallingConvention(cc);
            } catch (ghidra.util.exception.InvalidInputException e) {
                throw KrakenError.rejected("bad calling convention `" + cc + "`: " + e.getMessage());
            }
        }
        return fd;
    }

    /** A function signature definition for ApplyFunctionSignatureCmd, named `name`. */
    FunctionDefinitionDataType signature(FunctionPrototype p, String name) {
        return functionDefinition(
            new FunctionPrototype(
                name, p.returnType(), p.params(), p.callingConvention(), p.varargs(), p.noreturn()),
            name);
    }

    /** Define (or replace) a named type in the program's manager; returns the managed type. */
    DataType define(TypeDef def) {
        try {
            DataType built =
                switch (def) {
                    case TypeDef.Struct s -> {
                        ensurePlaceholder(s.def().name(), false);
                        yield buildComposite(s.def(), false);
                    }
                    case TypeDef.Union u -> {
                        ensurePlaceholder(u.def().name(), true);
                        yield buildComposite(u.def(), true);
                    }
                    case TypeDef.Enum e -> buildEnum(e.def());
                    case TypeDef.Typedef t ->
                        new TypedefDataType(CategoryPath.ROOT, t.def().name(), toGhidra(t.def().target()), dtm);
                    case TypeDef.Function f -> {
                        if (f.def().name() == null || f.def().name().isEmpty()) {
                            throw KrakenError.invalid("a function type definition needs a name");
                        }
                        yield functionDefinition(f.def(), f.def().name());
                    }
                };
            return dtm.resolve(built, DataTypeConflictHandler.REPLACE_HANDLER);
        } catch (IllegalArgumentException | ghidra.program.model.data.InvalidDataTypeException e) {
            throw KrakenError.rejected(e.getMessage());
        }
    }

    /** Self-referencing types need the name to resolve before the body is built. */
    private void ensurePlaceholder(String name, boolean union) {
        if (dtm.getDataType(CategoryPath.ROOT, name) == null) {
            DataType ph =
                union
                    ? new UnionDataType(CategoryPath.ROOT, name, dtm)
                    : new StructureDataType(CategoryPath.ROOT, name, 0, dtm);
            dtm.addDataType(ph, DataTypeConflictHandler.DEFAULT_HANDLER);
        }
    }

    private DataType buildComposite(Proto.Composite c, boolean union)
            throws ghidra.program.model.data.InvalidDataTypeException {
        if (union) {
            UnionDataType u = new UnionDataType(CategoryPath.ROOT, c.name(), dtm);
            for (Field f : c.fields()) {
                DataType ft = toGhidra(f.type());
                if (f.bitfield() != null) {
                    u.insertBitField(
                        u.getNumComponents(), ft, f.bitfield().bitSize(), f.name(), null);
                } else {
                    u.add(ft, ft.getLength(), f.name(), null);
                }
            }
            return u;
        }
        if (c.size() < 0 || c.size() > Integer.MAX_VALUE) {
            throw KrakenError.invalid("bad struct size " + c.size());
        }
        StructureDataType s = new StructureDataType(CategoryPath.ROOT, c.name(), (int) c.size(), dtm);
        s.setPackingEnabled(false);
        for (Field f : c.fields()) {
            DataType ft = toGhidra(f.type());
            int off = (int) f.offset();
            if (f.bitfield() != null) {
                s.insertBitFieldAt(
                    off, ft.getLength(), f.bitfield().bitOffset(), ft, f.bitfield().bitSize(), f.name(), null);
            } else {
                if (ft.getLength() <= 0) {
                    throw KrakenError.invalid("field `" + f.name() + "` has no size");
                }
                s.replaceAtOffset(off, ft, ft.getLength(), f.name(), null);
            }
        }
        if (c.align() > 1) {
            s.setExplicitMinimumAlignment(c.align());
        }
        return s;
    }

    private DataType buildEnum(EnumDef e) {
        EnumDataType en = new EnumDataType(CategoryPath.ROOT, e.name(), e.size(), dtm);
        for (EnumVariant v : e.variants()) {
            en.add(v.name(), v.value());
        }
        return en;
    }

    // ---- Ghidra -> neutral ----------------------------------------------------------------

    TypeRef toNeutral(DataType dt) {
        if (dt instanceof Pointer p) {
            DataType t = p.getDataType();
            TypeRef target = t == null ? voidRef() : toNeutral(t);
            return new TypeRef.Pointer(target, p.getLength());
        }
        if (dt instanceof Array a) {
            return new TypeRef.Array(toNeutral(a.getDataType()), a.getNumElements());
        }
        if (dt instanceof ghidra.program.model.data.TypeDef
                || dt instanceof ghidra.program.model.data.Structure
                || dt instanceof Union
                || dt instanceof ghidra.program.model.data.Enum
                || dt instanceof FunctionDefinition) {
            return new TypeRef.Named(dt.getName());
        }
        if (dt instanceof VoidDataType) {
            return voidRef();
        }
        if (dt instanceof BooleanDataType) {
            return new TypeRef.Primitive("bool", 1, false);
        }
        if (dt instanceof WideChar16DataType) {
            return new TypeRef.Primitive("char", 2, false);
        }
        if (dt instanceof WideChar32DataType) {
            return new TypeRef.Primitive("char", 4, false);
        }
        if (dt instanceof CharDataType c) {
            return new TypeRef.Primitive("char", c.getLength(), c.isSigned());
        }
        if (dt instanceof AbstractIntegerDataType i) {
            return new TypeRef.Primitive("int", i.getLength(), i.isSigned());
        }
        if (dt instanceof AbstractFloatDataType) {
            return new TypeRef.Primitive("float", dt.getLength(), true);
        }
        if (Undefined.isUndefined(dt)) {
            return new TypeRef.Primitive("undefined", dt.getLength(), false);
        }
        return new TypeRef.Named(dt.getName());
    }

    private static TypeRef voidRef() {
        return new TypeRef.Primitive("void", 0, false);
    }

    /** Neutral definition of a named program type, or null if it is not a definable kind. */
    TypeDef toNeutralDef(DataType dt) {
        if (dt instanceof Structure s) {
            return new TypeDef.Struct(composite(s));
        }
        if (dt instanceof Union u) {
            return new TypeDef.Union(composite(u));
        }
        if (dt instanceof ghidra.program.model.data.Enum e) {
            List<EnumVariant> vs = new ArrayList<>();
            for (String n : e.getNames()) {
                vs.add(new EnumVariant(n, e.getValue(n)));
            }
            vs.sort(Comparator.comparingLong(EnumVariant::value).thenComparing(EnumVariant::name));
            return new TypeDef.Enum(new EnumDef(e.getName(), e.getLength(), vs));
        }
        if (dt instanceof ghidra.program.model.data.TypeDef t) {
            return new TypeDef.Typedef(new TypedefDef(t.getName(), toNeutral(t.getDataType())));
        }
        if (dt instanceof FunctionDefinition f) {
            return new TypeDef.Function(prototype(f));
        }
        return null;
    }

    FunctionPrototype prototype(ghidra.program.model.listing.FunctionSignature f) {
        List<Param> params = new ArrayList<>();
        for (ParameterDefinition p : f.getArguments()) {
            String n = p.getName();
            params.add(new Param(n == null || n.isEmpty() ? null : n, toNeutral(p.getDataType()), null));
        }
        DataType ret = f.getReturnType();
        return new FunctionPrototype(
            f.getName(),
            ret == null ? voidRef() : toNeutral(ret),
            params,
            f.getCallingConventionName(),
            f.hasVarArgs(),
            f.hasNoReturn());
    }

    private Proto.Composite composite(ghidra.program.model.data.Composite c) {
        List<Field> fields = new ArrayList<>();
        for (DataTypeComponent comp : c.getDefinedComponents()) {
            String name = comp.getFieldName();
            if (name == null) {
                name = comp.getDefaultFieldName();
            }
            DataType dt = comp.getDataType();
            if (dt instanceof BitFieldDataType bf) {
                fields.add(
                    new Field(
                        name,
                        comp.getOffset(),
                        toNeutral(bf.getBaseDataType()),
                        new Bitfield(bf.getBitOffset(), bf.getBitSize())));
            } else {
                fields.add(new Field(name, comp.getOffset(), toNeutral(dt), null));
            }
        }
        fields.sort(Comparator.comparingLong(Field::offset));
        return new Proto.Composite(c.getName(), c.getLength(), Math.max(1, c.getAlignment()), fields);
    }

    /** All definable named types in the program, sorted by name. */
    List<TypeDef> allDefs(String nameFilter) {
        List<DataType> all = new ArrayList<>();
        dtm.getAllDataTypes(all);
        all.sort(
            Comparator.comparing(DataType::getName).thenComparing(d -> d.getCategoryPath().getPath()));
        List<TypeDef> out = new ArrayList<>();
        for (DataType dt : all) {
            if (nameFilter != null && !dt.getName().equals(nameFilter)) {
                continue;
            }
            try {
                TypeDef d = toNeutralDef(dt);
                if (d != null) {
                    out.add(d);
                }
            } catch (KrakenError e) {
                System.err.println("kraken-ghidra: skipping type " + dt.getName() + ": " + e.getMessage());
            }
        }
        return out;
    }
}
