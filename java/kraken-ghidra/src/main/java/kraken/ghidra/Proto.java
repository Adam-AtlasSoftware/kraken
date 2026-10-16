package kraken.ghidra;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.List;
import java.util.Set;
import java.util.function.Function;

/**
 * Hand-written DTOs for the kraken-proto wire types. Each type parses strictly from and
 * serializes to exactly the JSON the Rust types produce (checked against schema/samples).
 */
final class Proto {
    private Proto() {}

    static final String DEFAULT_SPACE = "ram";

    private static String spaceOf(JsonObject o) {
        String s = J.optStr(o, "space");
        return s == null ? DEFAULT_SPACE : s;
    }

    private static JsonObject tagged(String key, String tag) {
        JsonObject o = new JsonObject();
        o.addProperty(key, tag);
        return o;
    }

    private static KrakenError unknownTag(String type, String tag) {
        return KrakenError.invalid("unknown " + type + " variant `" + tag + "`");
    }

    // ---- locator ------------------------------------------------------------------------

    sealed interface Locator {
        JsonElement toJson();

        record Native(String space, long offset) implements Locator {
            public JsonElement toJson() {
                JsonObject o = tagged("kind", "native");
                o.addProperty("space", space);
                o.add("offset", J.hexJson(offset));
                return o;
            }
        }

        static Locator fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "locator");
            String tag = J.tag(o, "kind");
            if (tag.equals("native")) {
                return new Native(spaceOf(o), J.hex(o, "offset"));
            }
            throw unknownTag("locator", tag);
        }
    }

    sealed interface Anchor {
        JsonElement toJson();

        record Native(String space, long offset, long fnEntry, String fnHash) implements Anchor {
            public JsonElement toJson() {
                JsonObject o = tagged("kind", "native");
                o.addProperty("space", space);
                o.add("offset", J.hexJson(offset));
                o.add("fn_entry", J.hexJson(fnEntry));
                o.addProperty("fn_hash", fnHash);
                return o;
            }
        }

        record Managed(String token) implements Anchor {
            public JsonElement toJson() {
                JsonObject o = tagged("kind", "managed");
                o.addProperty("token", token);
                return o;
            }
        }

        record Banked(String bank, String space, long offset) implements Anchor {
            public JsonElement toJson() {
                JsonObject o = tagged("kind", "banked");
                o.addProperty("bank", bank);
                o.addProperty("space", space);
                o.add("offset", J.hexJson(offset));
                return o;
            }
        }

        static Anchor fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "anchor");
            String tag = J.tag(o, "kind");
            return switch (tag) {
                case "native" ->
                    new Native(spaceOf(o), J.hex(o, "offset"), J.hex(o, "fn_entry"), J.str(o, "fn_hash"));
                case "managed" -> new Managed(J.str(o, "token"));
                case "banked" -> new Banked(J.str(o, "bank"), J.str(o, "space"), J.hex(o, "offset"));
                default -> throw unknownTag("anchor", tag);
            };
        }
    }

    record AddressRange(String space, long start, long end) {
        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("space", space);
            o.add("start", J.hexJson(start));
            o.add("end", J.hexJson(end));
            return o;
        }

        static AddressRange fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "address_range");
            return new AddressRange(spaceOf(o), J.hex(o, "start"), J.hex(o, "end"));
        }
    }

    // ---- types --------------------------------------------------------------------------

    sealed interface TypeRef {
        JsonElement toJson();

        record Named(String name) implements TypeRef {
            public JsonElement toJson() {
                JsonObject o = tagged("kind", "named");
                o.addProperty("name", name);
                return o;
            }
        }

        record Primitive(String cls, int size, boolean signed) implements TypeRef {
            public JsonElement toJson() {
                JsonObject o = tagged("kind", "primitive");
                o.addProperty("class", cls);
                o.addProperty("size", size);
                o.addProperty("signed", signed);
                return o;
            }
        }

        record Pointer(TypeRef target, int size) implements TypeRef {
            public JsonElement toJson() {
                JsonObject o = tagged("kind", "pointer");
                o.add("target", target.toJson());
                o.addProperty("size", size);
                return o;
            }
        }

        record Array(TypeRef element, long count) implements TypeRef {
            public JsonElement toJson() {
                JsonObject o = tagged("kind", "array");
                o.add("element", element.toJson());
                o.addProperty("count", count);
                return o;
            }
        }

        record Function(FunctionPrototype proto) implements TypeRef {
            public JsonElement toJson() {
                JsonObject o = proto.toJson();
                o.addProperty("kind", "function");
                return o;
            }
        }

        Set<String> CLASSES = Set.of("void", "bool", "int", "float", "char", "undefined");

        static TypeRef fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "type_ref");
            String tag = J.tag(o, "kind");
            return switch (tag) {
                case "named" -> new Named(J.str(o, "name"));
                case "primitive" -> {
                    String cls = J.str(o, "class");
                    if (!CLASSES.contains(cls)) {
                        throw KrakenError.invalid("unknown primitive class `" + cls + "`");
                    }
                    yield new Primitive(cls, (int) J.num(o, "size"), J.bool(o, "signed"));
                }
                case "pointer" ->
                    new Pointer(fromJson(J.req(o, "target")), (int) J.num(o, "size"));
                case "array" -> new Array(fromJson(J.req(o, "element")), J.num(o, "count"));
                case "function" -> new Function(FunctionPrototype.fromJson(o));
                default -> throw unknownTag("type_ref", tag);
            };
        }
    }

    record Param(String name, TypeRef type, String storage) {
        JsonElement toJson() {
            JsonObject o = new JsonObject();
            J.put(o, "name", name);
            o.add("type", type.toJson());
            J.put(o, "storage", storage);
            return o;
        }

        static Param fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "param");
            return new Param(
                J.optStr(o, "name"), TypeRef.fromJson(J.req(o, "type")), J.optStr(o, "storage"));
        }
    }

    record FunctionPrototype(
            String name,
            TypeRef returnType,
            List<Param> params,
            String callingConvention,
            boolean varargs,
            boolean noreturn) {
        JsonObject toJson() {
            JsonObject o = new JsonObject();
            J.put(o, "name", name);
            o.add("return_type", returnType.toJson());
            o.add("params", J.array(params, Param::toJson));
            o.addProperty("calling_convention", callingConvention);
            o.addProperty("varargs", varargs);
            o.addProperty("noreturn", noreturn);
            return o;
        }

        static FunctionPrototype fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "function_prototype");
            return new FunctionPrototype(
                J.optStr(o, "name"),
                TypeRef.fromJson(J.req(o, "return_type")),
                J.list(o, "params", Param::fromJson),
                J.str(o, "calling_convention"),
                J.bool(o, "varargs"),
                J.bool(o, "noreturn"));
        }
    }

    record Bitfield(int bitOffset, int bitSize) {
        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("bit_offset", bitOffset);
            o.addProperty("bit_size", bitSize);
            return o;
        }

        static Bitfield fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "bitfield");
            return new Bitfield((int) J.num(o, "bit_offset"), (int) J.num(o, "bit_size"));
        }
    }

    record Field(String name, long offset, TypeRef type, Bitfield bitfield) {
        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("name", name);
            o.addProperty("offset", offset);
            o.add("type", type.toJson());
            if (bitfield != null) {
                o.add("bitfield", bitfield.toJson());
            }
            return o;
        }

        static Field fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "field");
            JsonElement bf = J.opt(o, "bitfield");
            return new Field(
                J.str(o, "name"),
                J.num(o, "offset"),
                TypeRef.fromJson(J.req(o, "type")),
                bf == null ? null : Bitfield.fromJson(bf));
        }
    }

    record Composite(String name, long size, int align, List<Field> fields) {
        JsonObject toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("name", name);
            o.addProperty("size", size);
            o.addProperty("align", align);
            o.add("fields", J.array(fields, Field::toJson));
            return o;
        }

        static Composite fromJson(JsonObject o) {
            return new Composite(
                J.str(o, "name"),
                J.num(o, "size"),
                (int) J.num(o, "align"),
                J.list(o, "fields", Field::fromJson));
        }
    }

    record EnumVariant(String name, long value) {
        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("name", name);
            o.addProperty("value", value);
            return o;
        }

        static EnumVariant fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "enum_variant");
            return new EnumVariant(J.str(o, "name"), J.num(o, "value"));
        }
    }

    record EnumDef(String name, int size, List<EnumVariant> variants) {
        JsonObject toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("name", name);
            o.addProperty("size", size);
            o.add("variants", J.array(variants, EnumVariant::toJson));
            return o;
        }

        static EnumDef fromJson(JsonObject o) {
            return new EnumDef(
                J.str(o, "name"),
                (int) J.num(o, "size"),
                J.list(o, "variants", EnumVariant::fromJson));
        }
    }

    record TypedefDef(String name, TypeRef target) {
        JsonObject toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("name", name);
            o.add("target", target.toJson());
            return o;
        }

        static TypedefDef fromJson(JsonObject o) {
            return new TypedefDef(J.str(o, "name"), TypeRef.fromJson(J.req(o, "target")));
        }
    }

    sealed interface TypeDef {
        JsonElement toJson();

        String name();

        record Struct(Composite def) implements TypeDef {
            public JsonElement toJson() {
                JsonObject o = def.toJson();
                o.addProperty("kind", "struct");
                return o;
            }

            public String name() {
                return def.name();
            }
        }

        record Union(Composite def) implements TypeDef {
            public JsonElement toJson() {
                JsonObject o = def.toJson();
                o.addProperty("kind", "union");
                return o;
            }

            public String name() {
                return def.name();
            }
        }

        record Enum(EnumDef def) implements TypeDef {
            public JsonElement toJson() {
                JsonObject o = def.toJson();
                o.addProperty("kind", "enum");
                return o;
            }

            public String name() {
                return def.name();
            }
        }

        record Typedef(TypedefDef def) implements TypeDef {
            public JsonElement toJson() {
                JsonObject o = def.toJson();
                o.addProperty("kind", "typedef");
                return o;
            }

            public String name() {
                return def.name();
            }
        }

        record Function(FunctionPrototype def) implements TypeDef {
            public JsonElement toJson() {
                JsonObject o = def.toJson();
                o.addProperty("kind", "function");
                return o;
            }

            public String name() {
                return def.name();
            }
        }

        static TypeDef fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "type_def");
            String tag = J.tag(o, "kind");
            return switch (tag) {
                case "struct" -> new Struct(Composite.fromJson(o));
                case "union" -> new Union(Composite.fromJson(o));
                case "enum" -> new Enum(EnumDef.fromJson(o));
                case "typedef" -> new Typedef(TypedefDef.fromJson(o));
                case "function" -> new Function(FunctionPrototype.fromJson(o));
                default -> throw unknownTag("type_def", tag);
            };
        }
    }

    // ---- log ops ------------------------------------------------------------------------

    static final int LOG_SCHEMA_VERSION = 1;
    static final Set<String> COMMENT_KINDS = Set.of("plate", "pre", "eol", "post", "repeatable");

    sealed interface CodeData {
        JsonElement toJson();

        record Code() implements CodeData {
            public JsonElement toJson() {
                return tagged("kind", "code");
            }
        }

        record Data(TypeRef dataType) implements CodeData {
            public JsonElement toJson() {
                JsonObject o = tagged("kind", "data");
                if (dataType != null) {
                    o.add("data_type", dataType.toJson());
                }
                return o;
            }
        }

        record Undefined() implements CodeData {
            public JsonElement toJson() {
                return tagged("kind", "undefined");
            }
        }

        static CodeData fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "code_data");
            String tag = J.tag(o, "kind");
            return switch (tag) {
                case "code" -> new Code();
                case "data" -> {
                    JsonElement t = J.opt(o, "data_type");
                    yield new Data(t == null ? null : TypeRef.fromJson(t));
                }
                case "undefined" -> new Undefined();
                default -> throw unknownTag("code_data", tag);
            };
        }
    }

    sealed interface LogOp {
        Anchor anchor();

        JsonObject toJson();

        record Rename(Anchor anchor, String oldName, String newName) implements LogOp {
            public JsonObject toJson() {
                JsonObject o = tagged("op", "rename");
                o.add("anchor", anchor.toJson());
                J.put(o, "old_name", oldName);
                o.addProperty("new_name", newName);
                return o;
            }
        }

        record SetType(Anchor anchor, TypeRef old, TypeRef neu) implements LogOp {
            public JsonObject toJson() {
                JsonObject o = tagged("op", "set_type");
                o.add("anchor", anchor.toJson());
                if (old != null) {
                    o.add("old", old.toJson());
                }
                o.add("new", neu.toJson());
                return o;
            }
        }

        record SetComment(Anchor anchor, String commentKind, String old, String neu)
                implements LogOp {
            public JsonObject toJson() {
                JsonObject o = tagged("op", "set_comment");
                o.add("anchor", anchor.toJson());
                o.addProperty("comment_kind", commentKind);
                J.put(o, "old", old);
                J.put(o, "new", neu);
                return o;
            }
        }

        record CreateFunction(Anchor anchor, String name, AddressRange body) implements LogOp {
            public JsonObject toJson() {
                JsonObject o = tagged("op", "create_function");
                o.add("anchor", anchor.toJson());
                J.put(o, "name", name);
                if (body != null) {
                    o.add("body", body.toJson());
                }
                return o;
            }
        }

        record DeleteFunction(Anchor anchor, AddressRange oldBody) implements LogOp {
            public JsonObject toJson() {
                JsonObject o = tagged("op", "delete_function");
                o.add("anchor", anchor.toJson());
                if (oldBody != null) {
                    o.add("old_body", oldBody.toJson());
                }
                return o;
            }
        }

        record SetFunctionBounds(Anchor anchor, AddressRange old, AddressRange neu)
                implements LogOp {
            public JsonObject toJson() {
                JsonObject o = tagged("op", "set_function_bounds");
                o.add("anchor", anchor.toJson());
                if (old != null) {
                    o.add("old", old.toJson());
                }
                o.add("new", neu.toJson());
                return o;
            }
        }

        record SetCodeData(Anchor anchor, CodeData old, CodeData neu, Long length)
                implements LogOp {
            public JsonObject toJson() {
                JsonObject o = tagged("op", "set_code_data");
                o.add("anchor", anchor.toJson());
                if (old != null) {
                    o.add("old", old.toJson());
                }
                o.add("new", neu.toJson());
                if (length != null) {
                    o.add("length", J.hexJson(length));
                }
                return o;
            }
        }

        record SetCallingConvention(Anchor anchor, String old, String neu) implements LogOp {
            public JsonObject toJson() {
                JsonObject o = tagged("op", "set_calling_convention");
                o.add("anchor", anchor.toJson());
                J.put(o, "old", old);
                o.addProperty("new", neu);
                return o;
            }
        }

        private static TypeRef optType(JsonObject o, String k) {
            JsonElement e = J.opt(o, k);
            return e == null ? null : TypeRef.fromJson(e);
        }

        private static AddressRange optRange(JsonObject o, String k) {
            JsonElement e = J.opt(o, k);
            return e == null ? null : AddressRange.fromJson(e);
        }

        private static CodeData optCode(JsonObject o, String k) {
            JsonElement e = J.opt(o, k);
            return e == null ? null : CodeData.fromJson(e);
        }

        static LogOp fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "log_op");
            String tag = J.tag(o, "op");
            Anchor a = Anchor.fromJson(J.req(o, "anchor"));
            return switch (tag) {
                case "rename" ->
                    new Rename(a, J.optStr(o, "old_name"), J.str(o, "new_name"));
                case "set_type" ->
                    new SetType(a, optType(o, "old"), TypeRef.fromJson(J.req(o, "new")));
                case "set_comment" -> {
                    String kind = J.str(o, "comment_kind");
                    if (!COMMENT_KINDS.contains(kind)) {
                        throw KrakenError.invalid("unknown comment kind `" + kind + "`");
                    }
                    yield new SetComment(a, kind, J.optStr(o, "old"), J.optStr(o, "new"));
                }
                case "create_function" ->
                    new CreateFunction(a, J.optStr(o, "name"), optRange(o, "body"));
                case "delete_function" -> new DeleteFunction(a, optRange(o, "old_body"));
                case "set_function_bounds" ->
                    new SetFunctionBounds(
                        a, optRange(o, "old"), AddressRange.fromJson(J.req(o, "new")));
                case "set_code_data" ->
                    new SetCodeData(
                        a,
                        optCode(o, "old"),
                        CodeData.fromJson(J.req(o, "new")),
                        J.optHex(o, "length"));
                case "set_calling_convention" ->
                    new SetCallingConvention(a, J.optStr(o, "old"), J.str(o, "new"));
                default -> throw unknownTag("log_op", tag);
            };
        }
    }

    record VersionedLogOp(int schemaVersion, LogOp op) {
        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("schema_version", schemaVersion);
            o.add("op", op.toJson());
            return o;
        }

        static VersionedLogOp fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "versioned_log_op");
            int v = (int) J.num(o, "schema_version");
            if (v > LOG_SCHEMA_VERSION) {
                throw KrakenError.unsupported(
                    "log schema version " + v + " is newer than supported " + LOG_SCHEMA_VERSION);
            }
            return new VersionedLogOp(v, LogOp.fromJson(J.req(o, "op")));
        }
    }

    // ---- meta ---------------------------------------------------------------------------

    /** Completeness, LogStatus and SyncState: a "kind" tag plus an optional reason. */
    record Kinded(String kind, String reason) {
        JsonElement toJson() {
            JsonObject o = tagged("kind", kind);
            J.put(o, "reason", reason);
            return o;
        }

        static Kinded complete() {
            return new Kinded("complete", null);
        }

        static Kinded partial(String reason) {
            return new Kinded("partial", reason);
        }

        static Kinded notAnalyzed() {
            return new Kinded("not_analyzed", null);
        }

        static Kinded fromJson(JsonElement e, String type, Set<String> plain, Set<String> withReason) {
            JsonObject o = J.obj(e, type);
            String tag = J.tag(o, "kind");
            if (plain.contains(tag)) {
                return new Kinded(tag, null);
            }
            if (withReason.contains(tag)) {
                return new Kinded(tag, J.str(o, "reason"));
            }
            throw unknownTag(type, tag);
        }

        static Kinded completeness(JsonElement e) {
            return fromJson(e, "completeness", Set.of("complete", "not_analyzed"), Set.of("partial"));
        }

        static Kinded logStatus(JsonElement e) {
            return fromJson(e, "log_status", Set.of("applied", "orphaned"), Set.of("rejected"));
        }

        static Kinded syncState(JsonElement e) {
            return fromJson(
                e, "sync_state", Set.of("pending", "pushed"), Set.of("engine_rejected"));
        }
    }

    static String provenance(JsonElement e) {
        String s = J.str(e, "provenance");
        if (!Set.of("user", "agent", "agent_from_binary_text").contains(s)) {
            throw KrakenError.invalid("unknown provenance `" + s + "`");
        }
        return s;
    }

    record FunctionSummary(
            Locator locator,
            String name,
            Long size,
            String signature,
            String fnHash,
            Kinded completeness) {
        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.add("locator", locator.toJson());
            o.addProperty("name", name);
            J.put(o, "size", size);
            J.put(o, "signature", signature);
            J.put(o, "fn_hash", fnHash);
            o.add("completeness", completeness.toJson());
            return o;
        }

        static FunctionSummary fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "function_summary");
            return new FunctionSummary(
                Locator.fromJson(J.req(o, "locator")),
                J.str(o, "name"),
                J.optNum(o, "size"),
                J.optStr(o, "signature"),
                J.optStr(o, "fn_hash"),
                Kinded.completeness(J.req(o, "completeness")));
        }
    }

    record Token(
            long start, long end, String kind, Locator target, String symbol, String varnode) {
        static final Set<String> KINDS =
            Set.of(
                "keyword", "variable", "function", "type", "field", "constant", "comment", "op",
                "other");

        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("start", start);
            o.addProperty("end", end);
            o.addProperty("kind", kind);
            if (target != null) {
                o.add("target", target.toJson());
            }
            J.put(o, "symbol", symbol);
            J.put(o, "varnode", varnode);
            return o;
        }

        static Token fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "token");
            String kind = J.str(o, "kind");
            if (!KINDS.contains(kind)) {
                throw KrakenError.invalid("unknown token kind `" + kind + "`");
            }
            JsonElement t = J.opt(o, "target");
            return new Token(
                J.num(o, "start"),
                J.num(o, "end"),
                kind,
                t == null ? null : Locator.fromJson(t),
                J.optStr(o, "symbol"),
                J.optStr(o, "varnode"));
        }
    }

    record DecompileResult(
            Locator function,
            String language,
            String text,
            List<Token> tokens,
            List<String> warnings,
            Kinded completeness) {
        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.add("function", function.toJson());
            o.addProperty("language", language);
            o.addProperty("text", text);
            o.add("tokens", J.array(tokens, Token::toJson));
            JsonArray w = new JsonArray();
            warnings.forEach(w::add);
            o.add("warnings", w);
            o.add("completeness", completeness.toJson());
            return o;
        }

        static DecompileResult fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "decompile_result");
            String lang = J.optStr(o, "language");
            return new DecompileResult(
                Locator.fromJson(J.req(o, "function")),
                lang == null ? "c" : lang,
                J.str(o, "text"),
                J.list(o, "tokens", Token::fromJson),
                J.list(o, "warnings", x -> J.str(x, "warning")),
                Kinded.completeness(J.req(o, "completeness")));
        }
    }

    record ProtoError(String code, String message, JsonElement details) {
        static final Set<String> CODES =
            Set.of(
                "not_found", "invalid_argument", "conflict_stale_read", "rejected_human_priority",
                "engine_rejected", "unsupported", "analysis_incomplete", "timeout", "cancelled",
                "internal");

        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("code", code);
            o.addProperty("message", message);
            J.put(o, "details", details);
            return o;
        }

        static ProtoError fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "error");
            String code = J.str(o, "code");
            if (!CODES.contains(code)) {
                throw KrakenError.invalid("unknown error code `" + code + "`");
            }
            return new ProtoError(code, J.str(o, "message"), J.opt(o, "details"));
        }
    }

    record Capability(String name, int version) {
        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("name", name);
            o.addProperty("version", version);
            return o;
        }

        static Capability fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "capability");
            return new Capability(J.str(o, "name"), (int) J.num(o, "version"));
        }
    }

    /** protocol is {major, minor} as serialized by kraken-proto's ProtocolVersion. */
    record Handshake(int major, int minor, String build, List<Capability> capabilities) {
        JsonElement toJson() {
            JsonObject o = new JsonObject();
            JsonObject p = new JsonObject();
            p.addProperty("major", major);
            p.addProperty("minor", minor);
            o.add("protocol", p);
            o.addProperty("build", build);
            o.add("capabilities", J.array(capabilities, Capability::toJson));
            return o;
        }

        static Handshake fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "handshake");
            JsonObject p = J.obj(J.req(o, "protocol"), "protocol");
            return new Handshake(
                (int) J.num(p, "major"),
                (int) J.num(p, "minor"),
                J.str(o, "build"),
                J.list(o, "capabilities", Capability::fromJson));
        }
    }

    record PageRequest(String cursor, Integer limit) {
        static final int MAX_LIMIT = 500;
        static final int DEFAULT_LIMIT = 100;

        JsonElement toJson() {
            JsonObject o = new JsonObject();
            J.put(o, "cursor", cursor);
            J.put(o, "limit", limit);
            return o;
        }

        static PageRequest fromJson(JsonObject o) {
            Long l = J.optNum(o, "limit");
            return new PageRequest(J.optStr(o, "cursor"), l == null ? null : (int) (long) l);
        }

        int effectiveLimit() {
            int l = limit == null ? DEFAULT_LIMIT : limit;
            return Math.max(1, Math.min(MAX_LIMIT, l));
        }
    }

    record Page<T>(List<T> items, String nextCursor, Long total) {
        JsonElement toJson(Function<T, JsonElement> f) {
            JsonObject o = new JsonObject();
            o.add("items", J.array(items, f));
            J.put(o, "next_cursor", nextCursor);
            J.put(o, "total", total);
            return o;
        }

        static <T> Page<T> fromJson(JsonElement e, Function<JsonElement, T> f) {
            JsonObject o = J.obj(e, "page");
            return new Page<>(
                J.list(o, "items", f), J.optStr(o, "next_cursor"), J.optNum(o, "total"));
        }
    }

    // ---- program data -------------------------------------------------------------------

    private static String oneOf(JsonObject o, String key, Set<String> allowed) {
        String v = J.str(o, key);
        if (!allowed.contains(v)) {
            throw KrakenError.invalid("unknown " + key + " `" + v + "`");
        }
        return v;
    }

    private static JsonArray strings(List<String> l) {
        JsonArray a = new JsonArray();
        l.forEach(a::add);
        return a;
    }

    static String hexBytes(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xf, 16)).append(Character.forDigit(x & 0xf, 16));
        }
        return sb.toString();
    }

    record MemoryBlock(
            String name,
            String space,
            long start,
            long end,
            String perms,
            boolean initialized,
            String kind) {
        static final Set<String> KINDS =
            Set.of("default", "overlay", "byte_mapped", "bit_mapped", "external");

        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("name", name);
            o.addProperty("space", space);
            o.add("start", J.hexJson(start));
            o.add("end", J.hexJson(end));
            o.addProperty("perms", perms);
            o.addProperty("initialized", initialized);
            o.addProperty("kind", kind);
            return o;
        }

        static MemoryBlock fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "memory_block");
            return new MemoryBlock(
                J.str(o, "name"),
                spaceOf(o),
                J.hex(o, "start"),
                J.hex(o, "end"),
                J.str(o, "perms"),
                J.bool(o, "initialized"),
                oneOf(o, "kind", KINDS));
        }
    }

    record BytesRead(long start, byte[] bytes, List<AddressRange> uninitialized) {
        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.add("start", J.hexJson(start));
            o.addProperty("bytes", java.util.Base64.getEncoder().encodeToString(bytes));
            if (!uninitialized.isEmpty()) {
                o.add("uninitialized", J.array(uninitialized, AddressRange::toJson));
            }
            return o;
        }

        static BytesRead fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "bytes_read");
            byte[] data;
            try {
                data = java.util.Base64.getDecoder().decode(J.str(o, "bytes"));
            } catch (IllegalArgumentException ex) {
                throw KrakenError.invalid("bytes is not valid base64");
            }
            List<AddressRange> un =
                J.opt(o, "uninitialized") == null
                    ? List.of()
                    : J.list(o, "uninitialized", AddressRange::fromJson);
            return new BytesRead(J.hex(o, "start"), data, un);
        }
    }

    record OperandToken(String text, String kind, Locator target) {
        static final Set<String> KINDS = Set.of("register", "immediate", "address", "symbol", "other");

        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("text", text);
            o.addProperty("kind", kind);
            if (target != null) {
                o.add("target", target.toJson());
            }
            return o;
        }

        static OperandToken fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "operand_token");
            JsonElement t = J.opt(o, "target");
            return new OperandToken(
                J.str(o, "text"), oneOf(o, "kind", KINDS), t == null ? null : Locator.fromJson(t));
        }
    }

    record DisasmRow(
            long address,
            String bytes,
            String mnemonic,
            List<OperandToken> operands,
            String comment,
            List<String> labels,
            String flow) {
        static final Set<String> FLOWS =
            Set.of("fallthrough", "jump", "conditional_jump", "call", "return", "indirect", "other");

        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.add("address", J.hexJson(address));
            o.addProperty("bytes", bytes);
            o.addProperty("mnemonic", mnemonic);
            o.add("operands", J.array(operands, OperandToken::toJson));
            J.put(o, "comment", comment);
            if (!labels.isEmpty()) {
                o.add("labels", strings(labels));
            }
            o.addProperty("flow", flow);
            return o;
        }

        static DisasmRow fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "disasm_row");
            List<String> labels =
                J.opt(o, "labels") == null ? List.of() : J.list(o, "labels", x -> J.str(x, "label"));
            return new DisasmRow(
                J.hex(o, "address"),
                J.str(o, "bytes"),
                J.str(o, "mnemonic"),
                J.list(o, "operands", OperandToken::fromJson),
                J.optStr(o, "comment"),
                labels,
                oneOf(o, "flow", FLOWS));
        }
    }

    record FunctionRef(long address, String name) {
        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.add("address", J.hexJson(address));
            o.addProperty("name", name);
            return o;
        }

        static FunctionRef fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "function_ref");
            return new FunctionRef(J.hex(o, "address"), J.str(o, "name"));
        }
    }

    record Xref(long from, long to, String kind, FunctionRef fromFunction, FunctionRef toFunction) {
        static final Set<String> KINDS =
            Set.of("call", "jump", "read", "write", "data", "fallthrough", "other");

        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.add("from", J.hexJson(from));
            o.add("to", J.hexJson(to));
            o.addProperty("kind", kind);
            if (fromFunction != null) {
                o.add("from_function", fromFunction.toJson());
            }
            if (toFunction != null) {
                o.add("to_function", toFunction.toJson());
            }
            return o;
        }

        static Xref fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "xref");
            JsonElement f = J.opt(o, "from_function");
            JsonElement t = J.opt(o, "to_function");
            return new Xref(
                J.hex(o, "from"),
                J.hex(o, "to"),
                oneOf(o, "kind", KINDS),
                f == null ? null : FunctionRef.fromJson(f),
                t == null ? null : FunctionRef.fromJson(t));
        }
    }

    record CfgBlock(long start, long end, long instructions) {
        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.add("start", J.hexJson(start));
            o.add("end", J.hexJson(end));
            o.addProperty("instructions", instructions);
            return o;
        }

        static CfgBlock fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "cfg_block");
            return new CfgBlock(J.hex(o, "start"), J.hex(o, "end"), J.num(o, "instructions"));
        }
    }

    record CfgEdge(long from, long to, String kind) {
        static final Set<String> KINDS =
            Set.of("fallthrough", "jump", "conditional_true", "conditional_false", "switch");

        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.add("from", J.hexJson(from));
            o.add("to", J.hexJson(to));
            o.addProperty("kind", kind);
            return o;
        }

        static CfgEdge fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "cfg_edge");
            return new CfgEdge(J.hex(o, "from"), J.hex(o, "to"), oneOf(o, "kind", KINDS));
        }
    }

    record Cfg(long function, List<CfgBlock> blocks, List<CfgEdge> edges) {
        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.add("function", J.hexJson(function));
            o.add("blocks", J.array(blocks, CfgBlock::toJson));
            o.add("edges", J.array(edges, CfgEdge::toJson));
            return o;
        }

        static Cfg fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "cfg");
            return new Cfg(
                J.hex(o, "function"),
                J.list(o, "blocks", CfgBlock::fromJson),
                J.list(o, "edges", CfgEdge::fromJson));
        }
    }

    record StringEntry(long address, String value, String encoding, long length) {
        static final Set<String> ENCODINGS = Set.of("ascii", "utf8", "utf16", "utf32", "other");

        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.add("address", J.hexJson(address));
            o.addProperty("value", value);
            o.addProperty("encoding", encoding);
            o.addProperty("length", length);
            return o;
        }

        static StringEntry fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "string_entry");
            return new StringEntry(
                J.hex(o, "address"),
                J.str(o, "value"),
                oneOf(o, "encoding", ENCODINGS),
                J.num(o, "length"));
        }
    }

    record SymbolEntry(String name, Long address, String library, String kind) {
        static final Set<String> KINDS = Set.of("function", "data", "other");

        JsonElement toJson() {
            JsonObject o = new JsonObject();
            o.addProperty("name", name);
            if (address != null) {
                o.add("address", J.hexJson(address));
            }
            J.put(o, "library", library);
            o.addProperty("kind", kind);
            return o;
        }

        static SymbolEntry fromJson(JsonElement e) {
            JsonObject o = J.obj(e, "symbol_entry");
            return new SymbolEntry(
                J.str(o, "name"),
                J.optHex(o, "address"),
                J.optStr(o, "library"),
                oneOf(o, "kind", KINDS));
        }
    }

    /** Untrusted<String>: {"untrusted": true, "value": ...}. */
    static JsonElement untrustedString(JsonElement e) {
        JsonObject o = J.obj(e, "untrusted");
        if (!J.bool(o, "untrusted")) {
            throw KrakenError.invalid("`untrusted` must be true");
        }
        String v = J.str(o, "value");
        JsonObject out = new JsonObject();
        out.addProperty("untrusted", true);
        out.addProperty("value", v);
        return out;
    }

    /** Parse and re-serialize a sample by its type name (the file name prefix before the first dot). */
    static JsonElement roundTrip(String type, JsonElement e) {
        return switch (type) {
            case "locator" -> Locator.fromJson(e).toJson();
            case "anchor" -> Anchor.fromJson(e).toJson();
            case "address_range" -> AddressRange.fromJson(e).toJson();
            case "type_ref" -> TypeRef.fromJson(e).toJson();
            case "type_def" -> TypeDef.fromJson(e).toJson();
            case "log_op" -> VersionedLogOp.fromJson(e).toJson();
            case "provenance" -> new com.google.gson.JsonPrimitive(provenance(e));
            case "log_status" -> Kinded.logStatus(e).toJson();
            case "sync_state" -> Kinded.syncState(e).toJson();
            case "completeness" -> Kinded.completeness(e).toJson();
            case "function_summary" -> FunctionSummary.fromJson(e).toJson();
            case "decompile_result" -> DecompileResult.fromJson(e).toJson();
            case "error" -> ProtoError.fromJson(e).toJson();
            case "handshake" -> Handshake.fromJson(e).toJson();
            case "page_request" -> PageRequest.fromJson(J.obj(e, "page_request")).toJson();
            case "function_page" ->
                Page.fromJson(e, FunctionSummary::fromJson).toJson(FunctionSummary::toJson);
            case "untrusted_string" -> untrustedString(e);
            case "memory_block" -> MemoryBlock.fromJson(e).toJson();
            case "bytes_read" -> BytesRead.fromJson(e).toJson();
            case "disasm_row" -> DisasmRow.fromJson(e).toJson();
            case "xref" -> Xref.fromJson(e).toJson();
            case "cfg" -> Cfg.fromJson(e).toJson();
            case "string_entry" -> StringEntry.fromJson(e).toJson();
            case "symbol_entry" -> SymbolEntry.fromJson(e).toJson();
            default -> throw KrakenError.invalid("no DTO for sample type `" + type + "`");
        };
    }
}
