package kraken.ghidra;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import kraken.ghidra.Proto.DecompileResult;
import kraken.ghidra.Proto.FunctionSummary;
import kraken.ghidra.Proto.Locator;
import kraken.ghidra.Proto.Page;
import kraken.ghidra.Proto.Token;
import kraken.ghidra.Proto.TypeDef;

/** In-process end-to-end check of the sidecar against a real binary. Prints PASS/FAIL lines. */
final class SelfTest {
    private interface Step {
        String run() throws Exception;
    }

    private final Dispatcher d;
    private final List<JsonObject> notifications = new CopyOnWriteArrayList<>();
    private int failures;

    private SelfTest() {
        d = new Dispatcher(notifications::add);
    }

    static int run(String binary, String projectDir, String samplesDir) {
        SelfTest t = new SelfTest();
        try {
            t.all(binary, projectDir, samplesDir);
        } finally {
            t.d.shutdownNow();
        }
        System.out.println(t.failures == 0 ? "ALL PASS" : t.failures + " FAILED");
        System.out.flush();
        return t.failures == 0 ? 0 : 1;
    }

    private void step(String name, Step s) {
        try {
            String detail = s.run();
            System.out.println("PASS " + name + (detail == null || detail.isEmpty() ? "" : " (" + detail + ")"));
        } catch (Throwable e) {
            failures++;
            System.out.println("FAIL " + name + ": " + e);
            if (!(e instanceof AssertionError) && !(e instanceof KrakenError)) {
                e.printStackTrace(System.err);
            }
        }
        System.out.flush();
    }

    private static void check(boolean ok, String message) {
        if (!ok) {
            throw new AssertionError(message);
        }
    }

    private static JsonObject obj(Object... kv) {
        JsonObject o = new JsonObject();
        for (int i = 0; i < kv.length; i += 2) {
            String k = (String) kv[i];
            Object v = kv[i + 1];
            switch (v) {
                case JsonElement e -> o.add(k, e);
                case String s -> o.addProperty(k, s);
                case Number n -> o.addProperty(k, n);
                case Boolean b -> o.addProperty(k, b);
                default -> throw new IllegalArgumentException(String.valueOf(v));
            }
        }
        return o;
    }

    private static JsonObject parse(String json) {
        return JsonParser.parseString(json).getAsJsonObject();
    }

    private KrakenError expectError(String method, JsonObject params) {
        try {
            d.call(method, params);
        } catch (KrakenError e) {
            return e;
        }
        throw new AssertionError(method + " unexpectedly succeeded");
    }

    private JsonObject anchor(long entry) {
        return parse(
            "{\"kind\":\"native\",\"space\":\"ram\",\"offset\":\"0x" + Long.toHexString(entry)
                + "\",\"fn_entry\":\"0x" + Long.toHexString(entry) + "\",\"fn_hash\":\"" + "0".repeat(64) + "\"}");
    }

    private static JsonObject versioned(JsonObject op) {
        return obj("schema_version", 1, "op", op);
    }

    private JsonObject applyOp(JsonObject op) throws KrakenError {
        return d.call("apply_op", obj("op", versioned(op))).getAsJsonObject();
    }

    private static JsonObject loc(long offset) {
        return parse("{\"kind\":\"native\",\"space\":\"ram\",\"offset\":\"0x" + Long.toHexString(offset) + "\"}");
    }

    private static long offsetOf(Locator l) {
        return ((Locator.Native) l).offset();
    }

    private static JsonObject prim(String cls, int size, boolean signed) {
        return obj("kind", "primitive", "class", cls, "size", size, "signed", signed);
    }

    private FunctionSummary function(long entry) {
        return FunctionSummary.fromJson(d.call("get_function", obj("locator", loc(entry))));
    }

    private DecompileResult decompile(long entry) {
        return DecompileResult.fromJson(d.call("decompile", obj("locator", loc(entry))));
    }

    // state shared across steps
    private long target;
    private String targetOldName;
    private long scratch;

    private void all(String binary, String projectDir, String samplesDir) {
        step("samples conformance", () -> samples(samplesDir));
        step(
            "handshake",
            () -> {
                Proto.Handshake h = Proto.Handshake.fromJson(d.call("handshake", new JsonObject()));
                check(h.major() == 0 && h.minor() == 1, "protocol " + h.major() + "." + h.minor());
                check(!h.capabilities().isEmpty(), "no capabilities");
                return h.build();
            });
        step(
            "unknown method is unsupported",
            () -> {
                KrakenError e = expectError("no_such_method", new JsonObject());
                check(e.code.equals("unsupported"), e.code);
                return null;
            });
        step(
            "open_binary",
            () -> {
                JsonObject info =
                    d.call("open_binary", obj("path", binary, "project_dir", projectDir)).getAsJsonObject();
                check(!info.get("analyzed").getAsBoolean(), "fresh import should not be analyzed");
                check(info.get("image_base").getAsString().startsWith("0x"), "image_base not hex");
                return info.get("language").getAsString() + ", " + info.get("format").getAsString();
            });
        step(
            "open_binary missing file is not_found",
            () -> {
                KrakenError e =
                    expectError("open_binary", obj("path", binary + ".missing", "project_dir", projectDir));
                check(e.code.equals("not_found"), e.code);
                // the failed open closed the program; reopen for the next steps
                d.call("open_binary", obj("path", binary, "project_dir", projectDir));
                return null;
            });
        step(
            "analyze (staged, progress)",
            () -> {
                long t0 = System.nanoTime();
                JsonObject r = d.call("analyze", obj("job_id", "selftest-1")).getAsJsonObject();
                long ms = (System.nanoTime() - t0) / 1_000_000;
                check(r.getAsJsonArray("stages_completed").size() == 2, "stages " + r);
                check(r.get("function_count").getAsInt() > 50, "functions " + r.get("function_count"));
                boolean progressSeen = false;
                boolean midSave = false;
                for (JsonObject n : notifications) {
                    if (n.get("method").getAsString().equals("progress")) {
                        JsonObject p = n.getAsJsonObject("params");
                        check(p.get("job_id").getAsString().equals("selftest-1"), "job id");
                        check(p.has("stage") && p.has("done") && p.has("total") && p.has("message"), "progress fields");
                        progressSeen = true;
                    }
                }
                check(progressSeen, "no progress notifications");
                return r.get("function_count").getAsInt() + " functions in " + ms + " ms, "
                    + notifications.size() + " progress notifications";
            });
        step(
            "analyze again is a no-op (resume)",
            () -> {
                JsonObject r = d.call("analyze", obj("job_id", "selftest-2")).getAsJsonObject();
                check(r.getAsJsonArray("stages_completed").size() == 0, "stages " + r);
                return null;
            });
        step(
            "cancel an analysis job",
            () -> {
                Thread t =
                    new Thread(
                        () -> {
                            try {
                                Thread.sleep(2000);
                                d.call("cancel", obj("job_id", "selftest-cancel"));
                            } catch (Exception e) {
                                System.err.println("cancel thread: " + e);
                            }
                        });
                t.start();
                KrakenError e =
                    expectError("analyze", obj("job_id", "selftest-cancel", "force", true));
                t.join();
                check(e.code.equals("cancelled"), e.code + ": " + e.getMessage());
                return e.getMessage();
            });
        step(
            "list_functions paging",
            () -> {
                List<FunctionSummary> all = new ArrayList<>();
                String cursor = null;
                long total = -1;
                int pages = 0;
                do {
                    JsonObject req = obj("limit", 100);
                    if (cursor != null) {
                        req.addProperty("cursor", cursor);
                    }
                    Page<FunctionSummary> page = Page.fromJson(d.call("list_functions", req), FunctionSummary::fromJson);
                    check(page.items().size() <= 100, "page too big");
                    all.addAll(page.items());
                    total = page.total();
                    cursor = page.nextCursor();
                    pages++;
                } while (cursor != null);
                check(all.size() == total, all.size() + " items vs total " + total);
                check(pages > 1, "expected several pages");
                long prev = -1;
                for (FunctionSummary f : all) {
                    long off = offsetOf(f.locator());
                    check(off > prev, "not address-sorted at " + Long.toHexString(off));
                    prev = off;
                    check(f.fnHash() != null && f.fnHash().matches("[0-9a-f]{64}"), "bad fn_hash " + f.fnHash());
                    check(f.completeness().kind().equals("complete"), "completeness " + f.completeness());
                }
                // pick a mid-sized, non-thunk function to work on, and a second one for later
                for (FunctionSummary f : all) {
                    if (f.name().startsWith("FUN_") && f.size() != null && f.size() > 80 && f.size() < 600) {
                        if (target == 0) {
                            target = offsetOf(f.locator());
                            targetOldName = f.name();
                        } else if (scratch == 0) {
                            scratch = offsetOf(f.locator());
                        }
                    }
                }
                check(target != 0 && scratch != 0, "no suitable functions");
                return all.size() + " functions, " + pages + " pages";
            });
        step(
            "get_function",
            () -> {
                FunctionSummary f = function(target);
                check(f.name().equals(targetOldName), f.name());
                check(f.signature() != null && f.size() != null, "missing signature/size");
                KrakenError e = expectError("get_function", obj("locator", loc(0x10)));
                check(e.code.equals("not_found"), e.code);
                return f.signature();
            });
        step(
            "decompile",
            () -> {
                DecompileResult r = decompile(target);
                check(!r.text().isEmpty() && r.text().contains("("), "empty text");
                byte[] bytes = r.text().getBytes(StandardCharsets.UTF_8);
                int fnTokens = 0;
                int targeted = 0;
                for (Token t : r.tokens()) {
                    check(t.start() <= t.end() && t.end() <= bytes.length, "token span out of range");
                    if (t.kind().equals("function")) {
                        fnTokens++;
                    }
                    if (t.target() != null) {
                        targeted++;
                    }
                }
                check(fnTokens > 0, "no function tokens");
                check(targeted > 0, "no tokens with targets");
                boolean nameTokenFound = false;
                for (Token t : r.tokens()) {
                    String s = new String(bytes, (int) t.start(), (int) (t.end() - t.start()), StandardCharsets.UTF_8);
                    if (t.symbol() != null) {
                        check(s.equals(t.symbol()), "token text " + s + " != symbol " + t.symbol());
                    }
                    if (s.equals(targetOldName)) {
                        nameTokenFound = true;
                    }
                }
                check(nameTokenFound, "function name token not found");
                return r.tokens().size() + " tokens, " + targeted + " with targets";
            });
        step(
            "rename shows up in decompile",
            () -> {
                applyOp(
                    obj(
                        "op", "rename", "anchor", anchor(target), "old_name", targetOldName, "new_name",
                        "kraken_renamed_fn"));
                check(function(target).name().equals("kraken_renamed_fn"), "get_function name");
                DecompileResult r = decompile(target);
                check(r.text().contains("kraken_renamed_fn"), "decompile text lacks the new name");
                return null;
            });
        step(
            "rename to an invalid name is engine_rejected",
            () -> {
                KrakenError e =
                    expectError(
                        "apply_op",
                        obj(
                            "op",
                            versioned(
                                obj("op", "rename", "anchor", anchor(scratch), "new_name", "has space"))));
                check(e.code.equals("engine_rejected"), e.code + ": " + e.getMessage());
                return e.getMessage();
            });
        step(
            "apply_op with a bad space is invalid_argument",
            () -> {
                JsonObject a = anchor(target);
                a.addProperty("space", "nowhere");
                KrakenError e =
                    expectError(
                        "apply_op",
                        obj("op", versioned(obj("op", "rename", "anchor", a, "new_name", "x"))));
                check(e.code.equals("invalid_argument"), e.code);
                return null;
            });
        step(
            "set_comment (plate) shows up in decompile",
            () -> {
                applyOp(
                    obj(
                        "op", "set_comment", "anchor", anchor(target), "comment_kind", "plate", "new",
                        "kraken-plate-comment"));
                applyOp(
                    obj(
                        "op", "set_comment", "anchor", anchor(target), "comment_kind", "eol", "new",
                        "kraken-eol-comment"));
                check(decompile(target).text().contains("kraken-plate-comment"), "plate comment missing");
                applyOp(obj("op", "set_comment", "anchor", anchor(target), "comment_kind", "plate"));
                check(!decompile(target).text().contains("kraken-plate-comment"), "plate comment not cleared");
                return null;
            });
        step(
            "set_type (function signature) and set_calling_convention",
            () -> {
                JsonObject proto =
                    obj(
                        "kind", "function",
                        "return_type", prim("int", 4, true),
                        "params",
                            arr(
                                obj("name", "kraken_arg", "type", prim("int", 4, true)),
                                obj(
                                    "name", "kraken_ptr", "type",
                                    obj("kind", "pointer", "size", 8, "target", prim("char", 1, true)))),
                        "calling_convention", "",
                        "varargs", false,
                        "noreturn", false);
                applyOp(obj("op", "set_type", "anchor", anchor(target), "new", proto));
                FunctionSummary f = function(target);
                check(f.signature().contains("kraken_arg"), "signature " + f.signature());
                check(decompile(target).text().contains("kraken_arg"), "decompile lacks kraken_arg");
                applyOp(obj("op", "set_calling_convention", "anchor", anchor(target), "new", "__stdcall"));
                KrakenError e =
                    expectError(
                        "apply_op",
                        obj(
                            "op",
                            versioned(
                                obj(
                                    "op", "set_calling_convention", "anchor", anchor(target), "new",
                                    "__no_such_cc"))));
                check(e.code.equals("engine_rejected"), e.code);
                return f.signature();
            });
        step("types round trip", this::typesRoundTrip);
        step(
            "set_function_bounds",
            () -> {
                FunctionSummary f = function(scratch);
                long size = f.size();
                applyOp(
                    obj(
                        "op", "set_function_bounds", "anchor", anchor(scratch), "new",
                        parse(
                            "{\"space\":\"ram\",\"start\":\"0x" + Long.toHexString(scratch) + "\",\"end\":\"0x"
                                + Long.toHexString(scratch + size) + "\"}")));
                check(function(scratch).size() == size, "size changed");
                return null;
            });
        step("code/data and create/delete function", this::createDelete);
        step(
            "save",
            () -> {
                check(function(target).name().equals("kraken_renamed_fn"), "rename lost before save: " + function(target).name());
                JsonObject r = d.call("save", new JsonObject()).getAsJsonObject();
                check(!r.get("checkpoint").getAsString().isEmpty(), "empty checkpoint");
                return r.get("checkpoint").getAsString();
            });
        step(
            "reopen keeps analysis and edits",
            () -> {
                JsonObject info =
                    d.call("open_binary", obj("path", binary, "project_dir", projectDir)).getAsJsonObject();
                check(info.get("analyzed").getAsBoolean(), "analysis state lost: " + info);
                String n = function(target).name();
                check(n.equals("kraken_renamed_fn"), "rename lost, name is " + n);
                return null;
            });
        step(
            "forced re-analysis keeps user edits",
            () -> {
                d.call("analyze", obj("job_id", "selftest-3", "force", true));
                String n = function(target).name();
                check(n.equals("kraken_renamed_fn"), "name after forced re-analysis: " + n);
                return null;
            });
        step("shutdown", () -> {
            d.call("shutdown", new JsonObject());
            return null;
        });
    }

    private static JsonArray arr(JsonElement... xs) {
        JsonArray a = new JsonArray();
        for (JsonElement x : xs) {
            a.add(x);
        }
        return a;
    }

    private String samples(String dir) throws Exception {
        File[] files = new File(dir).listFiles((f, n) -> n.endsWith(".json"));
        check(files != null && files.length > 0, "no samples in " + dir);
        Arrays.sort(files);
        List<String> bad = new ArrayList<>();
        for (File f : files) {
            String type = f.getName().substring(0, f.getName().indexOf('.'));
            try {
                JsonElement in = JsonParser.parseString(Files.readString(f.toPath()));
                JsonElement out = Proto.roundTrip(type, in);
                if (!in.equals(out)) {
                    bad.add(f.getName() + ": re-serialized JSON differs\n  in:  " + in + "\n  out: " + out);
                }
            } catch (RuntimeException e) {
                bad.add(f.getName() + ": " + e);
            }
        }
        check(bad.isEmpty(), String.join("\n", bad));
        // strictness: the wire rules the Rust side enforces
        for (String badJson : new String[] {
            "{\"kind\":\"native\",\"offset\":4198400}",
            "{\"kind\":\"native\",\"offset\":\"401000\"}",
            "{\"kind\":\"nope\"}",
        }) {
            try {
                Locator.fromJson(JsonParser.parseString(badJson));
                throw new AssertionError("accepted bad locator " + badJson);
            } catch (KrakenError expected) {
                // ok
            }
        }
        return files.length + " files";
    }

    private String typesRoundTrip() {
        JsonObject i32 = prim("int", 4, true);
        JsonObject node =
            parse(
                "{\"kind\":\"struct\",\"name\":\"kraken_node\",\"size\":24,\"align\":8,\"fields\":["
                    + "{\"name\":\"next\",\"offset\":0,\"type\":{\"kind\":\"pointer\",\"size\":8,\"target\":{\"kind\":\"named\",\"name\":\"kraken_node\"}}},"
                    + "{\"name\":\"value\",\"offset\":8,\"type\":" + i32 + "},"
                    + "{\"name\":\"tag\",\"offset\":12,\"type\":{\"kind\":\"array\",\"count\":4,\"element\":" + prim("char", 1, true) + "}},"
                    + "{\"name\":\"weight\",\"offset\":16,\"type\":" + prim("float", 8, true) + "}]}");
        JsonObject union =
            parse(
                "{\"kind\":\"union\",\"name\":\"kraken_value\",\"size\":8,\"align\":8,\"fields\":["
                    + "{\"name\":\"i\",\"offset\":0,\"type\":" + prim("int", 8, true) + "},"
                    + "{\"name\":\"d\",\"offset\":0,\"type\":" + prim("float", 8, true) + "}]}");
        JsonObject en =
            parse(
                "{\"kind\":\"enum\",\"name\":\"kraken_color\",\"size\":4,\"variants\":["
                    + "{\"name\":\"NEG\",\"value\":-5},{\"name\":\"RED\",\"value\":0},{\"name\":\"BLUE\",\"value\":7}]}");
        JsonObject typedef =
            parse(
                "{\"kind\":\"typedef\",\"name\":\"kraken_u32\",\"target\":" + prim("int", 4, false) + "}");
        JsonObject fn =
            parse(
                "{\"kind\":\"function\",\"name\":\"kraken_cb\",\"return_type\":" + prim("void", 0, false)
                    + ",\"params\":[{\"name\":\"ctx\",\"type\":{\"kind\":\"pointer\",\"size\":8,\"target\":{\"kind\":\"named\",\"name\":\"kraken_node\"}}},"
                    + "{\"name\":\"flags\",\"type\":{\"kind\":\"named\",\"name\":\"kraken_u32\"}}],"
                    + "\"calling_convention\":\"__stdcall\",\"varargs\":false,\"noreturn\":false}");
        for (JsonObject def : new JsonObject[] {node, union, en, typedef, fn}) {
            String name = def.get("name").getAsString();
            JsonObject back = d.call("define_type", obj("def", def)).getAsJsonObject();
            JsonObject page =
                d.call("get_types", obj("name", name)).getAsJsonObject();
            check(page.getAsJsonArray("items").size() == 1, name + ": get_types returned " + page);
            JsonObject listed = page.getAsJsonArray("items").get(0).getAsJsonObject();
            check(back.equals(listed), name + ": define_type result differs from get_types\n " + back + "\n " + listed);
            JsonObject want = def.deepCopy();
            JsonObject got = back.deepCopy();
            // alignment is Ghidra-computed; everything else must round-trip exactly
            want.remove("align");
            got.remove("align");
            if (def == fn) {
                // storage is not part of a type definition; Ghidra reports no per-parameter storage
                check(got.equals(want), name + ": differs\n want " + want + "\n got  " + got);
            } else {
                check(got.equals(want), name + ": differs\n want " + want + "\n got  " + got);
            }
        }
        JsonObject all = d.call("get_types", obj("limit", 500)).getAsJsonObject();
        Page<TypeDef> page = Page.fromJson(all, TypeDef::fromJson);
        check(page.items().stream().anyMatch(t -> t.name().equals("kraken_node")), "kraken_node not listed");
        return page.total() + " types in the program";
    }

    private String createDelete() {
        long a = scratch;
        long len = function(a).size();
        applyOp(
            obj(
                "op", "delete_function", "anchor", anchor(a), "old_body",
                parse("{\"space\":\"ram\",\"start\":\"0x" + Long.toHexString(a) + "\",\"end\":\"0x" + Long.toHexString(a + len) + "\"}")));
        KrakenError gone = expectError("get_function", obj("locator", loc(a)));
        check(gone.code.equals("not_found"), "function still there after delete: " + gone.code);
        KrakenError dup =
            expectError("apply_op", obj("op", versioned(obj("op", "delete_function", "anchor", anchor(a)))));
        check(dup.code.equals("not_found"), "second delete: " + dup.code);

        JsonObject i32 = prim("int", 4, true);
        applyOp(
            obj(
                "op", "set_code_data", "anchor", anchor(a), "new",
                obj("kind", "data", "data_type", i32), "length", "0x4"));
        applyOp(obj("op", "set_code_data", "anchor", anchor(a), "new", obj("kind", "undefined"), "length", "0x4"));
        applyOp(obj("op", "set_code_data", "anchor", anchor(a), "new", obj("kind", "code")));

        applyOp(obj("op", "create_function", "anchor", anchor(a), "name", "kraken_created"));
        FunctionSummary f = function(a);
        check(f.name().equals("kraken_created"), "created function named " + f.name());
        check(f.size() != null && f.size() > 0, "created function has no body");
        applyOp(obj("op", "delete_function", "anchor", anchor(a)));
        KrakenError gone2 = expectError("get_function", obj("locator", loc(a)));
        check(gone2.code.equals("not_found"), "created function still there: " + gone2.code);
        return "created body " + f.size() + " bytes";
    }
}
