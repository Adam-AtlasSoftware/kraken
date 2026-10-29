package kraken.ghidra;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;
import kraken.ghidra.Proto.Capability;
import kraken.ghidra.Proto.Handshake;
import kraken.ghidra.Proto.Locator;
import kraken.ghidra.Proto.PageRequest;
import kraken.ghidra.Proto.TypeDef;
import kraken.ghidra.Proto.VersionedLogOp;

/**
 * Routes RPC methods to the engine. Read-only requests run on a worker pool; anything that
 * mutates the project or program runs, in arrival order, on one mutator thread (Ghidra
 * transactions are not re-entrant across threads). handshake and cancel run inline so they are
 * never queued behind long work.
 */
final class Dispatcher {
    static final String VERSION = "0.0.0";
    static final int PROTOCOL_MAJOR = 0;
    static final int PROTOCOL_MINOR = 1;

    private static final Set<String> MUTATING =
        Set.of("open_binary", "analyze", "apply_op", "define_type", "remove_type", "save", "shutdown");
    private static final Set<String> INLINE = Set.of("handshake", "cancel", "ping");

    private final Engine engine = new Engine();
    private final Consumer<JsonObject> notifier;
    private final ExecutorService pool =
        Executors.newFixedThreadPool(4, r -> daemon(r, "kraken-worker"));
    private final ExecutorService mutator =
        Executors.newSingleThreadExecutor(r -> daemon(r, "kraken-mutator"));

    Dispatcher(Consumer<JsonObject> notifier) {
        this.notifier = notifier;
    }

    private static Thread daemon(Runnable r, String name) {
        Thread t = new Thread(r, name);
        t.setDaemon(true);
        return t;
    }

    /** Runs `method` on the right thread. The future fails with KrakenError for protocol errors. */
    CompletableFuture<JsonElement> submit(String method, JsonObject params, String requestId) {
        if (INLINE.contains(method)) {
            try {
                return CompletableFuture.completedFuture(invoke(method, params, requestId));
            } catch (Throwable t) {
                return CompletableFuture.failedFuture(t);
            }
        }
        ExecutorService ex = MUTATING.contains(method) ? mutator : pool;
        return CompletableFuture.supplyAsync(() -> invokeChecked(method, params, requestId), ex);
    }

    /** Blocking call for in-process use (the self-test). */
    JsonElement call(String method, JsonObject params) throws KrakenError {
        try {
            return submit(method, params, "self-" + System.nanoTime()).get();
        } catch (ExecutionException e) {
            throw asKrakenError(e.getCause());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw KrakenError.internal("interrupted");
        }
    }

    static KrakenError asKrakenError(Throwable t) {
        while (t instanceof CompletionException && t.getCause() != null) {
            t = t.getCause();
        }
        if (t instanceof KrakenError k) {
            return k;
        }
        t.printStackTrace();
        return KrakenError.internal(t.toString());
    }

    private JsonElement invokeChecked(String method, JsonObject params, String requestId) {
        try {
            return invoke(method, params, requestId);
        } catch (KrakenError e) {
            throw e;
        } catch (Exception e) {
            throw asKrakenError(e);
        }
    }

    private JsonElement invoke(String method, JsonObject params, String requestId) throws Exception {
        switch (method) {
            case "ping" -> {
                JsonObject o = new JsonObject();
                o.addProperty("pong", true);
                return o;
            }
            case "handshake" -> {
                return handshake().toJson();
            }
            case "open_binary" -> {
                String loader = J.optStr(params, "loader_spec");
                return engine.openBinary(J.str(params, "path"), J.str(params, "project_dir"), loader);
            }
            case "analyze" -> {
                String jobId = J.optStr(params, "job_id");
                if (jobId == null) {
                    jobId = "job-" + requestId;
                }
                List<String> stages = null;
                if (J.opt(params, "stages") != null) {
                    stages = J.list(params, "stages", e -> J.str(e, "stage"));
                }
                boolean force =
                    J.opt(params, "force") != null && J.bool(params, "force");
                return engine.analyze(jobId, stages, force, this::progress);
            }
            case "cancel" -> {
                String jobId = J.str(params, "job_id");
                if (!engine.cancelJob(jobId)) {
                    throw KrakenError.notFound("no running job " + jobId);
                }
                JsonObject o = new JsonObject();
                o.addProperty("cancelled", true);
                return o;
            }
            case "list_functions" -> {
                return engine
                    .listFunctions(PageRequest.fromJson(params))
                    .toJson(Proto.FunctionSummary::toJson);
            }
            case "get_function" -> {
                return engine.getFunction(Locator.fromJson(J.req(params, "locator"))).toJson();
            }
            case "decompile" -> {
                return engine
                    .decompile(Locator.fromJson(J.req(params, "locator")), J.optNum(params, "timeout_ms"))
                    .toJson();
            }
            case "memory_map" -> {
                return J.array(engine.inspect().memoryMap(), Proto.MemoryBlock::toJson);
            }
            case "read_bytes" -> {
                return engine
                    .inspect()
                    .readBytes(Locator.fromJson(J.req(params, "locator")), J.num(params, "length"))
                    .toJson();
            }
            case "assemble" -> {
                Inspect in = engine.inspect();
                return Assemble.line(
                    in.programForAssembly(), in.at(Locator.fromJson(J.req(params, "locator"))), J.str(params, "text"));
            }
            case "disassemble" -> {
                return engine
                    .inspect()
                    .disassemble(J.hex(params, "start"), J.str(params, "scope"), PageRequest.fromJson(params))
                    .toJson(Proto.DisasmRow::toJson);
            }
            case "xrefs" -> {
                boolean whole = J.opt(params, "whole_function") != null && J.bool(params, "whole_function");
                return engine
                    .inspect()
                    .xrefs(
                        J.hex(params, "address"),
                        J.str(params, "direction"),
                        J.optStr(params, "kind"),
                        whole,
                        PageRequest.fromJson(params))
                    .toJson(Proto.Xref::toJson);
            }
            case "cfg" -> {
                return engine.inspect().cfg(Locator.fromJson(J.req(params, "locator"))).toJson();
            }
            case "strings" -> {
                return engine
                    .inspect()
                    .strings(J.num(params, "min_len"), J.optStr(params, "filter"), PageRequest.fromJson(params))
                    .toJson(Proto.StringEntry::toJson);
            }
            case "imports" -> {
                return engine
                    .inspect()
                    .imports(PageRequest.fromJson(params))
                    .toJson(Proto.SymbolEntry::toJson);
            }
            case "exports" -> {
                return engine
                    .inspect()
                    .exports(PageRequest.fromJson(params))
                    .toJson(Proto.SymbolEntry::toJson);
            }
            case "apply_op" -> {
                engine.applyOp(VersionedLogOp.fromJson(J.req(params, "op")));
                JsonObject o = new JsonObject();
                o.addProperty("ok", true);
                return o;
            }
            case "get_types" -> {
                return engine
                    .getTypes(PageRequest.fromJson(params), J.optStr(params, "name"))
                    .toJson(TypeDef::toJson);
            }
            case "define_type" -> {
                return engine.defineType(TypeDef.fromJson(J.req(params, "def"))).toJson();
            }
            case "remove_type" -> {
                engine.removeType(J.str(params, "name"));
                JsonObject o = new JsonObject();
                o.addProperty("ok", true);
                return o;
            }
            case "save" -> {
                JsonObject o = new JsonObject();
                o.addProperty("checkpoint", engine.save(J.optStr(params, "watermark")));
                return o;
            }
            case "shutdown" -> {
                engine.closeProgram();
                JsonObject o = new JsonObject();
                o.addProperty("ok", true);
                return o;
            }
            default -> throw KrakenError.unsupported("method not found: " + method);
        }
    }

    private Handshake handshake() {
        List<Capability> caps =
            List.of(
                new Capability("open_binary", 1),
                new Capability("analyze.staged", 1),
                new Capability("list_functions", 1),
                new Capability("decompile.tokens", 1),
                new Capability("apply_op.v1", 1),
                new Capability("types.roundtrip", 1),
                new Capability("save", 1),
                new Capability("memory_map", 1),
                new Capability("read_bytes", 1),
                new Capability("disassemble", 1),
                new Capability("assemble", 1),
                new Capability("xrefs", 1),
                new Capability("cfg", 1),
                new Capability("strings", 1),
                new Capability("imports", 1),
                new Capability("exports", 1));
        return new Handshake(
            PROTOCOL_MAJOR,
            PROTOCOL_MINOR,
            "kraken-ghidra " + VERSION + " (ghidra " + engine.ghidraVersion() + ")",
            caps);
    }

    private void progress(
            String jobId, String stage, long done, long total, String message, Engine.Step step) {
        JsonObject p = new JsonObject();
        p.addProperty("job_id", jobId);
        p.addProperty("stage", stage);
        p.addProperty("done", done);
        p.addProperty("total", total);
        p.addProperty("message", message == null ? "" : message);
        if (step != null) {
            JsonObject st = new JsonObject();
            st.addProperty("name", step.name());
            st.addProperty("done", step.done());
            st.addProperty("total", step.total());
            p.add("step", st);
        }
        JsonObject n = new JsonObject();
        n.addProperty("jsonrpc", "2.0");
        n.addProperty("method", "progress");
        n.add("params", p);
        notifier.accept(n);
    }

    String ghidraVersion() {
        return engine.ghidraVersion();
    }

    void shutdownNow() {
        engine.closeProgram();
        pool.shutdownNow();
        mutator.shutdownNow();
    }

    static JsonArray emptyArray() {
        return new JsonArray();
    }
}
