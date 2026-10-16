package kraken.ghidra;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.app.util.opinion.LoadResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;

/**
 * Headless KRAKEN sidecar. Frames are a 4-byte big-endian length followed by a UTF-8 JSON-RPC 2.0
 * message. Only protocol frames are written to the real stdout; everything else goes to stderr.
 */
public final class KrakenSidecar {
    private static final int MAX_FRAME = 64 * 1024 * 1024;
    private static final Gson GSON = new Gson();

    private static GhidraProject project;

    private KrakenSidecar() {}

    public static void main(String[] args) throws Exception {
        // Capture the real stdout for protocol frames, then point System.out at stderr before
        // Ghidra (and log4j's console appender) initialises, so nothing else can corrupt framing.
        DataOutputStream out =
            new DataOutputStream(new BufferedOutputStream(new FileOutputStream(FileDescriptor.out)));
        System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.err), true));
        DataInputStream in =
            new DataInputStream(new BufferedInputStream(new FileInputStream(FileDescriptor.in)));

        String projectDir = args.length > 0 ? args[0] : System.getProperty("java.io.tmpdir");

        long t0 = System.nanoTime();
        Application.initializeApplication(
            new GhidraApplicationLayout(), new HeadlessGhidraApplicationConfiguration());
        project = GhidraProject.createProject(projectDir, "kraken", true);
        long initMs = (System.nanoTime() - t0) / 1_000_000;
        System.err.printf("kraken-ghidra: initialised in %d ms%n", initMs);

        // Readiness notification (JSON-RPC notification, no id).
        JsonObject ready = new JsonObject();
        ready.addProperty("jsonrpc", "2.0");
        ready.addProperty("method", "ready");
        JsonObject rp = new JsonObject();
        rp.addProperty("ghidra_version", Application.getApplicationVersion());
        rp.addProperty("init_ms", initMs);
        ready.add("params", rp);
        writeFrame(out, GSON.toJson(ready));

        while (true) {
            String frame;
            try {
                frame = readFrame(in);
            } catch (EOFException e) {
                break;
            }
            writeFrame(out, GSON.toJson(handle(frame)));
        }
        project.close();
        System.exit(0);
    }

    private static JsonObject handle(String frame) {
        JsonObject resp = new JsonObject();
        resp.addProperty("jsonrpc", "2.0");
        JsonElement id = null;
        try {
            JsonObject req = JsonParser.parseString(frame).getAsJsonObject();
            id = req.get("id");
            String method = req.get("method").getAsString();
            JsonObject params =
                req.has("params") ? req.getAsJsonObject("params") : new JsonObject();
            JsonElement result;
            switch (method) {
                case "ping" -> {
                    JsonObject o = new JsonObject();
                    o.addProperty("pong", true);
                    result = o;
                }
                case "open_binary" -> result = openBinary(params.get("path").getAsString());
                default -> throw new RpcError(-32601, "method not found: " + method);
            }
            resp.add("result", result);
        } catch (RpcError e) {
            resp.add("error", error(e.code, e.getMessage()));
        } catch (Throwable t) {
            t.printStackTrace();
            resp.add("error", error(-32603, String.valueOf(t)));
        }
        resp.add("id", id == null ? JsonNull.INSTANCE : id);
        return resp;
    }

    private static JsonObject error(int code, String message) {
        JsonObject e = new JsonObject();
        e.addProperty("code", code);
        e.addProperty("message", message);
        return e;
    }

    private static JsonObject openBinary(String path) throws Exception {
        long t0 = System.nanoTime();
        try (LoadResults<Program> results = ProgramLoader.builder()
                .source(new File(path))
                .project(project.getProject())
                .monitor(TaskMonitor.DUMMY)
                .load()) {
            Program program = results.getPrimaryDomainObject(project);
            long loadMs = (System.nanoTime() - t0) / 1_000_000;
            long a0 = System.nanoTime();
            int tx = program.startTransaction("kraken analysis");
            try {
                AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);
                mgr.initializeOptions();
                mgr.reAnalyzeAll(null);
                mgr.startAnalysis(TaskMonitor.DUMMY);
            } finally {
                program.endTransaction(tx, true);
            }
            long analyzeMs = (System.nanoTime() - a0) / 1_000_000;
            int count = program.getFunctionManager().getFunctionCount();
            String lang = program.getLanguageID().getIdAsString();
            program.release(project);
            JsonObject o = new JsonObject();
            o.addProperty("function_count", count);
            o.addProperty("language", lang);
            o.addProperty("load_ms", loadMs);
            o.addProperty("analyze_ms", analyzeMs);
            return o;
        }
    }

    private static String readFrame(DataInputStream in) throws IOException {
        int len = in.readInt();
        if (len < 0 || len > MAX_FRAME) {
            throw new IOException("bad frame length " + len);
        }
        byte[] buf = new byte[len];
        in.readFully(buf);
        return new String(buf, StandardCharsets.UTF_8);
    }

    private static void writeFrame(DataOutputStream out, String json) throws IOException {
        byte[] b = json.getBytes(StandardCharsets.UTF_8);
        out.writeInt(b.length);
        out.write(b);
        out.flush();
    }

    private static final class RpcError extends RuntimeException {
        final int code;

        RpcError(int code, String message) {
            super(message);
            this.code = code;
        }
    }
}
