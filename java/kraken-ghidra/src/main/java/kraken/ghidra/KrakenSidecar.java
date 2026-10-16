package kraken.ghidra;

import com.google.gson.JsonElement;
import com.google.gson.JsonNull;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;

/**
 * Headless KRAKEN sidecar. Frames are a 4-byte big-endian length plus a UTF-8 JSON-RPC 2.0
 * message. By default frames travel over the process's stdin file descriptor in both directions
 * (the parent passes one end of a socketpair as fd 0, decision 87); with --stdio they are written
 * to the real stdout instead, for manual testing. System.out is redirected to stderr before
 * Ghidra initialises so nothing else can corrupt framing.
 *
 * <pre>
 * KrakenSidecar [--stdio]
 * KrakenSidecar --self-test &lt;binary&gt; &lt;project_dir&gt; [samples_dir]
 * </pre>
 */
public final class KrakenSidecar {
    private KrakenSidecar() {}

    public static void main(String[] args) throws Exception {
        boolean stdio = false;
        boolean selfTest = false;
        java.util.List<String> rest = new java.util.ArrayList<>();
        for (String a : args) {
            switch (a) {
                case "--stdio" -> stdio = true;
                case "--self-test" -> selfTest = true;
                default -> rest.add(a);
            }
        }

        // Taken before anything can touch stdout; fd 0 is both input and (by default) output.
        OutputStream frameOut =
            new java.io.BufferedOutputStream(
                new FileOutputStream(stdio ? FileDescriptor.out : FileDescriptor.in));
        InputStream frameIn = new FileInputStream(FileDescriptor.in);
        System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.err), true));

        long t0 = System.nanoTime();
        Application.initializeApplication(
            new GhidraApplicationLayout(), new HeadlessGhidraApplicationConfiguration());
        long initMs = (System.nanoTime() - t0) / 1_000_000;
        System.err.printf("kraken-ghidra: initialised in %d ms%n", initMs);

        if (selfTest) {
            if (rest.size() < 2) {
                System.err.println("usage: --self-test <binary> <project_dir> [samples_dir]");
                System.exit(2);
            }
            int code = SelfTest.run(rest.get(0), rest.get(1), rest.size() > 2 ? rest.get(2) : "schema/samples");
            System.exit(code);
        }
        serve(new Wire(frameIn, frameOut), initMs);
    }

    private static void serve(Wire wire, long initMs) throws IOException {
        Dispatcher dispatcher =
            new Dispatcher(
                n -> {
                    try {
                        wire.write(n);
                    } catch (IOException e) {
                        System.err.println("kraken-ghidra: cannot write notification: " + e);
                    }
                });

        JsonObject ready = new JsonObject();
        ready.addProperty("jsonrpc", "2.0");
        ready.addProperty("method", "ready");
        JsonObject rp = new JsonObject();
        rp.addProperty("ghidra_version", dispatcher.ghidraVersion());
        rp.addProperty("init_ms", initMs);
        ready.add("params", rp);
        wire.write(ready);

        while (true) {
            String frame = wire.read();
            if (frame == null) {
                break;
            }
            JsonElement id = null;
            String method;
            JsonObject params;
            try {
                JsonObject req = JsonParser.parseString(frame).getAsJsonObject();
                id = req.get("id");
                method = J.str(req, "method");
                params = req.has("params") && !req.get("params").isJsonNull()
                    ? J.obj(req.get("params"), "params")
                    : new JsonObject();
            } catch (Exception e) {
                send(wire, id, null, new KrakenError("invalid_argument", "bad request: " + e.getMessage()));
                continue;
            }
            final JsonElement reqId = id;
            final boolean isShutdown = method.equals("shutdown");
            String idText = id == null ? "notify" : id.getAsString();
            dispatcher
                .submit(method, params, idText)
                .whenComplete(
                    (result, err) -> {
                        if (reqId != null) {
                            send(wire, reqId, result, err == null ? null : Dispatcher.asKrakenError(err));
                        }
                        if (isShutdown) {
                            System.exit(0);
                        }
                    });
        }
        dispatcher.shutdownNow();
        System.exit(0);
    }

    private static void send(Wire wire, JsonElement id, JsonElement result, KrakenError err) {
        JsonObject resp = new JsonObject();
        resp.addProperty("jsonrpc", "2.0");
        if (err != null) {
            JsonObject e = new JsonObject();
            e.addProperty("code", err.rpcCode());
            e.addProperty("message", String.valueOf(err.getMessage()));
            JsonObject data = new JsonObject();
            data.addProperty("code", err.code);
            if (err.details != null) {
                data.add("details", err.details);
            }
            e.add("data", data);
            resp.add("error", e);
        } else {
            resp.add("result", result == null ? JsonNull.INSTANCE : result);
        }
        resp.add("id", id == null ? JsonNull.INSTANCE : id);
        try {
            wire.write(resp);
        } catch (IOException e) {
            System.err.println("kraken-ghidra: cannot write response: " + e);
        }
    }
}
