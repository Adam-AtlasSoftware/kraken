package kraken.ghidra;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import java.io.BufferedInputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

/** Length-prefixed framing: 4-byte big-endian length, then a UTF-8 JSON-RPC 2.0 message. */
final class Wire {
    static final int MAX_FRAME = 64 * 1024 * 1024;
    private static final Gson GSON = new com.google.gson.GsonBuilder().disableHtmlEscaping().create();

    private final DataInputStream in;
    private final OutputStream out;
    private final Object writeLock = new Object();

    Wire(InputStream in, OutputStream out) {
        this.in = new DataInputStream(new BufferedInputStream(in, 1 << 16));
        this.out = out;
    }

    /** Next frame, or null on a clean EOF at a frame boundary. */
    String read() throws IOException {
        int len;
        try {
            len = in.readInt();
        } catch (EOFException e) {
            return null;
        }
        if (len < 0 || len > MAX_FRAME) {
            throw new IOException("bad frame length " + len);
        }
        byte[] buf = new byte[len];
        in.readFully(buf);
        return new String(buf, StandardCharsets.UTF_8);
    }

    void write(JsonElement message) throws IOException {
        byte[] b = GSON.toJson(message).getBytes(StandardCharsets.UTF_8);
        byte[] frame = new byte[4 + b.length];
        frame[0] = (byte) (b.length >>> 24);
        frame[1] = (byte) (b.length >>> 16);
        frame[2] = (byte) (b.length >>> 8);
        frame[3] = (byte) b.length;
        System.arraycopy(b, 0, frame, 4, b.length);
        synchronized (writeLock) {
            out.write(frame);
            out.flush();
        }
    }
}
