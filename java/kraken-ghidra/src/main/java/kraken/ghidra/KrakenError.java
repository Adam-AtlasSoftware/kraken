package kraken.ghidra;

import com.google.gson.JsonElement;

/** A failure reported to the client as a JSON-RPC error carrying a kraken-proto ErrorCode string. */
public final class KrakenError extends RuntimeException {
    public final String code;
    public final JsonElement details;

    public KrakenError(String code, String message) {
        this(code, message, null);
    }

    public KrakenError(String code, String message, JsonElement details) {
        super(message);
        this.code = code;
        this.details = details;
    }

    public static KrakenError invalid(String message) {
        return new KrakenError("invalid_argument", message);
    }

    public static KrakenError notFound(String message) {
        return new KrakenError("not_found", message);
    }

    public static KrakenError rejected(String message) {
        return new KrakenError("engine_rejected", message);
    }

    public static KrakenError unsupported(String message) {
        return new KrakenError("unsupported", message);
    }

    public static KrakenError internal(String message) {
        return new KrakenError("internal", message);
    }

    /** JSON-RPC numeric code for the wire; the kraken code is in error.data.code. */
    public int rpcCode() {
        return switch (code) {
            case "invalid_argument" -> -32602;
            case "unsupported" -> -32601;
            case "internal" -> -32603;
            default -> -32000;
        };
    }
}
