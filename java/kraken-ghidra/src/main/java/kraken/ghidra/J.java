package kraken.ghidra;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonPrimitive;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

/** Strict JSON accessors that turn shape errors into invalid_argument. */
final class J {
    private J() {}

    static JsonObject obj(JsonElement e, String what) {
        if (e == null || !e.isJsonObject()) {
            throw KrakenError.invalid(what + " must be an object");
        }
        return e.getAsJsonObject();
    }

    static JsonElement req(JsonObject o, String k) {
        JsonElement e = o.get(k);
        if (e == null || e.isJsonNull()) {
            throw KrakenError.invalid("missing field `" + k + "`");
        }
        return e;
    }

    static JsonElement opt(JsonObject o, String k) {
        JsonElement e = o.get(k);
        return e == null || e.isJsonNull() ? null : e;
    }

    static String str(JsonElement e, String what) {
        if (e == null || !e.isJsonPrimitive() || !e.getAsJsonPrimitive().isString()) {
            throw KrakenError.invalid(what + " must be a string");
        }
        return e.getAsString();
    }

    static String str(JsonObject o, String k) {
        return str(req(o, k), k);
    }

    static String optStr(JsonObject o, String k) {
        JsonElement e = opt(o, k);
        return e == null ? null : str(e, k);
    }

    static long num(JsonElement e, String what) {
        if (e == null || !e.isJsonPrimitive() || !e.getAsJsonPrimitive().isNumber()) {
            throw KrakenError.invalid(what + " must be a number");
        }
        try {
            return new java.math.BigDecimal(e.getAsString()).longValueExact();
        } catch (ArithmeticException | NumberFormatException ex) {
            throw KrakenError.invalid(what + " must be an integer");
        }
    }

    static long num(JsonObject o, String k) {
        return num(req(o, k), k);
    }

    static Long optNum(JsonObject o, String k) {
        JsonElement e = opt(o, k);
        return e == null ? null : num(e, k);
    }

    static boolean bool(JsonObject o, String k) {
        JsonElement e = req(o, k);
        if (!e.isJsonPrimitive() || !e.getAsJsonPrimitive().isBoolean()) {
            throw KrakenError.invalid(k + " must be a boolean");
        }
        return e.getAsBoolean();
    }

    /** Hex64: a "0x"-prefixed lowercase string; JSON numbers are rejected. */
    static long hex(JsonElement e, String what) {
        String s = str(e, what);
        if (!s.startsWith("0x") || s.length() < 3 || s.length() > 18) {
            throw KrakenError.invalid(what + " must be a 0x-prefixed hex string");
        }
        try {
            return Long.parseUnsignedLong(s.substring(2), 16);
        } catch (NumberFormatException ex) {
            throw KrakenError.invalid(what + " is not valid hex");
        }
    }

    static long hex(JsonObject o, String k) {
        return hex(req(o, k), k);
    }

    static Long optHex(JsonObject o, String k) {
        JsonElement e = opt(o, k);
        return e == null ? null : hex(e, k);
    }

    static JsonPrimitive hexJson(long v) {
        return new JsonPrimitive("0x" + Long.toHexString(v));
    }

    static <T> List<T> list(JsonObject o, String k, Function<JsonElement, T> f) {
        JsonElement e = req(o, k);
        if (!e.isJsonArray()) {
            throw KrakenError.invalid(k + " must be an array");
        }
        List<T> out = new ArrayList<>();
        for (JsonElement x : e.getAsJsonArray()) {
            out.add(f.apply(x));
        }
        return out;
    }

    static <T> JsonArray array(List<T> items, Function<T, JsonElement> f) {
        JsonArray a = new JsonArray();
        for (T t : items) {
            a.add(f.apply(t));
        }
        return a;
    }

    static void put(JsonObject o, String k, String v) {
        if (v != null) {
            o.addProperty(k, v);
        }
    }

    static void put(JsonObject o, String k, Number v) {
        if (v != null) {
            o.addProperty(k, v);
        }
    }

    static void put(JsonObject o, String k, JsonElement v) {
        if (v != null) {
            o.add(k, v);
        }
    }

    /** The tag of an internally tagged enum; the tag is consumed by the caller's switch. */
    static String tag(JsonObject o, String key) {
        return str(o, key);
    }
}
