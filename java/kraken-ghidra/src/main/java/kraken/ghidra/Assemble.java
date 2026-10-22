package kraken.ghidra;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.plugin.assembler.AssemblySelector;
import ghidra.app.plugin.assembler.AssemblySemanticException;
import ghidra.app.plugin.assembler.AssemblySyntaxException;
import ghidra.app.plugin.assembler.Assemblers;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyPatternBlock;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolutionResults;
import ghidra.app.plugin.assembler.sleigh.sem.AssemblyResolvedPatterns;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;

/** One line of assembly to machine code with Ghidra's SLEIGH assembler. The program is not changed. */
final class Assemble {
    /** Most encodings returned for one line. */
    private static final int MAX_CANDIDATES = 8;

    private Assemble() {}

    /** Keeps every encoding the resolver found, shortest first, besides selecting the first. */
    private static final class Collecting extends AssemblySelector {
        final List<byte[]> all = new ArrayList<>();

        @Override
        public Selection select(AssemblyResolutionResults rr, AssemblyPatternBlock ctx)
                throws AssemblySemanticException {
            List<AssemblyResolvedPatterns> sorted = filterCompatibleAndSort(rr, ctx);
            for (AssemblyResolvedPatterns p : sorted) {
                byte[] b = p.getInstruction().fillMask().getVals();
                if (all.stream().noneMatch(x -> Arrays.equals(x, b)) && all.size() < MAX_CANDIDATES) {
                    all.add(b);
                }
            }
            AssemblyResolvedPatterns first = sorted.get(0);
            return new Selection(first.getInstruction().fillMask(), first.getContext());
        }
    }

    static JsonObject line(Program program, Address at, String text) {
        String line = text == null ? "" : text.strip();
        if (line.isEmpty()) {
            throw KrakenError.invalid("type an instruction, for example `mov eax, 0x7`");
        }
        if (line.contains("\n")) {
            throw KrakenError.invalid("one instruction at a time");
        }
        // The processor's syntax is case-sensitive (x86 is upper case, ARM lower case); people
        // type either, so the line is tried as typed, then in upper and in lower case.
        Collecting sel = null;
        byte[] chosen = null;
        RuntimeException first = null;
        for (String attempt : variants(line)) {
            Collecting s = new Collecting();
            try {
                chosen = Assemblers.getAssembler(program, s).assembleLine(at, attempt);
                sel = s;
                break;
            } catch (AssemblySyntaxException e) {
                if (first == null) {
                    first = KrakenError.invalid(
                        "`" + line + "` is not an instruction this processor knows: " + firstLine(e));
                }
            } catch (AssemblySemanticException e) {
                if (first == null || first.getMessage().contains("not an instruction")) {
                    first = KrakenError.invalid("`" + line + "` cannot be encoded here: " + firstLine(e));
                }
            }
        }
        if (sel == null) {
            throw first;
        }
        if (sel.all.isEmpty()) {
            sel.all.add(chosen);
        }
        HexFormat hex = HexFormat.of();
        JsonArray out = new JsonArray();
        for (byte[] b : sel.all) {
            out.add(hex.formatHex(b));
        }
        JsonObject o = new JsonObject();
        o.add("encodings", out);
        return o;
    }

    private static List<String> variants(String line) {
        List<String> out = new ArrayList<>();
        out.add(line);
        // Upper case keeps hex prefixes readable to the parser (`0x`, not `0X`).
        String upper = line.toUpperCase(java.util.Locale.ROOT).replace("0X", "0x");
        String lower = line.toLowerCase(java.util.Locale.ROOT);
        for (String v : List.of(upper, lower)) {
            if (!out.contains(v)) {
                out.add(v);
            }
        }
        return out;
    }

    private static String firstLine(Exception e) {
        String m = e.getMessage() == null ? e.getClass().getSimpleName() : e.getMessage();
        int nl = m.indexOf('\n');
        String first = nl < 0 ? m : m.substring(0, nl);
        return first.length() > 300 ? first.substring(0, 300) : first;
    }
}
