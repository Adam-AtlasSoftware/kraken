package kraken.ghidra;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockIterator;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.block.SimpleBlockModel;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlockType;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.ExternalLocation;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.model.symbol.SymbolType;
import ghidra.program.util.string.FoundString;
import ghidra.program.util.string.StringSearcher;
import ghidra.util.task.TaskMonitor;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TreeMap;
import java.util.function.Supplier;
import kraken.ghidra.Proto.Locator;
import kraken.ghidra.Proto.Page;
import kraken.ghidra.Proto.PageRequest;

/**
 * Read-only views of the open program for the data commands: memory map, bytes, disassembly,
 * cross-references, control-flow graphs, strings and symbols. Everything here reads the program
 * and may run concurrently with other reads.
 */
final class Inspect {
    static final int MAX_READ = 1 << 20;
    static final int MAX_STRING_CHARS = 4096;

    private final Supplier<Program> programs;

    Inspect(Supplier<Program> programs) {
        this.programs = programs;
    }

    /** The open program, for the assembler. */
    Program programForAssembly() {
        return program();
    }

    private Program program() {
        return programs.get();
    }

    private Address at(long offset) {
        AddressSpace sp = program().getAddressFactory().getDefaultAddressSpace();
        try {
            return sp.getAddress(offset);
        } catch (ghidra.program.model.address.AddressOutOfBoundsException e) {
            throw KrakenError.invalid("address out of range: " + J.hexJson(offset).getAsString());
        }
    }

    Address at(Locator l) {
        if (!(l instanceof Locator.Native n)) {
            throw KrakenError.unsupported("managed locators are not supported by Ghidra");
        }
        AddressSpace sp = program().getAddressFactory().getAddressSpace(n.space());
        if (sp == null) {
            throw KrakenError.invalid("unknown address space `" + n.space() + "`");
        }
        try {
            return sp.getAddress(n.offset());
        } catch (ghidra.program.model.address.AddressOutOfBoundsException e) {
            throw KrakenError.invalid("address out of range: " + J.hexJson(n.offset()).getAsString());
        }
    }

    private static Locator locator(Address a) {
        return new Locator.Native(a.getAddressSpace().getName(), a.getOffset());
    }

    private static String hex(Address a) {
        return J.hexJson(a.getOffset()).getAsString();
    }

    private static int cursorIndex(PageRequest req) {
        if (req.cursor() == null) {
            return 0;
        }
        try {
            int i = Integer.parseInt(req.cursor());
            if (i < 0) {
                throw new NumberFormatException();
            }
            return i;
        } catch (NumberFormatException e) {
            throw KrakenError.invalid("malformed cursor");
        }
    }

    /** One page of an in-memory list; the cursor is the decimal index of the next item. */
    private static <T> Page<T> slice(List<T> all, PageRequest req) {
        int from = Math.min(cursorIndex(req), all.size());
        int to = (int) Math.min((long) all.size(), (long) from + req.effectiveLimit());
        return new Page<>(
            new ArrayList<>(all.subList(from, to)),
            to < all.size() ? String.valueOf(to) : null,
            (long) all.size());
    }

    private Function functionContaining(Address a) {
        Function f = program().getFunctionManager().getFunctionContaining(a);
        if (f == null) {
            throw KrakenError.notFound("no function at " + a);
        }
        return f;
    }

    // ---- memory -------------------------------------------------------------------------

    List<Proto.MemoryBlock> memoryMap() {
        List<Proto.MemoryBlock> out = new ArrayList<>();
        for (ghidra.program.model.mem.MemoryBlock b : program().getMemory().getBlocks()) {
            String kind;
            if (b.isExternalBlock()) {
                kind = "external";
            } else if (b.isOverlay()) {
                kind = "overlay";
            } else if (b.getType() == MemoryBlockType.BYTE_MAPPED) {
                kind = "byte_mapped";
            } else if (b.getType() == MemoryBlockType.BIT_MAPPED) {
                kind = "bit_mapped";
            } else {
                kind = "default";
            }
            out.add(
                new Proto.MemoryBlock(
                    b.getName(),
                    b.getStart().getAddressSpace().getName(),
                    b.getStart().getOffset(),
                    b.getEnd().getOffset() + 1,
                    (b.isRead() ? "r" : "-") + (b.isWrite() ? "w" : "-") + (b.isExecute() ? "x" : "-"),
                    b.isInitialized(),
                    kind));
        }
        out.sort(
            Comparator.comparing(Proto.MemoryBlock::space)
                .thenComparing(Proto.MemoryBlock::start, Long::compareUnsigned));
        return out;
    }

    Proto.BytesRead readBytes(Locator l, long length) {
        if (length <= 0) {
            throw KrakenError.invalid("length must be positive");
        }
        if (length > MAX_READ) {
            throw KrakenError.invalid("length is above " + MAX_READ);
        }
        Memory mem = program().getMemory();
        Address start = at(l);
        ghidra.program.model.mem.MemoryBlock first = mem.getBlock(start);
        if (first == null) {
            throw KrakenError.notFound("no memory at " + start);
        }
        byte[] buf = new byte[(int) length];
        int done = 0;
        List<Proto.AddressRange> uninit = new ArrayList<>();
        Address cur = start;
        while (done < buf.length) {
            ghidra.program.model.mem.MemoryBlock b = mem.getBlock(cur);
            if (b == null) {
                break;
            }
            long left = b.getEnd().subtract(cur) + 1;
            int n = (int) Math.min(left, (long) (buf.length - done));
            boolean ok = false;
            if (b.isInitialized()) {
                try {
                    ok = mem.getBytes(cur, buf, done, n) == n;
                } catch (MemoryAccessException e) {
                    ok = false;
                }
            }
            if (!ok) {
                Arrays.fill(buf, done, done + n, (byte) 0);
                addRange(uninit, cur, n);
            }
            done += n;
            if (done < buf.length) {
                try {
                    cur = cur.addNoWrap(n);
                } catch (ghidra.program.model.address.AddressOverflowException e) {
                    break;
                }
            }
        }
        return new Proto.BytesRead(start.getOffset(), Arrays.copyOf(buf, done), uninit);
    }

    private static void addRange(List<Proto.AddressRange> ranges, Address from, int n) {
        String space = from.getAddressSpace().getName();
        long s = from.getOffset();
        if (!ranges.isEmpty()) {
            Proto.AddressRange last = ranges.get(ranges.size() - 1);
            if (last.space().equals(space) && last.end() == s) {
                ranges.set(ranges.size() - 1, new Proto.AddressRange(space, last.start(), s + n));
                return;
            }
        }
        ranges.add(new Proto.AddressRange(space, s, s + n));
    }

    // ---- disassembly --------------------------------------------------------------------

    Page<Proto.DisasmRow> disassemble(long start, String scope, PageRequest req) {
        Program p = program();
        Listing listing = p.getListing();
        int limit = req.effectiveLimit();
        Address from =
            req.cursor() == null
                ? at(start)
                : at(J.hex(new com.google.gson.JsonPrimitive(req.cursor()), "cursor"));
        InstructionIterator it;
        if (scope.equals("function")) {
            Function f = functionContaining(at(start));
            AddressSetView body = f.getBody();
            AddressSetView rest = body;
            if (req.cursor() != null) {
                rest =
                    from.compareTo(body.getMaxAddress()) > 0
                        ? new AddressSet()
                        : body.intersect(new AddressSet(from, body.getMaxAddress()));
            }
            it = listing.getInstructions(rest, true);
        } else if (scope.equals("linear")) {
            it = listing.getInstructions(from, true);
        } else {
            throw KrakenError.invalid("unknown scope `" + scope + "`");
        }
        List<Proto.DisasmRow> rows = new ArrayList<>();
        String next = null;
        while (it.hasNext()) {
            Instruction ins = it.next();
            if (rows.size() == limit) {
                next = hex(ins.getAddress());
                break;
            }
            rows.add(row(ins));
        }
        return new Page<>(rows, next, null);
    }

    private Proto.DisasmRow row(Instruction ins) {
        Program p = program();
        Listing listing = p.getListing();
        SymbolTable symtab = p.getSymbolTable();
        ReferenceManager refs = p.getReferenceManager();
        byte[] bytes;
        try {
            bytes = ins.getBytes();
        } catch (MemoryAccessException e) {
            bytes = new byte[0];
        }
        List<Proto.OperandToken> ops = new ArrayList<>();
        for (int i = 0; i < ins.getNumOperands(); i++) {
            if (i > 0) {
                String sep = ins.getSeparator(i - 1);
                ops.add(
                    new Proto.OperandToken(
                        sep == null || sep.isBlank() || sep.trim().equals(",") ? ", " : sep,
                        "other",
                        null));
            }
            Reference primary = refs.getPrimaryReferenceFrom(ins.getAddress(), i);
            for (Object o : ins.getDefaultOperandRepresentationList(i)) {
                if (o instanceof Register r) {
                    ops.add(new Proto.OperandToken(r.getName(), "register", null));
                } else if (o instanceof Scalar s) {
                    if (primary != null
                            && primary.isMemoryReference()
                            && (primary.getToAddress().getOffset() == s.getUnsignedValue()
                                || primary.getToAddress().getOffset() == s.getValue())) {
                        ops.add(addressToken(symtab, primary.getToAddress()));
                    } else {
                        long v = s.getValue();
                        String text =
                            s.isSigned() && v < 0
                                ? "-0x" + Long.toHexString(-v)
                                : "0x" + Long.toHexString(s.getUnsignedValue());
                        ops.add(new Proto.OperandToken(text, "immediate", null));
                    }
                } else if (o instanceof Address a) {
                    ops.add(addressToken(symtab, a));
                } else {
                    ops.add(new Proto.OperandToken(String.valueOf(o), "other", null));
                }
            }
        }
        String comment = null;
        for (CommentType t : new CommentType[] {CommentType.EOL, CommentType.PRE, CommentType.REPEATABLE}) {
            String c = listing.getComment(t, ins.getAddress());
            if (c != null && !c.isEmpty()) {
                comment = c;
                break;
            }
        }
        List<String> labels = new ArrayList<>();
        for (Symbol s : symtab.getSymbols(ins.getAddress())) {
            labels.add(s.getName());
        }
        labels.sort(Comparator.naturalOrder());
        return new Proto.DisasmRow(
            ins.getAddress().getOffset(),
            Proto.hexBytes(bytes),
            ins.getMnemonicString(),
            ops,
            comment,
            labels,
            flowKind(ins.getFlowType()));
    }

    private static Proto.OperandToken addressToken(SymbolTable symtab, Address a) {
        Symbol s = symtab.getPrimarySymbol(a);
        if (s != null) {
            return new Proto.OperandToken(s.getName(), "symbol", locator(a));
        }
        return new Proto.OperandToken("0x" + Long.toHexString(a.getOffset()), "address", locator(a));
    }

    static String flowKind(FlowType ft) {
        if (ft.isCall()) {
            return ft.isComputed() ? "indirect" : "call";
        }
        if (ft.isJump()) {
            if (ft.isComputed()) {
                return "indirect";
            }
            return ft.isConditional() ? "conditional_jump" : "jump";
        }
        if (ft.isTerminal()) {
            return "return";
        }
        if (ft == RefType.FALL_THROUGH) {
            return "fallthrough";
        }
        return "other";
    }

    // ---- cross-references ---------------------------------------------------------------

    private static final List<String> XREF_ORDER =
        List.of("call", "jump", "read", "write", "data", "fallthrough", "other");

    static String xrefKind(RefType t) {
        if (t.isCall()) {
            return "call";
        }
        if (t.isJump()) {
            return "jump";
        }
        if (t.isFallthrough()) {
            return "fallthrough";
        }
        if (t.isWrite()) {
            return "write";
        }
        if (t.isRead()) {
            return "read";
        }
        if (t.isData()) {
            return "data";
        }
        return "other";
    }

    Page<Proto.Xref> xrefs(
            long address, String direction, String kind, boolean whole, PageRequest req) {
        Program p = program();
        ReferenceManager rm = p.getReferenceManager();
        FunctionManager fm = p.getFunctionManager();
        Address a = at(address);
        if (kind != null && !XREF_ORDER.contains(kind)) {
            throw KrakenError.invalid("unknown xref kind `" + kind + "`");
        }
        Set<Proto.Xref> all = new LinkedHashSet<>();
        switch (direction) {
            case "to" -> {
                ReferenceIterator it = rm.getReferencesTo(a);
                while (it.hasNext()) {
                    addXref(all, fm, it.next(), kind);
                }
            }
            case "from" -> {
                if (whole) {
                    Function f = functionContaining(a);
                    AddressIterator src = rm.getReferenceSourceIterator(f.getBody(), true);
                    while (src.hasNext()) {
                        for (Reference r : rm.getReferencesFrom(src.next())) {
                            addXref(all, fm, r, kind);
                        }
                    }
                } else {
                    for (Reference r : rm.getReferencesFrom(a)) {
                        addXref(all, fm, r, kind);
                    }
                }
            }
            default -> throw KrakenError.invalid("unknown direction `" + direction + "`");
        }
        List<Proto.Xref> sorted = new ArrayList<>(all);
        sorted.sort(
            Comparator.comparingLong(Proto.Xref::from)
                .thenComparingLong(Proto.Xref::to)
                .thenComparingInt(x -> XREF_ORDER.indexOf(x.kind())));
        return slice(sorted, req);
    }

    private void addXref(Set<Proto.Xref> out, FunctionManager fm, Reference r, String kind) {
        if (!r.isMemoryReference()) {
            return;
        }
        String k = xrefKind(r.getReferenceType());
        if (kind != null && !kind.equals(k)) {
            return;
        }
        Function from = fm.getFunctionContaining(r.getFromAddress());
        Function to = fm.getFunctionAt(r.getToAddress());
        out.add(
            new Proto.Xref(
                r.getFromAddress().getOffset(),
                r.getToAddress().getOffset(),
                k,
                from == null ? null : new Proto.FunctionRef(from.getEntryPoint().getOffset(), from.getName()),
                to == null ? null : new Proto.FunctionRef(to.getEntryPoint().getOffset(), to.getName())));
    }

    // ---- control flow -------------------------------------------------------------------

    private static final List<String> EDGE_ORDER =
        List.of("fallthrough", "jump", "conditional_true", "conditional_false", "switch");

    Proto.Cfg cfg(Locator l) {
        Program p = program();
        Listing listing = p.getListing();
        Function f = functionContaining(at(l));
        TaskMonitor mon = TaskMonitor.DUMMY;
        try {
            SimpleBlockModel model = new SimpleBlockModel(p);
            TreeMap<Address, CodeBlock> blocks = new TreeMap<>();
            CodeBlockIterator bi = model.getCodeBlocksContaining(f.getBody(), mon);
            while (bi.hasNext()) {
                CodeBlock b = bi.next();
                blocks.put(b.getMinAddress(), b);
            }
            List<Proto.CfgBlock> outBlocks = new ArrayList<>();
            Set<Proto.CfgEdge> edges = new LinkedHashSet<>();
            for (CodeBlock b : blocks.values()) {
                int n = 0;
                for (InstructionIterator ii = listing.getInstructions(b, true); ii.hasNext(); ii.next()) {
                    n++;
                }
                outBlocks.add(
                    new Proto.CfgBlock(
                        b.getMinAddress().getOffset(), b.getMaxAddress().getOffset() + 1, n));
                Instruction last = listing.getInstructionContaining(b.getMaxAddress());
                FlowType lastFlow = last == null ? null : last.getFlowType();
                CodeBlockReferenceIterator di = model.getDestinations(b, mon);
                while (di.hasNext()) {
                    CodeBlockReference ref = di.next();
                    FlowType ft = ref.getFlowType();
                    Address dest = ref.getDestinationAddress();
                    CodeBlock target = blocks.get(dest);
                    if (target == null || ft.isCall()) {
                        continue;
                    }
                    String kind;
                    if (ft.isFallthrough()) {
                        kind =
                            lastFlow != null && lastFlow.isJump() && lastFlow.isConditional()
                                ? "conditional_false"
                                : "fallthrough";
                    } else if (ft.isJump()) {
                        if (ft.isComputed()) {
                            kind = "switch";
                        } else if (ft.isConditional()) {
                            kind = "conditional_true";
                        } else {
                            kind = "jump";
                        }
                    } else {
                        continue;
                    }
                    edges.add(
                        new Proto.CfgEdge(
                            b.getMinAddress().getOffset(), target.getMinAddress().getOffset(), kind));
                }
            }
            List<Proto.CfgEdge> outEdges = new ArrayList<>(edges);
            outEdges.sort(
                Comparator.comparingLong(Proto.CfgEdge::from)
                    .thenComparingLong(Proto.CfgEdge::to)
                    .thenComparingInt(e -> EDGE_ORDER.indexOf(e.kind())));
            return new Proto.Cfg(f.getEntryPoint().getOffset(), outBlocks, outEdges);
        } catch (ghidra.util.exception.CancelledException e) {
            throw KrakenError.internal("cancelled");
        }
    }

    // ---- strings ------------------------------------------------------------------------

    private static String encodingOf(String charset) {
        String c = charset == null ? "" : charset.toUpperCase(Locale.ROOT);
        if (c.equals("US-ASCII") || c.equals("ASCII")) {
            return "ascii";
        }
        if (c.equals("UTF-8")) {
            return "utf8";
        }
        if (c.startsWith("UTF-16")) {
            return "utf16";
        }
        if (c.startsWith("UTF-32")) {
            return "utf32";
        }
        return "other";
    }

    private static String cap(String s) {
        return s.length() <= MAX_STRING_CHARS ? s : s.substring(0, MAX_STRING_CHARS);
    }

    private record ScanKey(int min, long modification) {}

    private ScanKey scanKey;
    private List<Proto.StringEntry> scanResult = List.of();

    Page<Proto.StringEntry> strings(long minLen, String filter, PageRequest req) {
        int min = (int) Math.max(1, Math.min(minLen, 1 << 16));
        String needle = filter == null || filter.isEmpty() ? null : filter.toLowerCase(Locale.ROOT);
        List<Proto.StringEntry> all = new ArrayList<>();
        for (Proto.StringEntry e : scanStrings(min)) {
            if (needle == null || e.value().toLowerCase(Locale.ROOT).contains(needle)) {
                all.add(e);
            }
        }
        return slice(all, req);
    }

    /**
     * Every string of at least `min` characters, by address. Paging calls repeat the scan, which
     * is slow on large binaries, so the last result is kept until the program changes.
     */
    private synchronized List<Proto.StringEntry> scanStrings(int min) {
        Program p = program();
        ScanKey key = new ScanKey(min, p.getModificationNumber());
        if (key.equals(scanKey)) {
            return scanResult;
        }
        List<Proto.StringEntry> result = scan(p, min);
        scanKey = key;
        scanResult = result;
        return result;
    }

    private List<Proto.StringEntry> scan(Program p, int min) {
        Memory mem = p.getMemory();
        TreeMap<Address, Proto.StringEntry> found = new TreeMap<>();
        AddressSpace space = p.getAddressFactory().getDefaultAddressSpace();

        DataIterator di = p.getListing().getDefinedData(true);
        while (di.hasNext()) {
            Data d = di.next();
            if (!d.getAddress().getAddressSpace().equals(space) || !StringDataInstance.isString(d)) {
                continue;
            }
            StringDataInstance si = StringDataInstance.getStringDataInstance(d);
            String v = si.getStringValue();
            if (v == null) {
                continue;
            }
            found.put(
                d.getAddress(),
                new Proto.StringEntry(
                    d.getAddress().getOffset(), cap(v), encodingOf(si.getCharsetName()), d.getLength()));
        }

        // Strings nobody has defined yet, found in data blocks (code is mostly false positives).
        AddressSet area = new AddressSet(mem.getLoadedAndInitializedAddressSet());
        area.delete(mem.getExecuteSet());
        if (!area.isEmpty()) {
            StringSearcher searcher = new StringSearcher(p, Math.max(min, 3), 1, true, true);
            searcher.search(
                area,
                fs -> {
                    if (!fs.getAddress().getAddressSpace().equals(space)
                            || fs.isDefined()
                            || fs.conflicts()
                            || found.containsKey(fs.getAddress())) {
                        return;
                    }
                    String v = fs.getString(mem);
                    if (v == null) {
                        return;
                    }
                    found.put(
                        fs.getAddress(),
                        new Proto.StringEntry(
                            fs.getAddress().getOffset(),
                            cap(v),
                            encodingOfType(fs),
                            fs.getLength()));
                },
                true,
                TaskMonitor.DUMMY);
        }

        List<Proto.StringEntry> all = new ArrayList<>();
        for (Proto.StringEntry e : found.values()) {
            if (e.value().codePointCount(0, e.value().length()) >= min) {
                all.add(e);
            }
        }
        return List.copyOf(all);
    }

    private static String encodingOfType(FoundString fs) {
        String n = fs.getDataType() == null ? "" : fs.getDataType().getName().toLowerCase(Locale.ROOT);
        if (n.contains("utf8") || n.contains("utf-8")) {
            return "utf8";
        }
        if (n.equals("unicode32") || n.contains("32")) {
            return "utf32";
        }
        if (n.contains("unicode") || n.contains("utf16")) {
            return "utf16";
        }
        if (n.contains("string")) {
            return "ascii";
        }
        return "other";
    }

    // ---- symbols ------------------------------------------------------------------------

    Page<Proto.SymbolEntry> imports(PageRequest req) {
        Program p = program();
        SymbolTable symtab = p.getSymbolTable();
        List<Proto.SymbolEntry> all = new ArrayList<>();
        SymbolIterator it = symtab.getExternalSymbols();
        while (it.hasNext()) {
            Symbol s = it.next();
            SymbolType t = s.getSymbolType();
            if (t != SymbolType.FUNCTION && t != SymbolType.LABEL) {
                continue;
            }
            ExternalLocation loc = p.getExternalManager().getExternalLocation(s);
            Function ext = loc == null ? null : loc.getFunction();
            Long address = null;
            if (ext != null) {
                Address[] thunks = ext.getFunctionThunkAddresses(true);
                if (thunks != null && thunks.length > 0) {
                    long best = thunks[0].getOffset();
                    for (Address a : thunks) {
                        if (Long.compareUnsigned(a.getOffset(), best) < 0) {
                            best = a.getOffset();
                        }
                    }
                    address = best;
                }
            }
            if (address == null && loc != null && loc.getAddress() != null
                    && !loc.getAddress().isExternalAddress()) {
                address = loc.getAddress().getOffset();
            }
            String lib = loc == null ? null : loc.getLibraryName();
            if (lib != null && (lib.isEmpty() || lib.equals(UNKNOWN_LIBRARY))) {
                lib = null;
            }
            all.add(
                new Proto.SymbolEntry(
                    s.getName(),
                    address,
                    lib,
                    t == SymbolType.FUNCTION || (loc != null && loc.isFunction()) ? "function" : "data"));
        }
        all.sort(
            Comparator.comparing(
                    Proto.SymbolEntry::address, Comparator.<Long>nullsLast(Long::compareUnsigned))
                .thenComparing(Proto.SymbolEntry::name)
                .thenComparing(
                    Proto.SymbolEntry::library, Comparator.nullsFirst(Comparator.naturalOrder())));
        return slice(all, req);
    }

    private static final String UNKNOWN_LIBRARY = "<EXTERNAL>";

    Page<Proto.SymbolEntry> exports(PageRequest req) {
        Program p = program();
        SymbolTable symtab = p.getSymbolTable();
        FunctionManager fm = p.getFunctionManager();
        List<Proto.SymbolEntry> all = new ArrayList<>();
        AddressIterator it = symtab.getExternalEntryPointIterator();
        while (it.hasNext()) {
            Address a = it.next();
            Symbol s = symtab.getPrimarySymbol(a);
            String name = s == null ? "entry_" + Long.toHexString(a.getOffset()) : s.getName();
            String kind;
            if (fm.getFunctionAt(a) != null) {
                kind = "function";
            } else if (p.getListing().getDataAt(a) != null
                    && p.getListing().getDataAt(a).isDefined()) {
                kind = "data";
            } else {
                kind = "other";
            }
            all.add(new Proto.SymbolEntry(name, a.getOffset(), null, kind));
        }
        all.sort(
            Comparator.comparing(Proto.SymbolEntry::address, Comparator.<Long>nullsLast(Long::compareUnsigned))
                .thenComparing(Proto.SymbolEntry::name));
        return slice(all, req);
    }
}
