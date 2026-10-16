package kraken.ghidra;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.ClangBreak;
import ghidra.app.decompiler.ClangCommentToken;
import ghidra.app.decompiler.ClangFieldToken;
import ghidra.app.decompiler.ClangFuncNameToken;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.ClangOpToken;
import ghidra.app.decompiler.ClangToken;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangTypeToken;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.opinion.LoadResults;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.model.DomainFile;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.FunctionDefinitionDataType;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import kraken.ghidra.Proto.Anchor;
import kraken.ghidra.Proto.CodeData;
import kraken.ghidra.Proto.DecompileResult;
import kraken.ghidra.Proto.FunctionSummary;
import kraken.ghidra.Proto.Kinded;
import kraken.ghidra.Proto.Locator;
import kraken.ghidra.Proto.LogOp;
import kraken.ghidra.Proto.Page;
import kraken.ghidra.Proto.PageRequest;
import kraken.ghidra.Proto.Token;
import kraken.ghidra.Proto.TypeDef;
import kraken.ghidra.Proto.TypeRef;
import kraken.ghidra.Proto.VersionedLogOp;

/**
 * Ghidra operations behind the RPC methods. Methods that change the project or program must be
 * called from the single mutator thread; read methods may run concurrently with them.
 */
final class Engine {
    static final List<String> STAGES = List.of("core", "expensive");
    /** Analyzers moved to the second stage (decision 90). */
    static final List<String> EXPENSIVE =
        List.of("Decompiler Switch Analysis", "Decompiler Parameter ID");

    private static final String STATE_OPTIONS = "KRAKEN";
    private static final String STAGES_DONE = "stages_done";

    interface Progress {
        void emit(String jobId, String stage, long done, long total, String message);
    }

    private volatile GhidraProject project;
    private volatile Program program;
    private volatile String programName;
    private volatile String sourcePath;
    private volatile TypeConv types;

    private final Object decompLock = new Object();
    private DecompInterface decomp;
    private boolean decompNeedsReset;
    private boolean decompNeedsFlush;

    private final Map<String, JobMonitor> jobs = new ConcurrentHashMap<>();
    private long saveCounter;

    // ---- open ---------------------------------------------------------------------------

    JsonObject openBinary(String path, String projectDir, String loaderSpec) throws Exception {
        File binary = new File(path);
        if (!binary.isFile()) {
            throw KrakenError.notFound("no such file: " + path);
        }
        closeProgram();
        Files.createDirectories(new File(projectDir).toPath());
        boolean exists = new File(projectDir, "kraken.gpr").exists();
        GhidraProject gp =
            exists
                ? GhidraProject.openProject(projectDir, "kraken", true)
                : GhidraProject.createProject(projectDir, "kraken", false);
        project = gp;

        String name = binary.getName();
        DomainFile existing = gp.getRootFolder().getFile(name);
        if (existing == null) {
            ProgramLoader.Builder b =
                ProgramLoader.builder()
                    .source(binary)
                    .project(gp.getProject())
                    .projectFolderPath("/")
                    .name(name)
                    .monitor(TaskMonitor.DUMMY);
            if (loaderSpec != null && !loaderSpec.isEmpty()) {
                String[] parts = loaderSpec.split(";");
                if (!parts[0].isEmpty()) {
                    b.loaders(parts[0]);
                }
                if (parts.length > 1 && !parts[1].isEmpty()) {
                    b.language(parts[1]);
                }
                if (parts.length > 2 && !parts[2].isEmpty()) {
                    b.compiler(parts[2]);
                }
            }
            try (LoadResults<Program> results = b.load()) {
                name = results.getPrimary().getName();
                results.save(TaskMonitor.DUMMY);
            }
        }
        // Not GhidraProject.openProgram: it keeps one transaction open for the program's life, and
        // a rolled-back (rejected) edit would then abort every change made since the last save.
        DomainFile file = gp.getRootFolder().getFile(name);
        if (file == null) {
            throw KrakenError.internal("imported program is missing from the project: " + name);
        }
        Program p = (Program) file.getDomainObject(this, true, false, TaskMonitor.DUMMY);
        program = p;
        programName = name;
        sourcePath = path;
        types = new TypeConv(p.getDataTypeManager());
        return programInfo();
    }

    private Program requireProgram() {
        Program p = program;
        if (p == null) {
            throw KrakenError.invalid("no binary is open: call open_binary first");
        }
        return p;
    }

    JsonObject programInfo() {
        Program p = requireProgram();
        JsonObject o = new JsonObject();
        o.addProperty("name", programName);
        o.addProperty("path", sourcePath);
        o.addProperty("language", p.getLanguageID().getIdAsString());
        o.addProperty("compiler", p.getCompilerSpec().getCompilerSpecID().getIdAsString());
        o.addProperty("format", p.getExecutableFormat());
        o.add("image_base", J.hexJson(p.getImageBase().getOffset()));
        o.addProperty("pointer_size", p.getDefaultPointerSize());
        o.addProperty("function_count", internalFunctionCount());
        List<String> done = stagesDone();
        o.addProperty("analyzed", done.containsAll(STAGES));
        JsonArray sd = new JsonArray();
        done.forEach(sd::add);
        o.add("stages_done", sd);
        o.addProperty("sha256", p.getExecutableSHA256());
        return o;
    }

    private List<String> stagesDone() {
        String s = requireProgram().getOptions(STATE_OPTIONS).getString(STAGES_DONE, "");
        List<String> out = new ArrayList<>();
        for (String x : s.split(",")) {
            if (!x.isEmpty()) {
                out.add(x);
            }
        }
        return out;
    }

    // ---- analysis -----------------------------------------------------------------------

    /** Cancel-aware monitor that forwards message changes as progress notifications. */
    private static final class JobMonitor extends TaskMonitorAdapter {
        private final Runnable onChange;
        private volatile long lastEmit;

        JobMonitor(Runnable onChange) {
            super(true);
            this.onChange = onChange;
        }

        @Override
        public void setMessage(String message) {
            super.setMessage(message);
            long now = System.nanoTime();
            if (now - lastEmit > 200_000_000L) {
                lastEmit = now;
                onChange.run();
            }
        }
    }

    JsonObject analyze(String jobId, List<String> stages, boolean force, Progress progress)
            throws Exception {
        Program p = requireProgram();
        List<String> wanted = stages == null ? STAGES : stages;
        for (String s : wanted) {
            if (!STAGES.contains(s)) {
                throw KrakenError.invalid("unknown stage `" + s + "` (known: " + STAGES + ")");
            }
        }
        if (jobs.containsKey(jobId)) {
            throw KrakenError.invalid("job id already in use: " + jobId);
        }
        List<String> alreadyDone = stagesDone();
        List<String> todo = new ArrayList<>();
        for (String s : STAGES) {
            if (wanted.contains(s) && (force || !alreadyDone.contains(s))) {
                todo.add(s);
            }
        }

        String[] current = {"-"};
        int[] index = {0};
        JobMonitor monitor =
            new JobMonitor(
                () -> progress.emit(jobId, current[0], index[0], todo.size(), messageOf(jobs.get(jobId))));
        jobs.put(jobId, monitor);
        List<String> completed = new ArrayList<>();
        try {
            for (String stage : todo) {
                current[0] = stage;
                progress.emit(jobId, stage, index[0], todo.size(), "starting stage " + stage);
                long t0 = System.nanoTime();
                runStage(p, stage, monitor);
                boolean cancelled = monitor.isCancelled();
                if (!cancelled) {
                    markStageDone(p, stage);
                    completed.add(stage);
                }
                p.getDomainFile().save(TaskMonitor.DUMMY);
                System.err.printf(
                    "kraken-ghidra: stage %s took %d ms%s%n",
                    stage, (System.nanoTime() - t0) / 1_000_000, cancelled ? " (cancelled)" : "");
                if (cancelled) {
                    JsonObject d = new JsonObject();
                    d.addProperty("job_id", jobId);
                    d.add("stages_completed", stringArray(completed));
                    throw new KrakenError("cancelled", "analysis cancelled during stage " + stage, d);
                }
                index[0]++;
                progress.emit(jobId, stage, index[0], todo.size(), "finished stage " + stage);
            }
        } finally {
            jobs.remove(jobId);
            invalidateDecompiler(true);
        }
        JsonObject out = new JsonObject();
        out.addProperty("job_id", jobId);
        out.add("stages_completed", stringArray(completed));
        out.addProperty("function_count", internalFunctionCount());
        return out;
    }

    private static String messageOf(JobMonitor m) {
        return m == null ? "" : String.valueOf(m.getMessage());
    }

    private static JsonArray stringArray(List<String> l) {
        JsonArray a = new JsonArray();
        l.forEach(a::add);
        return a;
    }

    private void runStage(Program p, String stage, JobMonitor monitor) {
        AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(p);
        int tx = p.startTransaction("kraken analysis: " + stage);
        Options opts = p.getOptions(Program.ANALYSIS_PROPERTIES);
        Map<String, Boolean> original = new HashMap<>();
        try {
            mgr.initializeOptions();
            for (String name : opts.getOptionNames()) {
                if (opts.getType(name) == OptionType.BOOLEAN_TYPE && mgr.getAnalyzer(name) != null) {
                    original.put(name, opts.getBoolean(name, false));
                }
            }
            for (Map.Entry<String, Boolean> e : original.entrySet()) {
                boolean expensive = EXPENSIVE.contains(e.getKey());
                opts.setBoolean(e.getKey(), stage.equals("core") ? e.getValue() && !expensive : expensive);
            }
            mgr.initializeOptions();
            mgr.reAnalyzeAll(null);
            mgr.startAnalysis(monitor);
            System.err.println("kraken-ghidra: analysis task times:\n" + mgr.getTaskTimesString());
        } finally {
            for (Map.Entry<String, Boolean> e : original.entrySet()) {
                opts.setBoolean(e.getKey(), e.getValue());
            }
            mgr.initializeOptions();
            p.endTransaction(tx, true);
        }
    }

    private void markStageDone(Program p, String stage) {
        List<String> done = stagesDone();
        if (!done.contains(stage)) {
            done.add(stage);
        }
        int tx = p.startTransaction("kraken stage state");
        try {
            p.getOptions(STATE_OPTIONS).setString(STAGES_DONE, String.join(",", done));
        } finally {
            p.endTransaction(tx, true);
        }
    }

    boolean cancelJob(String jobId) {
        JobMonitor m = jobs.get(jobId);
        if (m == null) {
            return false;
        }
        m.cancel();
        return true;
    }

    // ---- addresses ----------------------------------------------------------------------

    private Address address(String space, long offset) {
        Program p = requireProgram();
        AddressSpace sp = p.getAddressFactory().getAddressSpace(space);
        if (sp == null) {
            throw KrakenError.invalid("unknown address space `" + space + "`");
        }
        try {
            return sp.getAddress(offset);
        } catch (ghidra.program.model.address.AddressOutOfBoundsException e) {
            throw KrakenError.invalid("address out of range: " + J.hexJson(offset).getAsString());
        }
    }

    private Address address(Locator l) {
        return switch (l) {
            case Locator.Native n -> address(n.space(), n.offset());
        };
    }

    private Address anchorAddress(Anchor a) {
        return switch (a) {
            case Anchor.Native n -> address(n.space(), n.offset());
            case Anchor.Managed m -> throw KrakenError.unsupported("managed anchors are not supported yet");
            case Anchor.Banked b -> throw KrakenError.unsupported("banked anchors are not supported yet");
        };
    }

    private static Locator locator(Address a) {
        return new Locator.Native(a.getAddressSpace().getName(), a.getOffset());
    }

    // ---- functions ----------------------------------------------------------------------

    /** Functions with a body in program memory; external (imported) functions are not listed. */
    private int internalFunctionCount() {
        int n = 0;
        for (var it = requireProgram().getFunctionManager().getFunctions(true); it.hasNext(); it.next()) {
            n++;
        }
        return n;
    }

    private Kinded completeness() {
        List<String> done = stagesDone();
        if (done.containsAll(STAGES)) {
            return Kinded.complete();
        }
        if (done.isEmpty()) {
            return Kinded.notAnalyzed();
        }
        List<String> pending = new ArrayList<>(STAGES);
        pending.removeAll(done);
        return Kinded.partial("analysis stages pending: " + String.join(", ", pending));
    }

    private FunctionSummary summary(Function f, Kinded completeness) {
        return new FunctionSummary(
            locator(f.getEntryPoint()),
            f.getName(),
            f.getBody().getNumAddresses(),
            f.getPrototypeString(false, false),
            fnHash(f),
            completeness);
    }

    /** sha256 (lowercase hex) of the function body's bytes in address order. */
    private String fnHash(Function f) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            var mem = requireProgram().getMemory();
            byte[] buf = new byte[65536];
            for (var range : f.getBody().getAddressRanges()) {
                Address a = range.getMinAddress();
                long left = range.getLength();
                while (left > 0) {
                    int n = (int) Math.min(left, buf.length);
                    try {
                        int got = mem.getBytes(a, buf, 0, n);
                        md.update(buf, 0, got);
                    } catch (MemoryAccessException e) {
                        // uninitialized bytes contribute nothing
                    }
                    left -= n;
                    if (left > 0) {
                        a = a.add(n);
                    }
                }
            }
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest()) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw KrakenError.internal(e.toString());
        }
    }

    Page<FunctionSummary> listFunctions(PageRequest req) {
        Program p = requireProgram();
        FunctionManager fm = p.getFunctionManager();
        int limit = req.effectiveLimit();
        Address start = null;
        if (req.cursor() != null) {
            start = p.getAddressFactory().getDefaultAddressSpace().getAddress(J.hex(new com.google.gson.JsonPrimitive(req.cursor()), "cursor"));
        }
        var it = start == null ? fm.getFunctions(true) : fm.getFunctions(start, true);
        Kinded comp = completeness();
        List<FunctionSummary> items = new ArrayList<>();
        String next = null;
        while (it.hasNext()) {
            Function f = it.next();
            if (items.size() == limit) {
                next = J.hexJson(f.getEntryPoint().getOffset()).getAsString();
                break;
            }
            items.add(summary(f, comp));
        }
        return new Page<>(items, next, (long) internalFunctionCount());
    }

    FunctionSummary getFunction(Locator l) {
        return summary(functionAt(l, true), completeness());
    }

    private Function functionAt(Locator l, boolean containing) {
        Address a = address(l);
        FunctionManager fm = requireProgram().getFunctionManager();
        Function f = fm.getFunctionAt(a);
        if (f == null && containing) {
            f = fm.getFunctionContaining(a);
        }
        if (f == null) {
            throw KrakenError.notFound("no function at " + a);
        }
        return f;
    }

    // ---- decompile ----------------------------------------------------------------------

    void invalidateDecompiler(boolean reset) {
        synchronized (decompLock) {
            if (reset) {
                decompNeedsReset = true;
            } else {
                decompNeedsFlush = true;
            }
        }
    }

    private DecompInterface decompiler() {
        if (decompNeedsReset && decomp != null) {
            decomp.dispose();
            decomp = null;
        }
        decompNeedsReset = false;
        if (decomp == null) {
            DecompInterface d = new DecompInterface();
            DecompileOptions o = new DecompileOptions();
            o.grabFromProgram(requireProgram());
            d.setOptions(o);
            d.toggleCCode(true);
            d.toggleSyntaxTree(true);
            d.setSimplificationStyle("decompile");
            if (!d.openProgram(requireProgram())) {
                throw KrakenError.internal("decompiler failed to open program: " + d.getLastMessage());
            }
            decomp = d;
            decompNeedsFlush = false;
        } else if (decompNeedsFlush) {
            decomp.flushCache();
            decompNeedsFlush = false;
        }
        return decomp;
    }

    DecompileResult decompile(Locator l, Long timeoutMs) {
        Function f = functionAt(l, true);
        int secs = timeoutMs == null ? 60 : (int) Math.max(1, (timeoutMs + 999) / 1000);
        DecompileResults res;
        synchronized (decompLock) {
            res = decompiler().decompileFunction(f, secs, TaskMonitor.DUMMY);
        }
        if (res == null) {
            throw KrakenError.internal("decompiler returned no result");
        }
        if (res.isTimedOut()) {
            throw new KrakenError("timeout", "decompiler timed out after " + secs + " s");
        }
        if (!res.decompileCompleted() || res.getCCodeMarkup() == null) {
            throw KrakenError.internal("decompilation failed: " + res.getErrorMessage());
        }
        List<String> warnings = new ArrayList<>();
        String err = res.getErrorMessage();
        if (err != null && !err.isBlank()) {
            warnings.add(err.strip());
        }
        Walk w = new Walk(f);
        w.visit(res.getCCodeMarkup());
        return new DecompileResult(
            locator(f.getEntryPoint()), "c", w.text.toString(), w.tokens, warnings, completeness());
    }

    /** Flattens the Clang tree into text plus tokens with UTF-8 byte offsets. */
    private final class Walk {
        final StringBuilder text = new StringBuilder();
        final List<Token> tokens = new ArrayList<>();
        private long bytes;
        private final Function function;

        Walk(Function function) {
            this.function = function;
        }

        void visit(ClangNode n) {
            if (n instanceof ClangTokenGroup g) {
                for (int i = 0; i < g.numChildren(); i++) {
                    visit(g.Child(i));
                }
            } else if (n instanceof ClangToken t) {
                leaf(t);
            }
        }

        private void append(String s) {
            text.append(s);
            bytes += s.getBytes(StandardCharsets.UTF_8).length;
        }

        private void leaf(ClangToken t) {
            if (t instanceof ClangBreak b) {
                append("\n" + " ".repeat(Math.max(0, b.getIndent())));
                return;
            }
            String s = t.getText();
            if (s == null || s.isEmpty()) {
                return;
            }
            long start = bytes;
            append(s);
            if (s.isBlank()) {
                return;
            }
            String kind = kindOf(t);
            Locator target = targetOf(t);
            Varnode vn = t.getVarnode();
            String vnText = vn == null ? null : vn.toString();
            boolean named = !kind.equals("other") && !kind.equals("op") && !kind.equals("comment");
            if (kind.equals("other") && target == null && vnText == null) {
                return;
            }
            tokens.add(new Token(start, bytes, kind, target, named ? s : null, vnText));
        }

        private String kindOf(ClangToken t) {
            if (t instanceof ClangFuncNameToken) {
                return "function";
            }
            if (t instanceof ClangFieldToken) {
                return "field";
            }
            if (t instanceof ClangTypeToken) {
                return "type";
            }
            if (t instanceof ClangCommentToken) {
                return "comment";
            }
            if (t instanceof ClangOpToken) {
                return "op";
            }
            return switch (t.getSyntaxType()) {
                case ClangToken.KEYWORD_COLOR -> "keyword";
                case ClangToken.COMMENT_COLOR -> "comment";
                case ClangToken.TYPE_COLOR -> "type";
                case ClangToken.FUNCTION_COLOR -> "function";
                case ClangToken.VARIABLE_COLOR, ClangToken.PARAMETER_COLOR, ClangToken.GLOBAL_COLOR ->
                    "variable";
                case ClangToken.CONST_COLOR -> "constant";
                default -> "other";
            };
        }

        private Locator targetOf(ClangToken t) {
            if (t instanceof ClangFuncNameToken) {
                PcodeOp op = t.getPcodeOp();
                if (op == null) {
                    return locator(function.getEntryPoint());
                }
                if (op.getOpcode() == PcodeOp.CALL && op.getNumInputs() > 0) {
                    Varnode v0 = op.getInput(0);
                    if (v0 != null && v0.isAddress()) {
                        return locator(v0.getAddress());
                    }
                }
                return null;
            }
            HighVariable hv = t.getHighVariable();
            if (hv != null) {
                HighSymbol hs = hv.getSymbol();
                Varnode vn = t.getVarnode();
                if (hs != null && hs.isGlobal() && vn != null && vn.isAddress()) {
                    return locator(vn.getAddress());
                }
            }
            return null;
        }
    }

    // ---- apply_op -----------------------------------------------------------------------

    private interface Body<T> {
        T run() throws Exception;
    }

    private <T> T inTransaction(String name, Body<T> body) {
        Program p = requireProgram();
        int tx = p.startTransaction(name);
        boolean ok = false;
        try {
            T r = body.run();
            ok = true;
            return r;
        } catch (KrakenError e) {
            throw e;
        } catch (ghidra.util.exception.DuplicateNameException
                | ghidra.util.exception.InvalidInputException
                | ghidra.program.model.util.CodeUnitInsertionException
                | ghidra.program.database.function.OverlappingFunctionException
                | ghidra.program.model.data.InvalidDataTypeException
                | IllegalArgumentException e) {
            throw KrakenError.rejected(String.valueOf(e.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            throw KrakenError.internal(e.toString());
        } finally {
            p.endTransaction(tx, ok);
        }
    }

    void applyOp(VersionedLogOp v) {
        Program p = requireProgram();
        LogOp op = v.op();
        Listing listing = p.getListing();
        FunctionManager fm = p.getFunctionManager();
        SymbolTable symtab = p.getSymbolTable();
        Address a = anchorAddress(op.anchor());
        switch (op) {
            case LogOp.Rename r ->
                inTransaction(
                    "kraken rename",
                    () -> {
                        Function f = fm.getFunctionAt(a);
                        if (f != null) {
                            f.setName(r.newName(), SourceType.USER_DEFINED);
                            return null;
                        }
                        Symbol s = symtab.getPrimarySymbol(a);
                        if (s != null) {
                            s.setName(r.newName(), SourceType.USER_DEFINED);
                        } else {
                            symtab.createLabel(a, r.newName(), SourceType.USER_DEFINED);
                        }
                        return null;
                    });
            case LogOp.SetType t -> {
                inTransaction(
                    "kraken set type",
                    () -> {
                        Function f = fm.getFunctionAt(a);
                        if (f != null) {
                            if (t.neu() instanceof TypeRef.Named n && n.name().equals("undefined")) {
                                // The log's "cleared" marker (undoing a prototype edit): drop the
                                // user-defined signature back to what the engine infers.
                                f.setReturnType(DataType.DEFAULT, SourceType.DEFAULT);
                                f.replaceParameters(
                                    Function.FunctionUpdateType.DYNAMIC_STORAGE_FORMAL_PARAMS,
                                    true,
                                    SourceType.DEFAULT);
                                f.setVarArgs(false);
                                return null;
                            }
                            if (!(t.neu() instanceof TypeRef.Function fn)) {
                                throw KrakenError.rejected("a function's type must be a function prototype");
                            }
                            FunctionDefinitionDataType sig = types.signature(fn.proto(), f.getName());
                            var cmd = new ApplyFunctionSignatureCmd(a, sig, SourceType.USER_DEFINED);
                            if (!cmd.applyTo(p, TaskMonitor.DUMMY)) {
                                throw KrakenError.rejected(String.valueOf(cmd.getStatusMsg()));
                            }
                        } else {
                            createDataAt(p, a, types.toGhidra(t.neu()), 0);
                        }
                        return null;
                    });
                invalidateDecompiler(true);
            }
            case LogOp.SetComment c ->
                inTransaction(
                    "kraken comment",
                    () -> {
                        listing.setComment(a, commentType(c.commentKind()), c.neu());
                        return null;
                    });
            case LogOp.CreateFunction c ->
                inTransaction(
                    "kraken create function",
                    () -> {
                        if (fm.getFunctionAt(a) != null) {
                            throw KrakenError.rejected("a function already exists at " + a);
                        }
                        if (listing.getInstructionAt(a) == null) {
                            new DisassembleCommand(a, null, true).applyTo(p, TaskMonitor.DUMMY);
                            if (listing.getInstructionAt(a) == null) {
                                throw KrakenError.rejected("no code can be disassembled at " + a);
                            }
                        }
                        AddressSetView body = c.body() == null ? null : toSet(c.body());
                        var cmd = new CreateFunctionCmd(c.name(), a, body, SourceType.USER_DEFINED);
                        if (!cmd.applyTo(p, TaskMonitor.DUMMY)) {
                            throw KrakenError.rejected(String.valueOf(cmd.getStatusMsg()));
                        }
                        return null;
                    });
            case LogOp.DeleteFunction d ->
                inTransaction(
                    "kraken delete function",
                    () -> {
                        if (!fm.removeFunction(a)) {
                            throw KrakenError.notFound("no function at " + a);
                        }
                        return null;
                    });
            case LogOp.SetFunctionBounds b ->
                inTransaction(
                    "kraken set function bounds",
                    () -> {
                        Function f = fm.getFunctionAt(a);
                        if (f == null) {
                            throw KrakenError.notFound("no function at " + a);
                        }
                        Address start = address(b.neu().space(), b.neu().start());
                        if (!start.equals(f.getEntryPoint())) {
                            throw KrakenError.rejected("the entry point cannot move; use delete and create");
                        }
                        f.setBody(toSet(b.neu()));
                        return null;
                    });
            case LogOp.SetCodeData cd ->
                inTransaction("kraken set code/data", () -> setCodeData(p, a, cd));
            case LogOp.SetCallingConvention cc -> {
                inTransaction(
                    "kraken calling convention",
                    () -> {
                        Function f = fm.getFunctionAt(a);
                        if (f == null) {
                            throw KrakenError.notFound("no function at " + a);
                        }
                        f.setCallingConvention(cc.neu());
                        return null;
                    });
                invalidateDecompiler(true);
            }
        }
        invalidateDecompiler(false);
    }

    private static CommentType commentType(String kind) {
        return switch (kind) {
            case "plate" -> CommentType.PLATE;
            case "pre" -> CommentType.PRE;
            case "eol" -> CommentType.EOL;
            case "post" -> CommentType.POST;
            case "repeatable" -> CommentType.REPEATABLE;
            default -> throw KrakenError.invalid("unknown comment kind " + kind);
        };
    }

    private AddressSet toSet(Proto.AddressRange r) {
        Address start = address(r.space(), r.start());
        if (r.end() <= r.start()) {
            throw KrakenError.invalid("empty address range");
        }
        Address end = address(r.space(), r.end() - 1);
        return new AddressSet(start, end);
    }

    /** Clears whatever code or data overlaps, then defines `dt` at `a`. */
    private void createDataAt(Program p, Address a, DataType dt, long len) throws Exception {
        long size = dt.getLength() > 0 ? dt.getLength() : len;
        if (size <= 0) {
            throw KrakenError.rejected("cannot size " + dt.getName() + "; pass a length");
        }
        p.getListing().clearCodeUnits(a, a.add(size - 1), false);
        DataUtilities.createData(
            p,
            a,
            dt,
            dt.getLength() > 0 ? -1 : (int) size,
            DataUtilities.ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
    }

    private Object setCodeData(Program p, Address a, LogOp.SetCodeData op) throws Exception {
        Listing listing = p.getListing();
        long len = op.length() == null ? 0 : op.length();
        switch (op.neu()) {
            case CodeData.Code c -> {
                AddressSet restrict = len > 0 ? new AddressSet(a, a.add(len - 1)) : null;
                var cmd = new DisassembleCommand(a, restrict, true);
                if (!cmd.applyTo(p, TaskMonitor.DUMMY) || listing.getInstructionAt(a) == null) {
                    throw KrakenError.rejected("cannot disassemble at " + a + ": " + cmd.getStatusMsg());
                }
            }
            case CodeData.Data d -> {
                DataType dt =
                    d.dataType() == null
                        ? Undefined.getUndefinedDataType((int) Math.max(1, len))
                        : types.toGhidra(d.dataType());
                createDataAt(p, a, dt, len);
            }
            case CodeData.Undefined u ->
                listing.clearCodeUnits(a, a.add(Math.max(1, len) - 1), false);
        }
        return null;
    }

    // ---- types --------------------------------------------------------------------------

    Page<TypeDef> getTypes(PageRequest req, String name) {
        requireProgram();
        List<TypeDef> all = types.allDefs(name);
        int offset = 0;
        if (req.cursor() != null) {
            try {
                offset = Integer.parseInt(req.cursor());
            } catch (NumberFormatException e) {
                throw KrakenError.invalid("bad cursor");
            }
        }
        int limit = req.effectiveLimit();
        int end = Math.min(all.size(), offset + limit);
        List<TypeDef> items = offset >= all.size() ? List.of() : all.subList(offset, end);
        return new Page<>(items, end < all.size() ? String.valueOf(end) : null, (long) all.size());
    }

    TypeDef defineType(TypeDef def) {
        Program p = requireProgram();
        TypeDef result =
            inTransaction(
                "kraken define type",
                () -> {
                    DataType managed = types.define(def);
                    TypeDef back = types.toNeutralDef(managed);
                    if (back == null) {
                        throw KrakenError.internal("defined type cannot be read back");
                    }
                    return back;
                });
        invalidateDecompiler(true);
        return result;
    }

    // ---- save / close -------------------------------------------------------------------

    String save(String watermark) throws Exception {
        Program p = requireProgram();
        p.getDomainFile().save(TaskMonitor.DUMMY);
        saveCounter++;
        return watermark != null ? watermark : "save-" + saveCounter + "-" + System.currentTimeMillis();
    }

    void closeProgram() {
        for (JobMonitor m : jobs.values()) {
            m.cancel();
        }
        synchronized (decompLock) {
            if (decomp != null) {
                decomp.dispose();
                decomp = null;
            }
        }
        GhidraProject gp = project;
        Program p = program;
        program = null;
        project = null;
        try {
            if (p != null) {
                p.release(this);
            }
        } finally {
            if (gp != null) {
                gp.close();
            }
        }
    }

    String ghidraVersion() {
        return Application.getApplicationVersion();
    }
}
