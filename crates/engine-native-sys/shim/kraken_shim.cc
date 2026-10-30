// KRAKEN native engine shim over the Ghidra decompiler library (libdecomp + Sleigh).
// SPDX-License-Identifier: GPL-3.0-or-later

#include "engine-native-sys/shim/kraken_shim.hh"
#include "engine-native-sys/src/lib.rs.h"

#include <chrono>
#include <map>
#include <cstdio>
#include <mutex>
#ifdef __GLIBC__
#include <malloc.h>
#endif
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "architecture.hh"
#include "comment.hh"
#include "fspec.hh"
#include "funcdata.hh"
#include "grammar.hh"
#include "jumptable.hh"
#include "loadimage.hh"
#include "printc.hh"
#include "sleigh.hh"
#include "sleigh_arch.hh"

namespace kraken {

using ghidra::Address;
using ghidra::AddrSpace;
using ghidra::Datatype;
using ghidra::Emit;
using ghidra::FlowBlock;
using ghidra::Funcdata;
using ghidra::PcodeOp;
using ghidra::Symbol;
using ghidra::Varnode;
using ghidra::VarnodeData;

namespace {

// Ghidra's exceptions do not derive from std::exception, so cxx cannot see them. Every entry
// point funnels its body through here and rethrows as std::runtime_error.
template <typename F> auto guarded(const char *what, F &&body) -> decltype(body()) {
  try {
    return body();
  } catch (ghidra::LowlevelError &e) {
    throw std::runtime_error(std::string(what) + ": " + e.explain);
  } catch (ghidra::DecoderError &e) {
    throw std::runtime_error(std::string(what) + ": " + e.explain);
  } catch (std::exception &e) {
    throw std::runtime_error(std::string(what) + ": " + e.what());
  } catch (...) {
    throw std::runtime_error(std::string(what) + ": unknown C++ exception");
  }
}

// Token kinds shared with Rust (see `TokenKind` mapping in lib.rs).
enum TokKind : uint8_t {
  TK_KEYWORD = 0,
  TK_VARIABLE = 1,
  TK_FUNCTION = 2,
  TK_TYPE = 3,
  TK_FIELD = 4,
  TK_CONSTANT = 5,
  TK_COMMENT = 6,
  TK_OP = 7,
  TK_OTHER = 8,
};

// Flow kinds shared with Rust (see `Flow` in lib.rs).
enum FlowCode : uint8_t {
  FL_FALLTHROUGH = 0,
  FL_JUMP = 1,
  FL_CJUMP = 2,
  FL_CALL = 3,
  FL_RETURN = 4,
  FL_IJUMP = 5,
  FL_ICALL = 6,
};

// Reference kinds shared with Rust (see `RefKind` in lib.rs).
enum RefCode : uint8_t {
  RF_DATA = 0,  // an address-sized constant (lea, mov imm64)
  RF_READ = 1,  // a direct or constant-pointer memory read
  RF_WRITE = 2, // a direct or constant-pointer memory write
  RF_IMM = 3,   // a constant narrower than an address (mov edi, imm32 in fixed-address code)
};

/// Reads program bytes through the Rust `ImageSource`.
class CallbackLoadImage : public ghidra::LoadImage {
  rust::Box<ImageSource> image;
  AddrSpace *space = nullptr;

public:
  explicit CallbackLoadImage(rust::Box<ImageSource> img)
      : ghidra::LoadImage("kraken"), image(std::move(img)) {}
  void attach(AddrSpace *spc) { space = spc; }
  void loadFill(ghidra::uint1 *ptr, ghidra::int4 size, const Address &addr) override {
    rust::Slice<uint8_t> buf(ptr, static_cast<size_t>(size));
    if (!image->load_fill(addr.getOffset(), buf)) {
      std::ostringstream s;
      s << "unable to load " << size << " bytes at 0x" << std::hex << addr.getOffset();
      // Sleigh fetches instructions 16 bytes at a time: code outside the image is a bad
      // instruction, which the decompiler's flow truncates with a warning (a jump into data
      // decoded as code can lead anywhere); other reads stay unavailable data
      if (size == 16)
        throw ghidra::BadDataError(s.str());
      throw ghidra::DataUnavailError(s.str());
    }
  }
  void getReadonly(ghidra::RangeList &list) const override {
    if (space == nullptr)
      return;
    rust::Vec<uint64_t> r = image->readonly_ranges();
    for (size_t i = 0; i + 1 < r.size(); i += 2)
      if (r[i + 1] > r[i])
        list.insertRange(space, r[i], r[i + 1] - 1);
  }
  bool interrupted() const { return image->interrupted(); }
  std::string getArchType(void) const override { return "kraken"; }
  void adjustVma(long) override {}
};

/// Writes tokens straight to a string and records their spans. No pretty printing: the line
/// breaks are the statement breaks PrintC asks for.
class TokenEmit : public Emit {
  std::string out;
  std::vector<TokenOut> toks;
  std::vector<std::string> warns;
  std::ostream *stream = nullptr;

  static std::string varnodeText(const Varnode *vn) {
    if (vn == nullptr)
      return std::string();
    char buf[64];
    std::snprintf(buf, sizeof buf, ":0x%llx:%d", (unsigned long long)vn->getOffset(),
                  (int)vn->getSize());
    return vn->getSpace()->getName() + buf;
  }

  // the symbol whose declaration is being printed; its tokens carry no varnode of their own
  const Symbol *declSymbol = nullptr;

  static std::string entryText(const ghidra::MapEntry *e) {
    char buf[64];
    std::snprintf(buf, sizeof buf, ":0x%llx:%d", (unsigned long long)e->getAddr().getOffset(),
                  (int)e->getSize());
    return e->getAddr().getSpace()->getName() + buf;
  }

  // Where the variable lives as the decompiler's scope maps it: the storage of its symbol, the
  // same at every use (a register or unique varnode names only one use). Falls back to the
  // varnode itself for variables without a mapped symbol.
  std::string variableText(const Varnode *vn) const {
    const Symbol *sym = declSymbol;
    if (vn != nullptr)
      sym = vn->getHigh() != nullptr ? vn->getHigh()->getSymbol() : nullptr;
    if (sym != nullptr)
      for (ghidra::int4 i = 0; i < sym->numEntries(); ++i) {
        const ghidra::MapEntry *m = dynamic_cast<const ghidra::MapEntry *>(sym->getMapEntry(i));
        if (m != nullptr)
          return entryText(m);
      }
    return varnodeText(vn);
  }

  void push(const std::string &text, uint8_t kind, const std::string &symbol = std::string(),
            bool has_target = false, uint64_t target = 0, const std::string &varnode = std::string()) {
    size_t start = out.size();
    out += text;
    bool blank = true;
    for (char c : text)
      if (c != ' ' && c != '\t' && c != '\n')
        blank = false;
    if (blank)
      return;
    TokenOut t;
    t.start = static_cast<uint32_t>(start);
    t.end = static_cast<uint32_t>(out.size());
    t.kind = kind;
    t.symbol = rust::String(symbol);
    t.has_target = has_target;
    t.target = target;
    t.varnode = rust::String(varnode);
    toks.push_back(std::move(t));
  }

  void newline(int indent) {
    emitPending();
    out += '\n';
    out.append(static_cast<size_t>(indent < 0 ? 0 : indent), ' ');
  }

public:
  void reset() {
    out.clear();
    toks.clear();
    warns.clear();
    clear();
  }
  std::string &text() { return out; }
  std::vector<TokenOut> &tokens() { return toks; }
  std::vector<std::string> &warnings() { return warns; }

  ghidra::int4 beginDocument(void) override { return 0; }
  void endDocument(ghidra::int4) override {}
  ghidra::int4 beginFunction(const Funcdata *) override { return 0; }
  void endFunction(ghidra::int4) override {}
  ghidra::int4 beginBlock(const FlowBlock *) override { return 0; }
  void endBlock(ghidra::int4) override {}
  void tagLine(void) override { newline(indentlevel); }
  void tagLine(ghidra::int4 indent) override { newline(indent); }
  ghidra::int4 beginReturnType(const Varnode *) override { return 0; }
  void endReturnType(ghidra::int4) override {}
  ghidra::int4 beginVarDecl(const Symbol *sym) override {
    declSymbol = sym;
    return 0;
  }
  void endVarDecl(ghidra::int4) override { declSymbol = nullptr; }
  ghidra::int4 beginStatement(const PcodeOp *) override { return 0; }
  void endStatement(ghidra::int4) override {}
  ghidra::int4 beginFuncProto(void) override { return 0; }
  void endFuncProto(ghidra::int4) override {}

  void tagVariable(const std::string &name, syntax_highlight hl, const Varnode *vn,
                   const PcodeOp *) override {
    if (hl == const_color) {
      push(name, TK_CONSTANT, std::string(), false, 0, varnodeText(vn));
      return;
    }
    bool global = vn != nullptr && vn->getSpace()->getType() == ghidra::IPTR_PROCESSOR;
    push(name, TK_VARIABLE, name, global, global ? vn->getOffset() : 0,
         global ? varnodeText(vn) : variableText(vn));
  }
  void tagOp(const std::string &name, syntax_highlight hl, const PcodeOp *) override {
    push(name, hl == keyword_color ? TK_KEYWORD : TK_OP);
  }
  void tagFuncName(const std::string &name, syntax_highlight, const Funcdata *fd,
                   const PcodeOp *op) override {
    bool has = false;
    uint64_t target = 0;
    if (op == nullptr && fd != nullptr) {
      has = true;
      target = fd->getAddress().getOffset();
    } else if (op != nullptr && op->code() == ghidra::CPUI_CALL && op->numInput() > 0) {
      const Varnode *vn = op->getIn(0);
      if (vn->getSpace()->getType() == ghidra::IPTR_FSPEC) {
        // after heritage the call target is a reference to the call's FuncCallSpecs
        const ghidra::FuncCallSpecs *fc = ghidra::FuncCallSpecs::getFspecFromConst(vn->getAddr());
        const Address &entry = fc->getEntryAddress();
        if (!entry.isInvalid() && entry.getSpace()->getType() == ghidra::IPTR_PROCESSOR) {
          has = true;
          target = entry.getOffset();
        }
      } else if (vn->getSpace()->getType() == ghidra::IPTR_PROCESSOR) {
        has = true;
        target = vn->getOffset();
      }
    }
    push(name, TK_FUNCTION, name, has, target);
  }
  void tagType(const std::string &name, syntax_highlight, const Datatype *) override {
    push(name, TK_TYPE, name);
  }
  void tagField(const std::string &name, syntax_highlight, const Datatype *, ghidra::int4,
                const PcodeOp *) override {
    push(name, TK_FIELD, name);
  }
  void tagBitField(const std::string &name, syntax_highlight, const Datatype *, ghidra::int4,
                   const PcodeOp *) override {
    push(name, TK_FIELD, name);
  }
  void tagComment(const std::string &name, syntax_highlight, const AddrSpace *,
                  ghidra::uintb) override {
    const std::string marker = "WARNING: ";
    size_t at = name.find(marker);
    if (at != std::string::npos) {
      std::string w = name.substr(at + marker.size());
      size_t end = w.find(" */");
      warns.push_back(end == std::string::npos ? w : w.substr(0, end));
    }
    push(name, TK_COMMENT);
  }
  void tagLabel(const std::string &name, syntax_highlight, const AddrSpace *spc,
                ghidra::uintb off) override {
    bool ram = spc != nullptr && spc->getType() == ghidra::IPTR_PROCESSOR;
    push(name, TK_OTHER, name, ram, ram ? off : 0);
  }
  void tagCaseLabel(const std::string &name, syntax_highlight, const PcodeOp *,
                    ghidra::uintb) override {
    push(name, TK_CONSTANT);
  }
  void print(const std::string &data, syntax_highlight hl) override {
    uint8_t kind = TK_OP;
    switch (hl) {
    case keyword_color:
      kind = TK_KEYWORD;
      break;
    case comment_color:
      kind = TK_COMMENT;
      break;
    case type_color:
      kind = TK_TYPE;
      break;
    case funcname_color:
      kind = TK_FUNCTION;
      break;
    case var_color:
    case param_color:
    case global_color:
      kind = TK_VARIABLE;
      break;
    case const_color:
      kind = TK_CONSTANT;
      break;
    default:
      kind = TK_OP;
    }
    push(data, kind);
  }
  ghidra::int4 openParen(const std::string &paren, ghidra::int4 id) override {
    push(paren, TK_OP);
    parenlevel += 1;
    return id;
  }
  void closeParen(const std::string &paren, ghidra::int4) override {
    push(paren, TK_OP);
    parenlevel -= 1;
  }
  void setOutputStream(std::ostream *t) override { stream = t; }
  std::ostream *getOutputStream(void) const override { return stream; }
  bool emitsMarkup(void) const override { return false; }
};

/// PrintC with the token-recording emitter in place of the pretty printer.
class KrakenPrintC : public ghidra::PrintC {
public:
  KrakenPrintC(ghidra::Architecture *g, TokenEmit *e) : ghidra::PrintC(g, "kraken-c") {
    delete emit;
    emit = e;
  }
  TokenEmit *tokens() { return static_cast<TokenEmit *>(emit); }
};

/// A Sleigh architecture over the callback load image. It owns a private Sleigh translator (the
/// base class shares one per language through a static map, which would tie sessions together).
class KrakenArchitecture : public ghidra::SleighArchitecture {
  rust::Box<ImageSource> *pending;
  std::unique_ptr<ghidra::Sleigh> *sleighOut;

  void buildLoader(ghidra::DocumentStorage &) override {
    collectSpecFiles(*errorstream);
    loader = new CallbackLoadImage(std::move(*pending));
  }
  ghidra::Translate *buildTranslator(ghidra::DocumentStorage &) override {
    sleighOut->reset(new ghidra::Sleigh(loader, context));
    return sleighOut->get();
  }
  void resolveArchitecture(void) override {
    archid = getTarget();
    ghidra::SleighArchitecture::resolveArchitecture();
  }
  // Whether `long` is 8 bytes (LP64: 64-bit targets other than Windows). On 32-bit targets
  // and 64-bit Windows Ghidra calls the 8-byte integers `longlong` and `ulonglong`.
  bool longIs64() const {
    const std::string &t = getTarget();
    bool windows = t.size() >= 8 && (t.compare(t.size() - 8, 8, ":windows") == 0 ||
                                     t.find(":clangwindows") != std::string::npos);
    return t.find(":64:") != std::string::npos && !windows;
  }
  // Core type names as Ghidra's Java side registers them, so output reads `int`, `uint`,
  // `undefined8` rather than the console defaults `int4`, `uint4`, `xunknown8`.
  void buildCoreTypes(ghidra::DocumentStorage &) override {
    using namespace ghidra;
    bool lp64 = longIs64();
    const char *int8 = lp64 ? "long" : "longlong";
    const char *uint8 = lp64 ? "ulong" : "ulonglong";
    types->setCoreType("void", 1, TYPE_VOID, false);
    types->setCoreType("bool", 1, TYPE_BOOL, false);
    types->setCoreType("byte", 1, TYPE_UINT, false);
    types->setCoreType("ushort", 2, TYPE_UINT, false);
    types->setCoreType("uint", 4, TYPE_UINT, false);
    types->setCoreType(uint8, 8, TYPE_UINT, false);
    types->setCoreType("sbyte", 1, TYPE_INT, false);
    types->setCoreType("short", 2, TYPE_INT, false);
    types->setCoreType("int", 4, TYPE_INT, false);
    types->setCoreType(int8, 8, TYPE_INT, false);
    types->setCoreType("float", 4, TYPE_FLOAT, false);
    types->setCoreType("double", 8, TYPE_FLOAT, false);
    types->setCoreType("float10", 10, TYPE_FLOAT, false);
    types->setCoreType("float16", 16, TYPE_FLOAT, false);
    types->setCoreType("undefined", 1, TYPE_UNKNOWN, false);
    types->setCoreType("undefined2", 2, TYPE_UNKNOWN, false);
    types->setCoreType("undefined4", 4, TYPE_UNKNOWN, false);
    types->setCoreType("undefined8", 8, TYPE_UNKNOWN, false);
    types->setCoreType("code", 1, TYPE_CODE, false);
    types->setCoreType("char", 1, TYPE_INT, true);
    types->setCoreType("wchar16", 2, TYPE_INT, true);
    types->setCoreType("wchar32", 4, TYPE_INT, true);
    types->cacheCoreTypes();
    // The other spellings stay known to the C grammar (after the cache, so the decompiler
    // still prints the preferred ones): `long` is 4 bytes where it is not 8.
    if (lp64) {
      types->setCoreType("longlong", 8, TYPE_INT, false);
      types->setCoreType("ulonglong", 8, TYPE_UINT, false);
    } else {
      types->setCoreType("long", 4, TYPE_INT, false);
      types->setCoreType("ulong", 4, TYPE_UINT, false);
    }
  }
  void postSpecFile(void) override {
    ghidra::Architecture::postSpecFile();
    static_cast<CallbackLoadImage *>(loader)->attach(getDefaultCodeSpace());
  }

public:
  KrakenArchitecture(const std::string &target, std::ostream *errs, rust::Box<ImageSource> *img,
                     std::unique_ptr<ghidra::Sleigh> *out)
      : ghidra::SleighArchitecture("kraken", target, errs), pending(img), sleighOut(out) {}
  static void collectSpecs(std::ostream &errs) { collectSpecFiles(errs); }
  void nameFunction(const Address &addr, std::string &name) const override {
    char buf[40];
    std::snprintf(buf, sizeof buf, "FUN_%08llx", (unsigned long long)addr.getOffset());
    name = buf;
  }
};

/// Collects the p-code of one instruction.
class CollectPcode : public ghidra::PcodeEmit {
public:
  struct Op {
    ghidra::OpCode opc;
    bool has_out;
    VarnodeData out;
    std::vector<VarnodeData> in;
  };
  std::vector<Op> ops;
  void dump(const Address &, ghidra::OpCode opc, VarnodeData *outvar, VarnodeData *vars,
            ghidra::int4 isize) override {
    Op op;
    op.opc = opc;
    op.has_out = outvar != nullptr;
    if (outvar != nullptr)
      op.out = *outvar;
    for (ghidra::int4 i = 0; i < isize; ++i)
      op.in.push_back(vars[i]);
    ops.push_back(std::move(op));
  }
};

class CollectAsm : public ghidra::AssemblyEmit {
public:
  std::string mnem, body;
  void dump(const Address &, const std::string &m, const std::string &b) override {
    mnem = m;
    body = b;
  }
};

VarnodeOut toVarnode(const VarnodeData &v) {
  VarnodeOut o;
  o.space = rust::String(v.space->getName());
  o.offset = v.offset;
  o.size = v.size;
  return o;
}

std::mutex startMutex;
bool started = false;

} // namespace

struct Session::Impl {
  // Declared first so it is destroyed last: the architecture's components refer to it.
  std::unique_ptr<ghidra::Sleigh> sleigh;
  std::ostringstream errs;
  std::unique_ptr<KrakenArchitecture> arch;
  KrakenPrintC *printer = nullptr;
  // the root action of the decompile carries break points, see `breakEverywhere`
  ghidra::Action *broken = nullptr;
  // call fixups of the compiler spec by the names of the functions they replace
  // (`__x86.get_pc_thunk.bx`): the C++ library keeps the payloads but drops the targets
  std::map<std::string, ghidra::int4> callFixups;
  // whether a branch to the next instruction guards the instruction's effect (ARM's
  // conditional execution, `if (!cond) goto inst_next`) rather than being a flow of its own;
  // x86 keeps its historical reading (`CMOVcc` and friends)
  bool condExec = false;
  // user names and types of locals by function entry; applied to the function's local scope
  // around each decompile (see `applyLocalTypes` and `applyLocalNames`)
  struct LocalOverride {
    AddrSpace *space;
    uint64_t offset;
    std::string name;
    std::string decl;
  };
  std::map<uint64_t, std::vector<LocalOverride>> locals;
  // the type-locked symbols we added to a function's scope, to take out before the next round
  std::map<uint64_t, std::vector<std::pair<AddrSpace *, uint64_t>>> addedLocals;
};

Session::Session(std::unique_ptr<Impl> i) : impl(std::move(i)) {}
Session::~Session() {
  if (impl) {
    impl->arch.reset();
    impl->sleigh.reset();
  }
}

void start_library(rust::Str sleigh_home) {
  guarded("start_library", [&]() {
    std::lock_guard<std::mutex> lock(startMutex);
    if (started)
      return;
    ghidra::AttributeId::initialize();
    ghidra::ElementId::initialize();
    ghidra::CapabilityPoint::initializeAll();
    ghidra::ArchitectureCapability::sortCapabilities();
    ghidra::SleighArchitecture::scanForSleighDirectories(std::string(sleigh_home));
    started = true;
  });
}

bool has_language(rust::Str language_id) {
  return guarded("has_language", [&]() {
    std::ostringstream errs;
    KrakenArchitecture::collectSpecs(errs);
    std::string id(language_id);
    for (const auto &d : ghidra::SleighArchitecture::getDescriptions())
      if (d.getId() == id)
        return true;
    return false;
  });
}

std::unique_ptr<Session> new_session(rust::Str language_id, rust::Str compiler_id,
                                     rust::Box<ImageSource> image) {
  return guarded("new_session", [&]() {
    if (!started)
      throw std::runtime_error("start_library has not run");
    auto impl = std::make_unique<Session::Impl>();
    std::string target = std::string(language_id) + ":" + std::string(compiler_id);
    rust::Vec<ContextOut> painted = image->context_ranges();
    rust::Box<ImageSource> img = std::move(image);
    impl->arch = std::make_unique<KrakenArchitecture>(target, &impl->errs, &img, &impl->sleigh);
    ghidra::DocumentStorage store;
    impl->arch->init(store);
    impl->arch->readonlypropagate = true;
    impl->condExec = target.compare(0, 4, "x86:") != 0;
    // context the loader worked out (ARM's TMode where the code is Thumb), painted before
    // anything is decoded; each range is its own region, so a `globalset` of an instruction
    // (`blx` into the other mode) repaints at most up to the next range
    {
      AddrSpace *ram = impl->arch->getDefaultCodeSpace();
      for (const ContextOut &c : painted)
        impl->arch->context->setVariableRegion(std::string(c.name), Address(ram, c.start),
                                               Address(ram, c.end), c.value);
    }
    if (const ghidra::Element *spec = store.getTag("compiler_spec")) {
      for (const ghidra::Element *el : spec->getChildren()) {
        if (el->getName() != "callfixup")
          continue;
        try {
          ghidra::int4 id = impl->arch->pcodeinjectlib->getPayloadId(
              ghidra::InjectPayload::CALLFIXUP_TYPE, el->getAttributeValue("name"));
          if (id < 0)
            continue;
          for (const ghidra::Element *t : el->getChildren())
            if (t->getName() == "target")
              impl->callFixups[t->getAttributeValue("name")] = id;
        } catch (ghidra::LowlevelError &) {
          // a fixup without a name or payload is left out
        }
      }
    }
    auto *printer = new KrakenPrintC(impl->arch.get(), new TokenEmit());
    printer->initializeFromArchitecture();
    impl->arch->printlist.push_back(printer);
    impl->arch->print = printer;
    printer->adjustTypeOperators();
    // user comments: pre (user2) as Ghidra shows by default, plus end-of-line (user1) and post
    // (user3); plate comments are header comments
    printer->setInstructionComment(ghidra::Comment::user1 | ghidra::Comment::user2 |
                                   ghidra::Comment::user3 | ghidra::Comment::warning);
    printer->setHeaderComment(ghidra::Comment::header | ghidra::Comment::warningheader);
    impl->printer = printer;
    return std::make_unique<Session>(std::move(impl));
  });
}

void Session::add_function(uint64_t addr, rust::Str name) {
  guarded("add_function", [&]() {
    ghidra::Architecture *a = impl->arch.get();
    Address at(a->getDefaultCodeSpace(), addr);
    std::string nm(name);
    ghidra::Scope *global = a->symboltab->getGlobalScope();
    Funcdata *fd = global->queryFunction(at);
    if (fd != nullptr) {
      if (fd->getName() == nm)
        return;
      // renameSymbol leaves the Funcdata's own name behind, so replace the symbol instead
      global->removeSymbol(fd->getSymbol());
    }
    ghidra::FunctionSymbol *sym = global->addFunction(at, nm);
    auto fix = impl->callFixups.find(nm);
    if (fix != impl->callFixups.end() && sym != nullptr)
      sym->getFunction()->getFuncProto().setInjectId(fix->second);
  });
}

rust::Vec<InsnOut> Session::decode(uint64_t addr, uint32_t max) {
  return guarded("decode", [&]() {
    rust::Vec<InsnOut> rows;
    ghidra::Architecture *a = impl->arch.get();
    AddrSpace *ram = a->getDefaultCodeSpace();
    AddrSpace *regs = a->getSpaceByName("register");
    uint64_t at = addr;
    for (uint32_t n = 0; n < max; ++n) {
      Address here(ram, at);
      CollectAsm as;
      CollectPcode pc;
      ghidra::int4 len;
      try {
        len = a->translate->printAssembly(as, here);
        a->translate->oneInstruction(pc, here);
      } catch (ghidra::LowlevelError &) {
        break; // undecodable or unmapped bytes end the run
      }
      if (len <= 0)
        break;
      InsnOut row;
      row.addr = at;
      row.length = static_cast<uint32_t>(len);
      row.mnemonic = rust::String(as.mnem);
      row.body = rust::String(as.body);
      row.flow = FL_FALLTHROUGH;
      row.fallthrough = true;
      row.via_pointer = false;
      int rank = 0; // keep the strongest flow seen in the instruction's p-code
      auto set = [&](int r, uint8_t f, bool falls) {
        if (r > rank) {
          rank = r;
          row.flow = f;
          row.fallthrough = falls;
        }
      };
      const uint64_t after = at + static_cast<uint64_t>(len);
      // conditional execution: the instruction does what its other p-code says, or nothing
      bool guarded = false;
      for (const auto &op : pc.ops) {
        bool ramTarget = !op.in.empty() && op.in[0].space->getType() == ghidra::IPTR_PROCESSOR;
        if (impl->condExec && op.opc == ghidra::CPUI_CBRANCH && ramTarget &&
            op.in[0].offset == after) {
          guarded = true;
          continue;
        }
        switch (op.opc) {
        case ghidra::CPUI_RETURN:
          set(6, FL_RETURN, false);
          break;
        case ghidra::CPUI_BRANCHIND:
          set(5, FL_IJUMP, false);
          // `jmp [constant]` (PLT and IFUNC stubs) loads its target from a fixed slot, so it
          // cannot be a switch; Sleigh gives the slot either as a direct memory operand or as
          // a LOAD from a constant pointer
          if (!op.in.empty() && op.in[0].space == ram)
            row.via_pointer = true;
          for (const auto &prev : pc.ops)
            if (prev.opc == ghidra::CPUI_LOAD && prev.has_out && !op.in.empty() &&
                prev.out.space == op.in[0].space && prev.out.offset == op.in[0].offset &&
                prev.in.size() > 1 && prev.in[1].space->getType() == ghidra::IPTR_CONSTANT)
              row.via_pointer = true;
          break;
        case ghidra::CPUI_BRANCH:
          if (ramTarget) {
            row.targets.push_back(op.in[0].offset);
            set(4, FL_JUMP, false);
          }
          break;
        case ghidra::CPUI_CBRANCH:
          if (ramTarget) {
            row.targets.push_back(op.in[0].offset);
            set(3, FL_CJUMP, true);
          }
          break;
        case ghidra::CPUI_CALL:
          if (ramTarget) {
            row.targets.push_back(op.in[0].offset);
            set(2, FL_CALL, true);
          }
          break;
        case ghidra::CPUI_CALLIND:
          set(1, FL_ICALL, true);
          break;
        default:
          break;
        }
        // constants that look like addresses (lea, mov imm) and absolute memory operands
        auto ref = [&](uint64_t a, uint8_t k) {
          row.refs.push_back(a);
          row.ref_kinds.push_back(k);
        };
        bool memop = op.opc == ghidra::CPUI_LOAD || op.opc == ghidra::CPUI_STORE;
        bool flowop = op.opc == ghidra::CPUI_BRANCH || op.opc == ghidra::CPUI_CBRANCH ||
                      op.opc == ghidra::CPUI_CALL;
        for (size_t k = 0; k < op.in.size(); ++k) {
          const auto &in = op.in[k];
          if (memop && k < 2)
            continue; // the space id and the pointer are handled below
          if (in.space->getType() == ghidra::IPTR_CONSTANT) {
            if (in.size == ram->getAddrSize())
              ref(in.offset, RF_DATA);
            else if (in.size == 4 && ram->getAddrSize() == 8 && in.offset >= 0x1000)
              ref(in.offset, RF_IMM);
          } else if (in.space == ram && !flowop)
            ref(in.offset, RF_READ);
        }
        if (op.has_out && op.out.space == ram)
          ref(op.out.offset, RF_WRITE);
        if (memop && op.in.size() > 1 && op.in[1].space->getType() == ghidra::IPTR_CONSTANT)
          ref(op.in[1].offset, op.opc == ghidra::CPUI_LOAD ? RF_READ : RF_WRITE);
        // registers read and written, packed as offset << 8 | size
        for (const auto &in : op.in)
          if (in.space == regs)
            row.reg_reads.push_back((in.offset << 8) | (in.size & 0xff));
        if (op.has_out && op.out.space == regs)
          row.reg_writes.push_back((op.out.offset << 8) | (op.out.size & 0xff));
      }
      if (guarded) {
        // a guarded branch is a conditional one; a guarded return, computed jump or call may
        // also fall through
        if (row.flow == FL_JUMP)
          row.flow = FL_CJUMP;
        row.fallthrough = true;
      }
      // A repeat prefix (`REP STOSQ`) is p-code that branches back to its own start and out to
      // the next instruction: the instruction loops internally and then falls through.
      uint64_t next = at + static_cast<uint64_t>(len);
      bool self = false, toNext = false;
      for (const auto &op : pc.ops) {
        if ((op.opc == ghidra::CPUI_BRANCH || op.opc == ghidra::CPUI_CBRANCH) && !op.in.empty() &&
            op.in[0].space == ram) {
          self |= op.in[0].offset == at;
          toNext |= op.opc == ghidra::CPUI_CBRANCH && op.in[0].offset == next;
        }
      }
      if (self && toNext) {
        rust::Vec<uint64_t> kept;
        for (uint64_t t : row.targets)
          if (t != at && t != next)
            kept.push_back(t);
        row.targets = std::move(kept);
        if (row.targets.empty() && (row.flow == FL_JUMP || row.flow == FL_CJUMP)) {
          row.flow = FL_FALLTHROUGH;
          row.fallthrough = true;
        }
      }
      rows.push_back(std::move(row));
      at += static_cast<uint64_t>(len);
    }
    return rows;
  });
}

rust::Vec<PcodeOpOut> Session::lift(uint64_t start, uint64_t end) {
  return guarded("lift", [&]() {
    rust::Vec<PcodeOpOut> out;
    ghidra::Architecture *a = impl->arch.get();
    AddrSpace *ram = a->getDefaultCodeSpace();
    uint64_t at = start;
    while (at < end) {
      CollectPcode pc;
      ghidra::int4 len = a->translate->oneInstruction(pc, Address(ram, at));
      if (len <= 0)
        break;
      uint32_t seq = 0;
      for (const auto &op : pc.ops) {
        PcodeOpOut o;
        o.addr = at;
        o.seq = seq++;
        o.opcode = rust::String(ghidra::get_opname(op.opc));
        o.has_output = op.has_out;
        if (op.has_out)
          o.output = toVarnode(op.out);
        else {
          o.output.space = rust::String();
          o.output.offset = 0;
          o.output.size = 0;
        }
        for (const auto &in : op.in)
          o.inputs.push_back(toVarnode(in));
        out.push_back(std::move(o));
      }
      at += static_cast<uint64_t>(len);
    }
    return out;
  });
}

namespace {

// Reaches the protected action list of a group through a member pointer of a derived class,
// which is the standard-conforming way to read a protected member.
struct GroupPeek : ghidra::ActionGroup {
  using ghidra::ActionGroup::list;
};

// Sets a start break point on `act` and every action below it. `Action::perform` then returns
// -1 at the start of each action and continues where it stopped on the next call, which gives
// the decompile a cooperative check point between actions (the decompiler's console uses the
// same break points for stepping). Rules inside a pool are not split further.
void breakEverywhere(ghidra::Action *act) {
  act->setBreakPoint(ghidra::Action::break_start, act->getName());
  if (auto *g = dynamic_cast<ghidra::ActionGroup *>(act)) {
    std::vector<ghidra::Action *> ghidra::ActionGroup::*members = &GroupPeek::list;
    for (ghidra::Action *child : g->*members)
      breakEverywhere(child);
  }
}

struct ScopePeek : ghidra::ScopeInternal {
  using ghidra::ScopeInternal::nametree;
  using ghidra::ScopeInternal::nextUniqueId;
};

// The global variables a decompile discovers (ActionMapGlobals adds them to the global scope,
// with the type this function uses them as) are removed again when the decompile ends, after
// its analysis is cleared. Kept, they would carry their type into the next decompiles, whose
// output then depended on what was decompiled before (`pcRam00103fe0` or `lRam00103fe0`); in
// Ghidra they are not saved either. Every decompile thus starts from the session's edits alone,
// which is what lets another session with the same edits give the same answers.
class DiscoveredGlobals {
  ghidra::Architecture *arch;
  Funcdata *fd;
  ghidra::ScopeInternal *scope;
  ghidra::uint8 mark = 0;

public:
  DiscoveredGlobals(ghidra::Architecture *a, Funcdata *f)
      : arch(a), fd(f),
        scope(dynamic_cast<ghidra::ScopeInternal *>(a->symboltab->getGlobalScope())) {
    if (scope != nullptr)
      mark = scope->*(&ScopePeek::nextUniqueId);
  }
  DiscoveredGlobals(const DiscoveredGlobals &) = delete;
  DiscoveredGlobals &operator=(const DiscoveredGlobals &) = delete;
  ~DiscoveredGlobals() {
    if (scope == nullptr || scope->*(&ScopePeek::nextUniqueId) == mark)
      return;
    try {
      // the analysis refers to the symbols until it is cleared
      if (fd->isProcStarted())
        arch->clearAnalysis(fd);
      // the low 40 bits of a symbol id are the scope's counter when it was added
      std::vector<Symbol *> added;
      for (Symbol *s : scope->*(&ScopePeek::nametree))
        if ((s->getId() & 0xffffffffffULL) >= mark)
          added.push_back(s);
      for (Symbol *s : added)
        scope->removeSymbol(s);
    } catch (...) {
      // a symbol that cannot be removed stays; the next decompile still works
    }
  }
};

Funcdata *functionAt(ghidra::Architecture *a, uint64_t addr) {
  Address at(a->getDefaultCodeSpace(), addr);
  ghidra::Scope *global = a->symboltab->getGlobalScope();
  Funcdata *fd = global->queryFunction(at);
  if (fd == nullptr) {
    std::string name;
    a->nameFunction(at, name);
    fd = global->addFunction(at, name)->getFunction();
  }
  return fd;
}

// Before the analysis: the user's types for locals go into the local scope as type-locked
// symbols (a name too when the user gave one; else the decompiler names it as any other).
// Symbols of an earlier round are taken out first; a variable the scope already has a symbol for
// (a parameter of a locked prototype) keeps its type and is only renamed afterwards.
void applyLocalTypes(Session::Impl *impl, ghidra::Architecture *a, Funcdata *fd, uint64_t fad,
                     std::vector<std::string> &warnings) {
  ghidra::ScopeLocal *sc = fd->getScopeLocal();
  auto &added = impl->addedLocals[fad];
  for (const auto &sp : added) {
    ghidra::SymbolEntry *e = sc->findAddr(Address(sp.first, sp.second), Address());
    if (e != nullptr && e->getSymbol()->getCategory() == ghidra::Symbol::no_category)
      sc->removeSymbol(e->getSymbol());
  }
  added.clear();
  auto it = impl->locals.find(fad);
  if (it == impl->locals.end())
    return;
  for (const auto &ov : it->second) {
    if (ov.decl.empty())
      continue;
    Address at(ov.space, ov.offset);
    if (sc->findAddr(at, Address()) != nullptr)
      continue;
    try {
      std::istringstream s{ov.decl};
      std::string ignored;
      ghidra::Datatype *ct = ghidra::parse_type(s, ignored, a);
      ghidra::int4 size = ct->getSize();
      if (size <= 0) {
        warnings.push_back("the type of the local at " + ov.space->getName() +
                           " has no size and was not applied");
        continue;
      }
      // A local that runs past the end of its space (a stack local past the frame base, into
      // the return address) or over another variable's storage crashes the analysis.
      ghidra::uintb highest = ov.space->getHighest();
      bool wraps = ov.offset > highest || static_cast<ghidra::uintb>(size - 1) > highest - ov.offset;
      if (wraps || sc->findOverlap(at, size) != nullptr) {
        warnings.push_back("the type of the local at " + ov.space->getName() +
                           " is larger than its storage (it overlaps another variable or the "
                           "frame base) and was not applied");
        continue;
      }
      ghidra::SymbolEntry *e = sc->addSymbol(ov.name, ct, at, Address());
      if (e == nullptr) {
        warnings.push_back("the type of the local at " + ov.space->getName() +
                           " overlaps another variable and was not applied");
        continue;
      }
      sc->setAttribute(e->getSymbol(),
                       ov.name.empty() ? ghidra::Varnode::typelock
                                       : (ghidra::Varnode::typelock | ghidra::Varnode::namelock));
      added.emplace_back(ov.space, ov.offset);
    } catch (const ghidra::LowlevelError &e) {
      warnings.push_back("a local's type was not applied: " + e.explain);
    }
  }
}

// After the analysis, before printing: names for the locals that got no symbol of ours above.
void applyLocalNames(Session::Impl *impl, Funcdata *fd, uint64_t fad,
                     std::vector<std::string> &warnings) {
  auto it = impl->locals.find(fad);
  if (it == impl->locals.end())
    return;
  ghidra::ScopeLocal *sc = fd->getScopeLocal();
  for (const auto &ov : it->second) {
    if (ov.name.empty())
      continue;
    Address at(ov.space, ov.offset);
    ghidra::Symbol *sym = nullptr;
    for (auto v = fd->beginLoc(at); v != fd->endLoc(at) && sym == nullptr; ++v) {
      ghidra::HighVariable *high = (*v)->getHigh();
      ghidra::Symbol *cand = high != nullptr ? high->getSymbol() : nullptr;
      if (cand == nullptr)
        continue;
      for (ghidra::int4 i = 0; i < cand->numEntries() && sym == nullptr; ++i) {
        const ghidra::MapEntry *m = dynamic_cast<const ghidra::MapEntry *>(cand->getMapEntry(i));
        if (m != nullptr && m->getAddr() == at)
          sym = cand;
      }
    }
    if (sym == nullptr) {
      warnings.push_back("no variable at " + ov.space->getName() + " to rename to " + ov.name);
      continue;
    }
    if (sym->getName() == ov.name)
      continue;
    try {
      sc->renameSymbol(sym, ov.name);
      sc->setAttribute(sym, ghidra::Varnode::namelock);
    } catch (const ghidra::LowlevelError &e) {
      warnings.push_back("cannot name a local " + ov.name + ": " + e.explain);
    }
  }
}

// The names Ghidra's Java side gives the stack variables of the frame: `local_<hex offset>` where
// the decompiler alone says `uStack_<hex offset>` (any type prefix; the caller-allocated `X` and
// unusual `Y` regions keep the decompiler's names).
void nameStackLocals(Funcdata *fd) {
  ghidra::AddrSpace *stack = fd->getArch()->getStackSpace();
  if (stack == nullptr)
    return;
  ghidra::ScopeLocal *sc = fd->getScopeLocal();
  std::set<ghidra::Symbol *> seen;
  for (auto v = fd->beginLoc(stack); v != fd->endLoc(stack); ++v) {
    ghidra::HighVariable *high = (*v)->getHigh();
    ghidra::Symbol *sym = high != nullptr ? high->getSymbol() : nullptr;
    if (sym == nullptr || sym->isNameLocked() || !seen.insert(sym).second)
      continue;
    const std::string &n = sym->getName();
    size_t at = n.find("Stack_");
    if (at == std::string::npos || n.size() == at + 6)
      continue;
    bool plain = n.find_first_not_of("abcdefghijklmnopqrstuvwxyz") >= at &&
                 n.find_first_not_of("0123456789abcdef", at + 6) == std::string::npos;
    if (!plain)
      continue;
    try {
      sc->renameSymbol(sym, "local_" + n.substr(at + 6));
    } catch (const ghidra::LowlevelError &) {
    }
  }
}

} // namespace

void Session::ensure_function(uint64_t addr) {
  guarded("ensure_function", [&]() { functionAt(impl->arch.get(), addr); });
}

rust::Vec<JumpEdgeOut> Session::jump_tables(uint64_t addr) {
  const auto began = std::chrono::steady_clock::now();
  auto out = guarded("jump_tables", [&]() {
    ghidra::Architecture *a = impl->arch.get();
    Funcdata *fd = functionAt(a, addr);
    if (fd->isProcStarted())
      a->clearAnalysis(fd);
    // flow following alone recovers the jump tables (each on a partial copy of the function)
    fd->startProcessing();
    rust::Vec<JumpEdgeOut> out;
    for (ghidra::int4 i = 0; i < fd->numJumpTables(); ++i) {
      ghidra::JumpTable *jt = fd->getJumpTable(i);
      for (ghidra::int4 j = 0; j < jt->numEntries(); ++j) {
        JumpEdgeOut e;
        e.op = jt->getOpAddress().getOffset();
        e.target = jt->getAddressByIndex(j).getOffset();
        out.push_back(e);
      }
    }
    impl->errs.str(std::string());
    a->clearAnalysis(fd);
    return out;
  });
#ifdef __GLIBC__
  // the switch analysis of a big function allocates gigabytes in small pieces; without this the
  // freed pages stay with the process (each thread has its own arena), and a long discovery on
  // several threads grows without bound
  if (std::chrono::steady_clock::now() - began > std::chrono::milliseconds(200))
    malloc_trim(0);
#endif
  return out;
}

// The tables of a full decompile: switches nested in the cases of another one only recover
// once the actions have propagated what the outer switch implies, which flow following alone
// does not do. Stops at the deadline and returns what it has recovered by then.
rust::Vec<JumpEdgeOut> Session::jump_tables_deep(uint64_t addr, uint32_t timeout_ms) {
  const auto began = std::chrono::steady_clock::now();
  auto out = guarded("jump_tables_deep", [&]() {
    ghidra::Architecture *a = impl->arch.get();
    Funcdata *fd = functionAt(a, addr);
    if (fd->isProcStarted())
      a->clearAnalysis(fd);
    ghidra::Action *act = a->allacts.getCurrent();
    if (impl->broken != act) {
      breakEverywhere(act);
      impl->broken = act;
    }
    CallbackLoadImage *img = static_cast<CallbackLoadImage *>(a->loader);
    const auto deadline = began + std::chrono::milliseconds(timeout_ms);
    DiscoveredGlobals discovered(a, fd);
    act->reset(*fd);
    while (act->perform(*fd) < 0) {
      if (img->interrupted() ||
          (timeout_ms != 0 && std::chrono::steady_clock::now() >= deadline))
        break;
    }
    rust::Vec<JumpEdgeOut> out;
    for (ghidra::int4 i = 0; i < fd->numJumpTables(); ++i) {
      ghidra::JumpTable *jt = fd->getJumpTable(i);
      for (ghidra::int4 j = 0; j < jt->numEntries(); ++j) {
        JumpEdgeOut e;
        e.op = jt->getOpAddress().getOffset();
        e.target = jt->getAddressByIndex(j).getOffset();
        out.push_back(e);
      }
    }
    impl->errs.str(std::string());
    a->clearAnalysis(fd);
    return out;
  });
#ifdef __GLIBC__
  if (std::chrono::steady_clock::now() - began > std::chrono::milliseconds(200))
    malloc_trim(0);
#endif
  return out;
}

DecompOut Session::decompile(uint64_t addr, uint32_t timeout_ms) {
  const auto began = std::chrono::steady_clock::now();
  DecompOut result = guarded("decompile", [&]() {
    ghidra::Architecture *a = impl->arch.get();
    Funcdata *fd = functionAt(a, addr);
    if (fd->isProcStarted())
      a->clearAnalysis(fd);
    ghidra::Action *act = a->allacts.getCurrent();
    if (impl->broken != act) {
      breakEverywhere(act);
      impl->broken = act;
    }
    DecompOut out;
    out.timed_out = false;
    out.interrupted = false;
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    CallbackLoadImage *img = static_cast<CallbackLoadImage *>(a->loader);
    DiscoveredGlobals discovered(a, fd);
    std::vector<std::string> localWarnings;
    applyLocalTypes(impl.get(), a, fd, addr, localWarnings);
    act->reset(*fd);
    while (act->perform(*fd) < 0) {
      if (img->interrupted())
        out.interrupted = true;
      else if (timeout_ms != 0 && std::chrono::steady_clock::now() >= deadline)
        out.timed_out = true;
      else
        continue;
      impl->errs.str(std::string());
      a->clearAnalysis(fd);
      return out;
    }

    applyLocalNames(impl.get(), fd, addr, localWarnings);
    nameStackLocals(fd);
    TokenEmit *te = impl->printer->tokens();
    te->reset();
    std::ostringstream sink;
    impl->printer->setOutputStream(&sink);
    impl->printer->docFunction(fd);

    out.text = rust::String(te->text());
    for (auto &t : te->tokens())
      out.tokens.push_back(std::move(t));
    for (auto &w : te->warnings())
      out.warnings.push_back(rust::String(w));
    for (const auto &w : localWarnings)
      out.warnings.push_back(rust::String(w));
    std::string errs = impl->errs.str();
    if (!errs.empty()) {
      out.warnings.push_back(rust::String(errs));
      impl->errs.str(std::string());
    }
    te->reset();
    // the next decompile starts from a fresh state; the analysis is not kept
    a->clearAnalysis(fd);
    return out;
  });
#ifdef __GLIBC__
  // as in jump_tables: a big decompile frees gigabytes into its thread's arena, and with several
  // sessions decompiling at once (the analysis job) every arena would keep its high-water mark
  // (Qt Widgets grew to 25 GB). Only after the big ones: the trim locks every arena in turn, and
  // after every decompile over 200 ms it made the analysis of Qt Core a quarter slower.
  if (std::chrono::steady_clock::now() - began > std::chrono::seconds(2))
    malloc_trim(0);
#endif
  return result;
}

void Session::declare_type(rust::Str decl) {
  guarded("declare_type", [&]() {
    std::istringstream s{std::string(decl)};
    ghidra::parse_C(impl->arch.get(), s);
  });
}

// A data symbol of the global scope: the user's or the symbol table's name, name-locked, and
// type-locked when `decl` ("int x", "char *x[4]") gives a type. Without one the symbol is an
// undefined type of `size` bytes and the decompiler infers the type from the uses.
static void putGlobal(Session::Impl *impl, uint64_t addr, rust::Str name, rust::Str decl,
                      uint32_t size, bool lockName) {
  {
    ghidra::Architecture *a = impl->arch.get();
    Address at(a->getDefaultCodeSpace(), addr);
    ghidra::Scope *global = a->symboltab->getGlobalScope();
    ghidra::TypeFactory *tf = a->types;
    ghidra::Datatype *ct = nullptr;
    std::string text(decl);
    if (!text.empty()) {
      std::istringstream s{text};
      std::string ignored;
      ct = ghidra::parse_type(s, ignored, a);
    }
    bool typed = ct != nullptr;
    if (!typed) {
      if (size == 0 || size > 4096)
        size = 1;
      ct = size <= 8 ? tf->getBase(size, ghidra::TYPE_UNKNOWN)
                     : tf->getTypeArray(size, tf->getBase(1, ghidra::TYPE_UNKNOWN));
    }
    // whatever data symbol is here goes first (function symbols are left alone)
    ghidra::SymbolEntry *old = global->findAddr(at, Address());
    if (old != nullptr && dynamic_cast<ghidra::FunctionSymbol *>(old->getSymbol()) == nullptr)
      global->removeSymbol(old->getSymbol());
    ghidra::SymbolEntry *e = global->addSymbol(std::string(name), ct, at, Address());
    if (e == nullptr)
      return;
    uint32_t attr = (lockName ? uint32_t(ghidra::Varnode::namelock) : 0u) |
                    (typed ? uint32_t(ghidra::Varnode::typelock) : 0u);
    if (attr != 0)
      global->setAttribute(e->getSymbol(), attr);
  }
}

void Session::set_global(uint64_t addr, rust::Str name, rust::Str decl, uint32_t size) {
  guarded("set_global", [&]() { putGlobal(impl.get(), addr, name, decl, size, true); });
}

// An automatic label (Ghidra's DAT_, PTR_ and s_ names): like `set_global`, without the name lock.
void Session::set_label(uint64_t addr, rust::Str name, rust::Str decl, uint32_t size) {
  guarded("set_label", [&]() { putGlobal(impl.get(), addr, name, decl, size, false); });
}

void Session::remove_global(uint64_t addr) {
  guarded("remove_global", [&]() {
    ghidra::Architecture *a = impl->arch.get();
    Address at(a->getDefaultCodeSpace(), addr);
    ghidra::Scope *global = a->symboltab->getGlobalScope();
    ghidra::SymbolEntry *old = global->findAddr(at, Address());
    if (old != nullptr && dynamic_cast<ghidra::FunctionSymbol *>(old->getSymbol()) == nullptr)
      global->removeSymbol(old->getSymbol());
  });
}

void Session::set_prototype(uint64_t addr, rust::Str decl) {
  guarded("set_prototype", [&]() {
    ghidra::Architecture *a = impl->arch.get();
    Funcdata *fd = functionAt(a, addr);
    ghidra::PrototypePieces pieces;
    std::string text(decl);
    if (text.find(';') == std::string::npos)
      text += ';'; // the grammar wants a complete declaration
    std::istringstream s{text};
    ghidra::parse_protopieces(pieces, s, a);
    if (pieces.model == nullptr)
      pieces.model = a->defaultfp;
    bool noreturn = fd->getFuncProto().isNoReturn();
    fd->getFuncProto().setPieces(pieces);
    fd->getFuncProto().setNoReturn(noreturn);
  });
}

void Session::set_noreturn(uint64_t addr, bool noreturn) {
  guarded("set_noreturn", [&]() {
    functionAt(impl->arch.get(), addr)->getFuncProto().setNoReturn(noreturn);
  });
}

void Session::remove_function(uint64_t addr) {
  guarded("remove_function", [&]() {
    ghidra::Architecture *a = impl->arch.get();
    Address at(a->getDefaultCodeSpace(), addr);
    ghidra::Scope *global = a->symboltab->getGlobalScope();
    Funcdata *fd = global->queryFunction(at);
    if (fd != nullptr)
      global->removeSymbol(fd->getSymbol());
  });
}

void Session::set_convention(uint64_t addr, rust::Str name) {
  guarded("set_convention", [&]() {
    ghidra::Architecture *a = impl->arch.get();
    std::string nm(name);
    ghidra::ProtoModel *model = a->defaultfp;
    if (!nm.empty()) {
      if (!a->hasModel(nm))
        throw std::runtime_error("unknown calling convention " + nm);
      model = a->getModel(nm);
    }
    Funcdata *fd = functionAt(a, addr);
    fd->getFuncProto().setModel(model);
    fd->getFuncProto().setModelLock(!nm.empty());
  });
}

void Session::set_local(uint64_t fad, rust::Str space, uint64_t offset, rust::Str name,
                        rust::Str decl) {
  guarded("set_local", [&]() {
    AddrSpace *spc = impl->arch->getSpaceByName(std::string(space));
    if (spc == nullptr)
      throw std::runtime_error("no address space " + std::string(space));
    auto &list = impl->locals[fad];
    for (size_t i = 0; i < list.size(); ++i)
      if (list[i].space == spc && list[i].offset == offset) {
        list.erase(list.begin() + static_cast<std::ptrdiff_t>(i));
        break;
      }
    if (!name.empty() || !decl.empty())
      list.push_back({spc, offset, std::string(name), std::string(decl)});
    if (list.empty())
      impl->locals.erase(fad);
  });
}

void Session::set_comments(uint64_t fad, rust::Slice<const CommentIn> comments) {
  guarded("set_comments", [&]() {
    ghidra::Architecture *a = impl->arch.get();
    AddrSpace *ram = a->getDefaultCodeSpace();
    Address f(ram, fad);
    const ghidra::uint4 user = ghidra::Comment::user1 | ghidra::Comment::user2 |
                               ghidra::Comment::user3 | ghidra::Comment::header;
    a->commentdb->clearType(f, user);
    for (const CommentIn &c : comments)
      a->commentdb->addCommentNoDuplicate(c.kind & user, f, Address(ram, c.addr),
                                          std::string(c.text));
  });
}

} // namespace kraken
