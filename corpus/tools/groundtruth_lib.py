#!/usr/bin/env python3
"""Emit ground truth for the library set of the KRAKEN corpus (stdlib only; run as `python3 -I`).

The set (corpus/lib/bin, built by `corpus/build.sh lib`) is one small C library, libkr, as every
kind of library and object file. The truth comes from the toolchain's own view of each file, read
with the host's GNU binutils (which need PE support: `objdump -i` lists pe-x86-64 and pe-i386):

- functions: the function symbols of every object (ELF `STT_FUNC` with `st_size`; COFF symbols of
  type 0x20 with the length from the object's DWARF), per archive member; for the shared library
  and the DLLs, their addresses too (the DLL's from its COFF symbol table, its sizes from the
  objects in corpus/lib/.build, which build.sh keeps).
- exports: the global, visible definitions of an object or archive; the dynamic symbols of the
  shared library; the export table of a DLL (with ordinals).
- imports: the undefined symbols of an object or archive; for an import library, each imported
  symbol with its DLL.

Output: corpus/lib/truth/<file>.json
  {binary, sha256, kind, arch, members, functions:[{member, name, demangled, size, entry?}],
   exports:[{name, ordinal?}], imports:[{name, library?}]}
`member` is null outside archives; `entry` is set for linked files only (link-time addresses).
"""
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

CORPUS = Path(__file__).resolve().parent.parent
LIB = CORPUS / "lib"
BIN = LIB / "bin"
BUILD = LIB / ".build"
TRUTH = LIB / "truth"


def run(*args, cwd=None):
    return subprocess.run(args, check=True, capture_output=True, text=True, cwd=cwd).stdout


def c_name(sym, x86):
    if x86:
        sym = sym[1:] if sym.startswith("_") else sym
        sym = re.sub(r"@\d+$", "", sym)
    return sym


def members(path):
    """[(member name, extracted path)] of an archive, in archive order."""
    tmp = Path(tempfile.mkdtemp(prefix="kr-truth-"))
    names = run("ar", "t", str(path)).split()
    out = []
    for i, name in enumerate(names):
        # `ar xN` takes the n-th member of a name; members here are unique, so N is always 1
        dest = tmp / f"{i:03}-{name}"
        dest.write_bytes(subprocess.run(["ar", "p", str(path), name], check=True,
                                        capture_output=True).stdout)
        out.append((name, dest))
    return out


ELF_SYM = re.compile(r"^\s*\d+:\s+([0-9a-f]+)\s+(\d+)\s+(\w+)\s+(\w+)\s+(\w+)\s+(\S+)\s+(\S+)(?: \(\d+\))?$")


def elf_symbols(path, dynamic=False):
    """[(value, size, type, bind, visibility, ndx, name)] from `readelf -sW`."""
    out, table = [], None
    for line in run("readelf", "-sW", str(path)).splitlines():
        if line.startswith("Symbol table"):
            table = ".dynsym" if "'.dynsym'" in line else ".symtab"
            continue
        m = ELF_SYM.match(line)
        if m and table == (".dynsym" if dynamic else ".symtab"):
            v, size, typ, bind, vis, ndx, name = m.groups()
            out.append((int(v, 16), int(size), typ, bind, vis, ndx, name.split("@")[0]))
    return out


def elf_object(path, member):
    funcs, exports, imports = [], [], []
    for v, size, typ, bind, vis, ndx, name in elf_symbols(path):
        if typ == "FUNC" and ndx != "UND":
            funcs.append({"member": member, "name": name, "demangled": name, "size": size})
        if bind in ("GLOBAL", "WEAK") and ndx != "UND" and vis == "DEFAULT" and typ != "FILE":
            exports.append({"name": name})
        if ndx == "UND" and name and name != "_GLOBAL_OFFSET_TABLE_":
            imports.append({"name": name})
    return funcs, exports, imports


DIE_RE = re.compile(r"^\s*<(\d+)><([0-9a-f]+)>:.*\((DW_TAG_\w+)\)")
ATTR_RE = re.compile(r"^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*)$")


def dwarf_sizes(path):
    """{function name: size} from the DWARF of one object file (a clone such as
    `bump.constprop.0` names its origin through `DW_AT_abstract_origin`)."""
    dies, cur = {}, None
    for line in run("objdump", "--dwarf=info", str(path)).splitlines():
        m = DIE_RE.match(line)
        if m:
            cur = {"tag": m.group(3), "a": {}}
            dies[int(m.group(2), 16)] = cur
            continue
        m = ATTR_RE.match(line)
        if m and cur is not None:
            cur["a"].setdefault(m.group(1), m.group(2).strip())

    def name_of(d):
        for _ in range(8):
            if d is None:
                return None
            if "DW_AT_name" in d["a"]:
                return d["a"]["DW_AT_name"].split(":")[-1].strip()
            link = d["a"].get("DW_AT_abstract_origin") or d["a"].get("DW_AT_specification")
            m = re.match(r"<0x([0-9a-f]+)>", link or "")
            d = dies.get(int(m.group(1), 16)) if m else None
        return None

    sizes = {}
    for d in dies.values():
        if d["tag"] == "DW_TAG_subprogram" and "DW_AT_high_pc" in d["a"]:
            name = name_of(d)
            if name:
                sizes[name] = int(d["a"]["DW_AT_high_pc"].split()[0], 16)
    return sizes


COFF_SYM = re.compile(r"^\[\s*\d+\]\(sec\s+(-?\d+)\)\(fl [^)]*\)\(ty\s+([0-9a-f]+)\)\(scl\s+(\d+)\) "
                      r"\(nx \d+\) 0x([0-9a-f]+) (\S+)$")


def coff_object(path, member, x86):
    sizes = dwarf_sizes(path)
    funcs, exports, imports = [], [], []
    for line in run("objdump", "-t", str(path)).splitlines():
        m = COFF_SYM.match(line)
        if not m:
            continue
        sec, ty, scl, _, name = int(m.group(1)), m.group(2), int(m.group(3)), m.group(4), m.group(5)
        if sec > 0 and ty == "20":
            plain = c_name(name, x86) if scl == 2 or x86 else name
            size = sizes.get(plain.split(".")[0])
            if size is None:
                raise SystemExit(f"{path}: no DWARF size for {name}")
            funcs.append({"member": member, "name": name, "demangled": plain, "size": size})
        if scl == 2 and sec > 0 and not name.startswith("."):
            exports.append({"name": c_name(name, x86)})
        if scl == 2 and sec == 0 and int(m.group(4), 16) == 0 and not name.startswith("."):
            plain = name[len("__imp_"):] if name.startswith("__imp_") else name
            imports.append({"name": c_name(plain, x86)})
    return funcs, exports, imports


def import_library(path, x86):
    """[{name, library}] of an import library (GNU long format: `.idata$` members)."""
    dll, entries = None, []
    for name, member in members(path):
        syms = run("nm", str(member)).split("\n")
        # objdump fails on a member without either section; its output is still complete
        dump = subprocess.run(["objdump", "-s", "-j", ".idata$6", "-j", ".idata$7", str(member)],
                              capture_output=True, text=True).stdout
        sections, cur = {}, None
        for line in dump.splitlines():
            m = re.match(r"^Contents of section (\S+):", line)
            if m:
                cur = m.group(1)
                sections[cur] = b""
                continue
            m = re.match(r"^ [0-9a-f]+ ((?:[0-9a-f]{2,8} ?)+)", line)
            if m and cur:
                sections[cur] += bytes.fromhex(m.group(1).replace(" ", ""))
        if any(s.endswith("_iname") for s in syms) and ".idata$7" in sections:
            dll = sections[".idata$7"].split(b"\0")[0].decode()
        imp = [s.split()[-1] for s in syms if " I __imp_" in s]
        if imp:
            raw = sections.get(".idata$6", b"")[2:].split(b"\0")[0].decode()
            entries.append(raw or c_name(imp[0][len("__imp_"):], x86))
    return [{"name": n, "library": dll} for n in sorted(entries)]


def dll_exports(path):
    """[{name, ordinal}] from the export table (`objdump -p`); `name` is null for an export by
    ordinal only (NONAME)."""
    ordinals, named, table = [], {}, None
    for line in run("objdump", "-p", str(path)).splitlines():
        if line.startswith("Export Address Table -- "):
            table = "eat"
            continue
        if line.startswith("[Ordinal/Name Pointer] Table -- "):
            table = "names"
            continue
        if not line.strip():
            table = None
            continue
        m = re.match(r"^\s+\[\s*\d+\]\s+\+base\[\s*(\d+)\]\s+([0-9a-f]+)\s*(\S*)", line)
        if m and table == "eat":
            ordinals.append(int(m.group(1)))
        elif m and table == "names":
            named[int(m.group(1))] = m.group(3)
    return [{"name": named.get(o), "ordinal": o} for o in ordinals]


def kind_and_arch(path):
    head = path.read_bytes()[:8]
    fmt = run("objdump", "-f", str(path))
    arch = "x86" if ("i386" in fmt and "x86-64" not in fmt) else "x86-64"
    return head, arch


def truth(path):
    name = path.name
    head, arch = kind_and_arch(path)
    x86 = arch == "x86"
    win = "x64" in name or "x86" in name
    funcs, exports, imports, mlist, kind = [], [], [], [], None
    if head.startswith(b"!<arch>"):
        mlist = run("ar", "t", str(path)).split()
        if name.endswith(".dll.a"):
            kind = "import library"
            imports = import_library(path, x86)
        else:
            kind = ("Windows" if win else "Linux") + f" static library with {len(mlist)} objects"
            for member, extracted in members(path):
                f, e, i = (coff_object(extracted, member, x86) if win
                           else elf_object(extracted, member))
                funcs += f
                exports += e
                imports += i
            # a reference one member defines for another is no import
            defined = {e["name"] for e in exports}
            imports = [i for i in imports if i["name"] not in defined]
    elif name.endswith(".so"):
        kind = "Linux shared library"
        for v, size, typ, bind, vis, ndx, sym in elf_symbols(path):
            if typ == "FUNC" and ndx != "UND" and v:
                funcs.append({"member": None, "name": sym, "demangled": sym, "size": size,
                              "entry": f"{v:#x}"})
        for v, size, typ, bind, vis, ndx, sym in elf_symbols(path, dynamic=True):
            if ndx == "UND" and sym:
                imports.append({"name": sym})
            elif bind in ("GLOBAL", "WEAK") and sym:
                exports.append({"name": sym})
    elif name.endswith(".dll"):
        kind = "Windows DLL"
        build = BUILD / ("x86" if x86 else "x64")
        own = {}
        for obj in sorted(build.glob("*.obj")):
            for f in coff_object(obj, None, x86)[0]:
                own[f["name"]] = f
        for line in run("nm", "--defined-only", "-n", str(path)).splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[1] in "Tt":
                base = parts[2]
                f = own.get(base) or own.get(base.split(".")[0])
                if f and not any(x["entry"] == f"{int(parts[0], 16):#x}" for x in funcs):
                    funcs.append({**f, "name": base, "entry": f"{int(parts[0], 16):#x}"})
        exports = dll_exports(path)
    elif name.endswith(".o") or name.endswith(".obj"):
        kind = "COFF object" if win else "Linux object file"
        funcs, exports, imports = (coff_object(path, None, x86) if win
                                   else elf_object(path, None))
    dedup = lambda xs: sorted({json.dumps(x, sort_keys=True) for x in xs})
    return {
        "binary": name,
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "kind": kind,
        "arch": arch,
        "members": mlist,
        "functions": funcs,
        "exports": [json.loads(x) for x in dedup(exports)],
        "imports": [json.loads(x) for x in dedup(imports)],
    }


def main():
    TRUTH.mkdir(exist_ok=True)
    for path in sorted(BIN.iterdir()):
        t = truth(path)
        out = TRUTH / f"{path.name}.json"
        out.write_text(json.dumps(t, indent=2) + "\n")
        print(f"{out.relative_to(CORPUS)}: {t['kind']}, {len(t['functions'])} functions, "
              f"{len(t['exports'])} exports, {len(t['imports'])} imports")


if __name__ == "__main__":
    main()
