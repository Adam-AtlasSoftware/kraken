#!/usr/bin/env python3
"""Emit ground truth for the PE set of the KRAKEN corpus (stdlib only; run as `python3 -I`).

The PE binaries carry no debug information (like a Windows binary without its PDB), so the truth
comes from the toolchain: the functions are the text symbols of the program's own object file
(`corpus/pe/.build/<arch>-<opt>/<program>.o`, kept by build.sh), placed at the address the
linked image's COFF symbol table gives them. Sizes come from the objects' DWARF (build.sh compiles
with -g and links with --strip-debug, so the images have none). Stripped
binaries take the truth of their unstripped twin. Needs binutils with PE support (`nm`,
`objdump`; the host's GNU binutils usually have it, or the mingw-w64 ones).

Output: corpus/pe/truth/<binary>.json
  {binary, ground_truth_from, sha256, source_file, opt, arch,
   functions:[{name, demangled, entry, size}]}
`name` is the COFF symbol (`_main`, `_on_tls@12` on x86), `demangled` the C name (`main`,
`on_tls`). Entries are virtual addresses at the image base the PE header names.
"""
import hashlib
import json
import re
import subprocess
from pathlib import Path

CORPUS = Path(__file__).resolve().parent.parent
PE = CORPUS / "pe"
BIN = PE / "bin"
BUILD = PE / ".build"
TRUTH = PE / "truth"
SOURCES = {"win_tls": "pe/src/win_tls.c", "win_dll": "pe/src/win_dll.c",
           "switch_vm": "src/switch_vm.c"}
NAME_RE = re.compile(r"^(?P<prog>[a-z_]+)-(?P<arch>x64|x86)-(?P<opt>O[0-9])(?P<strip>-stripped)?"
                     r"\.(?:exe|dll)$")


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def text_symbols(path):
    """[(addr, name)] of the defined text symbols (no section symbols), in address order."""
    out = []
    for line in run("nm", "--defined-only", "-n", str(path)).splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[1] not in "Tt" or parts[2].startswith("."):
            continue
        out.append((int(parts[0], 16), parts[2]))
    return out


DIE_RE = re.compile(r"^\s*<(\d+)><([0-9a-f]+)>:.*\((DW_TAG_\w+)\)")
ATTR_RE = re.compile(r"^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*)$")
INDIRECT_RE = re.compile(r"^\(indirect[^)]*\):\s*(.*)$")


def object_sizes(path):
    """{(function name, offset in its section): size} from the DWARF of an object file (`DW_AT_high_pc` is the length)."""
    dies, cur = [], None
    for line in run("objdump", "--dwarf=info", str(path)).splitlines():
        m = DIE_RE.match(line)
        if m:
            cur = {"off": int(m.group(2), 16), "tag": m.group(3), "attrs": {}}
            dies.append(cur)
            continue
        m = ATTR_RE.match(line)
        if m and cur is not None:
            v = m.group(2)
            ind = INDIRECT_RE.match(v)
            cur["attrs"].setdefault(m.group(1), (ind.group(1) if ind else v).strip())
    by_off = {d["off"]: d for d in dies}

    def name_of(d):
        for _ in range(8):
            if d is None:
                return None
            if "DW_AT_name" in d["attrs"]:
                return d["attrs"]["DW_AT_name"]
            link = d["attrs"].get("DW_AT_abstract_origin") or d["attrs"].get("DW_AT_specification")
            m = re.match(r"<0x([0-9a-f]+)>", link or "")
            d = by_off.get(int(m.group(1), 16)) if m else None
        return None

    sizes = {}
    for d in dies:
        a = d["attrs"]
        if d["tag"] == "DW_TAG_subprogram" and "DW_AT_low_pc" in a and "DW_AT_high_pc" in a:
            name = name_of(d)
            if name:
                low = int(a["DW_AT_low_pc"].split()[0], 16)
                sizes[(name, low)] = int(a["DW_AT_high_pc"].split()[0], 16)
    return sizes


def c_name(sym, arch):
    if arch == "x86":
        sym = sym[1:] if sym.startswith("_") else sym
        sym = re.sub(r"@\d+$", "", sym)
    return sym


def object_functions(path):
    """[(section, offset, name)] of the functions an object file defines (`objdump -t`)."""
    out = []
    for line in run("objdump", "-t", str(path)).splitlines():
        m = re.match(r"^\[\s*\d+\]\(sec\s+(\d+)\)\(fl [^)]*\)\(ty\s+20\)\(scl\s+\d+\) \(nx \d+\) "
                     r"0x([0-9a-f]+) (\S+)$", line)
        if m and int(m.group(1)) > 0:
            out.append((int(m.group(1)), int(m.group(2), 16), m.group(3)))
    return out


def truth_for(binary, twin, prog, arch, opt):
    obj = BUILD / f"{arch}-{opt}" / f"{prog}.o"
    own = object_functions(obj)
    by_name = {}
    for addr, name in text_symbols(BIN / twin):
        by_name.setdefault(name, []).append(addr)
    sizes = object_sizes(obj)
    # a name defined once in the image places its object section; the static inline wrappers of
    # mingw's headers (`printf`, `fprintf`) exist in several objects and are placed through it
    anchor = {}
    for sec, off, name in own:
        if len(by_name.get(name, [])) == 1:
            anchor.setdefault(sec, by_name[name][0] - off)
    seen, offsets = {}, {}
    for sec, off, name in own:
        offsets[name] = off
        cands = by_name.get(name, [])
        if sec in anchor and anchor[sec] + off in cands:
            seen[name] = anchor[sec] + off
        elif len(cands) == 1:
            seen[name] = cands[0]
        else:
            raise SystemExit(f"{twin}: cannot place {name} ({len(cands)} candidates)")
    functions = []
    for name, addr in sorted(seen.items(), key=lambda kv: kv[1]):
        # a clone (`fprintf.constprop.0`) has the DWARF name of its origin
        size = sizes.get((c_name(name, arch).split(".")[0], offsets[name]))
        if size is None:
            raise SystemExit(f"{twin}: no DWARF size for {name}")
        functions.append({"name": name, "demangled": c_name(name, arch),
                          "entry": f"{addr:#x}", "size": size})
    data = (BIN / binary).read_bytes()
    return {
        "binary": binary,
        "ground_truth_from": twin,
        "sha256": hashlib.sha256(data).hexdigest(),
        "source_file": SOURCES[prog],
        "opt": opt,
        "arch": arch,
        "functions": functions,
    }


def main():
    TRUTH.mkdir(exist_ok=True)
    for path in sorted(BIN.iterdir()):
        m = NAME_RE.match(path.name)
        if not m:
            continue
        twin = path.name.replace("-stripped", "")
        t = truth_for(path.name, twin, m["prog"], m["arch"], m["opt"])
        out = TRUTH / f"{path.name}.json"
        out.write_text(json.dumps(t, indent=2) + "\n")
        print(f"{out.relative_to(CORPUS)}: {len(t['functions'])} functions")


if __name__ == "__main__":
    main()
