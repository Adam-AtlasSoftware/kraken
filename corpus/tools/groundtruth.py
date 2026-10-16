#!/usr/bin/env python3
"""Emit ground-truth JSON for the KRAKEN corpus (stdlib only; run as `python3 -I`).

For every unstripped binary in corpus/bin this reads DWARF via `readelf --debug-dump=info`
(set of source-level functions, entry address, size, source file) and `nm` (symbol names,
mangled and demangled). Stripped binaries (`*-stripped`) get the truth of their unstripped
twin: strip does not move code, so addresses are identical (verified via section headers).

Output: corpus/truth/<binary>.json
  {binary, ground_truth_from, sha256, source_file, opt, functions:[{name, demangled, entry, size}]}
"""
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

CORPUS = Path(__file__).resolve().parent.parent
BIN = CORPUS / "bin"
TRUTH = CORPUS / "truth"

DIE_RE = re.compile(r"^\s*<(\d+)><([0-9a-f]+)>:.*\((DW_TAG_\w+)\)")
ATTR_RE = re.compile(r"^\s*<[0-9a-f]+>\s+(DW_AT_\w+)\s*:\s*(.*)$")
INDIRECT_RE = re.compile(r"^\(indirect[^)]*\):\s*(.*)$")


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def attr_value(raw):
    m = INDIRECT_RE.match(raw)
    return (m.group(1) if m else raw).strip()


def parse_dies(path):
    """Return list of dicts {depth, off, tag, attrs}."""
    dies = []
    cur = None
    for line in run("readelf", "--debug-dump=info", str(path)).splitlines():
        m = DIE_RE.match(line)
        if m:
            cur = {"depth": int(m.group(1)), "off": int(m.group(2), 16),
                   "tag": m.group(3), "attrs": {}}
            dies.append(cur)
            continue
        m = ATTR_RE.match(line)
        if m and cur is not None:
            cur["attrs"].setdefault(m.group(1), attr_value(m.group(2)))
    return dies


def parse_nm(path, demangle):
    """Return {addr: (name, size)} for sized text symbols."""
    args = ["nm", "--defined-only", "-S", "-n"] + (["-C"] if demangle else []) + [str(path)]
    out = {}
    for line in run(*args).splitlines():
        parts = line.split(None, 3)
        if len(parts) != 4 or parts[2] not in "TtWw":
            continue
        addr, size = int(parts[0], 16), int(parts[1], 16)
        out.setdefault(addr, (parts[3], size))
    return out


def ref_off(v):
    m = re.match(r"<0x([0-9a-f]+)>", v)
    return int(m.group(1), 16) if m else None


def dwarf_name(die, by_off):
    """Resolve a subprogram's name through abstract_origin / specification links."""
    seen = 0
    while die is not None and seen < 8:
        a = die["attrs"]
        if "DW_AT_linkage_name" in a:
            return a["DW_AT_linkage_name"]
        if "DW_AT_name" in a:
            return a["DW_AT_name"]
        link = a.get("DW_AT_abstract_origin") or a.get("DW_AT_specification")
        die = by_off.get(ref_off(link)) if link else None
        seen += 1
    return None


def truth_for(path):
    dies = parse_dies(path)
    by_off = {d["off"]: d for d in dies}
    mangled = parse_nm(path, False)
    pretty = parse_nm(path, True)
    by_name = {}  # symbol name (mangled or plain) -> addr
    for addr, (n, _) in mangled.items():
        by_name.setdefault(n, addr)

    cu_name = None
    source_file = None
    funcs = {}
    for d in dies:
        if d["tag"] == "DW_TAG_compile_unit":
            cu_name = d["attrs"].get("DW_AT_name")
            if cu_name and cu_name.startswith("src/") and source_file is None:
                source_file = cu_name
            continue
        if d["tag"] != "DW_TAG_subprogram" or not (cu_name or "").startswith("src/"):
            continue
        a = d["attrs"]
        if "DW_AT_low_pc" in a and "DW_AT_high_pc" in a:
            entry = int(a["DW_AT_low_pc"].split()[0], 16)
            size = int(a["DW_AT_high_pc"].split()[0], 16)
        elif "DW_AT_ranges" in a:
            # Hot/cold split: DWARF has no single low_pc; locate the primary symbol by name.
            name = dwarf_name(d, by_off)
            entry = by_name.get(name)
            if entry is None:
                continue
            size = mangled[entry][1]
        else:
            continue  # declaration or abstract-only instance
        sym = mangled.get(entry)
        name = sym[0] if sym else (dwarf_name(d, by_off) or f"sub_{entry:x}")
        demangled = pretty.get(entry, (name, 0))[0]
        funcs[entry] = {"name": name, "demangled": demangled,
                        "entry": f"0x{entry:x}", "size": size}
    return source_file, [funcs[k] for k in sorted(funcs)]


def text_layout(path):
    """(name, addr, size) of allocated sections, used to check stripped twins match."""
    out = []
    for line in run("readelf", "-SW", str(path)).splitlines():
        m = re.match(r"\s*\[\s*\d+\]\s+(\S+)\s+\S+\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)", line)
        if m and m.group(1).startswith((".text", ".init", ".fini", ".plt", ".rodata")):
            out.append((m.group(1), m.group(2), m.group(3)))
    return out


def main():
    TRUTH.mkdir(exist_ok=True)
    for old in TRUTH.glob("*.json"):
        old.unlink()
    bins = sorted(p for p in BIN.iterdir() if p.is_file())
    for p in bins:
        stripped = p.name.endswith("-stripped")
        twin = BIN / p.name[: -len("-stripped")] if stripped else p
        if stripped and text_layout(p) != text_layout(twin):
            sys.exit(f"{p.name}: section layout differs from twin {twin.name}")
        source_file, funcs = truth_for(twin)
        if not funcs:
            sys.exit(f"{twin.name}: no functions found")
        opt = re.search(r"-(O\d)", p.name).group(1)
        doc = {
            "binary": p.name,
            "ground_truth_from": twin.name,
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest(),
            "source_file": source_file,
            "opt": opt,
            "functions": funcs,
        }
        (TRUTH / f"{p.name}.json").write_text(json.dumps(doc, indent=2) + "\n")
        print(f"{p.name}: {len(funcs)} functions ({source_file})")


if __name__ == "__main__":
    main()
