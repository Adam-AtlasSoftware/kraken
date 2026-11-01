#!/usr/bin/env python3
"""Emit ground truth for the Mach-O set of the KRAKEN corpus (stdlib only; run as `python3 -I`).

Like the PE set, the binaries carry no debug information. The truth is the symbol table of the
linked file (`llvm-nm`), with the functions that lie in `__TEXT,__text`; a size is the distance to
the next symbol or to the end of the section. Stripped binaries take the truth of their twin.

Output: corpus/macho/truth/<binary>.json
  {binary, ground_truth_from, sha256, source_file, opt, arch,
   functions:[{name, demangled, entry, size}]}
`name` is the Mach-O symbol (`_main`), `demangled` the C name (`main`).
"""
import hashlib
import json
import re
import subprocess
from pathlib import Path

CORPUS = Path(__file__).resolve().parent.parent
MACHO = CORPUS / "macho"
BIN = MACHO / "bin"
TRUTH = MACHO / "truth"
NAME_RE = re.compile(r"^(?P<prog>[a-z_]+)-(?P<arch>x64|arm64)-(?P<opt>O[0-9])"
                     r"(?P<strip>-stripped)?(?P<classic>-classic)?(?:\.dylib)?$")
SECTION_RE = re.compile(r"^\s*\d+\s+__text\s+([0-9a-f]+)\s+([0-9a-f]+)\s")


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def text_range(path):
    for line in run("llvm-objdump", "--section-headers", str(path)).splitlines():
        m = SECTION_RE.match(line)
        if m:
            size, start = int(m.group(1), 16), int(m.group(2), 16)
            return start, start + size
    raise SystemExit(f"{path}: no __text")


def functions(path):
    lo, hi = text_range(path)
    syms = []
    for line in run("llvm-nm", "--defined-only", "-n", str(path)).splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in "Tt" and lo <= int(parts[0], 16) < hi:
            syms.append((int(parts[0], 16), parts[2]))
    out = []
    for i, (addr, name) in enumerate(syms):
        end = syms[i + 1][0] if i + 1 < len(syms) else hi
        out.append({"name": name, "demangled": name.removeprefix("_"),
                    "entry": hex(addr), "size": end - addr})
    return out


def main():
    TRUTH.mkdir(exist_ok=True)
    for path in sorted(BIN.iterdir()):
        m = NAME_RE.match(path.name)
        if not m:
            continue
        twin = path.name.replace("-stripped", "")
        source = f"macho/src/{m['prog']}.c" if m["prog"] == "mac_lib" else f"src/{m['prog']}.c"
        truth = {
            "binary": path.name,
            "ground_truth_from": twin,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "source_file": source,
            "opt": m["opt"],
            "arch": m["arch"],
            "functions": functions(BIN / twin),
        }
        (TRUTH / f"{path.name}.json").write_text(json.dumps(truth, indent=1) + "\n")
        print(f"{path.name}: {len(truth['functions'])} functions")


if __name__ == "__main__":
    main()
