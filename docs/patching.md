# Byte patching

Byte patches let you change a program's bytes — overwrite an instruction, flip a constant, blank a
call — and produce a patched copy of the binary, or run one in the emulator to see what the change
does. Patches are a separate overlay over the program's bytes; they are not analysis annotations and
they change nothing until you export or run them.

```
patch_set {"address": "0x401136", "bytes": "9090", "note": "two NOPs over the jump"}
```

## In the window

Everything below is also in the GUI, under the **Patch** menu:

1. **Stage a patch.** In the **Listing**, click an instruction and press **Patch bytes**; in the
   **Hex** view, select bytes and press **Patch selection** (or **Patch > Patch bytes here...**).
   The dialog shows the instruction and the bytes there now. Type the new instruction
   (`mov eax, 0x7`, in either case) and press Enter: it is assembled for that address and its
   shortest encoding goes in the hex field, with the other encodings offered beside it. Several
   instructions can be typed at once, separated by `;`. On the native engine, function and symbol
   names work as operands (`call cmp_id`), so do labels (`again: dec ecx; jnz again`), relative
   branches are encoded for the address they sit at, the result is decoded back through Sleigh to
   check it means what you typed, and it is padded with `nop`s to the next instruction boundary
   (a note says how many following instructions the bytes replace). When the replacement is
   shorter than the instruction it says so, and on x86 **Fill with nop** pads it with `90`. A
   longer one is flagged too, since it overwrites what follows. The Ghidra engine assembles with
   its SLEIGH assembler; the native engine assembles x86 and x86-64 itself, and ARM, AArch64 and
   RISC-V through `llvm-mc` when it is installed (otherwise it says so; type the hex). Branch
   targets for those are numbers, as `llvm-mc` reads them.
   ![The patch dialog: the instruction there now, a new instruction assembled to 31 c0 with its other encoding, and the note that the rest of the instruction stays](images/patch-dialog.png)

2. **Check it.** **Patch > Show patches** opens the **Patches** tab: every staged patch with its
   original and new bytes, note and author, with **Edit** and **Remove**. **Run original vs
   patched** runs the program twice in the emulator and puts the two runs side by side. Staged
   bytes are tinted in the Hex view (which keeps showing the bytes on disk).
   ![The Patches tab with one staged patch, its original and new bytes, and the Run, Export and Refresh buttons; the staged bytes tinted in the Hex view](images/patches.png)

3. **Export.** **Export patched binary...** asks where to write the copy (type a path, a relative
   one lands in the project folder, or press **Browse...** for a save dialog), then asks for
   approval like every dangerous command. When it is written the window shows the file's
   **SHA-256** (with **Copy SHA-256**) and **Open folder**; the Patches tab keeps the last one.
   `patch_export` returns the same hash as `sha256`.

### One-click patches

Right-click an instruction in the **Listing** and open **Patch** (in the **Decompiler** only
**Make function return...** and **Fill...** apply):

- **NOP this** replaces the instruction with NOPs in the processor's own encoding (x86 gets the
  multi-byte forms, ARM, Thumb, AArch64 and RISC-V their own);
- **Invert branch**, **Always take branch** and **Never take branch** change a conditional jump
  (x86 `jcc` short and near, ARM and Thumb `b<cond>`, `cbz`, `cbnz`, AArch64 `b.cond`, `cbz`,
  `cbnz`, `tbz`, `tbnz`, RISC-V branches); on anything else they say it is not a conditional
  branch;
- **Make function return...** makes a function return a number right away;
- **Fill...** fills a range with a repeated byte.

Each opens a small preview first: the bytes there now, the bytes that will be written and the
new disassembly. **Apply** records an ordinary patch, so it shows in the Patches tab and the
History and **Undo** takes it back. None of this needs an assembler, so it works on every engine.

The same intents are commands. Each takes `"preview": true` to show what it would write without
recording it:

```
patch_branch {"address": "0x401136", "mode": "invert"}
patch_nop {"address": "0x401140", "count": 2}
patch_return {"address": "0x401200", "value": 1}
patch_fill {"address": "0x402000", "length": 16, "pattern": "cc"}
patch_constant {"address": "0x401150", "value": 100}
```

`patch_constant` changes the immediate of one instruction without changing its length (x86
`mov`/`cmp`/`add`/..., AArch64 `mov`/`add`/`sub`/`cmp`, ARM and Thumb data-processing, RISC-V
`addi`/`lui`); a value the encoding cannot hold is refused instead of overflowing. Two patches
may not overlap: setting one over bytes another covers is refused (remove the old one first), and
for an agent it would never apply on its own. Replacing the patch at the same address is fine.

### Edit the C instead (experimental)

With a function open, **Patch function** in the Decompiler opens the **Edit** tab next to it:
the function's C, editable. Change what you want (a constant, a comparison, which branch runs)
and press **Plan patch**. The assistant's model gets the decompile, your edit and the disassembly
and plans the smallest in-place byte change that does the same; KRAKEN then checks the plan
before you see it:

- every patch must lie inside the function's instructions, replace bytes with the same number of
  bytes, and actually change something; the original bytes come from the disassembly, never
  from the model;
- the patched bytes are decompiled again: a copy of the binary with the patches goes into a
  temporary directory and a second engine of the project's kind decompiles the function, and
  the model compares that with your edit. The tab says **Verified**, **Partly verified**, **Not
  verified**, or **Not checked** when the second engine could not run, and shows the patched
  decompile. A failed check is planned again once with what it saw.

![The Edit tab next to the decompiler: the edited C on the left, the plan with its verdict and the patch on the right](images/edit-tab.png)

**Stage patches** stages the plan with `patch_set` (each patch's note says it came from your
edit); **Run original vs patched** then compares the two in the Patches tab. It works best for
small, local changes: an edit that needs more room, a new call or new data comes back with no
patches and says why. Planning costs AI calls on the assistant's model (two per round) and asks
first like other AI work. The command behind it is `patch_from_source`, a job that only plans:

```
patch_from_source {"address": "0x401136", "source": "int f(void)\n{\n  return 7;\n}"}
```

The assistant can stage and remove patches too. Whether it may export is the assistant's
[danger mode](assistant.md#dangerous-commands-deny-ask-or-yolo): never (Deny), after asking you
(Ask, the default) or without asking (YOLO).

## How it works

A patch records an address, the **replacement** bytes you give, and the **original** bytes that were
there (read from the program when you set the patch). Keeping the originals means a patch can be
checked against the file before it is written and can be removed to get the exact bytes back.

Setting and removing a patch are edits in the project's edit log, like a rename: each shows in the
**History** tab with who made it and in which assistant or agent run, and **Undo**, undoing one
entry or undoing a whole run take it back (undoing a replacement brings the earlier patch back).
An agent's new patch applies at once; an agent replacing or removing a patch makes a proposal for
you to accept. Patches never reach the analysis engine and never alter the program you are
analysing. The commands:

- `patch_set` — record (or replace) the patch at an address. `bytes` is hex, with or without spaces
  and a leading `0x` (`"eb 10"`, `"eb10"` and `"0xEB10"` are the same two bytes). The replacement
  length decides how many original bytes are read; the address must be mapped and hold that many
  bytes. At most 4096 bytes per patch.
- `patch_remove` — delete the patch at an address, putting the overlay back the way it was.
- `patch_list` — every patch with its original and replacement bytes, note and who set it.
- `patch_export` — write a copy of the binary with every patch applied.
- `assemble` — one instruction to its encodings at an address (`assemble {"address":
  "0x401136", "text": "mov eax, 0x7"}`), shortest first; nothing is written.

Recording and removing patches are ordinary reversible edits to the overlay — nothing is written
to disk and nothing runs — so they do not ask for approval. Producing a patched binary with
`patch_export` is the **dangerous** step and asks every time (ADR 0005), whether the caller is you
or an agent.

## Exporting a patched binary

```
patch_export {"output_path": "patched.bin", "overwrite": true}
```

`patch_export` reads the project's binary, applies every patch to a fresh copy and writes it to
`output_path` (a relative path is taken relative to the project directory). The original file is
never touched, and on Unix the copy keeps the original's executable permission so it stays runnable.

Each patch's address is turned into a file offset through the binary's own layout — ELF program
headers, or PE and Mach-O sections. The file's own virtual addresses are tried first and then the
native engine's load base for a position-independent executable, and the recorded original bytes are
checked at the mapped offset before anything is written. If a patch does not line up — an address
that is in no part of the file that holds bytes, or bytes that are not what the patch recorded — the
export is refused with that patch named, rather than a corrupted file being written. The result lists
each patch and the offset it landed at.

## Running a patched copy in the emulator

Pass `patched: true` to [`emulate_run`](emulation.md) to run a copy with the patches applied instead
of the original:

```
emulate_run {"patched": true, "stdin": "hello\n"}
```

The patched copy is built in the run's private directory and, like any emulated run, executes fully
confined — nothing runs on your computer and nothing in the project changes. The `notes` say how many
patches were applied. It is the quickest way to tell whether a patch does what you intended before
you export a binary from it.
