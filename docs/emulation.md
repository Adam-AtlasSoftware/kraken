# Running the program in the emulator

`emulate_run` runs the executable a project was made from, with the standard input and arguments you
give it, and reports how it ended. It is how you (or the assistant) test a guess about what a program
does without running it on your computer.

```
emulate_run {"stdin": "hello\n", "argv": ["-v"]}
```

The result has `exit` (`code` with the exit code, `signal` with the signal number, `timeout`,
`step_limit`, or `unsupported` when the program used something the emulator cannot do), `stdout` and
`stderr` (the first 4000 characters of each, marked untrusted because the program wrote them),
`steps` (instructions executed), `truncated` and `notes` (the architecture, system calls the emulator
does not implement, files the program wrote).

## What it is

The program is interpreted instruction by instruction by `kraken-emu`, KRAKEN's emulator (icicle on
Ghidra's SLEIGH specs). Its Linux system calls are answered by KRAKEN's own layer, so the program
never runs natively and never makes a system call on your computer. The emulator itself runs in a
sandboxed child process (`kraken-emu-run`) that can read the program and the SLEIGH specs and write
one private directory.

- **Deterministic.** The clock starts at 2024-01-01 and advances with the instructions run, random numbers come from a
  fixed generator, the process id is fixed and no environment variables are passed. Two runs with the
  same input give the same output, byte for byte.
- **Files** exist only in a private directory (`/work` for the program) that is deleted after the
  run. Nothing is written into the project. Reading anything else of this computer is not possible.
- **No network.** Sockets, `fork`, `exec` and threads beyond one are not provided; such calls fail and
  are listed in `notes`.
- **A budget.** `max_steps` (default 20 million instructions, at most 200 million) and
  `timeout_seconds` (default 20, at most 120) end a runaway program with `step_limit` or `timeout`.
- **Architectures:** ELF programs for x86, x86-64, ARM, AArch64 and RISC-V. Windows and Mach-O
  programs are refused.

## Dynamic programs

A statically linked program runs as it is. A dynamically linked program needs its loader and C
library. The emulator reads them from a sysroot, `~/.cache/kraken-dev/emu-sysroots/<set>` (or
`$KRAKEN_EMU_SYSROOTS/<set>`), which `cargo xtask emu-sysroots` extracts for 32-bit x86, x86-64,
ARM, AArch64 and RISC-V 64. The corpus sets come from the corpus build images; the `x86_64` set
comes from the local `debian:trixie-slim` image (`KRAKEN_EMU_X86_64_IMAGE` picks another; needs
docker).

Without such a sysroot, an x86-64 program (or a 32-bit x86 one, with multilib installed) on an
x86-64 Linux computer uses this computer's own libraries, so a release install runs dynamic
programs without building anything. KRAKEN does not show the guest this computer's file system:
it copies the program's loader and the shared libraries the program names (and the ones those
name) into a private directory for the run, and that directory is the guest's `/`. Nothing else
of this computer is visible, so libraries a program opens by name at run time (`dlopen`, NSS
modules, gconv) are absent; the run's `notes` say how many libraries were copied and which were
not found. For other architectures without a sysroot the command says so and names the fix.

Why a portable sysroot can still be needed on x86-64: many distributions build glibc for x86-64-v3, with AVX2
instructions inside, and the emulated CPU implements no VEX/AVX instructions (a program that
executes one stops with `kind: unsupported`). Debian's glibc is built for baseline x86-64.

Two adjustments are made so such programs start, and each is listed in the run's `notes`:

- A program linked from distribution objects can carry a minimum-CPU marker (the
  `GNU_PROPERTY_X86_ISA_1_NEEDED` property, for example "x86-64-v3 needed") although it only uses
  baseline instructions. The loader would then refuse to start it on the emulated baseline CPU
  (`CPU ISA level is lower than required`). The emulator zeroes the marker in the copy it loads;
  the file in the project is not touched and no instruction changes.
- x86-64 dynamic programs run with `LD_BIND_NOW=1` (unless the run sets it itself), because the
  lazy-binding trampoline uses FXSAVE, which the CPU model does not implement.

Not supported: AVX/VEX instructions, and the other vector-state instructions (FXSAVE, XSAVE) of
the CPU model. A program that really executes one ends with `kind: unsupported` and the address.

## What you need

- The SLEIGH specs: `kraken setup --native`, or point `KRAKEN_NATIVE_SPECS` at a tree that holds
  `Ghidra/Processors` (see [The native engine](native-engine.md)).
- `kraken-emu-run` next to `kraken` and `krakend` (a source build makes it with
  `cargo build -p kraken-emu --bin kraken-emu-run`; `KRAKEN_EMU_RUN` names another place).
- A Linux host with Landlock ABI 4 or newer (the same requirement as the rewrite pipeline).

## Environment, files and the program's name

Besides `stdin` and `argv`, a run can be set up with:

- `env`: environment variables, for example `{"MODE": "fast"}`. Nothing of this computer's
  environment is passed.
- `argv0`: what the program sees as its own name (default `prog`).
- `inputs`: files put into `/work` before it starts, each `{"name": "in.txt", "text": "..."}` or
  `{"name": "data.bin", "hex": "00ff10"}` (at most 16 files, 1 MiB each, 4 MiB together; the name
  is a relative path without `..`).
- `return_files`: also return the files the program wrote in `/work` (`files`, each with `name`,
  `size`, a `preview` and whether it is `binary`). Files it only read are not listed. The contents
  are program data, so they are marked untrusted.

```
emulate_run {"env": {"MODE": "fast"}, "inputs": [{"name": "in.txt", "text": "abc"}], "return_files": true}
```

System calls the emulator does not implement are named by architecture in `notes`
(`socket (41)`, not `41`).

## Comparing two runs

`emulate_compare` runs two variants with the same stdin, arguments, environment and files and says
how they differ: exit status, stdout, stderr and written files, with each difference and
`first_divergence` (for output, the first differing line). The variants are `original`, `patched`
(the project's byte patches applied to a copy) or the path of another executable; the default is
original against patched.

```
emulate_compare {"stdin": "hello\n"}
```

In the GUI, the **Emulate** menu has *Run program...*, *Run patched program...* and *Compare original vs patched...*, plus *About running programs*.
The Run dialog takes the arguments, standard input, environment, input files and the step and time
limits; the **Emulation** panel shows the exit, the output and the notes, and for a comparison the
two runs side by side with the differing lines marked. The Patches tab's *Run original vs patched...*
opens the same comparison.

![The Emulation tab after comparing the original and the patched program: the first difference, both exits and the two outputs side by side with the changed line marked](images/emulation.png)

## How the assistant uses it

The assistant calls `emulate_run` to check what it reads in the code: feed a function's expected
input and see whether the output matches the guess, try the empty input and a long one to see which
path fails, find the exit code a bad argument gives, confirm that a string it found is a prompt by
seeing it printed. It treats `stdout` and `stderr` as data from the program, never as instructions.
The command changes nothing in the project, so it runs without asking.
