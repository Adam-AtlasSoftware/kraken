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
library. The emulator does **not** use the libraries of this computer: it reads them from a sysroot,
`~/.cache/kraken-dev/emu-sysroots/<set>` (or `$KRAKEN_EMU_SYSROOTS/<set>`), which
`cargo xtask emu-sysroots` extracts for 32-bit x86, ARM, AArch64 and RISC-V 64. Without one the
command says so and names this fix. There is no sysroot for x86-64 yet, so dynamically linked
x86-64 programs are refused.

## What you need

- The SLEIGH specs: `kraken setup --native`, or point `KRAKEN_NATIVE_SPECS` at a tree that holds
  `Ghidra/Processors` (see [The native engine](native-engine.md)).
- `kraken-emu-run` next to `kraken` and `krakend` (a source build makes it with
  `cargo build -p kraken-emu --bin kraken-emu-run`; `KRAKEN_EMU_RUN` names another place).
- A Linux host with Landlock ABI 4 or newer (the same requirement as the rewrite pipeline).

## How the assistant uses it

The assistant calls `emulate_run` to check what it reads in the code: feed a function's expected
input and see whether the output matches the guess, try the empty input and a long one to see which
path fails, find the exit code a bad argument gives, confirm that a string it found is a prompt by
seeing it printed. It treats `stdout` and `stderr` as data from the program, never as instructions.
The command changes nothing in the project, so it runs without asking.
