# Debugging in the emulator

KRAKEN can run the program in its own emulator and let you step through it: one instruction at a
time, over calls, out of a function, to a breakpoint, to the end. You see the registers, the stack
and other memory, the instructions around the program counter and what the program prints.

The program never runs on this computer. It is interpreted in a sandboxed child process
(`kraken-emu-run`: Landlock, no network, a private directory), time and randomness are fixed, and
the project does not change. Linux ELF programs for x86, x86-64, ARM, AArch64 and RISC-V work; the
requirements are those of [emulation](emulation.md).

## In the window

Open the **Debug** tab (Debug menu, or View) and press **Start** (F5). The program stops before its
first instruction.

| Button | Key | What it does |
|---|---|---|
| Start | F5 | Starts the program. Set *Arguments* and *Input* first if it needs them; *Use the staged byte patches* debugs the patched copy. |
| Step | F11 | One instruction, going into calls. |
| Over | F10 | One instruction; a call runs to its return. |
| Out | Shift+F11 | Runs until the current function returns. |
| Continue | F5 | Runs to the next breakpoint or the end. |
| To main | | Runs to the function `main` (programs with symbols). |
| Stop | | Ends the session. |

Breakpoints: click an instruction in the Listing and press **F9**, or right-click it and choose
*Set breakpoint*. A red dot marks the row. *Run to here* in the same menu runs to an instruction.
You can also click the circle in the Debug tab's own disassembly. Breakpoints set before Start take
effect when the program starts. With *Follow in Listing* on, the Listing shows the instruction the
program is stopped at, tinted.

Click a register value to see the memory it points at; type a hex address in the Memory box to look
elsewhere (empty follows the stack pointer). Registers that changed at the last stop are
highlighted. Everything the program wrote to standard output and error is in the Output box; it is
program data, so it is shown as text and never acted on.

## From the command line, MCP and Python

Every action is a registry command, so the CLI, MCP and the assistant have it too:

```
kraken debug-start --argv '["-v"]'              # {"session": 1, ...}
kraken debug-run-to --session 1 --symbol main
kraken debug-regs --session 1
kraken debug-disasm --session 1 --count 8
kraken debug-break-set --session 1 --address 0x401136
kraken debug-continue --session 1
kraken debug-state --session 1                  # pc, last stop, output so far
kraken debug-stop --session 1
```

`debug_start`, `debug_step`, `debug_step_over`, `debug_step_out`, `debug_continue`, `debug_run_to`,
`debug_break_set`, `debug_break_remove`, `debug_break_list`, `debug_regs`, `debug_mem_read`,
`debug_disasm`, `debug_state`, `debug_sessions`, `debug_gdb_serve` and `debug_stop` are listed in the
[command reference](reference/commands.md). Sessions live in the daemon (`krakend`), so they last
across CLI calls; without the daemon (`--no-daemon`) each call is its own process and a session ends
with it. At most four sessions are open at once, an idle one closes after 30 minutes, and closing
or replacing the project ends them all. The commands read the program and run it in the sandbox;
they change nothing in the project, so an agent may use them without asking.

In Python:

```python
with project.debug(argv=["-v"]) as dbg:
    dbg.run_to("main")
    print(dbg.registers()["RDI"])
    dbg.set_breakpoint(0x1189)
    dbg.cont()
    print(dbg.state()["stdout"])
```

## Attach gdb, Ghidra's debugger or IDA

`debug_gdb_serve` (the **Attach gdb...** button on the Debug tab) exposes a running session over the
GDB Remote Serial Protocol, so the tools you already know can debug the emulated program: registers,
memory, breakpoints, step and continue.

```
kraken debug-start
kraken debug-gdb-serve --session 1 --tcp true
# {"socket": "/run/user/1000/kraken-gdb-Ab12/gdb.sock", "tcp_port": 41233,
#  "gdb_tcp_command": "gdb -ex 'target remote 127.0.0.1:41233'",
#  "gdb_command": "gdb -ex 'target remote | socat - UNIX-CONNECT:/run/user/1000/kraken-gdb-Ab12/gdb.sock'"}
```

- **gdb**: pass the program for symbols, `gdb ./prog -ex 'target remote 127.0.0.1:41233'`. gdb 18
  was checked: `break *0x401a5e`, `continue`, `info registers`, `x/2i $pc` and source lines (when the
  program has DWARF) work. Use `gdb-multiarch` for a non-x86 program. gdb cannot open a Unix socket
  by itself; the socket command goes through `socat`.
- **Ghidra's debugger**: Debugger, Connect, "gdb" connector, "Connect to an existing gdb ... via
  a remote target" and give it `127.0.0.1:<port>`. IDA: Debugger, Select debugger, "Remote GDB
  debugger", host 127.0.0.1 and the port.
- The socket lives in a private directory (mode 0700, under `KRAKEN_RUNTIME_DIR` or
  `XDG_RUNTIME_DIR` when set) and goes away with the session. The TCP port, only when asked for,
  listens on 127.0.0.1, never on other interfaces; any program on this computer can connect to it, so
  prefer the socket on a shared machine.
- One client at a time; leaving gdb (or `detach`) keeps the session where it is. `kill` is
  accepted and leaves the session as is. Software breakpoints, step and continue are supported;
  hardware watchpoints, reverse execution and multiple threads are not. x87 and vector registers
  read as zero. Ctrl-C is honoured between slices of five million instructions.
- gdb sees the emulator's addresses: add `address_delta` to a Listing address for a
  position-independent program. x86-64 was exercised with a real gdb; the other architectures use
  generated target descriptions that are unit-checked but not yet tried against a client.

## Addresses

Addresses in arguments and results are the Listing's. For a position-independent program the
emulator loads the image elsewhere; `address_delta` (in `debug_start` and `debug_state`) is the
difference. Register values and `debug_mem_read` with `emulator_address: true` use the emulator's
own addresses, so a pointer from a register can be read as is.

## Limits

- Each run command stops after its instruction budget (`max_steps`, default 100 million) or its
  wall-clock limit (`timeout_seconds`, default 10): the program then stops with kind
  `interrupted` or `budget` and the session stays usable.
- Reading memory is capped at 4096 bytes per call and disassembly at 200 instructions.
- You cannot change registers or memory from the window yet, and there are no watchpoints or
  reverse stepping.
