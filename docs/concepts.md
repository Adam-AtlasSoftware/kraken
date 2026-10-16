# Concepts

A short primer for developers who have not done reverse engineering (RE) before.

## Binary

A **binary** is a compiled program: machine instructions and data, with the source code gone. Reverse engineering is working out what such a program does. People do it to check software for malware, find security bugs, or understand a program they have no source for.

## Function

Compiled programs are still organised into **functions**, small units of code that other code calls. The first job of an analysis tool is to find where each function starts and ends.

## Disassembly and decompiler

- **Disassembly** shows the actual processor instructions, one per line (`mov`, `call`, ...). It is exact but hard to read.
- The **decompiler** guesses a C-like version of the same code. It is far easier to read, but it is a reconstruction, not the original source.

KRAKEN's `decompile` command gives you the decompiler view.

## Cross-references (xrefs)

A cross-reference says "this place uses that place": function A calls function B, or an instruction reads a string. Following xrefs backwards answers "who calls this?", which is how you find out what a mystery function is for.

## Symbols and why names matter

A **symbol** is a name attached to an address. Programs built for release are often stripped, so Ghidra invents names like `FUN_00101189`. Reading code full of `FUN_` names is miserable. Once you work out that a function builds a list node and call it `list_push`, every place that calls it becomes readable. Naming (and typing and commenting) is most of the work, and it is what you and your AI agents do with KRAKEN.

## The edit log

Every change you make (a rename, a comment, a type) is written to an **edit log** inside your project. The log is the source of truth. Ghidra's own project is only a cache that KRAKEN can rebuild from the log (`rebuild`). Each entry records who made the change: you, or a named AI agent and its run.

## Undo

Because every change is a log entry, it can be reversed. `undo` reverses your most recent edit. `undo-run` reverses everything one AI agent run did, newest first. `history` shows the log.

## Proposals

AI agents are fast, and they read text from the binary that an attacker may have written. So KRAKEN limits what they change on their own:

- **Additive changes apply immediately.** Naming a function that still has a default `FUN_` name, or adding a new comment, cannot destroy anything you did.
- **Everything else becomes a proposal.** Overwriting a name you chose, or going past the per-run cap, waits in a list. You review with `proposals-list` and decide with `proposal-accept` or `proposal-reject`. Agents cannot accept proposals themselves.

See [Connecting AI agents](mcp.md) and [Security](security.md) for the details.
