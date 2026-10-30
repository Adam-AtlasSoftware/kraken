# Debug information

Debug information is what makes a decompiled function readable: real function names, parameter names, types and the lines of the source. A program can have it in three places.

| Where | What it means |
|---|---|
| Inside the program | DWARF sections (`.debug_info` and friends), plain or compressed. KRAKEN uses them as they are. |
| In a separate file | A `.debug` file (ELF) or a `.pdb` file (Windows). The program does not hold the data; it only says which file it wants. |
| Nowhere | The program is stripped and names no file. Names come from symbols and analysis only. |

## What a program says about its debug file

- **GNU build-id**: a fingerprint the linker puts in the program. A debug file with the same build-id belongs to it. This is how `/usr/lib/debug/.build-id/ab/cdef....debug` is found.
- **Debug link** (`.gnu_debuglink`): the name of a debug file and the CRC-32 of its contents. Used when there is no build-id.
- **PDB reference**: the name of the PDB, its GUID and its age. The GUID and age identify the exact build.

KRAKEN never trusts a file because of its name. A candidate is checked:

- an ELF debug file must carry the program's build-id; without a build-id the CRC-32 of the file must be the one in the debug link; a file must also hold DWARF (`.debug_info`);
- a PDB must carry the program's GUID, and its age must agree.

When a file does not match, KRAKEN says why: `its build-id is 1f2e... but the program's is ab12...: it is from another build`, or `the GUID agrees but the PDB's age is 3 and the program's is 2: one of them was rebuilt or relinked`.

## Where KRAKEN looks

Beside the program (`<name>.debug`, `.debug/<name>.debug`, `<name>.pdb` or the name the PDB reference gives), under `/usr/lib/debug` (by directory and by build-id), and in the debuginfod download cache (`$DEBUGINFOD_CACHE_PATH`, else `$XDG_CACHE_HOME/debuginfod_client`, else `~/.cache/debuginfod_client`; KRAKEN only reads what a tool such as `debuginfod-find` already downloaded). You can point it at a file or a folder as well.

## In the window

**File > Import program...** has a step for debug information (for ELF and PE programs). It shows what the program refers to, every file that was checked with a verdict (matches, cannot be checked, does not match, not usable) and the reason, and two buttons: **Choose debug file...** and **Choose folder...**. A matching file is attached when you create the project (untick **Use this file** to leave it out).

A separate DWARF file is read by the native engine; when it is installed the wizard switches to it for you. A PDB is read by the Ghidra engine when it sits next to the program as `<name>.pdb`; the wizard tells you when it does not.

## On the command line

Look at a program (nothing is changed):

```
kraken debuginfo-probe --path ./prog
kraken debuginfo-probe --path ./prog --debug-file ./symbols/      # a file or a folder
```

`status` is `embedded`, `found`, `missing` or `none`; every candidate has a `verdict` and a `detail`; `best` is the file that would be used.

Create a project with the file attached, or attach it later (a job: the engine is rebuilt with the file, your edits are replayed):

```
kraken project-create --binary ./prog --engine native --debug-file ./symbols/prog.debug
kraken debuginfo-attach --debug-file ./symbols/prog.debug
kraken debuginfo-detach
```

The path is kept in the project's `meta.json` (`loader.debug_file`) and used again on every reopen and `rebuild`. A file of another build is refused before anything changes. The commands are `debuginfo_probe`, `debuginfo_attach` and `debuginfo_detach` in the [command reference](reference/commands.md); agents can call them through MCP and Python as well.

## Making a separate debug file yourself

```
objcopy --only-keep-debug prog prog.debug
objcopy --strip-all prog prog.stripped
objcopy --add-gnu-debuglink=prog.debug prog.stripped
```

`prog.stripped` now names `prog.debug` and carries its CRC-32.

## Limits

- The native engine reads separate DWARF for ELF programs. It does not read PDB files yet.
- Ghidra reads a PDB that sits beside the program under the program's name (`<name>.pdb`); `debuginfo_attach` refuses a PDB somewhere else and says where to copy it.
- Downloading symbols from a server is not part of this: KRAKEN only looks at files that are already on the computer.
