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

Beside the program (`<name>.debug`, `.debug/<name>.debug`, `<name>.pdb` or the name the PDB reference gives), under `/usr/lib/debug` (by directory and by build-id), and in the debuginfod download cache (`$DEBUGINFOD_CACHE_PATH`, else `$XDG_CACHE_HOME/debuginfod_client`, else `~/.cache/debuginfod_client`; KRAKEN only reads what a tool such as `debuginfod-find` already downloaded). KRAKEN's own download cache (see [Downloading from symbol servers](#downloading-from-symbol-servers)) is searched too. You can point it at a file or a folder as well.

## Downloading from symbol servers

When the debug file is not on this computer, KRAKEN can ask a server for it. This is off until you agree to it, because asking tells the server's operator which program you are looking at.

| Program | Asked | Request |
|---|---|---|
| ELF with a GNU build-id | a debuginfod server | `GET <server>/buildid/<build-id>/debuginfo` |
| PE with a CodeView record | a Microsoft-style symbol server | `GET <server>/<name>.pdb/<GUID><age>/<name>.pdb` (GUID without dashes, age in hex) |

Only the build-id, or the PDB's name, GUID and age, is sent.

- **Servers** come from `servers` in the `[debuginfo]` table of `config.toml` and from `DEBUGINFOD_URLS` (space separated). Only `http://` and `https://` addresses without credentials are accepted.
- **Consent** is `consent = true` in `[debuginfo]`. You give it in the Import wizard or with `kraken debuginfo-servers --consent true`; an agent cannot change it. An agent that calls `debuginfo_find` is asked for approval every time, whatever the file says.
- **Offline** is `offline = true` in `[debuginfo]` or the `KRAKEN_OFFLINE` environment variable. While it is on no server is asked.
- **Checked before it is kept.** The file must carry the program's build-id (or the PDB's GUID and age). A file of another build is thrown away and the server's answer is listed with the reason. A download over 1 GiB is abandoned.
- **Cache.** Verified files are kept in `$KRAKEN_DEBUGINFO_CACHE`, else `$XDG_DATA_HOME/kraken/debuginfo`, else `~/.local/share/kraken/debuginfo` (`buildid/<id>/debuginfo`, `symbols/<name>/<GUID><age>/<name>`). A cached file is used without asking any server, also offline, and `debuginfo_probe` lists it as `downloaded`.
- **Compressed PDBs.** Microsoft's server often holds a PDB only as `<name>.pd_` (a CAB archive). KRAKEN has no CAB reader, so it says so and does not unpack it: expand it with `cabextract` or `expand`, then attach the `.pdb` yourself.

```
kraken debuginfo-servers --servers '["https://debuginfod.elfutils.org"]' --consent true
kraken debuginfo-find --path ./prog          # a job; the result lists what each server said
kraken debuginfo-attach --debug-file <file from the result>
```

## In the window

**File > Import program...** has a step for debug information (for ELF and PE programs). It shows what the program refers to, every file that was checked with a verdict (matches, cannot be checked, does not match, not usable) and the reason, and two buttons: **Choose debug file...** and **Choose folder...**. A matching file is attached when you create the project (untick **Use this file** to leave it out).

When the program names debug information that is not on this computer, the step also offers **Symbol servers**: the servers (filled in from `config.toml`, `DEBUGINFOD_URLS` or a public default), a box **I agree to send this to these servers** and the button **Search symbol servers**, which stays disabled until the box is ticked. Pressing it records your consent in `config.toml`, asks the servers, checks what comes back and, when it matches, lists it as a match and attaches it like any other file.

A separate DWARF file is read by the native engine; when it is installed the wizard switches to it for you. A PDB is read by the native engine from beside the program or from a file you attach, and by the Ghidra engine when it sits next to the program as `<name>.pdb`.

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

The path is kept in the project's `meta.json` (`loader.debug_file`) and used again on every reopen and `rebuild`. A file of another build is refused before anything changes. The commands are `debuginfo_probe`, `debuginfo_attach`, `debuginfo_detach`, `debuginfo_find` and `debuginfo_servers` in the [command reference](reference/commands.md); agents can call them through MCP and Python as well.

## Making a separate debug file yourself

```
objcopy --only-keep-debug prog prog.debug
objcopy --strip-all prog prog.stripped
objcopy --add-gnu-debuglink=prog.debug prog.stripped
```

`prog.stripped` now names `prog.debug` and carries its CRC-32.

## Limits

- The native engine reads separate DWARF for ELF programs and PDB files for PE programs (x86 and x86-64). A PDB gives function names, sizes and prototypes (parameter names and types), global variable names and types, and the structs, unions, enums, pointers, arrays and function pointer types of the type stream. A PDB that is not the image's (GUID and age differ) is not used when it is found beside the program; `debuginfo_attach` refuses it. C++ member functions, templates and inline-function records are read as plain functions and names with `::` become `__`. Local variables and line numbers are not read.
- Ghidra reads a PDB that sits beside the program under the program's name (`<name>.pdb`); `debuginfo_attach` refuses a PDB somewhere else and says where to copy it.
- Downloading needs a server that answers the requests above; there is no support for symbol server proxies that need a login, nor for `.pd_` archives.
- The default servers the wizard suggests are `https://debuginfod.elfutils.org` (ELF) and `https://msdl.microsoft.com/download/symbols` (PDB); nothing is sent to them unless you press the button.
