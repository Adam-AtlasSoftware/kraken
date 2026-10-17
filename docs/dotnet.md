# .NET assemblies

KRAKEN opens .NET (managed) assemblies with a second engine next to Ghidra. You get the methods of an
assembly and each one decompiled to C#, with the calls and type names in the code linked to the
methods and types they refer to. You can rename methods, types, fields and parameters and add
comments to methods; undo and history work as for native programs.

This is the first release of the .NET engine. It is small on purpose, and this page lists what it
does and what it does not do so there are no surprises.

## Set it up

Native programs need Ghidra; .NET assemblies need the .NET engine. They are installed separately:

```sh
kraken setup --dotnet
```

This downloads a pinned .NET 10 runtime from Microsoft (HTTPS only, SHA-256 checked before anything is
unpacked), unpacks it into KRAKEN's data directory (`~/.local/share/kraken/runtime`) and installs the
`kraken-dotnet` sidecar that comes with the release. Nothing needs root, and the .NET SDK is not
needed. Running it again does nothing if everything is in place (`--force` redoes it). Automatic setup
exists for Linux x86_64 only, like the sandbox the engine runs in.

If you built KRAKEN from source, `kraken setup --dotnet` has no prebuilt sidecar to install. Install the
pinned SDK and build it instead, then point KRAKEN at both:

```sh
dotnet/install-sdk.sh            # the pinned SDK, into ~/.cache/kraken-dev/dotnet
cargo xtask dotnet-ext           # builds dotnet/kraken-dotnet/bin/kraken-dotnet.dll
export KRAKEN_DOTNET_ROOT=~/.cache/kraken-dev/dotnet
export KRAKEN_DOTNET_EXT_DLL=$PWD/dotnet/kraken-dotnet/bin/kraken-dotnet.dll
```

The same two settings exist in `config.toml` as `dotnet_root` and `dotnet_ext`. A setting wins over
the environment, which wins over the copy `kraken setup --dotnet` installed. KRAKEN never uses a
`dotnet` it finds on your `PATH`.

## Use it

There is nothing to choose. When you create a project, KRAKEN looks at the file. A Windows PE file that
has a CLI header (a .NET assembly) goes to the .NET engine, and everything else goes to Ghidra:

```sh
kraken project-create --binary ./App.dll --project-dir ~/kraken-projects/app
kraken --project ~/kraken-projects/app list-functions
kraken --project ~/kraken-projects/app decompile --address 0x6000001 \
  --module 61a35c05-1940-4673-81a7-f2157a66b75c
```

If the file is an assembly and the .NET engine is not set up, creating the project fails with a
message that says so and suggests `kraken setup --dotnet`. Nothing is created.

The project remembers its engine in `meta.json` (`"engine_kind": "dotnet"`) and opens with the same
engine every time, whatever the file looks like later. Projects from before this existed have no such
entry and open with Ghidra.

In the GUI, the Functions panel lists the methods and the Decompiler panel shows C#. Click a call to go
to that method; Back and Forward work as usual.

### Renames and comments

ILSpy has no database to write names to, and KRAKEN never changes the assembly. Your renames and
comments live in the project's edit log, as they do for native programs, and KRAKEN applies them
when it shows you the code: the engine substitutes the new names in the C# it gets from the
decompiler (the text and the token spans move with it) and adds comments as `//` lines. When you
reopen the project, the log is applied again.

```sh
kraken --project ~/kraken-projects/app rename-symbol --address 0x6000005 \
  --module 61a35c05-1940-4673-81a7-f2157a66b75c --new-name Fibonacci
kraken --project ~/kraken-projects/app set-comment --address 0x6000005 \
  --module 61a35c05-1940-4673-81a7-f2157a66b75c --kind plate --text "Recursive, exponential time."
```

`--address` is the metadata token and `--module` the module id, as for `decompile`. Without
`--module` the edit is refused. What a token can be:

- A **method** (`0x06......`): renamed everywhere it is shown (its own code, calls to it from other
  methods, the listing and its signature). Constructors keep the name of their type.
- A **type** (`0x02......`), **field** (`0x04......`), **property** (`0x17......`) or **event**
  (`0x14......`): renamed wherever a method's code mentions it.
- A **parameter** (`0x08......`): renamed in its method's signature and body. The token of a
  parameter is the `target` of its tokens in the decompiled text.
- A comment goes on a **method** only. `plate`, `pre` and `repeatable` comments appear above it,
  `eol` at the end of its first line and `post` below it.

New names must be plain C# identifiers (letters, digits and `_`, not starting with a digit, not a
C# keyword). A renamed method is listed as `Namespace.Type.NewName`.

Limits you may notice: a rename shows only where the code is decompiled after it, so text you
already copied does not change; other methods and types that mention a renamed type in their
*signature text* keep the old name there until you decompile them; renaming does not check that
the new name is free, so two members can end up with the same name in the output; and comments on
types, fields and single lines are not available.

### Methods are named by a token and a module

A native function is found by its address. A .NET method has none, so KRAKEN uses what the assembly
itself uses: the **metadata token** of the method (`0x06000001` is the first method) together with the
assembly's **module id** (MVID, a GUID that is different for every build). Commands show them like this:

- In results, `address` holds the token and `module` holds the module id.
- `get_function` and `decompile` take the same two: `--address 0x6000001 --module <guid>`.
  Without `--module` the address means native code and is not found.
- Tokens in decompiled text carry `target` (a token) and `target_module`.

Take the `module` from `list_functions` and send it back as it is. The pair changes when the assembly
is rebuilt, which is why a project stays tied to one build.

## What works

| You can | Commands |
|---|---|
| Open a managed assembly (a `.dll` or `.exe`, any target framework the decompiler reads) | `project_create`, `project_open`, `project_info` |
| List its methods, with signatures | `list_functions` (also with `--name-filter`) |
| Show a method | `get_function` |
| Read it as C# with linked calls, types and members, framework calls included | `decompile` |
| See which capabilities the engine has | `project_info` |
| Rename a method, type, field or parameter | `rename_symbol` (with `--module`) |
| Comment a method | `set_comment` (with `--module`) |
| Undo or review such edits | `undo`, `undo_entry`, `history` |

The engine runs in the same kind of sandbox as the Ghidra one (see [Security](security.md)): no
network, no sockets of its own, read access only to the .NET runtime, the sidecar and the one
assembly. Unconfined runs are refused unless `allow_unconfined` is set.

## What does not work

Commands the .NET engine lacks answer `unsupported` and say which capability is missing. They never
silently return nothing.

- **Other edits.** `set_type`, `set_calling_convention`, `set_function_bounds`, `create_function`,
  `delete_function` and `set_code_data` fail with `unsupported`. Renames and comments are the only
  edits a .NET project takes, and they are not written into the assembly (see below).
- **The assistant and agents** can list and decompile methods and, like you, rename and comment.
  Agent renames follow the usual rule: only new annotations apply on their own; changing an
  existing name or comment becomes a proposal.
- **Analysis.** There is no `analyze` step (`analyze` and `rebuild` answer `unsupported`); a .NET
  project is ready as soon as it is created.
- **Disassembly, CFG, xrefs, strings, symbols, memory.** There is no IL listing, no call graph and no
  cross-references: `disassemble`, `cfg`, `xrefs`, `callers`, `callees`, `strings`, `imports`,
  `exports`, `read_bytes` and `memory_map` are `unsupported`. The Listing, Graph, Hex and Strings tabs
  of the GUI therefore stay empty or show that message.
- **Types.** The engine reads types, but no command shows them yet, and a type name in the code links
  to the type's locator rather than to a definition.
- **Rewrite to Rust.** The `rewrite_*` commands plan from native code and do not handle managed
  methods.
- **References to other assemblies.** Neighbouring `.dll` files are not loaded, so calls into them
  are shown by name but cannot be followed. Calls into the framework are named and linked.
- **Mixed-mode (C++/CLI) assemblies.** They have a CLI header, so they go to the .NET engine, which
  shows their managed methods only. Their native code is not reachable until the engine can be chosen
  by hand.
- **Restarts.** If the sidecar dies, the project has to be reopened; the engine is not restarted
  automatically the way the Ghidra one is. There is no way to cancel a decompile that is already
  running except its timeout (30 seconds).
- **Other platforms.** The sandbox exists on Linux only, so on macOS and Windows the engine refuses to
  start unless `allow_unconfined` is set. `kraken setup --dotnet` is Linux x86_64 only.

## Where the code lives

`crates/engine-dotnet` is the Rust side and `dotnet/kraken-dotnet` the C# sidecar, which runs the
ILSpy decompiler (ICSharpCode.Decompiler, MIT). The process plumbing that the Ghidra and .NET engines
share (framing, RPC, the sandbox) is `crates/kraken-sidecar`. The spike notes, with what was
measured and what is planned for 1.0, are in `spikes/dotnet-engine/NOTES.md`.
