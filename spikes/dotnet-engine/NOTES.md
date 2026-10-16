# .NET engine spike (managed code behind the capability traits)

Date: 2026-10-16. Host: Arch x86_64, kernel 7.2.9 (Landlock ABI 10), system cargo 1.99.
Decisions touched: 3 (managed code is a 1.0 target), 31 (engine = capability traits), 54 (anchors
reserve `Managed`), 62 (engine provider manifest).

Result: a second engine kind works behind the existing traits. `engine-dotnet` opens an assembly,
lists methods with `Locator::Managed`, decompiles a method to C# with tokens (including references
into the framework) and lists types, all in a Landlock-confined C# sidecar. The 8 ignored tests in
`crates/engine-dotnet/tests/real_dotnet.rs` pass (about 1.4 s in total).

## Pins

| Thing | Pin | Notes |
| --- | --- | --- |
| .NET SDK | 10.0.402 (linux-x64) | .NET 10 is the current LTS (support to 2028-11-14); 8.0 and 9.0 both end 2026-11-10. |
| SDK archive sha512 | `1904a98d...687729c2` (full value in `dotnet/install-sdk.sh`) | From Microsoft's release metadata (`release-metadata/10.0/releases.json`), re-checked against the downloaded file. |
| `ICSharpCode.Decompiler` | 11.1.0.9782 (NuGet, MIT) | Targets netstandard2.0. Depends on `System.Reflection.Metadata` 9.0.0 and `System.Collections.Immutable` 9.0.0 (both MIT). |
| Sidecar target | `net10.0`, framework-dependent | Run as `dotnet kraken-dotnet.dll`; no apphost. |

Licenses: ILSpy/ICSharpCode.Decompiler MIT, .NET runtime and SDK MIT (plus third-party notices in
`ThirdPartyNotices.txt` of the SDK), SRM and SCI MIT. All compatible with GPL-3.0-or-later. The
sidecar is a separate process, so nothing links into the GPL Rust code. Redistributing the sidecar
means shipping the MIT texts; the SDK is only a dev dependency, a release would ship the runtime
only (see "1.0 design").

## Toolchain without touching the user's environment

- `dotnet/install-sdk.sh` downloads the tarball from `builds.dotnet.microsoft.com`, verifies the
  pinned sha512 and unpacks into `~/.cache/kraken-dev/dotnet`. I reviewed Microsoft's
  `dotnet-install.sh` (1887 lines) first but did not use it: it does not verify any hash, which the
  task required, so the script pins the archive hash itself. No PATH, `~/.dotnet` or system change.
- Every dotnet invocation (`cargo xtask dotnet-ext`, `corpus/dotnet/build.sh`) sets `DOTNET_ROOT`,
  `DOTNET_CLI_HOME` (`~/.cache/kraken-dev/dotnet-home`) and `NUGET_PACKAGES`
  (`~/.cache/kraken-dev/nuget`) under the cache, plus `DOTNET_CLI_TELEMETRY_OPTOUT=1`.
- `cargo xtask dotnet-ext` refuses when `~/.cache/kraken-dev/dotnet/dotnet` is missing. The first
  build restores `ICSharpCode.Decompiler` (6 MB in the cache) from nuget.org, so it needs the
  network once, unlike `ghidra-ext`. The output is `dotnet/kraken-dotnet/bin/` (ignored by git).
- Cache footprint: SDK 624 MB unpacked. A release needs only the runtime (about 70 MB).

## What is implemented

- `dotnet/kraken-dotnet` (C#, `net10.0`): same framing as the Ghidra sidecar (4-byte BE length +
  JSON-RPC 2.0). Socketpair on fd 0 by default (via `Socket(SafeSocketHandle(0))`), `--stdio` for
  Windows and debugging, `--watch-parent <pid>` for non-Linux. Methods: `handshake`,
  `open_assembly`, `list_functions`, `get_function`, `decompile`, `list_types`, `get_type`, `ping`,
  `shutdown`. `--dump-truth <dll>` prints names and tokens (used for the corpus truth file).
  Requests run one at a time; there is no `cancel` yet (the decompile deadline is passed as
  `timeout_ms`, which cancels through ILSpy's `CancellationToken`).
- `kraken-proto`: `Locator::Managed { module, token }` (module = MVID as a hyphenated GUID,
  token = ECMA-335 metadata token as a plain u32 JSON number), `LANGUAGE_CSHARP`, schema and
  `schema/samples/locator.managed.json`. The Java DTO parses `managed` locators and refuses them
  with `unsupported` (Ghidra never emits one). `Anchor::Managed { token }` is untouched.
- `crates/engine-dotnet`: `DotnetEngine` implements `Engine` with Loader, FunctionLister,
  Decompiler and a read-only TypeStore (`define_type` is `unsupported`). No Analyzer (a managed
  assembly has nothing to analyse; metadata is complete on open), no Mutator, no memory, disassembly,
  xrefs, CFG, strings or symbols yet.
- `corpus/dotnet`: C# source (enum, struct, interface, two classes, recursion, switch expression,
  string interpolation, calls into `System.Console`), `build.sh` (isolated SDK, deterministic,
  rebuild gives the same sha256), the committed `bin/kraken-corpus.dll` (5.6 KB) and
  `truth/kraken-corpus.json` (13 methods: name, token, IL size).

## Findings

### ILSpy as a library

- ILSpy 11's C# syntax tree is the new slot-based AST: there is no `Role`/`Roles`. The
  `TokenWriter` base class has `WriteKeyword(string)`, `WriteToken(string)`,
  `WritePrimitiveValue(object?, LiteralFormat)` (`LiteralFormat` lives in `...CSharp.Syntax`) and
  `WriteInterpolatedText(string)`; code written against ILSpy 8/9 samples does not compile.
- Tokens come from wrapping `TokenWriter.Create(...)`: record the output length before and after
  each call and classify with `AstNode.GetSymbol()` (`ICSharpCode.Decompiler.CSharp.AnnotationExtensions`)
  and `ILVariableResolveResult`. Resolved entities carry `MetadataToken` and `ParentModule`, so a
  call to `Console.WriteLine` gets a `Managed` locator in the `System.Console` module (its MVID).
  Offsets are UTF-16 in .NET and are converted to the UTF-8 byte offsets the wire wants. The inner
  writer emits indentation inside the first token of a line, so spans are trimmed.
- `CSharpDecompiler.Decompile(MethodDefinitionHandle)` returns only the member, not the type, which
  matches the "decompile this function" shape. Accessors (`get_Side`) decompile as methods.
- Reference resolution works with the runtime directory as an extra search directory
  (`RuntimeEnvironment.GetRuntimeDirectory()`), so `Console` resolves to the implementation
  assembly (`System.Console`), not the reference assembly the program was compiled against.
  Locators into other modules therefore name implementation modules; they cannot be opened
  by KRAKEN unless the user opens that assembly (as designed: a locator is module-qualified).
- Listing: `System.Reflection.Metadata` plus ILSpy's `MetadataModule.GetDefinition(handle)` for
  signatures. `fn_hash` is the SHA-256 of the IL body bytes (no relocations in IL, so the hash is
  stable across rebuilds that do not change the body). `size` is the IL size, not the native size.

### Engine plumbing

- `engine-dotnet` reuses `engine-ghidra` directly (`rpc::RpcClient`, `sandbox::Sandbox` /
  `WinSandbox`, `SpawnSpec`, `LogSink`). All of it is already public, so there is no code copy;
  the cost is that `engine-dotnet` depends on `engine-ghidra` (and so on Landlock/libc). The
  duplication to remove later is the other way round: move `rpc`, `sandbox`, `log` and the
  supervisor's handshake into a `kraken-sidecar` crate that both engines depend on. `RpcClient`'s
  `wait_ready` is Ghidra-shaped (`ghidra_version`), so the .NET sidecar has no `ready`
  notification and the engine uses a `handshake` call with a startup timeout instead.
- Sandbox (Linux): Landlock read-only on the .NET root, the sidecar directory, the single assembly
  file, plus `/proc` and `/sys` (the runtime reads cgroup and CPU topology); read-write on a private
  temp home only; TCP denied, netns when available, PDEATHSIG. `DOTNET_EnableDiagnostics=0` avoids the
  diagnostics IPC socket in `/tmp`; `DOTNET_GCHeapHardLimit` caps the managed heap. The sidecar runs
  under the report `is_confined()` (asserted in the test on Linux). Unconfined runs are refused
  unless `ConfinementOptions::allow_unconfined`, same as Ghidra. macOS and Windows have the same
  refusal until decision 71's sandboxes exist; the crate type-checks for `aarch64-apple-darwin`,
  `x86_64-pc-windows-gnu` and `-msvc` (with the isolated cross toolchain).
- Only the assembly file itself is readable, so sibling references (`Foo.dll` next to `App.dll`)
  are not resolved; framework assemblies are. A real engine should grant read on the assembly's
  directory or, better, take an explicit reference list from the project.
- `ProgramInfo` has no room for the MVID, so `DotnetEngine::module_mvid()` / `assembly_info()` expose
  it. The registry needs a neutral "program identity" in `ProgramInfo` (an optional `module_id`)
  before managed locators can be validated generically.
- Neutral type model: it is C-layout (size, offset, align). Managed enums map cleanly; classes and
  structs map to `Struct { size: 0, align: 1, fields[offset: 0] }` and field types are primitives or
  `Named` C# full names. That is lossy: no generics, no base types or interfaces, no methods, and
  types have no locator (so a token in decompiled text cannot yet link to a type definition in the
  type store, only to the type's `Managed` locator). A `TypeDef::Managed` variant (kind, base,
  interfaces, generic parameters, members as locators) is the proper fix.

### Gaps

- Renames/annotations: ILSpy has no persistent database and cannot change names. Annotations (names,
  comments) live only in KRAKEN's edit log and are applied when rendering: after `decompile`, the
  registry replaces tokens whose `target` has a rename in the log (the token spans make this exact)
  and shows comments beside the function. That matches decision 27 (the KRAKEN project DB is the
  source of truth; the engine is a rebuildable cache). The `Mutator` capability is therefore absent
  rather than faked; `apply` would return `unsupported`.
- Anchors: `Anchor::Managed { token: String }` needs `{module, token, il_hash}` to survive rebuilds
  (tokens change when members are added). Spike use: `fn_hash` (IL hash) plus the full name.
- No Analyzer, Disassembler (IL listing is easy with `ILSpy.Disassembler`), Xrefs (needs a metadata
  scan or ILSpy's `Analyzers`), CFG (ILSpy builds IL blocks), strings (`#US` heap), imports/exports.
  `Cap` has no `Il`/`Metadata` capability yet; IL disassembly would reuse `Disassembler` with
  `arch: "cil"` rows.
- No `cancel` RPC, no restart supervision (Ghidra's `Supervisor` is Ghidra-shaped), no progress.
- Obfuscated or mixed-mode assemblies: not tried. Single-file bundles and ReadyToRun images are
  not handled (ILSpy handles R2R by reading the IL, which is preserved; untested).
- Heap/time limits for huge assemblies are untested; the corpus is 5.6 KB.
- `Process.WaitForExit` based parent watch (non-Linux) is untested on macOS/Windows.

## Proposed 1.0 design for managed code

1. **Engine provider manifest (decision 62).** A TOML/JSON manifest per engine:
   `id`, `kinds` it opens (`native`, `dotnet`), capability list with versions, runtime
   requirements (`dotnet >= 10.0 LTS`), pinned artifacts with hashes (runtime archive, sidecar
   build), launch command template with `{runtime}`, `{sidecar}`, `{input}` placeholders, and
   the sandbox grants (read paths, read-write temp, network none). Ghidra and .NET become two
   providers. The registry picks a provider by the loader's detection result (`format`), not by
   hard-coded engine types. `kraken setup` provisions artifacts per manifest (the runtime only, via
   the same hash-pinned download as `install-sdk.sh`).
2. **Engine-neutral program identity.** `ProgramInfo` gains `format`-specific identity
   (`module_id` for managed). Locators and anchors carry it; the registry checks a locator's module
   against the open program before calling the engine.
3. **Language tags.** `DecompileResult.language` is already a free tag (`c`, `csharp`). The GUI picks
   syntax highlighting and the clipboard/export filename extension from it, and the agent prompt
   builder says which language it reads. Token kinds already cover C#; add `namespace` and
   `property`/`event` kinds later (today properties and events are `field`).
4. **Registry commands stay engine-neutral.** `list_functions`, `decompile`, `get_type`, `list_types`
   and `explain` work unchanged. Native-only commands (`memory_map`, `read_bytes`, `disassemble`
   with addresses, `cfg`, `xrefs` by address) return `unsupported` with a hint; their arguments are
   `Locator`s instead of `Hex64` addresses so managed targets can be expressed. Rename/comment
   commands write to the log with `Anchor::Managed` and render-time application, as above.
5. **Rewrite pipeline.** The Rust-rewrite goal for managed code needs a different oracle (run the
   method through the .NET runtime for differential tests instead of icicle-emu) and an IL-level
   semantic summary; out of scope for the spike but the sidecar could expose `invoke` behind the
   sandbox.
6. **Shared sidecar crate.** Extract rpc, sandbox, log and handshake supervision from `engine-ghidra`
   into `kraken-sidecar` so both engines share restart, cancel and diagnostics.
7. **Distribution.** Ship the framework-dependent sidecar (3 MB) and provision the .NET runtime
   (not the SDK) with a pinned hash; or publish self-contained trimmed (about 25 MB) to remove the
   runtime pin. Build the sidecar in CI with the SDK and sign the artifact hash into the manifest.

## Reproduce

```
dotnet/install-sdk.sh                  # once; isolated SDK under ~/.cache/kraken-dev/dotnet
cargo xtask dotnet-ext                 # builds dotnet/kraken-dotnet/bin
cargo test -p engine-dotnet -- --ignored --test-threads=1
corpus/dotnet/build.sh                 # only to rebuild the corpus dll and truth
```
