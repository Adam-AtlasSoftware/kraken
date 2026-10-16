# Scripting with the CLI

Every command is a `kraken` subcommand. Run `kraken --help` for the list and `kraken <command> --help` for its flags. The full list is in the [command reference](reference/commands.md).

## Choosing the project

Pass `--project <dir>` or set `KRAKEN_PROJECT`. Each `kraken` invocation opens the project, runs one command and exits.

## Machine-readable output

With `--json`, standard output is exactly the command's result as one line of JSON. Progress messages go to standard error, and errors are printed to standard error as JSON.

```sh
# Address and name of every function that still has a default name
kraken --json list-functions --limit 500 \
  | jq -r '.items[] | select(.name.value | startswith("FUN_")) | "\(.address) \(.name.value)"'

# The decompiled text of main
addr=$(kraken --json list-functions --name-filter main | jq -r '.items[0].address')
kraken --json decompile --address "$addr" | jq -r '.text.value'

# Rename a batch of functions from a file of "address name" lines
while read -r addr name; do
  kraken --json rename-symbol --address "$addr" --new-name "$name" | jq -r '.status'
done < names.txt

# What changed recently
kraken --json history | jq '.'
```

Text taken from the binary is wrapped as `{"untrusted": true, "value": "..."}`, so read it from `.value`. Check a command's exact output shape with `kraken commands --json`, which lists every command with its JSON Schemas.

Objects and arrays are given as JSON text. `--args-json '<json>'` supplies the whole argument object at once.

## Long jobs

`analyze` and `rebuild` wait until they finish, print progress to standard error, and print the final job result.

## Dangerous commands

They ask on the terminal. In scripts pass `--yes` to approve; without it they are denied.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 2 | Invalid arguments or usage error |
| 3 | Not found (function, project, proposal, ...) |
| 4 | Conflict or rejected (stale read, a human's edit has priority, analysis not finished, approval denied) |
| 5 | Unsupported by the engine, or an internal error |
| 6 | Cancelled or timed out |

```sh
kraken decompile --address 0x1189 || echo "failed with $?"
```

## Assistant commands

Beside the registry commands, `kraken explain <address>`, `kraken overview`, `kraken auto-name [--limit N] [--dry-run]` and `kraken glossary <term>` use the built-in assistant. They are described in [The built-in assistant](assistant.md).

## Rewriting

The `rewrite-*` commands translate functions to Rust and check them against the original. They are described in [The rewrite pipeline](design/0013-rewrite-pipeline.md) and the [command reference](reference/commands.md).

```sh
kraken rewrite-plan                                   # callees first; flags what cannot be tested yet
kraken rewrite-function --address 0x1189              # model call, sandboxed build, differential test
kraken rewrite-function --address 0x1189 --mode spec  # reimplement from a cited spec instead
kraken rewrite-status                                 # progress per function
kraken rewrite-accept --unit ru-4a0f7dbcbe726d81      # only you can accept
kraken rewrite-export --dir rewrite-out               # Cargo workspace with an FFI shim, built in the sandbox
```

The model comes from the `[provider]` table of `config.toml`, as for the assistant. Generated code runs only in a sandbox (Linux with Landlock); elsewhere the commands refuse.

## Local models

`kraken infer list|start|status|stop|logs` and `kraken infer setup llama` run a model on this computer under the daemon and can make the assistant use it (`--use`). See [Running a model on this computer](local-models.md).
