# Rewrite a program in Rust

KRAKEN can rewrite a program you have analyzed as Rust code, and check the Rust against the original program before you rely on it. This page walks through it from the first click to a Rust project you can open and build.

Before you start you need a project with an analyzed program (see [Getting started](getting-started.md)), an assistant that can write code (see [the assistant](assistant.md)), and a Linux computer with Landlock, because the Rust is only ever built and run inside a sandbox (see [What the sandbox does](#what-the-sandbox-does)). No demo is needed to look around: **Try the demo** on the welcome screen has a small program with a scripted rewrite that runs without a model.

![The rewrite wizard on the review step](images/rewrite-wizard.png)

## The short way: the wizard

Choose **Rewrite in Rust...** from the command palette (`Ctrl+K`), or press **Guided rewrite...** at the top of the Rewrite tab. A window walks through nine steps. Each step says in one sentence what it does, and when **Next** is off it says why, in plain words, under the steps.

| Step | What you do |
|---|---|
| **Scope** | Choose what to rewrite: one function, the plan (every function, callees first) or the whole program. |
| **Mode** | Choose **Translate the code** or **Write a spec, then reimplement**. |
| **Check** | See whether everything is in place: the assistant, the sandbox, the analysis, and how many functions and requests to the assistant the job takes. |
| **Run** | Press **Start**. A progress bar shows the job, and **Cancel** stops it. When it ends the wizard moves on by itself. |
| **Review** | See which functions matched the original. **Show** opens a function in the Rewrite tab. |
| **Accept** | Accept what you trust. This step is yours: assistants cannot accept. |
| **Export** | Write the accepted functions as a Rust project in a folder. **Browse...** opens a file dialog. |
| **Build** | Compile the project and run its tests in the sandbox. The log of each step is shown. |
| **Open** | **Open folder**, **Open in editor** or **Copy path**. |

Closing the wizard loses nothing. A running job keeps going, and every result is in the Rewrite tab.

## What happens, step by step

### 1. Plan

The plan lists the program's functions with the ones that call nothing else first. A function is rewritten only after the functions it calls, so each translation can use the ones before it. Functions that call each other are rewritten together. Import stubs and compiler glue are left out. In the Rewrite tab, **Plan the rewrite** makes the plan, and **Plan again** makes it again without losing results.

### 2. Translate

For each function the assistant reads the decompiled C and writes Rust. KRAKEN builds that Rust in the sandbox. If it does not build, or is refused because it uses something not allowed (files, network, processes), the assistant gets the error and tries again, up to three times.

### 3. Verify

KRAKEN runs the original function (in an emulator) and the Rust function on the same inputs, and compares the results and what they write to memory. The status of a function says what came out:

- **planned**: nothing has been translated yet.
- **translated**: Rust exists, but the test could not decide (for example, the function calls a library function the test cannot imitate).
- **verified**: the Rust agreed with the original on every test case that ran.
- **failed**: the Rust differed, or did not build. A counterexample shows the input where it differed.
- **accepted**: you accepted this version.

Verified means the Rust agreed on the cases tried. That is evidence, not proof. Open the functions that matter and read the Rust.

### 4. Accept

Accepting marks one version of a function as the one to export. Accept a function in its detail view, or use **Accept all verified** in the Rewrite tab. That asks you to confirm and lists how many functions it will accept. Agents can translate and test, but accepting is reserved for you.

### 5. Export

The export writes a Rust workspace with two crates: a library with the accepted functions, and a shim that exposes each one under its original name. You can link the shim in place of the original functions one at a time, and the functions you have not rewritten keep running from the original program. When an accepted function calls one you have not accepted, the export calls the original function by its name; the README lists these calls. Functions that use globals need to know where the original program's data is: call `kraken_attach_image` once first (the README says how). The folder must be empty or an earlier export. A folder inside the project needs no question; a folder outside it asks first.

### 6. Build and test

**Build and test** runs `cargo build` and `cargo test` on the exported folder, inside the sandbox. For a whole-program crate you can also tick **Run the program afterwards** and give it arguments. Each step shows pass or fail, how it ended and its log. Only folders KRAKEN exported are built: the folder must hold the `manifest.json` or `kraken-program.json` file KRAKEN wrote.

## One function, the plan, or the whole program

- **One function.** The best way to start. Select a function in the Decompiler and press **Rewrite in Rust**, or choose it in the wizard. You see how a translation and its test look.
- **The plan.** Every function in turn. **Translate all planned** runs them one after the other in plan order, so the assistant is never asked for twenty things at once. **Retry all failed** runs the failed ones again, each in the mode it was last run in. Both show how far they are and can be stopped.
- **The whole program.** In the Rewrite tab choose **Whole program**. KRAKEN translates every function the program's entry point reaches, writes one standalone Rust program, builds it, and then runs the original program and the Rust program on the same inputs. It compares the exit status, what each prints and what each writes to standard error. If they differ, KRAKEN finds the function most likely responsible from the first difference, translates it again with that case as evidence, and compares again (the **Repair rounds**, 0 to 4).

For the whole program you can add **test cases** under **Options**: a name, the arguments to start the program with (quotes group words) and text for its standard input. KRAKEN also runs a baseline case and generated ones. **Check every function too** also tests each function on its own, so a failure points at one function; turn it off to only compile the functions and rely on the program comparison. Each case compares the exit status, the standard output, the standard error and every file the program leaves in its working folder. **Folder for the Rust crate** is where the crate is written; leave it empty for `rewrite-program` inside the project.

Running the whole program starts the original program on your computer (inside the sandbox, with no network). KRAKEN asks before it does.

### What a whole-program rewrite can handle

Ordinary C and C++ programs for Linux on x86-64 work, not just small examples:

- **Globals.** The program's data (globals, static variables, constant tables, strings) is copied into the Rust program as one shared block at the addresses the decompiler shows. Every translated function reads and writes the same block, so state that one function sets is seen by the next, as in the original.
- **Floating point.** `float` and `double` parameters and results, and the math library (`sinf`, `powf`, `sqrt`, `lroundf`, ...), with the same results as the original.
- **Files and the C library.** Programs that write or read files (`fopen`, `fwrite`, `fprintf`, `perror`, ...), parse numbers (`strtod`, `strtol`, `atoi`), sort (`qsort`) or use `rand`. The files each program writes are compared too, not just what it prints.
- **C++.** Methods (they are named after their class, for example `Button_begin`), destructors, lambdas, library templates compiled into the program (`std::vector` growth, `std::sort` helpers), `new` and `delete`, and errors that end the program (`std::length_error`) with the same message. Exceptions that are caught are not modelled.
- **Functions reached through pointers.** Callbacks, dispatch tables and vtables in the program's data are found when a function that runs uses the table, and the table points at the Rust functions.

The test of each function on its own is a help, not a gate. A function whose own test fails, or cannot run (for example because it needs a pointer to an object the test cannot build), is still put in the program and marked **not checked on its own** (`unchecked`). The comparison of the whole program decides, and when it finds a difference, the repair rounds translate the likeliest function again with that difference as evidence.

For example, two C++ audio simulators of about 30 and 47 functions (floats, globals, `std::vector`, `.wav` files) were rewritten this way and matched the original on all 11 cases, including the files they write. One needed a second run and two repair rounds. If a run stops part way, start it again: translations from earlier runs that are still valid are reused, so only the rest is translated.

Limits: Linux x86-64 programs only; at most six integer and eight floating-point parameters per function; no varargs functions of the program itself; no threads, no `fork`, no network, no clock; exceptions that are caught are not modelled. A model run is slow: with a terminal agent each function takes one to two minutes.

## Translate or spec

- **Translate the code** is the default: the assistant writes Rust that does what the C does, quirks included. Choose it when you want the same behavior and when you do not yet understand the function.
- **Write a spec, then reimplement** first has the assistant write a plain description of the function, each statement tied to an address in the binary (click an address in the spec to jump there). It then writes the Rust from the description alone, without seeing the C. You get cleaner code and a document you can read, at the cost of one more request per function. The same test decides whether the Rust is right. Spec mode works function by function; it is not available for the whole program yet.

## What the sandbox does

The Rust comes from a model, so KRAKEN treats it as untrusted. It is built and run only in a confined process: the file system is read-only except for a private scratch folder, there is no network, memory, time and output are limited, and the environment is scrubbed. Before anything is built, a check refuses code that uses files, the network, processes, inline assembly or other things a translation does not need. If your computer cannot do this (Linux with Landlock ABI 4 or newer is required), the buttons that would build or run code are off and say so. There is no setting to run generated code without the sandbox. The sandbox shares your computer's kernel; for malware, use a virtual machine. See [Security](security.md).

Model requests send decompiled code to the assistant's service. The Check step shows which assistant is used and where requests go.

## Using it from an assistant or a script

Everything above is a command, so an assistant connected through [MCP](mcp.md) or a script using the [CLI](cli.md) can run the whole flow:

| Command | What it does |
|---|---|
| `rewrite_plan` | Plan the functions, callees first. |
| `rewrite_function` | Translate and verify one function (a job). |
| `rewrite_spec` | Write a cited spec of a function or the program (a job). |
| `rewrite_status`, `rewrite_unit` | Read the statuses, and the stored Rust, verdicts and versions of one function. |
| `rewrite_program`, `rewrite_program_status` | Rewrite the whole program and compare it with the original (a job), and read the run. `inputs` takes test cases, `dir` the output folder and `verify_functions` the per-function check. |
| `rewrite_accept` | Accept a verified version. People only. |
| `rewrite_export` | Write the accepted functions as a workspace (a job). |
| `rewrite_build` | Build and test an exported folder in the sandbox, and optionally run a program crate with `run_args` (a job). |

Jobs return a `job_id`; read progress and the result with `job_status` or `job_await`. `rewrite_program` and `rewrite_build` run generated code, so a call from an agent asks for your approval first. The [command reference](reference/commands.md) has every argument.

## If something does not work

- **The buttons are off with a note about the sandbox.** Your computer cannot confine generated code. Use Linux 6.7 or newer, or a kernel with Landlock ABI 4.
- **No assistant is set up.** Choose one in **Settings**, or name a provider in your KRAKEN config file. See [the assistant](assistant.md).
- **Everything comes out translated, not verified.** The functions call library functions the test cannot imitate yet. Open one: its flags say which. The whole-program comparison still tells you whether the program behaves like the original.
- **Many functions say "not checked on its own".** Their own test failed or could not run, often because they take a pointer to an object (a C++ `this`) that random test inputs cannot build. They are still in the program; the program comparison is what counts.
- **The program differs in a file it writes.** The differences name the file, both sizes and where the first difference is (a byte, or a 4 KiB block). The repair rounds use the first difference of the output; a file difference alone is shown to you.
- **A function failed.** Open it in the Rewrite tab. The counterexample shows the input where the Rust and the original differed, and the history lists earlier attempts. **Retry** runs it again.
- **The build failed.** The log of the failing step is in the Build step. The Rust is the assistant's; fix it by hand in the exported folder, or run the function again.
