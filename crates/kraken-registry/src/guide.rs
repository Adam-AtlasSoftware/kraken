//! What to do next: rules over facts about the open project.
//!
//! [`Facts`] is a plain description of the project (gathered by the `next_steps` command) and
//! [`suggest`] runs the [`RULES`] table over it. A rule looks at the facts and, when it applies,
//! returns a [`Suggestion`]: a title, the reason, and the registry command with arguments that
//! does it. The rules never touch the engine, so a table test can pin what each kind of program
//! gets.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// How much a project has of its debug information.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DebugFacts {
    /// Not looked at (no probe result).
    #[default]
    Unknown,
    /// The debug information is inside the program, or a debug file is attached.
    Have,
    /// The program holds none and a matching separate file was found.
    FileFound,
    /// The program names a separate file (a PDB, a build-id) that was not found.
    FileMissing,
    /// The program neither holds nor names any.
    None,
}

/// A local variable the decompiler named itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct AutoLocal {
    /// The name the decompiler gave (`local_28`, `iVar1`).
    pub name: String,
    /// Where it lives, as `set_local` takes it (`stack:0xffffffffffffffd8`).
    pub storage: String,
}

/// The function the person is looking at.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct CurrentFunction {
    /// Entry address, as `0x...`.
    pub address: String,
    /// Its name.
    pub name: String,
    /// Variables the decompiler named itself, one per storage location.
    pub auto_locals: Vec<AutoLocal>,
}

/// What the rules look at.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize, JsonSchema)]
pub struct Facts {
    /// Path of the analysed program.
    pub binary: String,
    /// Container format as the engine names it (`ELF`, `PE`).
    pub format: String,
    /// Architecture or language id.
    pub arch: String,
    /// Analysis has finished.
    pub analysed: bool,
    /// Analysis is running now.
    pub analysis_running: bool,
    /// The last analysis failed.
    pub analysis_failed: bool,
    /// Functions the engine knows.
    pub function_count: u64,
    /// Functions that still carry an engine default name (`FUN_...`, `sub_...`).
    pub auto_named: u64,
    /// Where the program stands with its debug information.
    pub debug: DebugFacts,
    /// The program names a PDB.
    pub names_pdb: bool,
    /// A debug file that `debuginfo_attach` can use.
    pub debug_candidate: Option<String>,
    /// Byte patches that are switched on.
    pub patches_on: u64,
    /// The patches that are on have a `patch_verify` verdict.
    pub patches_verified: bool,
    /// A dynamically linked program that needs a sysroot to run in the emulator, and none is
    /// installed for this architecture.
    pub needs_sysroot: bool,
    /// The function in view, when the caller names one.
    pub current: Option<CurrentFunction>,
}

/// One suggestion.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Suggestion {
    /// Stable id of the rule (`analyze`, `debug_probe`); a person can dismiss it by id.
    pub id: String,
    /// What to do, short.
    pub title: String,
    /// Why it is worth doing now, in a sentence or two.
    pub reason: String,
    /// The registry command that does it; absent when the step is outside KRAKEN.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,
    /// Arguments for `command`.
    #[serde(default)]
    pub args: Value,
    /// True when `command` can run as it stands. False when it still needs something from
    /// the person (a name, a file), so a client should open a dialog or ask instead.
    pub runnable: bool,
}

type Rule = fn(&Facts) -> Vec<Suggestion>;

/// The rules in order of importance.
pub const RULES: &[(&str, Rule)] = &[
    ("analyze", analyze),
    ("debug_attach", debug_attach),
    ("debug_probe", debug_probe),
    ("patch_verify", patch_verify),
    ("name_functions", name_functions),
    ("set_local", set_local),
    ("sysroot", sysroot),
    ("explore", explore),
];

/// Runs every rule over `facts`: the suggestions in order of importance.
pub fn suggest(facts: &Facts) -> Vec<Suggestion> {
    RULES.iter().flat_map(|(_, rule)| rule(facts)).collect()
}

fn sg(
    id: &str,
    title: impl Into<String>,
    reason: impl Into<String>,
    command: Option<&str>,
    args: Value,
    runnable: bool,
) -> Suggestion {
    Suggestion {
        id: id.into(),
        title: title.into(),
        reason: reason.into(),
        command: command.map(str::to_string),
        args,
        runnable,
    }
}

fn analyze(f: &Facts) -> Vec<Suggestion> {
    if f.analysed || f.analysis_running {
        return Vec::new();
    }
    let reason = if f.analysis_failed {
        "The last analysis did not finish. Run it again to find the functions."
    } else {
        "Nothing is analysed yet, so there are no functions to read. Analysis finds them and \
         names what it can."
    };
    vec![sg(
        "analyze",
        "Analyse the program",
        reason,
        Some("analyze"),
        json!({}),
        true,
    )]
}

fn debug_attach(f: &Facts) -> Vec<Suggestion> {
    match (&f.debug_candidate, f.debug) {
        (Some(file), DebugFacts::FileFound) => vec![sg(
            "debug_attach",
            "Attach the debug file that was found",
            "A separate debug file matches this program. With it the functions, types and \
             variables come back with their real names.",
            Some("debuginfo_attach"),
            json!({"debug_file": file}),
            true,
        )],
        _ => Vec::new(),
    }
}

fn debug_probe(f: &Facts) -> Vec<Suggestion> {
    if f.binary.is_empty() || !matches!(f.debug, DebugFacts::None | DebugFacts::FileMissing) {
        return Vec::new();
    }
    let reason = if f.names_pdb {
        "This Windows program names a PDB that is not attached. Debug information gives names \
         and types; check where KRAKEN looked."
    } else if f.debug == DebugFacts::FileMissing {
        "The program points at a separate debug file that was not found. See where KRAKEN \
         looked and what a matching file must carry."
    } else {
        "The program is stripped: it has no debug information inside it. Check whether a \
         matching debug file exists on this computer."
    };
    vec![sg(
        "debug_probe",
        "Look for a debug file",
        reason,
        Some("debuginfo_probe"),
        json!({"path": f.binary}),
        true,
    )]
}

fn patch_verify(f: &Facts) -> Vec<Suggestion> {
    if f.patches_on == 0 || f.patches_verified {
        return Vec::new();
    }
    vec![sg(
        "patch_verify",
        "Check what your patches do",
        format!(
            "{} patch{} on with no verdict. Verify runs the original and the patched program \
             side by side and reports the first difference.",
            f.patches_on,
            if f.patches_on == 1 { " is" } else { "es are" }
        ),
        Some("patch_verify"),
        json!({}),
        true,
    )]
}

/// Many default names: the program is mostly unnamed.
fn name_functions(f: &Facts) -> Vec<Suggestion> {
    if !f.analysed || f.auto_named < 10 || f.auto_named * 2 < f.function_count {
        return Vec::new();
    }
    vec![sg(
        "name_functions",
        "Name the unnamed functions",
        format!(
            "{} of {} functions still have default names. The assistant can suggest names \
             from what each one does (a model call, so it asks first). If you have a symbol \
             file, `symbols_import` applies it instead.",
            f.auto_named, f.function_count
        ),
        Some("assist_auto_name"),
        json!({"limit": 10}),
        true,
    )]
}

fn set_local(f: &Facts) -> Vec<Suggestion> {
    let Some(cur) = f.current.as_ref().filter(|c| !c.auto_locals.is_empty()) else {
        return Vec::new();
    };
    let first = &cur.auto_locals[0];
    let n = cur.auto_locals.len();
    vec![sg(
        "set_local",
        format!(
            "Name the {} unnamed variable{} in {}",
            n,
            if n == 1 { "" } else { "s" },
            cur.name
        ),
        format!(
            "The decompiler named {} itself (such as `{}`). Click one and press N to give it a \
             name that says what it holds; the code reads much faster.",
            if n == 1 { "it" } else { "them" },
            first.name
        ),
        Some("set_local"),
        json!({"address": cur.address, "storage": first.storage}),
        false,
    )]
}

fn sysroot(f: &Facts) -> Vec<Suggestion> {
    if !f.needs_sysroot {
        return Vec::new();
    }
    vec![sg(
        "sysroot",
        "Install an emulator sysroot",
        format!(
            "This program is dynamically linked for {} and the emulator needs that \
             architecture's loader and libraries to run it. Setup downloads them (about \
             20 MB from deb.debian.org); `kraken setup --sysroots` does the same.",
            f.arch
        ),
        Some("setup_sysroots"),
        json!({}),
        true,
    )]
}

/// A gentle first move when nothing else applies.
fn explore(f: &Facts) -> Vec<Suggestion> {
    if !f.analysed || f.function_count == 0 {
        return Vec::new();
    }
    let others = [
        debug_attach(f),
        debug_probe(f),
        patch_verify(f),
        name_functions(f),
        set_local(f),
        sysroot(f),
    ];
    if others.iter().any(|v| !v.is_empty()) {
        return Vec::new();
    }
    vec![sg(
        "explore",
        "See what the program imports",
        "The imports show what the program asks the system for: files, network, crypto. They \
         point at the functions worth reading first.",
        Some("imports"),
        json!({"limit": 50}),
        true,
    )]
}

/// True for the names the decompiler gives variables it has no better name for.
pub fn is_auto_local(name: &str) -> bool {
    for p in ["local_", "param_", "auStack_", "uStack_", "lStack_"] {
        if let Some(rest) = name.strip_prefix(p) {
            return !rest.is_empty();
        }
    }
    // `iVar1`, `uVar12`, `pcVar3`: one to four lower-case letters, `Var`, digits.
    let Some(at) = name.find("Var") else {
        return false;
    };
    let (prefix, digits) = (&name[..at], &name[at + 3..]);
    (1..=4).contains(&prefix.len())
        && prefix.bytes().all(|b| b.is_ascii_lowercase())
        && !digits.is_empty()
        && digits.bytes().all(|b| b.is_ascii_digit())
}

/// True for a function name the engine made up.
pub fn is_auto_function(name: &str) -> bool {
    ["FUN_", "sub_", "thunk_FUN_"].iter().any(|p| {
        name.strip_prefix(p)
            .is_some_and(|rest| !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_hexdigit()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(f: &Facts) -> Vec<String> {
        suggest(f).into_iter().map(|s| s.id).collect()
    }

    #[test]
    fn auto_names() {
        for n in ["local_28", "param_1", "iVar1", "pcVar12", "auStack_38"] {
            assert!(is_auto_local(n), "{n}");
        }
        for n in ["count", "local_", "Var1", "in_RAX", "bufVar", "argc"] {
            assert!(!is_auto_local(n), "{n}");
        }
        assert!(is_auto_function("FUN_00401136"));
        assert!(is_auto_function("sub_401000"));
        assert!(!is_auto_function("main"));
        assert!(!is_auto_function("FUN_"));
    }

    #[test]
    fn a_new_project_is_told_to_analyse_and_nothing_else_shouts() {
        let f = Facts {
            binary: "/p/a.out".into(),
            ..Facts::default()
        };
        assert_eq!(ids(&f), ["analyze"]);
    }

    #[test]
    fn a_stripped_analysed_program_gets_the_debug_probe_and_naming() {
        let f = Facts {
            binary: "/p/a.out".into(),
            analysed: true,
            function_count: 20,
            auto_named: 18,
            debug: DebugFacts::None,
            ..Facts::default()
        };
        assert_eq!(ids(&f), ["debug_probe", "name_functions"]);
    }

    #[test]
    fn a_found_debug_file_is_attached_before_anything_else() {
        let f = Facts {
            binary: "/p/a.out".into(),
            analysed: true,
            function_count: 20,
            debug: DebugFacts::FileFound,
            debug_candidate: Some("/d/a.debug".into()),
            ..Facts::default()
        };
        let s = suggest(&f);
        assert_eq!(s[0].id, "debug_attach");
        assert_eq!(s[0].args, json!({"debug_file": "/d/a.debug"}));
    }

    #[test]
    fn patches_without_a_verdict_and_unnamed_variables_and_sysroot() {
        let f = Facts {
            binary: "/p/a.out".into(),
            analysed: true,
            function_count: 5,
            debug: DebugFacts::Have,
            patches_on: 2,
            needs_sysroot: true,
            arch: "AARCH64:LE:64:v8A".into(),
            current: Some(CurrentFunction {
                address: "0x401000".into(),
                name: "main".into(),
                auto_locals: vec![AutoLocal {
                    name: "local_10".into(),
                    storage: "stack:0xfffffffffffffff0".into(),
                }],
            }),
            ..Facts::default()
        };
        assert_eq!(ids(&f), ["patch_verify", "set_local", "sysroot"]);
        let verified = Facts {
            patches_verified: true,
            ..f
        };
        assert_eq!(ids(&verified), ["set_local", "sysroot"]);
    }

    #[test]
    fn a_healthy_program_gets_the_gentle_default() {
        let f = Facts {
            binary: "/p/a.out".into(),
            analysed: true,
            function_count: 30,
            debug: DebugFacts::Have,
            ..Facts::default()
        };
        assert_eq!(ids(&f), ["explore"]);
    }
}
