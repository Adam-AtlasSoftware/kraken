//! Replies of the `rewrite_*` commands as the panel reads them. Only the fields the panel uses
//! are listed, and everything that a later daemon might add has a default, so an older GUI keeps
//! working against a newer daemon.

use kraken_proto::{Hex64, Untrusted};
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub(super) struct PlanWire {
    #[serde(default)]
    pub functions_total: u64,
    #[serde(default)]
    pub functions_planned: u64,
    #[serde(default)]
    pub skipped_imports: u64,
    #[serde(default)]
    pub skipped_runtime: u64,
    #[serde(default)]
    pub groups: u32,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default)]
    pub entries: Vec<PlanEntryWire>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct PlanEntryWire {
    pub address: Hex64,
    #[serde(default)]
    pub name: Option<Untrusted<String>>,
    #[serde(default)]
    pub group_size: u32,
    #[serde(default)]
    pub callees: Vec<Hex64>,
    #[serde(default)]
    pub imports: Vec<Untrusted<String>>,
    #[serde(default)]
    pub needs_stubs: Vec<Untrusted<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct StatusWire {
    #[serde(default)]
    pub plan_present: bool,
    #[serde(default)]
    pub counts: CountsWire,
    #[serde(default)]
    pub units: Vec<RowWire>,
    #[serde(default)]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct CountsWire {
    #[serde(default)]
    pub planned: u32,
    #[serde(default)]
    pub translated: u32,
    #[serde(default)]
    pub verified: u32,
    #[serde(default)]
    pub failed: u32,
    #[serde(default)]
    pub accepted: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct RowWire {
    #[serde(default)]
    pub unit: String,
    #[serde(default)]
    pub order: Option<u32>,
    pub address: Hex64,
    pub name: Untrusted<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub accepted_version: Option<u32>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub verdict: Option<String>,
    #[serde(default)]
    pub cases_run: u32,
    #[serde(default)]
    pub passed: u32,
    #[serde(default)]
    pub counterexamples: u32,
    #[serde(default)]
    pub provider: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub flags: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct CounterexampleWire {
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub differences: Vec<Untrusted<String>>,
}

/// A finished `rewrite_function` job, or one version in a `rewrite_unit` reply (the same fields,
/// plus the code).
#[derive(Debug, Clone, Deserialize)]
pub(super) struct VersionWire {
    #[serde(default)]
    pub unit: String,
    #[serde(default)]
    pub version: u32,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub accepted: bool,
    #[serde(default)]
    pub verdict: String,
    #[serde(default)]
    pub verdict_detail: Option<Untrusted<String>>,
    #[serde(default)]
    pub cases_run: u32,
    #[serde(default)]
    pub passed: u32,
    #[serde(default)]
    pub skipped: u32,
    #[serde(default)]
    pub counterexample: Option<CounterexampleWire>,
    #[serde(default, alias = "signature")]
    pub rust_prototype: String,
    #[serde(default)]
    pub rust_code: Option<Untrusted<String>>,
    #[serde(default)]
    pub sandbox: String,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub assumptions: Vec<Untrusted<String>>,
    #[serde(default)]
    pub unsupported: Vec<Untrusted<String>>,
}

/// The reply of `rewrite_unit`, a query the panel uses when the daemon offers it: the stored
/// versions of one function with their code, and its spec.
#[derive(Debug, Clone, Deserialize)]
pub(super) struct UnitWire {
    #[serde(default)]
    pub versions: Vec<VersionWire>,
    #[serde(default)]
    pub spec: Option<SpecWire>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct SpecWire {
    #[serde(default)]
    pub spec: u64,
    #[serde(default)]
    pub functions: u32,
    #[serde(default)]
    pub facts: u32,
    pub markdown: Untrusted<String>,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub model: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct AcceptWire {
    #[serde(default)]
    pub replaced_version: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct ExportWire {
    #[serde(default)]
    pub dir: String,
    #[serde(default)]
    pub crates: Vec<String>,
    #[serde(default)]
    pub symbols: Vec<String>,
    #[serde(default)]
    pub built: bool,
    #[serde(default)]
    pub sandbox: String,
    #[serde(default)]
    pub coverage: CoverageWire,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(super) struct CoverageWire {
    #[serde(default)]
    pub accepted: u32,
    #[serde(default)]
    pub planned: u32,
    #[serde(default)]
    pub functions_total: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct StartedWire {
    pub job_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub(super) struct DecompileTextWire {
    pub text: Untrusted<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kraken_registry::commands::RewriteUnitOut;
    use serde_json::json;

    /// The panel reads exactly what the registry's `rewrite_unit` produces.
    #[test]
    fn the_registry_reply_of_rewrite_unit_parses() {
        let reply = json!({
            "address": "0x10",
            "versions": [{
                "unit": "ru-1", "version": 2, "mode": "spec", "status": "accepted",
                "accepted": true, "verdict": "pass", "cases_run": 9, "passed": 9, "skipped": 0,
                "rust_code": {"untrusted": true, "value": "fn f() {}"},
                "signature": "pub unsafe extern \"C\" fn f()", "oracle_kind": "emu",
                "sandbox": "landlock", "created": 7, "provider": "p", "model": "m"
            }],
            "spec": {"spec": 3, "markdown": {"untrusted": true, "value": "# f"},
                     "citations": ["0x10"], "facts": 1, "provider": "p", "model": "m"}
        });
        serde_json::from_value::<RewriteUnitOut>(reply.clone()).expect("registry shape");
        let u: UnitWire = serde_json::from_value(reply).expect("panel shape");
        assert_eq!(
            u.versions[0].rust_prototype,
            "pub unsafe extern \"C\" fn f()"
        );
        assert!(u.versions[0].accepted);
        assert_eq!(u.spec.map(|s| s.markdown.0), Some("# f".to_string()));
    }
}
