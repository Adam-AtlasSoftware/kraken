//! Guards the `RUSTSEC-2026-0344` ignore in `deny.toml`: everything KRAKEN parses itself uses
//! `object` 0.40 (and with it `ruzstd` 0.9), so `object` 0.39 may remain only under icicle's
//! `addr2line`.

use std::collections::BTreeSet;
use std::process::Command;

#[test]
fn only_icicle_chain_uses_object_0_39() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--locked"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run cargo metadata");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let meta: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let packages = meta["packages"].as_array().unwrap();
    let id_of = |name: &str, version_prefix: &str| -> Option<String> {
        packages
            .iter()
            .find(|p| {
                p["name"] == name && p["version"].as_str().unwrap().starts_with(version_prefix)
            })
            .map(|p| p["id"].as_str().unwrap().to_string())
    };
    let Some(old) = id_of("object", "0.39.") else {
        return; // nothing left on 0.39: even better
    };
    let name_of = |id: &str| -> String {
        packages
            .iter()
            .find(|p| p["id"] == id)
            .map(|p| p["name"].as_str().unwrap().to_string())
            .unwrap()
    };
    let nodes = meta["resolve"]["nodes"].as_array().unwrap();
    let dependents: BTreeSet<String> = nodes
        .iter()
        .filter(|n| {
            n["dependencies"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d == old.as_str())
        })
        .map(|n| name_of(n["id"].as_str().unwrap()))
        .collect();
    assert_eq!(
        dependents,
        BTreeSet::from(["addr2line".to_string()]),
        "object 0.39 (ruzstd 0.8.3) must stay confined to icicle's addr2line; \
         move the new dependent to object 0.40"
    );
    // and addr2line is only reachable through icicle
    let addr = id_of("addr2line", "").unwrap();
    let users: BTreeSet<String> = nodes
        .iter()
        .filter(|n| {
            n["dependencies"]
                .as_array()
                .unwrap()
                .iter()
                .any(|d| d == addr.as_str())
        })
        .map(|n| name_of(n["id"].as_str().unwrap()))
        .collect();
    assert!(
        users.iter().all(|u| u.starts_with("icicle")),
        "addr2line is used by {users:?}, expected only icicle crates"
    );
}
