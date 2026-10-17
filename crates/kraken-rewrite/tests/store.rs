//! `rewrite.sqlite`: lifecycle, versions, specs, the stored plan and the migrations.

use kraken_registry::commands::{PlanFlag, RewriteMode, UnitStatus};
use kraken_rewrite::abi::{Arg, Observation, Param, Ret, Signature, Termination};
use kraken_rewrite::difftest::{CaseRecord, Counterexample, DiffReport, Verdict};
use kraken_rewrite::store::{
    DB_FILE, MIGRATIONS, NewSpec, PlannedFunction, RewriteStore, SCHEMA_VERSION, StoredPlan,
    StoredSpec, migrate,
};
use kraken_rewrite::unit::{
    FunctionAnchor, OracleInfo, Provenance, RewriteUnit, UnitSource, status_for,
};
use rusqlite::{Connection, params};

const PROG: &str = "ab12";

fn signature() -> Signature {
    Signature {
        name: "f".into(),
        params: vec![Param::Buf],
        ret: Ret::Int {
            bits: 32,
            signed: true,
        },
    }
}

fn case(n: u8) -> CaseRecord {
    CaseRecord {
        args: vec![Arg::Buf { data: vec![n; 4] }],
        expected: Observation::failed(Termination::Returned),
    }
}

fn unit_with(address: &str, code: &str, verdict: Verdict, mode: RewriteMode) -> RewriteUnit {
    let counterexamples = if verdict == Verdict::Fail {
        vec![Counterexample {
            args: vec![Arg::Buf { data: vec![9; 4] }],
            original: Observation::failed(Termination::Returned),
            translation: Observation::failed(Termination::Timeout),
            differences: vec!["return value: original Some(1), translation Some(2)".into()],
        }]
    } else {
        Vec::new()
    };
    let report = DiffReport {
        verdict,
        seed: u64::MAX - 5,
        cases_run: 3,
        passed: 3,
        skipped: 1,
        counterexamples,
        cases: vec![case(1), case(2), case(3)],
        sandbox: "landlock-v6".into(),
    };
    RewriteUnit::from_run(
        UnitSource {
            mode,
            spec_id: None,
            anchor: FunctionAnchor {
                program_sha256: PROG.into(),
                space: "ram".into(),
                address: address.into(),
                name: "f".into(),
            },
            source_decompile_hash: "dh".into(),
            callees: Vec::new(),
            signature: signature(),
            provenance: Provenance {
                author: "model".into(),
                provider: Some("replay".into()),
                model: Some("cassette".into()),
                task: "rewrite_function".into(),
                prompt_hash: "ph".into(),
            },
            oracle: OracleInfo {
                kind: "k".into(),
                emulator: "e".into(),
                binary: "b".into(),
                elf_vaddr: 0x1000,
            },
        },
        code.to_string(),
        report,
    )
}

fn pass(address: &str, code: &str) -> RewriteUnit {
    unit_with(address, code, Verdict::Pass, RewriteMode::Incremental)
}

#[test]
fn verdicts_decide_the_status() {
    assert_eq!(status_for(&Verdict::Pass), UnitStatus::Verified);
    assert_eq!(status_for(&Verdict::Fail), UnitStatus::Failed);
    assert_eq!(
        status_for(&Verdict::Rejected { reason: "x".into() }),
        UnitStatus::Failed
    );
    assert_eq!(
        status_for(&Verdict::Inconclusive { reason: "x".into() }),
        UnitStatus::Translated
    );
}

#[test]
fn units_are_versioned_per_function_and_read_back_whole() {
    let st = RewriteStore::open_in_memory().expect("store");
    assert_eq!(st.schema_version().expect("version"), SCHEMA_VERSION);
    let a1 = st.put_unit(pass("0x10", "fn a1")).expect("put");
    let a2 = st
        .put_unit(unit_with("0x10", "fn a2", Verdict::Fail, RewriteMode::Spec))
        .expect("put");
    let b1 = st.put_unit(pass("0x20", "fn b1")).expect("put");
    assert_eq!((a1.version, a2.version, b1.version), (1, 2, 1));

    let back = st.get(&a2.id).expect("get").expect("unit");
    assert_eq!(back, a2);
    assert_eq!(back.mode, RewriteMode::Spec);
    assert_eq!(back.status, UnitStatus::Failed);
    assert_eq!(back.counterexamples.len(), 1);
    assert_eq!(back.summary.seed, u64::MAX - 5, "u64 seeds survive SQLite");
    assert_eq!(back.test_cases.len(), 3);
    assert_eq!(
        st.latest(PROG, "0x10").expect("latest").expect("unit").id,
        a2.id
    );
    let all = st.versions(PROG, "0x10").expect("versions");
    assert_eq!(
        all.iter().map(|u| u.version).collect::<Vec<_>>(),
        vec![1, 2]
    );
    assert!(st.latest(PROG, "0x99").expect("latest").is_none());
    assert!(st.get("ru-unknown").expect("get").is_none());

    // The same translation stored again is a new version with its own id.
    let again = st.put_unit(pass("0x20", "fn b1")).expect("put");
    assert_eq!(again.version, 2);
    assert_ne!(again.id, b1.id);
    assert!(again.id.starts_with(&b1.id));
    let third = st.put_unit(pass("0x20", "fn b1")).expect("put");
    assert_eq!(third.version, 3);
    assert_ne!(third.id, again.id);

    let sums = st.summaries(PROG).expect("summaries");
    assert_eq!(sums.len(), 2);
    assert_eq!(sums[0].address, "0x10");
    assert_eq!(sums[0].status, UnitStatus::Failed);
    assert_eq!(sums[0].verdict.as_deref(), Some("fail"));
    assert_eq!(sums[0].counterexamples, 1);
    assert_eq!(sums[0].mode, RewriteMode::Spec);
    assert_eq!(sums[1].version, 3);
    assert!(st.summaries("other").expect("summaries").is_empty());
}

#[test]
fn accepting_follows_the_lifecycle_and_keeps_one_accepted_version() {
    let st = RewriteStore::open_in_memory().expect("store");
    let v1 = st.put_unit(pass("0x10", "fn one")).expect("put");
    let bad = st
        .put_unit(unit_with(
            "0x10",
            "fn bad",
            Verdict::Fail,
            RewriteMode::Incremental,
        ))
        .expect("put");
    let v3 = st.put_unit(pass("0x10", "fn three")).expect("put");

    let e = st
        .accept(&bad.id, "ann")
        .expect_err("failed units cannot be accepted");
    assert!(e.to_string().contains("failed"), "{e}");
    assert!(st.accept("ru-nope", "ann").is_err());

    let (acc, replaced) = st.accept(&v1.id, "ann").expect("accept");
    assert_eq!((acc.status, replaced), (UnitStatus::Accepted, None));
    assert!(st.accept(&v1.id, "ann").is_err(), "already accepted");
    assert_eq!(
        st.accepted(PROG, "0x10")
            .expect("accepted")
            .expect("unit")
            .id,
        v1.id
    );
    // The function reads as accepted although its newest version is verified only.
    let s = &st.summaries(PROG).expect("summaries")[0];
    assert_eq!(s.status, UnitStatus::Accepted);
    assert_eq!((s.version, s.accepted_version), (3, Some(1)));

    // A later translation of an accepted function does not unaccept it.
    let v4 = st.put_unit(pass("0x10", "fn four")).expect("put");
    assert_eq!(
        st.summaries(PROG).expect("summaries")[0].status,
        UnitStatus::Accepted
    );

    let (acc3, replaced) = st.accept(&v3.id, "bob").expect("accept v3");
    assert_eq!(replaced, Some(1));
    assert_eq!(acc3.version, 3);
    let versions = st.versions(PROG, "0x10").expect("versions");
    let status_of = |v: u32| {
        versions
            .iter()
            .find(|u| u.version == v)
            .map(|u| u.status)
            .expect("version")
    };
    assert_eq!(
        status_of(1),
        UnitStatus::Verified,
        "the replaced one goes back"
    );
    assert_eq!(status_of(2), UnitStatus::Failed);
    assert_eq!(status_of(3), UnitStatus::Accepted);
    assert_eq!(status_of(4), UnitStatus::Verified);
    assert_eq!(st.accepted_units(PROG).expect("accepted").len(), 1);
    let _ = v4;

    // The history of the function.
    let events = st.events(PROG, "0x10").expect("events");
    let summary: Vec<(u32, Option<&str>, &str, &str)> = events
        .iter()
        .map(|e| (e.0, e.1.as_deref(), e.2.as_str(), e.3.as_str()))
        .collect();
    assert_eq!(
        summary,
        vec![
            (1, None, "verified", "model"),
            (2, Some("verified"), "failed", "model"),
            (3, Some("failed"), "verified", "model"),
            (1, Some("verified"), "accepted", "ann"),
            (4, Some("accepted"), "verified", "model"),
            (1, Some("accepted"), "verified", "bob"),
            (3, Some("verified"), "accepted", "bob"),
        ]
    );
}

#[test]
fn specs_and_plans_round_trip() {
    let st = RewriteStore::open_in_memory().expect("store");
    let spec = |md: &str, addr: Option<&str>| NewSpec {
        program_sha256: PROG.into(),
        spec: StoredSpec {
            id: 0,
            scope: if addr.is_some() {
                "function"
            } else {
                "program"
            }
            .into(),
            address: addr.map(str::to_string),
            markdown: md.into(),
            citations: vec![0x10, 0x20],
            facts: 7,
            functions: 2,
            source_hash: "h".into(),
            provider: "p".into(),
            model: "m".into(),
            prompt_hash: "ph".into(),
        },
    };
    let a = st.put_spec(spec("one", Some("0x10"))).expect("spec");
    let b = st.put_spec(spec("two", Some("0x10"))).expect("spec");
    let p = st.put_spec(spec("whole", None)).expect("spec");
    assert!(a < b && b < p);
    let latest = st
        .latest_spec(PROG, Some("0x10"))
        .expect("read")
        .expect("spec");
    assert_eq!((latest.id, latest.markdown.as_str()), (b, "two"));
    assert_eq!(latest.citations, vec![0x10, 0x20]);
    assert_eq!(st.spec(a).expect("read").expect("spec").markdown, "one");
    assert_eq!(
        st.latest_spec(PROG, None)
            .expect("read")
            .expect("spec")
            .markdown,
        "whole"
    );
    assert!(st.latest_spec(PROG, Some("0x99")).expect("read").is_none());
    assert!(
        st.latest_spec("other", Some("0x10"))
            .expect("read")
            .is_none()
    );

    assert!(st.plan(PROG).expect("plan").is_none());
    let entry = |order: u32, address: u64, flags: Vec<PlanFlag>| PlannedFunction {
        order,
        address,
        name: format!("fn{order}"),
        group: order,
        group_size: 1,
        callees: if order > 0 { vec![0x100] } else { vec![] },
        imports: vec!["printf".into()],
        needs_stubs: vec!["calloc".into()],
        flags,
    };
    let plan = StoredPlan {
        functions_total: 9,
        skipped_imports: 3,
        skipped_runtime: 2,
        groups: 2,
        truncated: true,
        entries: vec![
            entry(0, 0x100, vec![]),
            entry(1, 0x200, vec![PlanFlag::NeedsStubs, PlanFlag::Recursive]),
        ],
    };
    st.save_plan(PROG, &plan).expect("save");
    assert_eq!(st.plan(PROG).expect("plan").expect("stored"), plan);
    // Saving again replaces it.
    let smaller = StoredPlan {
        entries: vec![entry(0, 0x100, vec![])],
        truncated: false,
        ..plan
    };
    st.save_plan(PROG, &smaller).expect("save");
    assert_eq!(st.plan(PROG).expect("plan").expect("stored"), smaller);
    assert!(st.plan("other").expect("plan").is_none());
}

/// A version 1 database as the first release wrote it: only the unit tables, no `spec_id`, no
/// specs or plan.
fn make_v1(path: &std::path::Path) {
    let mut conn = Connection::open(path).expect("open");
    migrate(&mut conn, &MIGRATIONS[..1]).expect("v1");
    let version: u32 = conn
        .query_row("SELECT MAX(version) FROM schema_version", [], |r| r.get(0))
        .expect("version");
    assert_eq!(version, 1);
    conn.execute(
        "INSERT INTO units (program_sha256, address, name, mode, status, current_version,
                accepted_version, created_at, updated_at)
         VALUES ('ab12', '0x10', 'old_fn', 'incremental', 'accepted', 1, 1, 100, 100)",
        [],
    )
    .expect("unit row");
    let sig = serde_json::to_string(&signature()).expect("sig");
    let oracle = serde_json::to_string(&OracleInfo {
        kind: "k".into(),
        emulator: "e".into(),
        binary: "b".into(),
        elf_vaddr: 16,
    })
    .expect("oracle");
    conn.execute(
        "INSERT INTO unit_versions (id, program_sha256, address, name, space, version, mode,
                status, source_decompile_hash, callees_json, rust_code, rust_code_hash,
                signature_json, rust_prototype, oracle_json, author, provider, model, task,
                prompt_hash, created_at)
         VALUES ('ru-old', 'ab12', '0x10', 'old_fn', 'ram', 1, 'incremental', 'accepted', 'dh',
                 '[]', 'fn old', 'rh', ?1, 'proto', ?2, 'model', 'replay', 'cassette',
                 'rewrite_function', 'ph', 100)",
        params![sig, oracle],
    )
    .expect("version row");
    conn.execute(
        "INSERT INTO test_cases (version_id, ordinal, case_json) VALUES ('ru-old', 0, ?1)",
        params![serde_json::to_string(&case(1)).expect("case")],
    )
    .expect("case row");
    conn.execute(
        "INSERT INTO verdicts (version_id, verdict, detail, seed, cases_run, passed, skipped,
                sandbox, counterexamples_json, created_at)
         VALUES ('ru-old', 'pass', NULL, 42, 5, 5, 0, 'landlock-v6', '[]', 100)",
        [],
    )
    .expect("verdict row");
    conn.execute(
        "INSERT INTO unit_events (program_sha256, address, version, from_status, to_status, actor,
                note, at) VALUES ('ab12', '0x10', 1, NULL, 'verified', 'model', NULL, 100)",
        [],
    )
    .expect("event row");
}

#[test]
fn a_version_1_database_migrates_in_place_and_keeps_its_units() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(DB_FILE);
    make_v1(&path);
    // Version 1 has no specs table.
    {
        let conn = Connection::open(&path).expect("open");
        assert!(
            conn.prepare("SELECT 1 FROM specs").is_err(),
            "specs arrive with migration 2"
        );
    }

    let st = RewriteStore::open(&path).expect("open migrates");
    assert_eq!(st.schema_version().expect("version"), 3);
    assert_eq!(SCHEMA_VERSION, 3);

    // The old unit reads back intact, with the new column empty.
    let u = st.get("ru-old").expect("get").expect("unit");
    assert_eq!(u.anchor.name, "old_fn");
    assert_eq!(u.rust_code, "fn old");
    assert_eq!(u.status, UnitStatus::Accepted);
    assert_eq!(u.spec_id, None);
    assert_eq!(u.summary.seed, 42);
    assert_eq!(u.verdict, Verdict::Pass);
    assert_eq!(u.test_cases.len(), 1);
    // Migration 3: no repair link on an old version, and nothing observed, so nothing stale.
    assert_eq!(u.repair, None);
    assert!(st.stale_reasons("ab12").expect("stale").is_empty());
    assert_eq!(st.events("ab12", "0x10").expect("events").len(), 1);
    assert_eq!(
        st.accepted("ab12", "0x10")
            .expect("accepted")
            .expect("unit")
            .id,
        "ru-old"
    );

    // The new tables work, and new versions continue the numbering.
    st.save_plan(
        "ab12",
        &StoredPlan {
            functions_total: 1,
            skipped_imports: 0,
            skipped_runtime: 0,
            groups: 0,
            truncated: false,
            entries: vec![],
        },
    )
    .expect("plan");
    let next = st.put_unit(pass("0x10", "fn new")).expect("put");
    assert_eq!(next.version, 2);
    drop(st);

    // Opening again changes nothing.
    let again = RewriteStore::open(&path).expect("reopen");
    assert_eq!(again.schema_version().expect("version"), 3);
    assert_eq!(again.versions("ab12", "0x10").expect("versions").len(), 2);
}

#[test]
fn a_database_from_a_newer_build_is_refused_untouched() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(DB_FILE);
    drop(RewriteStore::open(&path).expect("create"));
    {
        let conn = Connection::open(&path).expect("open");
        conn.execute("INSERT INTO schema_version (version) VALUES (99)", [])
            .expect("future version");
    }
    let err = RewriteStore::open(&path).expect_err("newer schema");
    assert!(err.to_string().contains("newer"), "{err}");
}

#[test]
fn the_store_lives_in_its_own_file_next_to_the_project_database() {
    let dir = tempfile::tempdir().expect("tempdir");
    let st = RewriteStore::in_project(dir.path()).expect("store");
    assert_eq!(st.path(), Some(dir.path().join("rewrite.sqlite").as_path()));
    st.put_unit(pass("0x10", "fn a")).expect("put");
    drop(st);
    assert!(dir.path().join("rewrite.sqlite").is_file());
    assert!(
        !dir.path().join("project.kraken.sqlite").exists(),
        "the project database is not touched"
    );
    // Data survives a reopen.
    let st = RewriteStore::in_project(dir.path()).expect("reopen");
    assert_eq!(st.versions(PROG, "0x10").expect("versions").len(), 1);
}
