//! Reusable contract test suite (feature `testing`).
//!
//! Every engine implementation (the fake, real Ghidra) runs [`run_contract_suite`] against the
//! expectations for its fixture binary. Absent capabilities are skipped, but the suite checks
//! that the handshake and the accessors agree.

use std::path::PathBuf;
use std::time::Duration;

use kraken_proto::{
    AddressRange, Anchor, DecompileResult, ErrorCode, FunctionSummary, Hex64, Locator, LogOp,
    PROTOCOL_VERSION, PageRequest, Primitive, PrimitiveClass, TypeDef, TypeRef, TypedefDef,
    VersionedLogOp,
};
use tokio_util::sync::CancellationToken;

use crate::caps::{Cap, Engine};
use crate::types::{AnalyzeRequest, LoaderSpec, ProgramInfo, Stage};

/// A function the engine must list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedFunction {
    /// Entry point.
    pub locator: Locator,
    /// Name before any mutation.
    pub name: String,
}

/// What the suite expects of the engine loaded with one fixture.
#[derive(Debug, Clone)]
pub struct FixtureExpectations {
    /// Path handed to the loader (a fake ignores it).
    pub binary_path: PathBuf,
    /// Expected result of opening the binary.
    pub program: ProgramInfo,
    /// Exactly these functions must be listed, ordered by (space, offset). At least one; the
    /// first is renamed and, with two or more, the last is deleted.
    pub functions: Vec<ExpectedFunction>,
    /// Name the suite renames the first function to; must not occur in the fixture.
    pub rename_to: String,
    /// An address with no function, used to create and delete a scratch function.
    pub scratch: Locator,
}

/// A contract violation.
#[derive(Debug, thiserror::Error)]
#[error("contract violation in {section}: {message}")]
pub struct ContractError {
    /// Which check failed.
    pub section: &'static str,
    /// What went wrong.
    pub message: String,
}

type Check = Result<(), String>;

macro_rules! ensure {
    ($cond:expr, $($arg:tt)+) => {
        if !$cond {
            return Err(format!($($arg)+));
        }
    };
}

macro_rules! call {
    ($ctx:expr, $e:expr) => {
        $e.await.map_err(|e| format!("{}: {}", $ctx, e))?
    };
}

fn expect_code<T: std::fmt::Debug, E: Into<kraken_proto::ProtoError>>(
    what: &str,
    r: Result<T, E>,
    code: ErrorCode,
) -> Check {
    match r {
        Ok(v) => Err(format!("{what}: expected {code}, got Ok({v:?})")),
        Err(e) => {
            let e: kraken_proto::ProtoError = e.into();
            ensure!(e.code == code, "{what}: expected {code}, got {}", e.code);
            Ok(())
        }
    }
}

fn key(l: &Locator) -> (String, u64) {
    match l {
        Locator::Native { space, offset } => (space.clone(), offset.0),
        _ => (String::new(), 0),
    }
}

fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

fn has_word(text: &str, word: &str) -> bool {
    text.match_indices(word).any(|(i, _)| {
        let before = text[..i].chars().next_back();
        let after = text[i + word.len()..].chars().next();
        !before.is_some_and(is_ident) && !after.is_some_and(is_ident)
    })
}

fn anchor_for(summary: &FunctionSummary) -> Anchor {
    let (space, offset) = key(&summary.locator);
    Anchor::Native {
        space,
        offset: Hex64(offset),
        fn_entry: Hex64(offset),
        fn_hash: summary.fn_hash.clone().unwrap_or_default(),
    }
}

/// Runs the whole suite. Mutating checks come last and change the engine's state (rename, create,
/// delete), so use a fresh engine per run.
pub async fn run_contract_suite(
    engine: &dyn Engine,
    exp: &FixtureExpectations,
) -> Result<(), ContractError> {
    macro_rules! section {
        ($name:literal, $fut:expr) => {
            $fut.await.map_err(|message| ContractError {
                section: $name,
                message,
            })?
        };
    }
    section!("capabilities", check_caps(engine));
    section!("loader", check_loader(engine, exp));
    section!("analyzer", check_analyzer(engine, exp));
    section!("listing", check_listing(engine, exp));
    section!("decompile", check_decompile(engine, exp));
    section!("types", check_types(engine));
    section!("cancellation", check_cancellation(engine, exp));
    section!("mutation", check_mutation(engine, exp));
    Ok(())
}

async fn check_caps(engine: &dyn Engine) -> Check {
    let caps = engine.capabilities();
    ensure!(
        caps.handshake.protocol == PROTOCOL_VERSION,
        "handshake protocol is {:?}",
        caps.handshake.protocol
    );
    let present = [
        (Cap::Loader, engine.loader().is_some()),
        (Cap::Analyzer, engine.analyzer().is_some()),
        (Cap::Decompiler, engine.decompiler().is_some()),
        (Cap::TypeStore, engine.type_store().is_some()),
        (Cap::FunctionLister, engine.function_lister().is_some()),
        (Cap::Mutator, engine.mutator().is_some()),
    ];
    for (cap, has_accessor) in present {
        ensure!(
            caps.has(cap) == has_accessor,
            "capability {} is {} in caps but accessor is {}",
            cap.name(),
            caps.has(cap),
            has_accessor
        );
        ensure!(
            caps.handshake
                .capabilities
                .iter()
                .any(|c| c.name == cap.name())
                == has_accessor,
            "handshake capability list disagrees about {}",
            cap.name()
        );
    }
    Ok(())
}

async fn check_loader(engine: &dyn Engine, exp: &FixtureExpectations) -> Check {
    let Some(loader) = engine.loader() else {
        return Ok(());
    };
    let cancel = CancellationToken::new();
    let info = call!(
        "open_binary",
        loader.open_binary(&exp.binary_path, &LoaderSpec::default(), &cancel)
    );
    ensure!(
        info == exp.program,
        "program info {:?} != expected {:?}",
        info,
        exp.program
    );
    let bad = LoaderSpec {
        format: Some("kraken-no-such-format".into()),
        ..LoaderSpec::default()
    };
    expect_code(
        "open_binary with unknown format",
        loader.open_binary(&exp.binary_path, &bad, &cancel).await,
        ErrorCode::Unsupported,
    )
}

async fn check_analyzer(engine: &dyn Engine, _exp: &FixtureExpectations) -> Check {
    let Some(analyzer) = engine.analyzer() else {
        return Ok(());
    };
    let mut job = call!(
        "analyze",
        analyzer.analyze(AnalyzeRequest::default(), CancellationToken::new())
    );
    let mut seen = Vec::new();
    let limit = Duration::from_secs(60);
    loop {
        let next = tokio::time::timeout(limit, job.next_progress())
            .await
            .map_err(|_| "no progress or end of stream within 60s".to_string())?;
        let Some(p) = next else { break };
        ensure!(
            p.done <= p.total,
            "progress done {} > total {}",
            p.done,
            p.total
        );
        seen.push(p);
    }
    let summary = tokio::time::timeout(limit, job.wait())
        .await
        .map_err(|_| "completion not ready within 60s".to_string())?
        .map_err(|e| format!("analysis failed: {e}"))?;
    ensure!(
        summary.stages_completed == Stage::ALL,
        "stages completed {:?}",
        summary.stages_completed
    );
    ensure!(
        seen.windows(2).all(|w| w[0].stage <= w[1].stage),
        "progress stages are not in order"
    );
    for stage in Stage::ALL {
        ensure!(
            seen.iter().any(|p| p.stage == stage),
            "no progress for stage {}",
            stage.as_str()
        );
    }

    let resumed = call!(
        "analyze resume",
        analyzer.analyze(
            AnalyzeRequest {
                resume_from: Some(Stage::Expensive),
            },
            CancellationToken::new(),
        )
    );
    let summary = call!("resumed analysis", resumed.wait());
    ensure!(
        summary.stages_completed == [Stage::Expensive],
        "resume_from=expensive ran {:?}",
        summary.stages_completed
    );
    Ok(())
}

async fn list_all(engine: &dyn Engine, limit: u32) -> Result<Vec<FunctionSummary>, String> {
    let Some(lister) = engine.function_lister() else {
        return Ok(Vec::new());
    };
    let cancel = CancellationToken::new();
    let mut out = Vec::new();
    let mut cursor = None;
    for _ in 0..100_000 {
        let page = call!(
            "list_functions",
            lister.list_functions(
                &PageRequest {
                    cursor: cursor.clone(),
                    limit: Some(limit),
                },
                &cancel,
            )
        );
        ensure!(
            page.items.len() <= limit as usize,
            "page has {} items for limit {limit}",
            page.items.len()
        );
        out.extend(page.items);
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => return Ok(out),
        }
    }
    Err("pagination did not terminate".into())
}

async fn check_listing(engine: &dyn Engine, exp: &FixtureExpectations) -> Check {
    let Some(lister) = engine.function_lister() else {
        return Ok(());
    };
    let cancel = CancellationToken::new();
    let full = list_all(engine, 500).await?;
    let got: Vec<(Locator, String)> = full
        .iter()
        .map(|f| (f.locator.clone(), f.name.clone()))
        .collect();
    let want: Vec<(Locator, String)> = exp
        .functions
        .iter()
        .map(|f| (f.locator.clone(), f.name.clone()))
        .collect();
    ensure!(got == want, "listing {got:?} != expected {want:?}");
    for limit in [1, 2] {
        let paged = list_all(engine, limit).await?;
        ensure!(
            paged == full,
            "paging with limit {limit} differs from the full listing"
        );
    }
    let page = call!(
        "list_functions limit 0",
        lister.list_functions(
            &PageRequest {
                cursor: None,
                limit: Some(0),
            },
            &cancel,
        )
    );
    ensure!(
        page.items.len() == 1.min(full.len()),
        "limit 0 must behave as limit 1, got {} items",
        page.items.len()
    );
    let first_page = call!(
        "list_functions total",
        lister.list_functions(&PageRequest::default(), &cancel)
    );
    if let Some(total) = first_page.total {
        ensure!(
            total == full.len() as u64,
            "total {total} != {}",
            full.len()
        );
    }
    expect_code(
        "list_functions with a garbage cursor",
        lister
            .list_functions(
                &PageRequest {
                    cursor: Some("\u{1}not a cursor".into()),
                    limit: None,
                },
                &cancel,
            )
            .await,
        ErrorCode::InvalidArgument,
    )?;
    for f in &full {
        let one = call!("get_function", lister.get_function(&f.locator, &cancel));
        ensure!(
            &one == f,
            "get_function {:?} differs from listing",
            f.locator
        );
    }
    expect_code(
        "get_function at the scratch address",
        lister.get_function(&exp.scratch, &cancel).await,
        ErrorCode::NotFound,
    )
}

fn check_result(r: &DecompileResult, at: &Locator) -> Check {
    ensure!(
        &r.function == at,
        "result is for {:?}, asked {:?}",
        r.function,
        at
    );
    ensure!(!r.language.is_empty(), "empty language");
    ensure!(!r.text.is_empty(), "empty text");
    r.validate_tokens().map_err(|e| e.to_string())?;
    ensure!(
        r.tokens.windows(2).all(|w| w[0].start <= w[1].start),
        "tokens are not in increasing start order"
    );
    Ok(())
}

async fn check_decompile(engine: &dyn Engine, exp: &FixtureExpectations) -> Check {
    let Some(dec) = engine.decompiler() else {
        return Ok(());
    };
    let cancel = CancellationToken::new();
    for f in &exp.functions {
        let r = call!("decompile", dec.decompile(&f.locator, &cancel));
        check_result(&r, &f.locator)?;
        ensure!(
            has_word(&r.text, &f.name),
            "decompiled text of {:?} does not mention {}",
            f.locator,
            f.name
        );
    }
    expect_code(
        "decompile at the scratch address",
        dec.decompile(&exp.scratch, &cancel).await,
        ErrorCode::NotFound,
    )
}

async fn check_types(engine: &dyn Engine) -> Check {
    let Some(ts) = engine.type_store() else {
        return Ok(());
    };
    let cancel = CancellationToken::new();
    let name = "kraken_contract_t";
    let def = TypeDef::Typedef(TypedefDef {
        name: name.into(),
        target: TypeRef::Primitive(Primitive {
            class: PrimitiveClass::Int,
            size: 4,
            signed: false,
        }),
    });
    expect_code(
        "get_type before define",
        ts.get_type(name, &cancel).await,
        ErrorCode::NotFound,
    )?;
    call!("define_type", ts.define_type(def.clone(), &cancel));
    let got = call!("get_type", ts.get_type(name, &cancel));
    ensure!(got == def, "get_type returned {got:?}");
    let mut cursor = None;
    let mut found = 0;
    loop {
        let page = call!(
            "list_types",
            ts.list_types(
                &PageRequest {
                    cursor: cursor.clone(),
                    limit: Some(1),
                },
                &cancel,
            )
        );
        found += page.items.iter().filter(|d| **d == def).count();
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => break,
        }
    }
    ensure!(found == 1, "defined type listed {found} times");
    Ok(())
}

async fn check_cancellation(engine: &dyn Engine, exp: &FixtureExpectations) -> Check {
    let cancelled = CancellationToken::new();
    cancelled.cancel();
    let at = exp.functions.first().map(|f| f.locator.clone());
    if let (Some(lister), Some(at)) = (engine.function_lister(), at.as_ref()) {
        expect_code(
            "list_functions with a cancelled token",
            lister
                .list_functions(&PageRequest::default(), &cancelled)
                .await,
            ErrorCode::Cancelled,
        )?;
        expect_code(
            "get_function with a cancelled token",
            lister.get_function(at, &cancelled).await,
            ErrorCode::Cancelled,
        )?;
    }
    if let (Some(dec), Some(at)) = (engine.decompiler(), at.as_ref()) {
        expect_code(
            "decompile with a cancelled token",
            dec.decompile(at, &cancelled).await,
            ErrorCode::Cancelled,
        )?;
    }
    if let Some(loader) = engine.loader() {
        expect_code(
            "open_binary with a cancelled token",
            loader
                .open_binary(&exp.binary_path, &LoaderSpec::default(), &cancelled)
                .await,
            ErrorCode::Cancelled,
        )?;
    }
    if let Some(analyzer) = engine.analyzer() {
        let job = call!(
            "analyze",
            analyzer.analyze(AnalyzeRequest::default(), CancellationToken::new())
        );
        job.cancel();
        let r = tokio::time::timeout(Duration::from_secs(60), job.wait())
            .await
            .map_err(|_| "cancelled analysis did not end within 60s".to_string())?;
        expect_code("cancelled analysis", r, ErrorCode::Cancelled)?;
    }
    Ok(())
}

async fn check_mutation(engine: &dyn Engine, exp: &FixtureExpectations) -> Check {
    let Some(m) = engine.mutator() else {
        return Ok(());
    };
    ensure!(!exp.functions.is_empty(), "expectations list no functions");
    let cancel = CancellationToken::new();
    let lister = engine.function_lister();
    let dec = engine.decompiler();
    let before = list_all(engine, 500).await?;
    let target = before
        .first()
        .ok_or("engine lists no functions to mutate")?
        .clone();
    let old_name = target.name.clone();
    let anchor = anchor_for(&target);
    let rename = |old: Option<&str>, new: &str| {
        VersionedLogOp::new(LogOp::Rename {
            anchor: anchor.clone(),
            old_name: old.map(str::to_string),
            new_name: new.to_string(),
        })
    };

    // rename is visible in listings and decompiler output
    call!(
        "apply rename",
        m.apply(&rename(Some(&old_name), &exp.rename_to), &cancel)
    );
    if let Some(l) = lister {
        let now = call!(
            "get_function after rename",
            l.get_function(&target.locator, &cancel)
        );
        ensure!(
            now.name == exp.rename_to,
            "name after rename is {}",
            now.name
        );
        let listed = list_all(engine, 500).await?;
        ensure!(
            listed
                .iter()
                .any(|f| f.locator == target.locator && f.name == exp.rename_to),
            "renamed function not in listing"
        );
        ensure!(
            !listed.iter().any(|f| f.name == old_name),
            "old name still listed"
        );
    }
    if let Some(d) = dec {
        let r = call!(
            "decompile after rename",
            d.decompile(&target.locator, &cancel)
        );
        check_result(&r, &target.locator)?;
        ensure!(
            has_word(&r.text, &exp.rename_to),
            "decompiled text lacks the new name"
        );
        ensure!(
            !has_word(&r.text, &old_name),
            "decompiled text still has the old name"
        );
        ensure!(
            !r.tokens
                .iter()
                .any(|t| t.symbol.as_deref() == Some(old_name.as_str())),
            "a token still carries the old symbol"
        );
        ensure!(
            r.tokens
                .iter()
                .any(|t| t.symbol.as_deref() == Some(exp.rename_to.as_str())),
            "no token carries the new symbol"
        );
    }
    // idempotent re-apply, stale read, then the watermark
    call!(
        "re-apply rename",
        m.apply(&rename(Some(&old_name), &exp.rename_to), &cancel)
    );
    expect_code(
        "rename based on a stale old_name",
        m.apply(
            &rename(Some("kraken_never_this_name"), "kraken_other"),
            &cancel,
        )
        .await,
        ErrorCode::ConflictStaleRead,
    )?;
    let w1 = call!("save", m.save(&cancel));
    ensure!(!w1.0.is_empty(), "empty watermark");

    // unsupported anchors and schema versions
    let managed = VersionedLogOp::new(LogOp::Rename {
        anchor: Anchor::Managed {
            token: "0x06000001".into(),
        },
        old_name: None,
        new_name: "x".into(),
    });
    expect_code(
        "managed anchor",
        m.apply(&managed, &cancel).await,
        ErrorCode::Unsupported,
    )?;
    let mut future = rename(None, &exp.rename_to);
    future.schema_version = u32::MAX;
    expect_code(
        "newer log schema version",
        m.apply(&future, &cancel).await,
        ErrorCode::Unsupported,
    )?;

    // create then delete a scratch function
    let (space, offset) = key(&exp.scratch);
    let scratch_anchor = Anchor::Native {
        space: space.clone(),
        offset: Hex64(offset),
        fn_entry: Hex64(offset),
        fn_hash: "scratch-hash".into(),
    };
    let body = AddressRange {
        space,
        start: Hex64(offset),
        end: Hex64(offset + 0x10),
    };
    call!(
        "apply create_function",
        m.apply(
            &VersionedLogOp::new(LogOp::CreateFunction {
                anchor: scratch_anchor.clone(),
                name: Some("kraken_scratch".into()),
                body: Some(body.clone()),
            }),
            &cancel,
        )
    );
    if let Some(l) = lister {
        let f = call!(
            "get_function (created)",
            l.get_function(&exp.scratch, &cancel)
        );
        ensure!(
            f.name == "kraken_scratch",
            "created function is named {}",
            f.name
        );
        let n = list_all(engine, 500).await?.len();
        ensure!(
            n == before.len() + 1,
            "listing has {n} functions after create"
        );
    }
    if let Some(d) = dec {
        let r = call!("decompile (created)", d.decompile(&exp.scratch, &cancel));
        check_result(&r, &exp.scratch)?;
    }
    let delete_scratch = VersionedLogOp::new(LogOp::DeleteFunction {
        anchor: scratch_anchor,
        old_body: Some(body),
    });
    call!("apply delete_function", m.apply(&delete_scratch, &cancel));
    if let Some(l) = lister {
        expect_code(
            "get_function (deleted)",
            l.get_function(&exp.scratch, &cancel).await,
            ErrorCode::NotFound,
        )?;
        let n = list_all(engine, 500).await?.len();
        ensure!(n == before.len(), "listing has {n} functions after delete");
    }
    expect_code(
        "deleting a missing function",
        m.apply(&delete_scratch, &cancel).await,
        ErrorCode::NotFound,
    )?;

    // delete an original function
    if let Some(victim) = before.get(1..).and_then(|rest| rest.last()) {
        let del = VersionedLogOp::new(LogOp::DeleteFunction {
            anchor: anchor_for(victim),
            old_body: None,
        });
        call!(
            "apply delete of an original function",
            m.apply(&del, &cancel)
        );
        if let Some(l) = lister {
            expect_code(
                "get_function (deleted original)",
                l.get_function(&victim.locator, &cancel).await,
                ErrorCode::NotFound,
            )?;
        }
        if let Some(d) = dec {
            expect_code(
                "decompile (deleted original)",
                d.decompile(&victim.locator, &cancel).await,
                ErrorCode::NotFound,
            )?;
        }
    }
    let w2 = call!("second save", m.save(&cancel));
    ensure!(w1 != w2, "watermark did not advance after further edits");
    Ok(())
}
