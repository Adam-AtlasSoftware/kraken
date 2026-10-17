//! Tests against the real .NET sidecar. All `#[ignore]`d: run with
//! `cargo xtask dotnet-ext && cargo test -p engine-dotnet -- --ignored`.
//!
//! The runtime comes from `KRAKEN_DOTNET_ROOT` or `~/.cache/kraken-dev/dotnet` (install it with
//! `dotnet/install-sdk.sh`), the sidecar from `KRAKEN_DOTNET_EXT_DLL` or the xtask output.
// Needs the isolated .NET SDK and `cargo xtask dotnet-ext`; enable with `--features real-dotnet`.
#![cfg(feature = "real-dotnet")]
#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use engine_dotnet::{DotnetEngine, DotnetInstall, EngineConfig, InstallConfig, LANGUAGE_CSHARP};
use kraken_engine::{
    CancellationToken, Decompiler, Engine, FunctionLister, Loader, LoaderSpec, TypeStore,
};
use kraken_proto::{
    Completeness, ErrorCode, FunctionSummary, Locator, PageRequest, TokenKind, TypeDef,
};
use serde::Deserialize;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn corpus_dll() -> PathBuf {
    repo_root().join("corpus/dotnet/bin/kraken-corpus.dll")
}

#[derive(Deserialize)]
struct Truth {
    module_mvid: String,
    sha256: String,
    functions: Vec<TruthFn>,
}

#[derive(Deserialize)]
struct TruthFn {
    name: String,
    token: String,
    #[serde(default)]
    size: Option<u64>,
}

fn truth() -> Truth {
    let text = std::fs::read_to_string(repo_root().join("corpus/dotnet/truth/kraken-corpus.json"))
        .expect("truth json");
    serde_json::from_str(&text).expect("truth parses")
}

fn token_of(t: &TruthFn) -> u32 {
    u32::from_str_radix(t.token.trim_start_matches("0x"), 16).expect("hex token")
}

fn engine() -> DotnetEngine {
    let install = DotnetInstall::discover(&InstallConfig::default()).unwrap_or_else(|e| {
        panic!("{e}; run dotnet/install-sdk.sh and `cargo xtask dotnet-ext` first")
    });
    DotnetEngine::new(EngineConfig::new(install))
}

async fn opened() -> DotnetEngine {
    let e = engine();
    e.open_binary(
        &corpus_dll(),
        &LoaderSpec::default(),
        &CancellationToken::new(),
    )
    .await
    .expect("open");
    e
}

async fn all_functions(e: &DotnetEngine, limit: u32) -> Vec<FunctionSummary> {
    let cancel = CancellationToken::new();
    let mut out = vec![];
    let mut cursor = None;
    loop {
        let page = e
            .list_functions(
                &PageRequest {
                    cursor: cursor.clone(),
                    limit: Some(limit),
                },
                &cancel,
            )
            .await
            .expect("list");
        out.extend(page.items);
        match page.next_cursor {
            Some(c) => cursor = Some(c),
            None => return out,
        }
    }
}

fn locator_token(l: &Locator) -> (String, u32) {
    match l {
        Locator::Managed { module, token } => (module.clone(), *token),
        other => panic!("expected a managed locator, got {other:?}"),
    }
}

#[tokio::test]
#[ignore = "needs the isolated .NET SDK and `cargo xtask dotnet-ext`"]
async fn open_reports_dotnet_program_info() {
    let e = engine();
    let t = truth();
    let info = e
        .open_binary(
            &corpus_dll(),
            &LoaderSpec::default(),
            &CancellationToken::new(),
        )
        .await
        .expect("open");
    assert_eq!(info.format, "dotnet");
    assert_eq!(info.arch, "cil");
    assert_eq!(info.sha256, t.sha256);
    assert!(info.size > 0);
    assert_eq!(e.module_mvid().unwrap(), t.module_mvid);
    let diag = e.diagnostics();
    assert_eq!(diag.state, "running");
    #[cfg(target_os = "linux")]
    assert!(
        diag.confinement.as_ref().is_some_and(|c| c.is_confined()),
        "the sidecar must run under Landlock: {diag:?}"
    );

    let caps = e.capabilities();
    assert!(caps.has(kraken_engine::Cap::Decompiler) && caps.has(kraken_engine::Cap::Mutator));
    assert!(e.mutator().is_some());
}

#[tokio::test]
#[ignore = "needs the isolated .NET SDK and `cargo xtask dotnet-ext`"]
async fn a_native_format_or_a_non_assembly_is_refused() {
    let e = engine();
    let cancel = CancellationToken::new();
    let err = e
        .open_binary(
            &corpus_dll(),
            &LoaderSpec {
                format: Some("elf".into()),
                ..LoaderSpec::default()
            },
            &cancel,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::Unsupported);

    let err = e
        .open_binary(
            &repo_root().join("Cargo.toml"),
            &LoaderSpec::default(),
            &cancel,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument, "{err}");

    let err = e
        .list_functions(&PageRequest::default(), &cancel)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
#[ignore = "needs the isolated .NET SDK and `cargo xtask dotnet-ext`"]
async fn list_functions_matches_truth_and_pages_concatenate() {
    let e = opened().await;
    let t = truth();
    let full = all_functions(&e, 500).await;
    let small = all_functions(&e, 4).await;
    assert_eq!(full, small, "concatenated pages equal one full listing");
    assert_eq!(full.len(), t.functions.len());

    let by_token: BTreeMap<u32, &FunctionSummary> = full
        .iter()
        .map(|f| (locator_token(&f.locator).1, f))
        .collect();
    for want in &t.functions {
        let got = by_token
            .get(&token_of(want))
            .unwrap_or_else(|| panic!("token {} missing", want.token));
        assert_eq!(got.name, want.name);
        assert_eq!(got.size, want.size);
        assert_eq!(locator_token(&got.locator).0, t.module_mvid);
        assert_eq!(got.completeness, Completeness::Complete);
    }
    let names: Vec<&str> = full.iter().map(|f| f.name.as_str()).collect();
    for expected in [
        "KrakenCorpus.Calc.Add",
        "KrakenCorpus.Calc.Fib",
        "KrakenCorpus.Calc.Describe",
        "KrakenCorpus.Program.Main",
        "KrakenCorpus.Circle.Area",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} missing from {names:?}"
        );
    }
    // Ordered by token.
    let tokens: Vec<u32> = full.iter().map(|f| locator_token(&f.locator).1).collect();
    assert!(tokens.windows(2).all(|w| w[0] < w[1]));

    let cancel = CancellationToken::new();
    let err = e
        .list_functions(
            &PageRequest {
                cursor: Some("zz".into()),
                limit: None,
            },
            &cancel,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

fn find<'a>(fns: &'a [FunctionSummary], name: &str) -> &'a FunctionSummary {
    fns.iter()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("{name} not listed"))
}

#[tokio::test]
#[ignore = "needs the isolated .NET SDK and `cargo xtask dotnet-ext`"]
async fn get_function_and_not_found() {
    let e = opened().await;
    let cancel = CancellationToken::new();
    let fns = all_functions(&e, 500).await;
    let fib = find(&fns, "KrakenCorpus.Calc.Fib");
    assert_eq!(&e.get_function(&fib.locator, &cancel).await.unwrap(), fib);

    let (module, _) = locator_token(&fib.locator);
    let err = e
        .get_function(&Locator::managed(module.clone(), 0x0600_0999), &cancel)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);
    let err = e
        .get_function(
            &Locator::managed("00000000-0000-0000-0000-000000000000", 0x0600_0001),
            &cancel,
        )
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);
    let err = e
        .get_function(&Locator::ram(0x1000), &cancel)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
}

#[tokio::test]
#[ignore = "needs the isolated .NET SDK and `cargo xtask dotnet-ext`"]
async fn decompile_shows_csharp_with_resolved_tokens() {
    let e = opened().await;
    let cancel = CancellationToken::new();
    let fns = all_functions(&e, 500).await;
    let fib = find(&fns, "KrakenCorpus.Calc.Fib");
    let describe = find(&fns, "KrakenCorpus.Calc.Describe");

    let r = e
        .decompile(&fib.locator, &cancel)
        .await
        .expect("decompile Fib");
    assert_eq!(r.language, LANGUAGE_CSHARP);
    assert_eq!(r.function, fib.locator);
    assert!(r.text.contains("int Fib(int n)"), "{}", r.text);
    assert!(r.text.contains("return n;"), "{}", r.text);
    r.validate_tokens().expect("token spans are valid");

    // The recursive call refers back to Fib itself.
    let self_refs = r
        .tokens
        .iter()
        .filter(|t| {
            t.kind == TokenKind::Function
                && t.target.as_ref() == Some(&fib.locator)
                && &r.text[t.start as usize..t.end as usize] == "Fib"
        })
        .count();
    assert!(
        self_refs >= 3,
        "declaration plus two calls, got {self_refs}\n{}",
        r.text
    );

    // Describe calls Fib: a function token whose target is Fib's locator.
    let r = e
        .decompile(&describe.locator, &cancel)
        .await
        .expect("decompile Describe");
    assert!(r.text.contains("Describe"), "{}", r.text);
    assert!(
        r.tokens
            .iter()
            .any(|t| t.kind == TokenKind::Function && t.target.as_ref() == Some(&fib.locator)),
        "no reference to Fib in {}",
        r.text
    );
    assert!(r.tokens.iter().any(|t| t.kind == TokenKind::Variable));
    assert!(r.tokens.iter().any(|t| t.kind == TokenKind::Keyword));
    assert!(r.tokens.windows(2).all(|w| w[0].start <= w[1].start));

    // A call into the framework resolves to a managed locator in another module.
    let main = find(&fns, "KrakenCorpus.Program.Main");
    let r = e
        .decompile(&main.locator, &cancel)
        .await
        .expect("decompile Main");
    let (own_module, _) = locator_token(&main.locator);
    let foreign = r.tokens.iter().find_map(|t| match (&t.kind, &t.target) {
        (TokenKind::Function, Some(Locator::Managed { module, .. })) if *module != own_module => {
            t.symbol.clone()
        }
        _ => None,
    });
    assert_eq!(foreign.as_deref(), Some("WriteLine"), "{}", r.text);
}

#[tokio::test]
#[ignore = "needs the isolated .NET SDK and `cargo xtask dotnet-ext`"]
async fn decompile_rejects_bad_locators() {
    let e = opened().await;
    let cancel = CancellationToken::new();
    let err = e
        .decompile(&Locator::ram(0x40_1000), &cancel)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::InvalidArgument);
    let module = e.module_mvid().unwrap();
    // 0x02 is the TypeDef table, not a method.
    let err = e
        .decompile(&Locator::managed(module, 0x0200_0002), &cancel)
        .await
        .unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);
}

#[tokio::test]
#[ignore = "needs the isolated .NET SDK and `cargo xtask dotnet-ext`"]
async fn types_are_listed_read_only() {
    let e = opened().await;
    let cancel = CancellationToken::new();
    let page = e
        .list_types(&PageRequest::default(), &cancel)
        .await
        .expect("list_types");
    let names: Vec<String> = page
        .items
        .iter()
        .filter_map(|t| kraken_engine::type_def_name(t).map(str::to_string))
        .collect();
    assert_eq!(
        names,
        [
            "KrakenCorpus.Calc",
            "KrakenCorpus.Circle",
            "KrakenCorpus.Color",
            "KrakenCorpus.IShape",
            "KrakenCorpus.Point",
            "KrakenCorpus.Program",
            "KrakenCorpus.Square"
        ]
    );
    let color = e.get_type("KrakenCorpus.Color", &cancel).await.unwrap();
    match color {
        TypeDef::Enum(def) => {
            let v: Vec<(&str, i64)> = def
                .variants
                .iter()
                .map(|v| (v.name.as_str(), v.value))
                .collect();
            assert_eq!(v, [("Red", 1), ("Green", 2), ("Blue", 4)]);
        }
        other => panic!("Color should be an enum, got {other:?}"),
    }
    let err = e.get_type("Nope", &cancel).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::NotFound);
    let err = e.define_type(color_def(), &cancel).await.unwrap_err();
    assert_eq!(err.code, ErrorCode::Unsupported);
}

fn color_def() -> TypeDef {
    TypeDef::Enum(kraken_proto::types::EnumDef {
        name: "X".into(),
        size: 4,
        variants: vec![],
    })
}

#[tokio::test]
#[ignore = "needs the isolated .NET SDK and `cargo xtask dotnet-ext`"]
async fn dropping_the_engine_stops_the_sidecar() {
    let e = opened().await;
    let pid = e.diagnostics().pid.expect("pid");
    drop(e);
    // The kill is asynchronous; poll /proc for a short while.
    let proc = PathBuf::from(format!("/proc/{pid}"));
    for _ in 0..50 {
        if !proc.exists() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("sidecar {pid} is still running");
}

fn managed_anchor(l: &Locator) -> kraken_proto::Anchor {
    let (module, token) = locator_token(l);
    kraken_proto::Anchor::managed(&module, token)
}

fn rename_op(l: &Locator, old: Option<&str>, new: &str) -> kraken_proto::VersionedLogOp {
    kraken_proto::VersionedLogOp::new(kraken_proto::LogOp::Rename {
        anchor: managed_anchor(l),
        old_name: old.map(str::to_string),
        new_name: new.to_string(),
    })
}

fn comment_op(
    l: &Locator,
    kind: kraken_proto::CommentKind,
    old: Option<&str>,
    new: Option<&str>,
) -> kraken_proto::VersionedLogOp {
    kraken_proto::VersionedLogOp::new(kraken_proto::LogOp::SetComment {
        anchor: managed_anchor(l),
        comment_kind: kind,
        old: old.map(str::to_string),
        new: new.map(str::to_string),
    })
}

fn tokens_with<'a>(
    r: &'a kraken_proto::DecompileResult,
    table: u32,
    own_module: &str,
) -> Vec<(&'a kraken_proto::Token, u32)> {
    r.tokens
        .iter()
        .filter_map(|t| match &t.target {
            Some(Locator::Managed { module, token })
                if module == own_module && token >> 24 == table =>
            {
                Some((t, *token))
            }
            _ => None,
        })
        .collect()
}

#[tokio::test]
#[ignore = "needs the isolated .NET SDK and `cargo xtask dotnet-ext`"]
async fn methods_are_renamed_and_commented_in_the_decompiled_csharp() {
    use kraken_proto::CommentKind;

    let e = opened().await;
    let cancel = CancellationToken::new();
    let m = e.mutator().expect("mutator");
    let fns = all_functions(&e, 500).await;
    let fib = find(&fns, "KrakenCorpus.Calc.Fib").clone();
    let describe = find(&fns, "KrakenCorpus.Calc.Describe").clone();
    let (own, _) = locator_token(&fib.locator);

    m.apply(
        &rename_op(&fib.locator, Some(&fib.name), "Fibonacci"),
        &cancel,
    )
    .await
    .expect("rename");
    m.apply(
        &rename_op(&fib.locator, Some(&fib.name), "Fibonacci"),
        &cancel,
    )
    .await
    .expect("re-applying a rename that is in effect is Ok");

    let g = e.get_function(&fib.locator, &cancel).await.unwrap();
    assert_eq!(g.name, "KrakenCorpus.Calc.Fibonacci");
    assert!(
        g.signature.as_deref().unwrap().contains("Fibonacci("),
        "{g:?}"
    );
    let listed = all_functions(&e, 500).await;
    assert!(
        listed
            .iter()
            .any(|f| f.name == "KrakenCorpus.Calc.Fibonacci")
    );
    assert!(!listed.iter().any(|f| f.name == "KrakenCorpus.Calc.Fib"));

    let r = e.decompile(&fib.locator, &cancel).await.unwrap();
    r.validate_tokens().unwrap();
    assert!(r.text.contains("int Fibonacci(int n)"), "{}", r.text);
    assert!(!r.text.contains("Fib("), "{}", r.text);
    let calls = r
        .tokens
        .iter()
        .filter(|t| t.target.as_ref() == Some(&fib.locator))
        .inspect(|t| {
            assert_eq!(&r.text[t.start as usize..t.end as usize], "Fibonacci");
            assert_eq!(t.symbol.as_deref(), Some("Fibonacci"));
        })
        .count();
    assert!(calls >= 3, "{}", r.text);

    // Callers of the method show the new name too.
    let d = e.decompile(&describe.locator, &cancel).await.unwrap();
    assert!(d.text.contains("Fibonacci(n)"), "{}", d.text);

    // A parameter has a token of its own and is renamed through it.
    let (_, param) = tokens_with(&r, 0x08, &own)
        .into_iter()
        .next()
        .expect("a parameter token");
    let param_loc = Locator::managed(own.clone(), param);
    m.apply(&rename_op(&param_loc, None, "count"), &cancel)
        .await
        .expect("rename parameter");
    let r = e.decompile(&fib.locator, &cancel).await.unwrap();
    assert!(r.text.contains("int Fibonacci(int count)"), "{}", r.text);
    assert!(r.text.contains("count < 2"), "{}", r.text);
    r.validate_tokens().unwrap();

    // A type is renamed wherever the method mentions it.
    let d = e.decompile(&describe.locator, &cancel).await.unwrap();
    let (tok, type_token) = tokens_with(&d, 0x02, &own)
        .into_iter()
        .find(|(t, _)| t.symbol.as_deref() == Some("Color"))
        .expect("Color in Describe");
    assert_eq!(tok.kind, TokenKind::Type);
    m.apply(
        &rename_op(&Locator::managed(own.clone(), type_token), None, "Hue"),
        &cancel,
    )
    .await
    .expect("rename type");
    let d = e.decompile(&describe.locator, &cancel).await.unwrap();
    assert!(d.text.contains("Hue c"), "{}", d.text);
    assert!(d.text.contains("Hue.Red"), "{}", d.text);
    assert!(!d.text.contains("Color"), "{}", d.text);

    // Comments: above, at the end of the first line and below.
    let comments = [
        (CommentKind::Plate, "computes fibonacci\nrecursively"),
        (CommentKind::Eol, "public api"),
        (CommentKind::Post, "end"),
    ];
    for (kind, text) in comments {
        m.apply(&comment_op(&fib.locator, kind, None, Some(text)), &cancel)
            .await
            .expect("comment");
    }
    let r = e.decompile(&fib.locator, &cancel).await.unwrap();
    r.validate_tokens().unwrap();
    assert!(
        r.text
            .starts_with("// computes fibonacci\n// recursively\n"),
        "{}",
        r.text
    );
    assert!(r.text.contains("(int count) // public api\n"), "{}", r.text);
    assert!(r.text.trim_end().ends_with("// end"), "{}", r.text);
    for t in r.tokens.iter().filter(|t| t.symbol.is_some()) {
        let s = &r.text[t.start as usize..t.end as usize];
        assert_eq!(Some(s), t.symbol.as_deref(), "{}", r.text);
    }

    // Undo is the inverse op: the listed name comes back and the original text with it.
    m.apply(
        &rename_op(&fib.locator, Some("KrakenCorpus.Calc.Fibonacci"), &fib.name),
        &cancel,
    )
    .await
    .expect("undo rename");
    m.apply(&rename_op(&param_loc, Some("count"), ""), &cancel)
        .await
        .expect("undo parameter rename");
    for (kind, text) in comments {
        m.apply(&comment_op(&fib.locator, kind, Some(text), None), &cancel)
            .await
            .expect("clear comment");
    }
    let plain = e.decompile(&fib.locator, &cancel).await.unwrap();
    assert!(
        plain.text.starts_with("public static int Fib(int n)"),
        "{}",
        plain.text
    );
    assert!(!plain.text.contains("//"), "{}", plain.text);
    assert_eq!(
        e.get_function(&fib.locator, &cancel).await.unwrap().name,
        fib.name
    );
}

#[tokio::test]
#[ignore = "needs the isolated .NET SDK and `cargo xtask dotnet-ext`"]
async fn bad_edits_are_rejected_by_the_engine() {
    use kraken_proto::{CommentKind, LogOp, VersionedLogOp};

    let e = opened().await;
    let cancel = CancellationToken::new();
    let m = e.mutator().expect("mutator");
    let fns = all_functions(&e, 500).await;
    let fib = find(&fns, "KrakenCorpus.Calc.Fib").clone();
    let ctor = find(&fns, "KrakenCorpus.Point..ctor").clone();
    let code = |r: Result<(), kraken_engine::EngineRejected>| r.expect_err("rejected").code;

    for bad in ["class", "a b", "1x", "a.b", "x;"] {
        assert_eq!(
            code(m.apply(&rename_op(&fib.locator, None, bad), &cancel).await),
            ErrorCode::InvalidArgument,
            "{bad}"
        );
    }
    assert_eq!(
        code(
            m.apply(&rename_op(&ctor.locator, None, "Make"), &cancel)
                .await
        ),
        ErrorCode::InvalidArgument
    );
    assert_eq!(
        code(
            m.apply(&rename_op(&fib.locator, Some("Nope"), "Other"), &cancel)
                .await
        ),
        ErrorCode::ConflictStaleRead
    );
    let (module, token) = locator_token(&fib.locator);
    let elsewhere = Locator::managed("00000000-0000-0000-0000-000000000000", token);
    assert_eq!(
        code(m.apply(&rename_op(&elsewhere, None, "X"), &cancel).await),
        ErrorCode::NotFound
    );
    let missing = Locator::managed(module.clone(), 0x0600_ffff);
    assert_eq!(
        code(m.apply(&rename_op(&missing, None, "X"), &cancel).await),
        ErrorCode::NotFound
    );
    // Native anchors and other operations do not apply to managed code.
    let native = VersionedLogOp::new(LogOp::Rename {
        anchor: kraken_proto::Anchor::Native {
            space: "ram".into(),
            offset: kraken_proto::Hex64(0x1000),
            fn_entry: kraken_proto::Hex64(0x1000),
            fn_hash: String::new(),
        },
        old_name: None,
        new_name: "x".into(),
    });
    assert_eq!(
        code(m.apply(&native, &cancel).await),
        ErrorCode::Unsupported
    );
    let cc = VersionedLogOp::new(LogOp::SetCallingConvention {
        anchor: managed_anchor(&fib.locator),
        old: None,
        new: "stdcall".into(),
    });
    assert_eq!(code(m.apply(&cc, &cancel).await), ErrorCode::Unsupported);
    // A comment on something that is not a method.
    let type_loc = Locator::managed(module, 0x0200_0002);
    assert_eq!(
        code(
            m.apply(
                &comment_op(&type_loc, CommentKind::Plate, None, Some("x")),
                &cancel
            )
            .await
        ),
        ErrorCode::Unsupported
    );
    // Nothing above changed the output.
    let r = e.decompile(&fib.locator, &cancel).await.unwrap();
    assert!(r.text.contains("int Fib(int n)"), "{}", r.text);
}

#[tokio::test]
#[ignore = "needs the isolated .NET SDK and `cargo xtask dotnet-ext`"]
async fn opening_an_assembly_again_forgets_the_annotations() {
    let e = opened().await;
    let cancel = CancellationToken::new();
    let fns = all_functions(&e, 500).await;
    let fib = find(&fns, "KrakenCorpus.Calc.Fib").clone();
    e.mutator()
        .unwrap()
        .apply(&rename_op(&fib.locator, None, "Fibonacci"), &cancel)
        .await
        .unwrap();
    e.open_binary(&corpus_dll(), &LoaderSpec::default(), &cancel)
        .await
        .unwrap();
    assert_eq!(
        e.get_function(&fib.locator, &cancel).await.unwrap().name,
        fib.name
    );
}
