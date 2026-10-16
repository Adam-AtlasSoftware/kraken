use std::sync::Arc;

use kraken_engine::testing::run_contract_suite;
use kraken_engine::{Cap, Engine, SharedEngine};
use kraken_proto::Hex64;

use crate::{FakeEngine, FixtureFile, Perturb};

const TINY: &str = include_str!("../fixtures/tiny.json");

fn fixture() -> FixtureFile {
    FixtureFile::from_json(TINY).unwrap()
}

#[test]
fn fixture_round_trips_and_is_valid() {
    let fx = fixture();
    assert_eq!(fx.functions.len(), 3);
    for f in &fx.functions {
        assert_eq!(f.summary.locator, f.decompile.function);
        f.decompile.validate_tokens().unwrap();
    }
    assert_eq!(FixtureFile::from_json(&fx.to_json().unwrap()).unwrap(), fx);
}

#[tokio::test]
async fn contract_suite_normal() {
    let fx = fixture();
    let exp = fx.expectations("tiny.elf");
    let engine = FakeEngine::new(fx);
    run_contract_suite(&engine, &exp).await.unwrap();
}

#[tokio::test]
async fn contract_suite_as_shared_dyn_engine() {
    let fx = fixture();
    let exp = fx.expectations("tiny.elf");
    let engine: SharedEngine = Arc::new(FakeEngine::new(fx));
    run_contract_suite(engine.as_ref(), &exp).await.unwrap();
}

#[tokio::test]
async fn contract_suite_perturbed() {
    let fx = fixture();
    let perturb = Perturb {
        base_shift: 0x10000,
        split: vec![Hex64(0x401000)],
        merge: vec![(Hex64(0x401040), Hex64(0x401080))],
    };
    let expected = perturb.apply(&fx);
    assert_eq!(expected.program.base, Hex64(0x410000));
    let exp = expected.expectations("tiny.elf");
    assert_eq!(exp.functions.len(), 3, "3 + split - merge");
    let names: Vec<_> = exp.functions.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(names, ["main", "main_part2", "helper"]);
    let engine = FakeEngine::perturbed(fx, perturb);
    run_contract_suite(&engine, &exp).await.unwrap();
}

#[tokio::test]
async fn contract_suite_without_optional_capabilities() {
    let fx = fixture();
    let exp = fx.expectations("tiny.elf");
    let engine = FakeEngine::new(fx)
        .without(Cap::Decompiler)
        .without(Cap::Analyzer)
        .without(Cap::TypeStore)
        .without(Cap::Loader);
    assert!(engine.decompiler().is_none() && engine.analyzer().is_none());
    assert!(!engine.capabilities().has(Cap::Decompiler));
    run_contract_suite(&engine, &exp).await.unwrap();
}

#[tokio::test]
async fn suite_detects_broken_capability_list() {
    struct Liar(FakeEngine);
    impl Engine for Liar {
        fn capabilities(&self) -> kraken_engine::EngineCaps {
            kraken_engine::EngineCaps::new("liar", [])
        }
        fn function_lister(&self) -> Option<&dyn kraken_engine::FunctionLister> {
            self.0.function_lister()
        }
    }
    let fx = fixture();
    let exp = fx.expectations("tiny.elf");
    let err = run_contract_suite(&Liar(FakeEngine::new(fx)), &exp)
        .await
        .unwrap_err();
    assert_eq!(err.section, "capabilities");
}

#[tokio::test]
async fn rename_updates_text_and_tokens() {
    use kraken_engine::CancellationToken;
    use kraken_proto::{Anchor, LogOp, VersionedLogOp};

    let fx = fixture();
    let engine = FakeEngine::new(fx);
    let cancel = CancellationToken::new();
    let loc = kraken_proto::Locator::ram(0x401040);
    engine
        .mutator()
        .unwrap()
        .apply(
            &VersionedLogOp::new(LogOp::Rename {
                anchor: Anchor::Native {
                    space: "ram".into(),
                    offset: Hex64(0x401040),
                    fn_entry: Hex64(0x401040),
                    fn_hash: "h-helper".into(),
                },
                old_name: Some("helper".into()),
                new_name: "do_the_thing".into(),
            }),
            &cancel,
        )
        .await
        .unwrap();
    let main = engine
        .decompiler()
        .unwrap()
        .decompile(&kraken_proto::Locator::ram(0x401000), &cancel)
        .await
        .unwrap();
    // callers keep the stale call-site name in this fake; only the renamed function changes
    assert!(main.text.contains("helper(argc)"));
    let r = engine
        .decompiler()
        .unwrap()
        .decompile(&loc, &cancel)
        .await
        .unwrap();
    assert!(r.text.starts_with("void do_the_thing(int n)"));
    r.validate_tokens().unwrap();
    let t = r
        .tokens
        .iter()
        .find(|t| t.symbol.as_deref() == Some("do_the_thing"))
        .unwrap();
    assert_eq!(&r.text[t.start as usize..t.end as usize], "do_the_thing");
    assert_eq!(engine.applied_ops().len(), 1);
}
