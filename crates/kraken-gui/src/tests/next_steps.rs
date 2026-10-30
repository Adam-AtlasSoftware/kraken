//! The next-steps strip above the Decompiler over the demo project: suggestions show up, one
//! click runs one, the cross hides one.

use egui_kittest::kittest::Queryable;
use kraken_viewmodel::{AnalysisPhase, Connection};

use super::shell::{Kit, kit};

fn ready() -> Kit {
    let mut k = kit(true);
    for _ in 0..3000 {
        k.h.run_steps(1);
        let done = k.h.state().view_model().is_some_and(|vm| {
            vm.connection == Connection::Open
                && vm.analysis.phase == AnalysisPhase::Complete
                && !vm.tools.next_steps.visible().is_empty()
        });
        if done {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(4));
    }
    k.h.run_steps(3);
    k
}

fn titles(k: &Kit) -> Vec<String> {
    k.h.state()
        .view_model()
        .map(|vm| {
            vm.tools
                .next_steps
                .visible()
                .iter()
                .map(|s| s.title.clone())
                .collect()
        })
        .unwrap_or_default()
}

#[test]
fn the_strip_lists_at_most_three_suggestions_each_with_a_button_and_a_cross() {
    let k = ready();
    let shown = titles(&k);
    assert!(!shown.is_empty() && shown.len() <= 3, "{shown:?}");
    for t in &shown {
        assert!(k.h.query_by_label(t).is_some(), "no button for {t}");
    }
    assert_eq!(k.h.query_all_by_label("x").count(), shown.len());
    assert!(k.h.query_by_label("Next:").is_some());
}

#[test]
fn the_cross_hides_a_suggestion_and_a_click_runs_one() {
    let mut k = ready();
    let shown = titles(&k);
    let first = shown[0].clone();

    k.h.query_all_by_label("x").next().expect("a cross").click();
    k.h.run_steps(3);
    assert!(
        !titles(&k).contains(&first),
        "the hidden suggestion is gone"
    );

    if let Some(second) = titles(&k).first().cloned() {
        k.h.get_by_label(&second).click();
        for _ in 0..500 {
            k.h.run_steps(1);
            let ran =
                k.h.state()
                    .view_model()
                    .is_some_and(|vm| vm.tools.result.is_some() || !vm.toasts.is_empty());
            if ran {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(4));
        }
        panic!("clicking {second} did nothing");
    }
}
