//! The help window, F1, the tour and the Help menu.

use egui::{Key, Modifiers};
use egui_kittest::kittest::Queryable;
use kraken_viewmodel::AppAction;

use super::Harness;
use super::shell::kit;
use crate::help::Topic;
use crate::workspace::Tab;

#[test]
fn f1_opens_help_on_getting_started_when_no_project_is_open() {
    let mut h = Harness::new(false);
    h.key(Key::F1, Modifiers::NONE);
    h.step();
    assert_eq!(h.app.help_topic(), Some(Topic::Start));
    h.key(Key::Escape, Modifiers::NONE);
    assert_eq!(h.app.help_topic(), None, "Escape closes it");
}

#[test]
fn f1_in_a_project_opens_the_topic_of_the_panel_in_focus() {
    let mut h = Harness::ready_demo();
    h.app.focus_tab(Tab::Hex);
    h.step();
    h.key(Key::F1, Modifiers::NONE);
    h.step();
    assert_eq!(h.app.help_topic(), Some(Topic::Panel(Tab::Hex)));
}

#[test]
fn the_help_menu_lists_help_the_tour_and_the_user_guide() {
    let mut k = kit(false);
    k.h.run_steps(3);
    k.h.get_by_label("Help").click();
    k.h.run_steps(3);
    assert!(
        k.h.query_all_by_label_contains("Take the tour").count() >= 2,
        "the menu item and the welcome button"
    );
    assert!(k.h.query_by_label_contains("User guide").is_some());
}

#[test]
fn the_help_window_lists_every_topic_and_the_steps_have_buttons() {
    let mut k = kit(false);
    let ctx = k.h.ctx.clone();
    k.h.state_mut().dispatch(AppAction::ShowHelp, &ctx);
    k.h.run_steps(4);
    for t in crate::help::topics() {
        assert!(
            k.h.query_all_by_label(t.title()).next().is_some(),
            "no topic {}",
            t.title()
        );
    }
    assert!(
        k.h.query_by_label_contains("Do it: Open a program")
            .is_some(),
        "the first step has its button"
    );
    k.h.query_all_by_label("Keyboard shortcuts")
        .next()
        .expect("the topic")
        .click();
    k.h.run_steps(3);
    assert_eq!(k.h.state().help_topic(), Some(Topic::Shortcuts));
}

#[test]
fn the_shortcut_page_is_built_from_the_shortcut_list() {
    let mut k = kit(false);
    let ctx = k.h.ctx.clone();
    k.h.state_mut().dispatch(AppAction::ShowHelp, &ctx);
    k.h.run_steps(3);
    k.h.query_all_by_label("Keyboard shortcuts")
        .next()
        .expect("the topic")
        .click();
    k.h.run_steps(3);
    assert_eq!(k.h.state().help_topic(), Some(Topic::Shortcuts));
    for s in kraken_viewmodel::SHORTCUTS {
        assert!(
            k.h.query_all_by_label(s.keys).next().is_some(),
            "{} is missing from the page",
            s.keys
        );
    }
}

#[test]
fn the_tour_can_be_walked_back_and_forth_and_skipped() {
    let mut k = kit(false);
    let ctx = k.h.ctx.clone();
    k.h.state_mut().dispatch(AppAction::TakeTour, &ctx);
    k.h.run_steps(3);
    assert_eq!(k.h.state().tour_step(), Some(0));
    k.h.get_by_label("Next").click();
    k.h.run_steps(3);
    assert_eq!(k.h.state().tour_step(), Some(1));
    k.h.get_by_label("Back").click();
    k.h.run_steps(3);
    assert_eq!(k.h.state().tour_step(), Some(0));
    k.h.get_by_label("Skip tour").click();
    k.h.run_steps(3);
    assert_eq!(k.h.state().tour_step(), None);
}

#[test]
fn the_tour_waits_for_a_project_on_steps_that_need_one() {
    let mut k = kit(false);
    let ctx = k.h.ctx.clone();
    k.h.state_mut().dispatch(AppAction::TakeTour, &ctx);
    k.h.run_steps(2);
    for _ in 0..2 {
        k.h.get_by_label("Next").click();
        k.h.run_steps(3);
    }
    assert_eq!(k.h.state().tour_step(), Some(2));
    assert!(
        k.h.query_by_label_contains("Open a program or the demo project")
            .is_some(),
        "it says to open a project"
    );
}
