//! The rewrite wizard: one window that walks from "which function" to "open the Rust project".
//!
//! Each step says in one sentence what it does, and when "Next" is off it says why. The state and
//! the calls are the view-model's (`vm.rewrite.wizard`); every button here is also a button of the
//! Rewrite tab or a registry command an assistant can call.

use egui::{Align2, Id, Key, RichText, vec2};
use kraken_gui_widgets::Palette;
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::rewrite::{
    CheckLevel, RewriteMode, UnitItem, UnitStatus, WizardScope, WizardStep, status_explain,
    verdict_line, wizard_scope_explain,
};

use super::browse::{FolderField, Purpose, folder_field, open_buttons};
use super::{gated_button, gated_primary, status_color};
use crate::style::{self, chip, medium, pal, primary_button};
use crate::workspace::Tab;

/// Draws the wizard while it is open.
pub fn window(ctx: &egui::Context, vm: &mut ViewModel, front: &mut Option<Tab>) {
    if !vm.rewrite.wizard.open {
        return;
    }
    vm.rewrite_wizard_tick();
    let mut close = false;
    let max_h = (ctx.content_rect().height() - 120.0).clamp(300.0, 760.0);
    egui::Window::new(medium("Rewrite in Rust", 15.0))
        .id(Id::new("kraken_rewrite_wizard"))
        .collapsible(false)
        .resizable(false)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, -20.0))
        .default_width(780.0)
        .max_width(780.0)
        .show(ctx, |ui| {
            stepper(ui, vm);
            ui.separator();
            egui::ScrollArea::vertical()
                .id_salt("kraken_wizard_scroll")
                .max_height(max_h - 150.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    step_header(ui, vm);
                    ui.add_space(4.0);
                    match vm.rewrite.wizard.step {
                        WizardStep::Scope => scope_step(ui, vm),
                        WizardStep::Mode => mode_step(ui, vm),
                        WizardStep::Check => check_step(ui, vm),
                        WizardStep::Run => run_step(ui, vm),
                        WizardStep::Review => review_step(ui, vm, front),
                        WizardStep::Accept => accept_step(ui, vm, front),
                        WizardStep::Export => export_step(ui, vm),
                        WizardStep::Build => build_step(ui, vm),
                        WizardStep::Open => open_step(ui, vm),
                    }
                });
            ui.separator();
            footer(ui, vm, &mut close);
        });
    if ctx.input(|i| i.key_pressed(Key::Escape)) {
        close = true;
    }
    if close {
        vm.rewrite_wizard_close();
    }
}

fn stepper(ui: &mut egui::Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let current = vm.rewrite.wizard.step;
    let busy = vm.rewrite_wizard_running();
    ui.horizontal_wrapped(|ui| {
        ui.spacing_mut().item_spacing.x = 10.0;
        for step in WizardStep::ALL {
            let skipped = vm.rewrite_wizard_skips(step);
            let text = format!("{}  {}", step.index() + 1, step.label());
            if step == current {
                ui.add(
                    egui::Button::new(medium(text, 12.5).color(p.text_strong))
                        .fill(p.selection)
                        .stroke(egui::Stroke::new(1.5, p.accent)),
                )
                .on_hover_text(format!("You are here. {}", step.sentence()));
            } else if skipped {
                ui.add_enabled(false, egui::Button::new(RichText::new(text).size(12.5)))
                    .on_disabled_hover_text(
                        "Not needed for the whole program: the run already wrote the Rust crate to its folder.",
                    );
            } else if step.index() < current.index() {
                let r = ui.add_enabled(
                    !busy,
                    egui::Button::new(RichText::new(text).size(12.5).color(s.success)).frame(false),
                )
                .on_disabled_hover_text("Wait for the job to finish");
                if r.on_hover_text(format!("Done. {} Click to go back to this step.", step.sentence()))
                    .clicked()
                {
                    vm.rewrite.wizard.step = step;
                }
            } else {
                ui.add_enabled(
                    false,
                    egui::Button::new(RichText::new(text).size(12.5).color(p.text_dim)).frame(false),
                )
                .on_disabled_hover_text(format!(
                    "Later. {} Finish the steps before it first.",
                    step.sentence()
                ));
            }
        }
    });
}

fn step_header(ui: &mut egui::Ui, vm: &ViewModel) {
    let p = pal(ui);
    let step = vm.rewrite.wizard.step;
    ui.label(
        medium(
            format!(
                "Step {} of {}: {}",
                step.index() + 1,
                WizardStep::ALL.len(),
                step.label()
            ),
            14.0,
        )
        .color(p.text_strong),
    );
    ui.label(RichText::new(step.sentence()).size(12.5).color(p.text_dim));
}

fn footer(ui: &mut egui::Ui, vm: &mut ViewModel, close: &mut bool) {
    let s = style::status(style::dark(ui));
    let blocker = vm.rewrite_wizard_blocker();
    let step = vm.rewrite.wizard.step;
    if let Some(why) = blocker.as_ref().filter(|_| step != WizardStep::Open) {
        ui.label(RichText::new(why).size(12.0).color(s.warning));
    }
    ui.horizontal(|ui| {
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if step == WizardStep::Open {
                if primary_button(ui, "Done")
                    .on_hover_text("Close the wizard. Nothing is lost: the results stay in the Rewrite tab.")
                    .clicked()
                {
                    *close = true;
                }
            } else if gated_primary(
                ui,
                "Next",
                blocker.as_deref(),
                "Go to the next step.",
            ) {
                vm.rewrite_wizard_next();
            }
            let can_back = step != WizardStep::Scope && !vm.rewrite_wizard_running();
            if gated_button(
                ui,
                "Back",
                (!can_back).then_some(if step == WizardStep::Scope {
                    "This is the first step."
                } else {
                    "The rewrite is running. Wait for it, or cancel it."
                }),
                "Go back one step. Nothing is undone.",
            ) {
                vm.rewrite_wizard_back();
            }
            if step != WizardStep::Open
                && ui
                    .button("Close")
                    .on_hover_text("Close the wizard. A running job keeps going, and everything done so far stays in the Rewrite tab.")
                    .clicked()
            {
                *close = true;
            }
        });
    });
}

// ---------------------------------------------------------------- scope

fn scope_step(ui: &mut egui::Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let current = vm.rewrite.wizard.scope;
    for sc in WizardScope::ALL {
        let r = ui
            .selectable_label(current == sc, medium(sc.label(), 13.0))
            .on_hover_text(wizard_scope_explain(sc));
        if r.clicked() {
            vm.rewrite_wizard_set_scope(sc);
        }
        if current == sc {
            ui.label(
                RichText::new(wizard_scope_explain(sc))
                    .size(12.0)
                    .color(p.text_dim),
            );
            ui.add_space(2.0);
            match sc {
                WizardScope::Function => function_picker(ui, vm),
                WizardScope::Plan => plan_summary(ui, vm),
                WizardScope::Program => {
                    ui.label(
                        RichText::new(
                            "The Run step lets you choose the folder, add your own test cases, and turn the per-function check off.",
                        )
                        .size(12.0)
                        .color(p.text_dim),
                    );
                }
            }
            ui.add_space(6.0);
        }
    }
}

fn function_picker(ui: &mut egui::Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let chosen = vm.rewrite_wizard_function_name();
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Function").size(12.0).color(p.text_dim));
        match &chosen {
            Some(n) => ui.label(RichText::new(n).monospace().color(p.text_strong)),
            None => ui.label(RichText::new("none chosen").color(p.text_dim)),
        };
        if let Some(c) = vm.current.as_ref().map(|c| (c.address, c.name.clone()))
            && vm.rewrite.wizard.function != Some(c.0)
            && ui
                .small_button(format!("Use {}", c.1))
                .on_hover_text("Rewrite the function that is open in the Decompiler.")
                .clicked()
        {
            vm.rewrite_wizard_set_function(c.0);
        }
    });
    let id = Id::new("kraken_wizard_function_filter");
    let mut text: String = ui.data_mut(|d| d.get_temp(id).unwrap_or_default());
    ui.add(
        egui::TextEdit::singleline(&mut text)
            .hint_text("Type part of a name to find another function")
            .desired_width(300.0),
    )
    .on_hover_text("Search the functions that are loaded in the Functions list.");
    ui.data_mut(|d| d.insert_temp(id, text.clone()));
    let q = text.trim().to_lowercase();
    if !q.is_empty() {
        let hits: Vec<(u64, String)> = vm
            .functions
            .items
            .iter()
            .filter(|f| !f.stub && f.name.to_lowercase().contains(&q))
            .take(6)
            .map(|f| (f.address, f.name.clone()))
            .collect();
        if hits.is_empty() {
            ui.label(
                RichText::new("No loaded function has that in its name.")
                    .size(12.0)
                    .color(p.text_dim),
            );
        }
        for (a, n) in hits {
            if ui
                .link(RichText::new(&n).monospace().size(12.0))
                .on_hover_text("Rewrite this function.")
                .clicked()
            {
                vm.rewrite_wizard_set_function(a);
            }
        }
    }
}

fn plan_summary(ui: &mut egui::Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    if vm.rewrite.rows.is_empty() {
        if vm.rewrite.loading {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Reading the plan...");
            });
        } else if ui
            .button("Plan the rewrite")
            .on_hover_text("List the program's functions with the ones that call nothing else first, so each is rewritten and checked before the functions that call it.")
            .clicked()
        {
            vm.rewrite_make_plan();
        }
        return;
    }
    let c = vm.rewrite.counts;
    ui.label(
        RichText::new(format!(
            "{} functions in the plan: {} planned, {} translated, {} verified, {} failed, {} accepted.",
            c.total(),
            c.planned,
            c.translated,
            c.verified,
            c.failed,
            c.accepted
        ))
        .size(12.0)
        .color(p.text_dim),
    );
}

// ---------------------------------------------------------------- mode

fn mode_step(ui: &mut egui::Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let program = vm.rewrite.wizard.scope == WizardScope::Program;
    for (mode, title, body) in [
        (
            RewriteMode::Incremental,
            "Translate the code",
            "The assistant reads the decompiled C and writes Rust that does the same thing, quirks included. KRAKEN then runs both on the same inputs. Best when you want the same behavior, and for code you do not fully understand yet.",
        ),
        (
            RewriteMode::Spec,
            "Write a spec, then reimplement",
            "The assistant first writes a plain description of what the function does, every statement tied to an address in the binary. It then writes the Rust from that description alone, without seeing the C, and KRAKEN checks the result. Cleaner code and a document you can read, but one more request per function.",
        ),
    ] {
        let off = program && mode == RewriteMode::Spec;
        let on = vm.rewrite.wizard.mode == mode;
        let r = ui.add_enabled(!off, egui::Button::selectable(on, medium(title, 13.0)));
        let r = if off {
            r.on_disabled_hover_text(
                "Not available for the whole program yet. Choose \"The plan\" in the first step to use spec mode function by function.",
            )
        } else {
            r.on_hover_text(body)
        };
        if r.clicked() {
            vm.rewrite_wizard_set_mode(mode);
        }
        ui.label(RichText::new(body).size(12.0).color(p.text_dim));
        if off {
            ui.label(
                RichText::new("Not available for the whole program yet.")
                    .size(12.0)
                    .color(style::status(style::dark(ui)).warning),
            );
        }
        ui.add_space(6.0);
    }
}

// ---------------------------------------------------------------- check

fn check_step(ui: &mut egui::Ui, vm: &mut ViewModel) {
    check_list(ui, vm);
    model_for_run(ui, vm);
}

/// The Check step's choice of model for this run only (not saved unless the person saves it).
fn model_for_run(ui: &mut egui::Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    ui.separator();
    ui.label(medium("Model for this run", 13.0).color(p.text_strong));
    let mut other = vm.ai.run_override.is_some();
    if ui
        .checkbox(&mut other, "Use a different model for this run")
        .on_hover_text(
            "Pick the model for this rewrite only. Your settings stay as they are unless you save it.",
        )
        .changed()
    {
        vm.ai.run_override = other.then(kraken_viewmodel::ai::RunOverride::default);
    }
    let configured = vm
        .ai
        .policy
        .rewrite
        .as_ref()
        .map_or_else(|| "none set up".to_string(), |c| c.label());
    let Some(mut o) = vm.ai.run_override.clone() else {
        ui.label(
            RichText::new(format!(
                "The configured rewrite model is used: {configured}."
            ))
            .size(12.0)
            .color(p.text_dim),
        );
        return;
    };
    ui.horizontal(|ui| {
        ui.radio_value(
            &mut o.which,
            kraken_assist::RewriteModel::Configured,
            "The rewrite model",
        )
        .on_hover_text(
            "The [rewrite] table of your config, or the assistant's model when there is none",
        );
        ui.radio_value(
            &mut o.which,
            kraken_assist::RewriteModel::Assistant,
            "The assistant's model",
        )
        .on_hover_text("The model the assistant uses ([provider] in your config)");
    });
    ui.horizontal(|ui| {
        ui.label("Model name");
        ui.add(
            egui::TextEdit::singleline(&mut o.model)
                .hint_text("leave empty for the configured name")
                .desired_width(240.0),
        )
        .on_hover_text("Ask the same provider for another model, for example a cheaper one");
    });
    if vm.ai.run_override.as_ref() != Some(&o) {
        vm.ai.run_override = Some(o);
    }
    let chosen = vm.ai_rewrite_choice();
    let can_save = vm.ai.config_path.is_some() && chosen.is_some();
    let save = ui
        .add_enabled(can_save, egui::Button::new("Save as the rewrite model"))
        .on_hover_text(
            "Also use this model for future rewrites (writes the [rewrite] table of config.toml)",
        )
        .on_disabled_hover_text("There is no config file to save to, or no model is set up");
    if save.clicked()
        && let (Some(path), Some(c)) = (vm.ai.config_path.clone(), chosen)
    {
        match kraken_assist::save_rewrite_config(&path, Some(&c.config)) {
            Ok(()) => {
                vm.ai.run_override = None;
                vm.ai_reload();
                vm.toast(
                    kraken_viewmodel::ToastLevel::Success,
                    format!("Saved: rewrites now use {}.", c.label()),
                );
            }
            Err(e) => vm.toast(
                kraken_viewmodel::ToastLevel::Warning,
                format!("Could not save the rewrite model: {e}"),
            ),
        }
    }
}

fn check_list(ui: &mut egui::Ui, vm: &ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    for c in vm.rewrite_wizard_checks() {
        ui.horizontal_wrapped(|ui| {
            let (word, color, tip) = match c.level {
                CheckLevel::Ok => ("Ready", s.success, "This is in place."),
                CheckLevel::Warn => (
                    "Note",
                    s.warning,
                    "Worth knowing. It does not stop the rewrite.",
                ),
                CheckLevel::Blocked => (
                    "Stop",
                    s.danger,
                    "The rewrite cannot start until this is fixed.",
                ),
            };
            chip(ui, word, color).on_hover_text(tip);
            ui.label(medium(c.title, 13.0).color(p.text_strong));
        });
        ui.label(RichText::new(&c.detail).size(12.0).color(p.text));
        ui.add_space(6.0);
    }
}

// ---------------------------------------------------------------- run

fn run_step(ui: &mut egui::Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let w = vm.rewrite.wizard.clone();
    let running = vm.rewrite_wizard_running();
    let (functions, calls) = vm.rewrite_wizard_estimate();
    let name = vm.rewrite_wizard_function_name();
    let what = match w.scope {
        WizardScope::Function => format!("the function {}", name.unwrap_or_default()),
        WizardScope::Plan => format!("{functions} planned function{}", plural(functions)),
        WizardScope::Program => "the whole program".into(),
    };
    ui.label(
        RichText::new(format!(
            "Rewrite {what}{}. Up to {calls} request{} to the assistant. Decompiled code is sent to its service.",
            if w.mode == RewriteMode::Spec { " from a spec" } else { "" },
            plural(calls),
        ))
        .size(12.5),
    );
    if w.scope == WizardScope::Program && !running {
        ui.add_space(4.0);
        super::program::options(ui, vm);
        ui.label(
            RichText::new(
                "Starting asks you first: the original program is run on the test inputs, in a sandbox with no network.",
            )
            .size(11.5)
            .color(p.text_dim),
        );
    }
    ui.add_space(6.0);
    if running {
        super::jobs_strip(ui, vm);
        if w.scope == WizardScope::Plan && vm.rewrite.bulk.total > 0 {
            ui.label(
                RichText::new(format!(
                    "{} of {} functions done.",
                    vm.rewrite_bulk_done(),
                    vm.rewrite.bulk.total
                ))
                .size(12.0)
                .color(p.text_dim),
            );
        }
        if ui
            .button("Cancel")
            .on_hover_text("Stop the rewrite. For a plan, the function in progress is asked to stop and the rest are not started. What is finished stays.")
            .clicked()
        {
            vm.rewrite_wizard_cancel();
        }
    } else {
        let blocker = vm
            .rewrite_wizard_checks()
            .into_iter()
            .find(|c| c.level == CheckLevel::Blocked)
            .map(|c| format!("{}: {}", c.title, c.detail));
        if gated_primary(
            ui,
            if w.started { "Run again" } else { "Start" },
            blocker.as_deref(),
            "Start the rewrite now. Each function is translated, built in the sandbox and tested against the original.",
        ) {
            vm.rewrite_wizard_start();
        }
    }
    if let Some(e) = run_error(vm) {
        ui.add_space(4.0);
        ui.label(RichText::new(e).size(12.0).color(s.danger));
    }
}

fn run_error(vm: &ViewModel) -> Option<String> {
    let w = &vm.rewrite.wizard;
    match w.scope {
        WizardScope::Function => w
            .function
            .and_then(|a| vm.rewrite.details.get(&a))
            .and_then(|d| d.error.clone()),
        WizardScope::Plan => vm.rewrite.error.clone(),
        WizardScope::Program => vm
            .rewrite
            .program
            .error
            .clone()
            .or_else(|| vm.rewrite.program.declined.clone()),
    }
}

fn plural(n: u32) -> &'static str {
    if n == 1 { "" } else { "s" }
}

// ---------------------------------------------------------------- review

fn show_in_tab(ui: &mut egui::Ui, vm: &mut ViewModel, front: &mut Option<Tab>, a: &UnitItem) {
    if ui
        .small_button("Show")
        .on_hover_text(
            "Open this function in the Rewrite tab: its C next to the Rust, with the test results.",
        )
        .clicked()
    {
        vm.rewrite_select(a.address);
        *front = Some(Tab::Rewrite);
    }
}

fn row_line(ui: &mut egui::Ui, r: &UnitItem, p: &Palette, dark: bool) {
    ui.label(
        RichText::new(&r.name)
            .monospace()
            .size(12.5)
            .color(p.text_strong),
    );
    chip(ui, r.status.as_str(), status_color(r.status, dark, p))
        .on_hover_text(status_explain(r.status));
    let tests = if r.cases_run == 0 {
        "no test ran".to_string()
    } else {
        format!("{} of {} cases agreed", r.passed, r.cases_run)
    };
    ui.label(RichText::new(tests).size(12.0).color(p.text_dim));
}

fn review_step(ui: &mut egui::Ui, vm: &mut ViewModel, front: &mut Option<Tab>) {
    let p = pal(ui);
    let dark = style::dark(ui);
    let s = style::status(dark);
    match vm.rewrite.wizard.scope {
        WizardScope::Function => {
            match vm.rewrite_wizard_row().cloned() {
                Some(r) => {
                    ui.horizontal_wrapped(|ui| {
                        row_line(ui, &r, &p, dark);
                        show_in_tab(ui, vm, front, &r);
                    });
                    ui.label(
                        RichText::new(status_explain(r.status))
                            .size(12.0)
                            .color(p.text_dim),
                    );
                }
                None => {
                    ui.label("This function is not in the plan yet.");
                }
            }
            if let Some(e) = run_error(vm) {
                ui.label(RichText::new(e).size(12.0).color(s.danger));
            }
        }
        WizardScope::Plan => plan_review(ui, vm, front, &p, dark),
        WizardScope::Program => program_review(ui, vm, front, &p, dark),
    }
}

fn plan_review(
    ui: &mut egui::Ui,
    vm: &mut ViewModel,
    front: &mut Option<Tab>,
    p: &Palette,
    dark: bool,
) {
    let c = vm.rewrite.counts;
    ui.label(
        RichText::new(format!(
            "{} verified, {} accepted, {} failed, {} translated but undecided, {} not yet translated.",
            c.verified, c.accepted, c.failed, c.translated, c.planned
        ))
        .size(12.5),
    );
    let rows: Vec<UnitItem> = vm
        .rewrite
        .rows
        .iter()
        .filter(|r| r.status != UnitStatus::Planned)
        .take(14)
        .cloned()
        .collect();
    let more = (c.total() - c.planned) as usize - rows.len().min((c.total() - c.planned) as usize);
    for r in &rows {
        ui.horizontal_wrapped(|ui| {
            row_line(ui, r, p, dark);
            show_in_tab(ui, vm, front, r);
        });
    }
    if more > 0 {
        ui.label(
            RichText::new(format!("and {more} more in the Rewrite tab"))
                .size(12.0)
                .color(p.text_dim),
        );
    }
    if vm.rewrite_failed_count() > 0 {
        ui.add_space(4.0);
        if gated_button(
            ui,
            &format!("Retry all failed ({})", vm.rewrite_failed_count()),
            vm.rewrite_bulk_retry_blocker().as_deref(),
            "Run every failed function again. Earlier attempts stay in each function's history.",
        ) {
            vm.rewrite_bulk_retry_failed();
            vm.rewrite.wizard.step = WizardStep::Run;
        }
    }
}

fn program_review(
    ui: &mut egui::Ui,
    vm: &mut ViewModel,
    front: &mut Option<Tab>,
    p: &Palette,
    dark: bool,
) {
    let s = style::status(dark);
    let Some(d) = vm.rewrite.program.detail.clone() else {
        if let Some(e) = run_error(vm) {
            ui.label(RichText::new(e).size(12.0).color(s.danger));
        }
        return;
    };
    ui.horizontal_wrapped(|ui| {
        let color = match d.verdict.verdict.as_str() {
            "pass" => s.success,
            "fail" | "incomplete" => s.danger,
            "inconclusive" => s.warning,
            _ => p.text_dim,
        };
        chip(ui, &d.verdict.verdict, color).on_hover_text(
            "The program-level verdict. Only this one says the program as a whole behaves like the original on the inputs tried.",
        );
        ui.label(RichText::new(verdict_line(&d.verdict)).size(12.5));
    });
    ui.label(
        RichText::new(format!(
            "{} of {} planned functions are in the crate; {} never compared with the original on their own.",
            d.included,
            d.functions_planned,
            d.unverified()
        ))
        .size(12.0)
        .color(p.text_dim),
    );
    let bad: Vec<_> = d
        .verdict
        .cases
        .iter()
        .filter(|c| !c.agree)
        .take(4)
        .collect();
    if !bad.is_empty() {
        ui.add_space(4.0);
        ui.label(medium("Cases that differ", 12.5).color(p.text_strong));
    }
    for c in bad {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new(&c.name).monospace().size(12.0));
            ui.label(
                RichText::new(c.differences.first().map_or("", String::as_str))
                    .size(12.0)
                    .color(s.danger),
            );
        });
    }
    ui.add_space(4.0);
    if ui
        .button("Open the whole-program view")
        .on_hover_text("The function table, every case with a diff of what each program printed, and the repair rounds.")
        .clicked()
    {
        vm.rewrite.show_program_request = true;
        *front = Some(Tab::Rewrite);
    }
}

// ---------------------------------------------------------------- accept

fn accept_step(ui: &mut egui::Ui, vm: &mut ViewModel, front: &mut Option<Tab>) {
    let p = pal(ui);
    let c = vm.rewrite.counts;
    ui.label(
        RichText::new(format!(
            "{} verified and waiting, {} accepted.",
            c.verified, c.accepted
        ))
        .size(12.5),
    );
    ui.label(
        RichText::new(
            "Accepting is your decision. A verified function agreed with the original on every test, which is evidence, not proof. Open the ones that matter and read the Rust first. Agents can write and test Rust, but only you can accept it.",
        )
        .size(12.0)
        .color(p.text_dim),
    );
    if vm.rewrite.wizard.scope == WizardScope::Program {
        ui.label(
            RichText::new(
                "For a whole-program rewrite this step is optional: the crate already holds the translations. Accepted functions are reused by later runs and by the library export.",
            )
            .size(12.0)
            .color(p.text_dim),
        );
    }
    ui.add_space(4.0);
    let function_scope = vm.rewrite.wizard.scope == WizardScope::Function;
    let verified = vm.rewrite_verified_count();
    let label = if function_scope {
        "Accept this function".to_string()
    } else {
        format!("Accept all verified ({verified})")
    };
    ui.horizontal(|ui| {
        if gated_primary(
            ui,
            &label,
            vm.rewrite_wizard_accept_blocker().as_deref(),
            "Mark the Rust as the one to export. You can accept another version later; the newest accepted one is used.",
        ) {
            vm.rewrite_wizard_accept();
        }
        if function_scope
            && let Some(r) = vm.rewrite_wizard_row().cloned()
        {
            show_in_tab(ui, vm, front, &r);
        }
    });
    if let Some(a) = &vm.rewrite.bulk.accepting {
        ui.label(
            RichText::new(format!("{} of {} answered...", a.done, a.total))
                .size(12.0)
                .color(p.text_dim),
        );
    }
}

// ---------------------------------------------------------------- export

fn export_step(ui: &mut egui::Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let running = vm.rewrite.exporting();
    ui.label(
        RichText::new(vm.rewrite.coverage_line())
            .size(12.5)
            .color(p.text),
    );
    ui.label(
        RichText::new(
            "A Rust library with the accepted functions, and a shim that exposes each one under the original name so it can stand in for the original.",
        )
        .size(12.0)
        .color(p.text_dim),
    );
    ui.add_space(4.0);
    ui.label("Folder to write to");
    let check = vm.rewrite_export_check();
    let mut dir = vm.rewrite.export.dir.clone();
    folder_field(
        ui,
        vm,
        &mut dir,
        Some(&check),
        !running,
        &FolderField {
            id: "kraken_wizard_export_dir",
            hint: "rewrite-export",
            purpose: Purpose::Export,
            title: "Where should the Rust project be written?",
            tip: "A folder name inside your project, or a full path. It must be empty, or an earlier export.",
        },
    );
    vm.rewrite_export_set_dir(dir);
    if vm.rewrite.export.ask_outside {
        ui.label(
            RichText::new(format!(
                "Write outside the project, into {}? Nothing there is deleted, but the folder must be empty or an earlier export.",
                vm.rewrite.export.dir.trim()
            ))
            .size(12.0)
            .color(s.warning),
        );
        if ui
            .button("Yes, write there")
            .on_hover_text("Create the files in that folder.")
            .clicked()
        {
            vm.rewrite_export_agree_outside();
        }
    }
    ui.add_space(4.0);
    let no_accept = vm.rewrite.counts.accepted == 0;
    let blocker = if no_accept {
        Some("Accept at least one verified function first.")
    } else if running {
        Some("The export is running.")
    } else {
        None
    };
    ui.horizontal(|ui| {
        if gated_primary(
            ui,
            "Export",
            blocker,
            "Write the accepted functions as a Rust project into the folder.",
        ) {
            vm.rewrite_wizard_export();
        }
        if running {
            ui.spinner();
        }
    });
    if let Some(e) = &vm.rewrite.export.error {
        ui.label(RichText::new(e).size(12.0).color(s.danger));
    }
    if let Some(r) = &vm.rewrite.export.result {
        ui.label(
            RichText::new(format!(
                "Written to {}: {} function{} in {} crate{}.",
                r.dir,
                r.symbols.len(),
                if r.symbols.len() == 1 { "" } else { "s" },
                r.crates.len(),
                if r.crates.len() == 1 { "" } else { "s" },
            ))
            .size(12.0)
            .color(s.success),
        );
    }
}

// ---------------------------------------------------------------- build

fn build_step(ui: &mut egui::Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let Some(dir) = vm.rewrite_wizard_crate_dir() else {
        ui.label("There is no project folder yet. Go back and export first.");
        return;
    };
    let building = vm.rewrite.building();
    let program = vm.rewrite.wizard.scope == WizardScope::Program;
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Project").size(12.0).color(p.text_dim));
        ui.label(
            RichText::new(&dir)
                .monospace()
                .size(12.0)
                .color(p.text_strong),
        );
    });
    ui.add_enabled(
        !building,
        egui::Checkbox::new(&mut vm.rewrite.build.test, "Run the tests"),
    )
    .on_hover_text("Run cargo test after the build. A project without tests passes this step.")
    .on_disabled_hover_text("Wait for the build to finish");
    if program {
        ui.add_enabled(
            !building,
            egui::Checkbox::new(&mut vm.rewrite.build.run, "Run the program afterwards"),
        )
        .on_hover_text("Start the built program once with the arguments below and show what it prints. It runs in the sandbox, with no network.")
        .on_disabled_hover_text("Wait for the build to finish");
        let run = vm.rewrite.build.run;
        ui.add_enabled(
            run && !building,
            egui::TextEdit::singleline(&mut vm.rewrite.build.run_args)
                .hint_text("arguments, for example -v input.txt")
                .desired_width(320.0),
        )
        .on_hover_text("What follows the program's name. Quotes group words.")
        .on_disabled_hover_text("Tick \"Run the program afterwards\" first");
    }
    ui.add_space(4.0);
    let blocker = vm
        .rewrite
        .blocked_note()
        .map(str::to_string)
        .or_else(|| building.then(|| "A build is running.".to_string()));
    ui.horizontal(|ui| {
        if gated_primary(
            ui,
            "Build and test",
            blocker.as_deref(),
            "Compile the project and run its tests inside the sandbox. KRAKEN asks first: the Rust was written by an assistant.",
        ) {
            vm.rewrite_wizard_build();
        }
        if building {
            ui.spinner();
        }
    });
    if building {
        super::jobs_strip(ui, vm);
    }
    for m in [&vm.rewrite.build.declined, &vm.rewrite.build.error]
        .into_iter()
        .flatten()
    {
        ui.label(RichText::new(m).size(12.0).color(s.warning));
    }
    if let Some(r) = vm.rewrite.build.result.clone() {
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            chip(
                ui,
                if r.passed { "passed" } else { "failed" },
                if r.passed { s.success } else { s.danger },
            )
            .on_hover_text("Every step that ran must pass.");
            ui.label(
                RichText::new(format!("Sandbox: {}", r.sandbox))
                    .size(11.5)
                    .color(p.text_dim),
            );
        });
        for st in &r.steps {
            ui.horizontal_wrapped(|ui| {
                chip(
                    ui,
                    if st.passed { "ok" } else { "failed" },
                    if st.passed { s.success } else { s.danger },
                );
                ui.label(medium(st.title(), 12.5).color(p.text_strong));
                ui.label(
                    RichText::new(format!("{}, {:.1} s", st.exit, st.seconds))
                        .size(11.5)
                        .color(p.text_dim),
                );
            });
            egui::CollapsingHeader::new(RichText::new("Log").size(12.0))
                .id_salt(("kraken_wizard_log", st.step.as_str()))
                .default_open(!st.passed)
                .show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt(("kraken_wizard_log_scroll", st.step.as_str()))
                        .max_height(180.0)
                        .show(ui, |ui| {
                            ui.add(
                                egui::Label::new(RichText::new(&st.log).monospace().size(11.5))
                                    .selectable(true),
                            );
                        });
                });
        }
    }
}

// ---------------------------------------------------------------- open

fn open_step(ui: &mut egui::Ui, vm: &ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let Some(dir) = vm.rewrite_wizard_crate_dir() else {
        ui.label("There is no project folder yet.");
        return;
    };
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Project").size(12.0).color(p.text_dim));
        ui.label(
            RichText::new(&dir)
                .monospace()
                .size(12.5)
                .color(p.text_strong),
        );
    });
    if let Some(r) = &vm.rewrite.build.result {
        let (text, color) = if r.passed {
            ("It built and its tests passed in the sandbox.", s.success)
        } else {
            (
                "The last build failed. The log is in the Build step.",
                s.danger,
            )
        };
        ui.label(RichText::new(text).size(12.5).color(color));
    }
    open_buttons(ui, &dir);
    ui.add_space(6.0);
    let how = if vm.rewrite.wizard.scope == WizardScope::Program {
        "Run it with `cargo run --release` in that folder. Read the code first: an assistant wrote it, and it was only tested on the inputs tried."
    } else {
        "The README.md in that folder says how to link the shim in place of the original functions, one at a time. Read the code first: an assistant wrote it."
    };
    ui.label(RichText::new(how).size(12.0).color(p.text_dim));
}
