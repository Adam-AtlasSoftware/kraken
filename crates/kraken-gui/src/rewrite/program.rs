//! The Program view of the Rewrite tab: the runs of "rewrite the whole program", the function
//! table of one run, where the generated crate is, the cases both programs were run on with a
//! diff of standard output, standard error and exit status, and the repair rounds.

use egui::{Color32, Frame, Margin, RichText, Sense, Ui, vec2};
use kraken_gui_widgets::Palette;
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::rewrite::{
    DiffKind, DiffLine, MAX_REPAIR_ROUNDS, ProgramCaseItem, ProgramFunctionItem, ProgramInput,
    ProgramRepairItem, ProgramRunDetail, UnitStatus, status_explain, verdict_line,
};

use super::browse::{FolderField, Purpose, folder_field};
use super::{chip_button, status_color};
use crate::style::{self, chip, empty_state, medium, pal, primary_button};
use crate::workspace::Tab;

/// What the person asked for in one frame.
#[derive(Default)]
pub(crate) struct ProgramActs {
    pub run: bool,
    pub refresh: bool,
    pub show_run: Option<u64>,
    pub rounds: Option<u32>,
    pub all_cases: Option<bool>,
    pub case: Option<usize>,
    pub function: Option<Option<u64>>,
    pub goto: Option<u64>,
}

/// GUI-only state of the view.
#[derive(Default)]
pub struct ProgramUi {
    /// Show the repair rounds.
    pub repairs_open: bool,
}

/// The colour of a program or function verdict chip.
fn verdict_color(verdict: &str, dark: bool, p: &Palette) -> Color32 {
    let s = style::status(dark);
    match verdict {
        "pass" => s.success,
        "fail" | "rejected" | "incomplete" => s.danger,
        "inconclusive" => s.warning,
        _ => p.text_dim,
    }
}

/// The Program view.
pub(super) fn panel(ui: &mut Ui, vm: &mut ViewModel, st: &mut ProgramUi, front: &mut Option<Tab>) {
    vm.rewrite_program_ensure_loaded();
    let mut acts = ProgramActs::default();
    toolbar(ui, vm, &mut acts);
    options(ui, vm);
    if let Some(note) = &vm.rewrite.program.declined {
        let s = style::status(style::dark(ui));
        ui.label(RichText::new(note).size(12.0).color(s.warning));
    }
    if let Some(e) = &vm.rewrite.program.error {
        let s = style::status(style::dark(ui));
        ui.label(RichText::new(e).size(12.0).color(s.danger));
    }
    ui.separator();
    match vm.rewrite.program.detail.clone() {
        None => empty(ui, vm),
        Some(d) => run_view(ui, vm, st, &d, &mut acts),
    }
    apply(vm, acts, front);
}

/// Output folder, the per-function check and the test cases, folded away until wanted.
pub(super) fn options(ui: &mut Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let running = vm.rewrite_program_running();
    let typed = vm
        .rewrite
        .program
        .inputs
        .iter()
        .filter(|i| !i.is_blank())
        .count();
    let summary = format!(
        "Options: {typed} test case{}, {}{}",
        if typed == 1 { "" } else { "s" },
        if vm.rewrite.program.output_dir.trim().is_empty() {
            "default folder"
        } else {
            "own folder"
        },
        if vm.rewrite.program.verify_functions {
            ""
        } else {
            ", functions not checked one by one"
        },
    );
    egui::CollapsingHeader::new(RichText::new(summary).size(12.5).color(p.text))
        .id_salt("kraken_program_options")
        .show(ui, |ui| {
            ui.label(RichText::new("Folder for the Rust crate").size(12.0).color(p.text_dim));
            let check = vm.rewrite_program_dir_check();
            let mut dir = vm.rewrite.program.output_dir.clone();
            folder_field(
                ui,
                vm,
                &mut dir,
                check.as_ref(),
                !running,
                &FolderField {
                    id: "kraken_program_dir",
                    hint: "rewrite-program (inside the project)",
                    purpose: Purpose::Program,
                    title: "Where should the Rust crate be written?",
                    tip: "Leave empty for the folder rewrite-program inside the project. The folder must be empty, or an earlier whole-program rewrite.",
                },
            );
            vm.rewrite.program.output_dir = dir;
            ui.add_space(4.0);
            ui.add_enabled(
                !running,
                egui::Checkbox::new(
                    &mut vm.rewrite.program.verify_functions,
                    "Check every function too",
                ),
            )
            .on_hover_text(
                "Besides comparing the whole programs, test each function on its own against the original. Slower, but a failure then points at one function. Turn it off to only compile the functions and rely on the whole-program comparison.",
            )
            .on_disabled_hover_text("Wait for the run to finish");
            ui.add_space(4.0);
            ui.label(RichText::new("Test cases").size(12.0).color(p.text_dim))
                .on_hover_text("Each case starts both programs with the arguments and input you give, and compares what they print and how they end.");
            inputs_editor(ui, vm, running);
        });
}

/// The rows of test cases: name, arguments, standard input, and a button to remove the row.
pub(crate) fn inputs_editor(ui: &mut Ui, vm: &mut ViewModel, locked: bool) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    ui.label(
        RichText::new(
            "KRAKEN also runs a baseline case and generated ones. Add your own for what matters to you: how the program is started, and what it reads.",
        )
        .size(11.5)
        .color(p.text_dim),
    );
    let mut remove = None;
    let mut add = false;
    ui.add_enabled_ui(!locked, |ui| {
        egui::Grid::new("kraken_program_inputs")
            .num_columns(4)
            .spacing([6.0, 4.0])
            .show(ui, |ui| {
                if !vm.rewrite.program.inputs.is_empty() {
                    for h in ["Name", "Arguments", "Standard input", ""] {
                        ui.label(RichText::new(h).size(11.5).color(p.text_dim));
                    }
                    ui.end_row();
                }
                for (i, row) in vm.rewrite.program.inputs.iter_mut().enumerate() {
                    ui.add(
                        egui::TextEdit::singleline(&mut row.name)
                            .id_salt(("rw_in_name", i))
                            .hint_text("short-run")
                            .desired_width(110.0),
                    )
                    .on_hover_text("A short label for this case in the report.");
                    ui.add(
                        egui::TextEdit::singleline(&mut row.args)
                            .id_salt(("rw_in_args", i))
                            .hint_text("-v --count 3")
                            .desired_width(170.0),
                    )
                    .on_hover_text(
                        "What follows the program's name on the command line. Quotes group words: \"two words\".",
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut row.stdin)
                            .id_salt(("rw_in_stdin", i))
                            .hint_text("text the program reads")
                            .desired_width(170.0),
                    )
                    .on_hover_text(
                        "Text written to the program's standard input, what it would read if you typed. Leave empty for none.",
                    );
                    if ui
                        .small_button("Remove")
                        .on_hover_text("Delete this test case.")
                        .clicked()
                    {
                        remove = Some(i);
                    }
                    ui.end_row();
                }
            });
        let full = vm.rewrite.program.inputs.len() >= kraken_registry::commands::MAX_USER_CASES;
        if ui
            .add_enabled(!full, egui::Button::new("Add a test case"))
            .on_hover_text(
                "Add a row: a name, the arguments to start the program with, and the text it should read.",
            )
            .on_disabled_hover_text("The most test cases a run takes is reached.")
            .clicked()
        {
            add = true;
        }
    });
    if let Some(i) = remove {
        vm.rewrite.program.inputs.remove(i);
    }
    if add {
        vm.rewrite.program.inputs.push(ProgramInput::default());
    }
    if let Some(why) = vm.rewrite_program_inputs_problem() {
        ui.label(RichText::new(why).size(12.0).color(s.danger));
    }
}

fn apply(vm: &mut ViewModel, acts: ProgramActs, front: &mut Option<Tab>) {
    if let Some(n) = acts.rounds {
        vm.rewrite_program_set_rounds(n);
    }
    if acts.run {
        vm.rewrite_program_run();
    }
    if acts.refresh {
        let run = vm.rewrite.program.detail.as_ref().map(|d| d.run);
        vm.rewrite_program_refresh(run);
    }
    if let Some(r) = acts.show_run {
        vm.rewrite_program_show_run(r);
    }
    if let Some(all) = acts.all_cases {
        vm.rewrite_program_set_all_cases(all);
    }
    if let Some(c) = acts.case {
        vm.rewrite_program_select_case(c);
    }
    if let Some(f) = acts.function {
        vm.rewrite_program_select_function(f);
    }
    if let Some(a) = acts.goto {
        vm.navigate_to(a);
        *front = Some(Tab::Decompiler);
    }
}

fn toolbar(ui: &mut Ui, vm: &ViewModel, acts: &mut ProgramActs) {
    let p = pal(ui);
    let r = &vm.rewrite;
    let running = vm.rewrite_program_running();
    ui.horizontal_wrapped(|ui| {
        let can = r.can_run() && !running;
        ui.add_enabled_ui(can, |ui| {
            if primary_button(ui, "Rewrite the whole program")
                .on_hover_text(
                    "Translate every function the program uses, write them as a standalone Rust crate, build it, and run the original program and the Rust one on the same inputs. KRAKEN asks first: the original program is run (inside a sandbox with no network). The decompiled code is sent to your configured AI provider.",
                )
                .clicked()
            {
                acts.run = true;
            }
        });
        ui.label(RichText::new("Repair rounds").size(12.0).color(p.text_dim))
            .on_hover_text(
                "When the program differs from the original, KRAKEN finds the functions most likely responsible from the first differing case, has them translated again with that case as evidence, and compares again. 0 turns it off.",
            );
        let mut rounds = r.program.repair_rounds;
        if ui
            .add_enabled(
                !running,
                egui::DragValue::new(&mut rounds).range(0..=MAX_REPAIR_ROUNDS),
            )
            .on_hover_text("How many times KRAKEN may repair the program. Drag or type. 0 turns it off")
            .on_disabled_hover_text("Wait for the run to finish")
            .changed()
        {
            acts.rounds = Some(rounds);
        }
        if running {
            ui.spinner();
        }
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            if ui
                .add_enabled(!r.program.loading, egui::Button::new("Refresh"))
                .on_hover_text("Read the stored runs again.")
                .on_disabled_hover_text("Already reading")
                .clicked()
            {
                acts.refresh = true;
            }
            if r.program.runs.len() > 1 || r.program.detail.is_some() {
                let shown = r.program.detail.as_ref().map(|d| d.run);
                let runs = egui::ComboBox::from_id_salt("kraken_program_run")
                    .selected_text(
                        shown.map_or("No run".to_string(), |n| format!("Run {n}")),
                    )
                    .show_ui(ui, |ui| {
                        for run in &r.program.runs {
                            let label = format!("Run {} - {}", run.run, run.verdict);
                            if ui
                                .selectable_label(shown == Some(run.run), label)
                                .on_hover_text("Show this run")
                                .clicked()
                            {
                                acts.show_run = Some(run.run);
                            }
                        }
                    });
                runs.response
                    .on_hover_text("Earlier runs of the whole-program rewrite");
            }
        });
    });
    if let Some(note) = r.blocked_note() {
        ui.label(RichText::new(note).size(12.0).color(p.text_dim));
    }
}

fn empty(ui: &mut Ui, vm: &ViewModel) {
    if vm.rewrite.program.loading || !vm.rewrite.program.loaded {
        ui.horizontal(|ui| {
            ui.spinner();
            ui.label("Reading the stored runs...");
        });
        return;
    }
    empty_state(
        ui,
        "No whole-program rewrite yet",
        "A whole-program rewrite translates every function the program uses, builds them into one Rust crate, and runs the original and the Rust program side by side on the same inputs. The result is a table of functions and a list of the cases with what each program printed.",
        Some("Use \"Rewrite the whole program\" above. It asks before it runs the original."),
    );
}

fn run_view(
    ui: &mut Ui,
    vm: &ViewModel,
    st: &mut ProgramUi,
    d: &ProgramRunDetail,
    acts: &mut ProgramActs,
) {
    egui::ScrollArea::vertical()
        .id_salt("kraken_program_scroll")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            summary(ui, d, acts);
            ui.add_space(6.0);
            function_table(ui, vm, d, acts);
            ui.add_space(8.0);
            if !d.repairs.is_empty() {
                repairs(ui, st, d);
                ui.add_space(8.0);
            }
            cases(ui, vm, d, acts);
        });
}

fn summary(ui: &mut Ui, d: &ProgramRunDetail, acts: &mut ProgramActs) {
    let p = pal(ui);
    let dark = style::dark(ui);
    ui.horizontal_wrapped(|ui| {
        ui.label(medium(format!("Run {}", d.run), 14.0).color(p.text_strong));
        chip(
            ui,
            &d.verdict.verdict,
            verdict_color(&d.verdict.verdict, dark, &p),
        )
        .on_hover_text(
            "The program-level verdict. Only this one says the program as a whole behaves like the original on the inputs tried; a function passing its own test says less.",
        );
        ui.label(RichText::new(verdict_line(&d.verdict)).size(12.5));
    });
    ui.horizontal_wrapped(|ui| {
        ui.label(
            RichText::new(format!(
                "Entry point {} at {:#x}. {} functions planned, {} in the crate",
                d.entry_name, d.entry, d.functions_planned, d.included
            ))
            .size(12.0)
            .color(p.text_dim),
        );
        if ui
            .link(RichText::new("show").size(12.0).color(p.address))
            .on_hover_text("Show the entry point in the Decompiler")
            .clicked()
        {
            acts.goto = Some(d.entry);
        }
        let mut notes: Vec<String> = Vec::new();
        if d.skipped > 0 {
            notes.push(format!("{} not reached", d.skipped));
        }
        if d.failed > 0 {
            notes.push(format!("{} without a translation", d.failed));
        }
        if d.reused_from_store > 0 {
            notes.push(format!("{} accepted earlier", d.reused_from_store));
        }
        let speed = d.speed_note();
        if !speed.is_empty() {
            notes.push(speed);
        }
        let unverified = d.unverified();
        if unverified > 0 {
            notes.push(format!(
                "{unverified} never compared with the original on their own"
            ));
        }
        if !notes.is_empty() {
            ui.label(
                RichText::new(format!("({})", notes.join(", ")))
                    .size(12.0)
                    .color(p.text_dim),
            );
        }
    });
    crate_row(ui, d);
    if !d.provider.is_empty() {
        ui.label(
            RichText::new(format!(
                "Translated by {} {}. Sandbox: {}.",
                d.provider,
                d.model,
                if d.verdict.sandbox.is_empty() {
                    "none (nothing was run)"
                } else {
                    &d.verdict.sandbox
                }
            ))
            .size(11.5)
            .color(p.text_dim),
        );
    }
}

fn crate_row(ui: &mut Ui, d: &ProgramRunDetail) {
    let p = pal(ui);
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("Crate").size(12.0).color(p.text_dim));
        if d.crate_dir.is_empty() {
            ui.label(RichText::new("none was written").size(12.0).color(p.text_dim));
            return;
        }
        ui.label(RichText::new(&d.crate_dir).monospace().size(12.0).color(p.text_strong));
        super::browse::open_buttons(ui, &d.crate_dir);
        if d.built {
            chip(ui, "built", style::status(style::dark(ui)).success)
                .on_hover_text("The crate was built in the sandbox with cargo.");
        } else {
            chip(ui, "not built", p.text_dim)
                .on_hover_text("The crate was not built (a function has no translation, or the build was off or failed).");
        }
    });
}

fn function_table(ui: &mut Ui, vm: &ViewModel, d: &ProgramRunDetail, acts: &mut ProgramActs) {
    let p = pal(ui);
    let dark = style::dark(ui);
    ui.label(medium("Functions", 13.0).color(p.text_strong));
    egui::Grid::new("kraken_program_functions")
        .num_columns(7)
        .spacing([10.0, 3.0])
        .striped(true)
        .show(ui, |ui| {
            for h in [
                "#",
                "Function",
                "Status",
                "Checked",
                "Function test",
                "Tries",
                "In crate",
            ] {
                ui.label(RichText::new(h).size(11.5).color(p.text_dim));
            }
            ui.end_row();
            for f in &d.functions {
                function_row(ui, vm, f, &p, dark, acts);
            }
        });
    if let Some(f) = vm.rewrite.program.function() {
        function_note(ui, f, &p);
    }
}

fn function_row(
    ui: &mut Ui,
    vm: &ViewModel,
    f: &ProgramFunctionItem,
    p: &Palette,
    dark: bool,
    acts: &mut ProgramActs,
) {
    let selected = vm.rewrite.program.selected_function == Some(f.address);
    ui.label(
        RichText::new(format!("{}", f.order + 1))
            .monospace()
            .size(11.5)
            .color(p.text_dim),
    );
    let name = ui.add(
        egui::Label::new(
            RichText::new(&f.name)
                .monospace()
                .size(12.5)
                .color(if selected { p.text_strong } else { p.text }),
        )
        .sense(Sense::click()),
    );
    if name
        .on_hover_text("Click for the details of this function; it is also in the Decompiler.")
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
    {
        acts.function = Some(if selected { None } else { Some(f.address) });
    }
    let status = if f.status == UnitStatus::Planned && f.check == "skipped" {
        None
    } else {
        Some(f.status)
    };
    match status {
        Some(s) => {
            chip(ui, s.as_str(), status_color(s, dark, p)).on_hover_text(status_explain(s));
        }
        None => {
            ui.label(RichText::new("-").color(p.text_dim));
        }
    }
    ui.label(RichText::new(f.check_label()).size(12.0));
    if f.verdict == "none" {
        ui.label(RichText::new("-").color(p.text_dim));
    } else {
        chip(ui, &f.verdict, verdict_color(&f.verdict, dark, p));
    }
    ui.label(
        RichText::new(f.attempts.to_string())
            .size(12.0)
            .color(p.text_dim),
    );
    ui.label(RichText::new(if f.included { "yes" } else { "no" }).size(12.0));
    ui.end_row();
}

fn function_note(ui: &mut Ui, f: &ProgramFunctionItem, p: &Palette) {
    Frame::new()
        .fill(p.row_hover)
        .corner_radius(6)
        .inner_margin(Margin::symmetric(8, 5))
        .show(ui, |ui| {
            ui.label(medium(&f.name, 12.5).color(p.text_strong));
            ui.label(
                RichText::new(format!("{:#x}. {}.", f.address, f.check_label()))
                    .size(12.0)
                    .color(p.text_dim),
            );
            if let Some(n) = &f.check_note {
                ui.label(RichText::new(n).size(12.0));
            }
            if !f.reused.is_empty() {
                ui.label(
                    RichText::new(format!(
                        "Calls the translations of {}.",
                        f.reused.join(", ")
                    ))
                    .size(12.0),
                );
            }
        });
}

fn repairs(ui: &mut Ui, st: &mut ProgramUi, d: &ProgramRunDetail) {
    let p = pal(ui);
    let replaced = d.repairs.iter().filter(|r| r.outcome == "replaced").count();
    let open = st.repairs_open;
    let head = format!(
        "{} {} repair {}: {} function{} translated again",
        if open { "v" } else { ">" },
        d.repairs.iter().map(|r| r.round).max().unwrap_or(0),
        if d.repairs.iter().map(|r| r.round).max().unwrap_or(0) == 1 {
            "round"
        } else {
            "rounds"
        },
        replaced,
        if replaced == 1 { "" } else { "s" },
    );
    if ui
        .add(egui::Label::new(medium(head, 13.0).color(p.text_strong)).sense(Sense::click()))
        .on_hover_text(
            "How the program verdict was fed back to the translations. Click to show or hide.",
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand)
        .clicked()
    {
        st.repairs_open = !st.repairs_open;
    }
    if st.repairs_open {
        for r in &d.repairs {
            repair_card(ui, r, &p);
        }
    }
}

fn repair_card(ui: &mut Ui, r: &ProgramRepairItem, p: &Palette) {
    let dark = style::dark(ui);
    Frame::new()
        .fill(p.row_hover)
        .corner_radius(6)
        .inner_margin(Margin::symmetric(8, 5))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!("Round {}", r.round))
                        .size(12.0)
                        .color(p.text_dim),
                );
                ui.label(medium(&r.name, 12.5).color(p.text_strong));
                let c = style::status(dark);
                chip(
                    ui,
                    &r.outcome,
                    match r.outcome.as_str() {
                        "replaced" => c.success,
                        "kept" => c.warning,
                        _ => p.text_dim,
                    },
                )
                .on_hover_text(r.outcome_text());
                ui.label(
                    RichText::new(format!("v{} to v{}", r.versions.0, r.versions.1))
                        .size(11.5)
                        .color(p.text_dim),
                );
                if !r.verdict_after.is_empty() {
                    chip(
                        ui,
                        &format!("then {}", r.verdict_after),
                        verdict_color(&r.verdict_after, dark, p),
                    )
                    .on_hover_text("The program verdict after this round.");
                }
            });
            ui.label(RichText::new(format!("Case `{}`. {}", r.case, r.why)).size(12.0));
            if !r.at.is_empty() {
                let stack = if r.stack.is_empty() {
                    "no call stack was available".to_string()
                } else {
                    r.stack.join(" <- ")
                };
                ui.label(
                    RichText::new(format!("The Rust program was {}, inside {stack}.", r.at))
                        .size(12.0)
                        .color(p.text_dim),
                );
            }
        });
    ui.add_space(3.0);
}

fn cases(ui: &mut Ui, vm: &ViewModel, d: &ProgramRunDetail, acts: &mut ProgramActs) {
    let p = pal(ui);
    let dark = style::dark(ui);
    let all = vm.rewrite.program.all_cases;
    ui.horizontal_wrapped(|ui| {
        ui.label(medium("Cases", 13.0).color(p.text_strong));
        ui.label(
            RichText::new(format!(
                "{} run, {} agreed, {} differed",
                d.verdict.cases_run, d.verdict.passed, d.verdict.failed
            ))
            .size(12.0)
            .color(p.text_dim),
        );
        if chip_button(
            ui,
            if all { "all cases" } else { "differing only" },
            p.text_dim,
            all,
        )
        .on_hover_text("Click to list the cases that agreed too, or only the ones that differed.")
        .clicked()
        {
            acts.all_cases = Some(!all);
        }
    });
    if d.verdict.cases.is_empty() {
        let text = if d.verdict.failed == 0 && d.verdict.cases_run > 0 {
            "No case differed. Show all cases to see what the programs printed."
        } else {
            "No case ran."
        };
        ui.label(RichText::new(text).size(12.0).color(p.text_dim));
        if let Some(detail) = &d.verdict.detail {
            ui.label(RichText::new(detail).size(12.0));
        }
        return;
    }
    ui.horizontal_top(|ui| {
        ui.vertical(|ui| {
            ui.set_width(210.0);
            for (i, c) in d.verdict.cases.iter().enumerate() {
                case_row(ui, vm, i, c, &p, dark, acts);
            }
        });
        ui.separator();
        ui.vertical(|ui| {
            if let Some(c) = vm.rewrite.program.case() {
                case_detail(ui, c, &p, dark);
            }
        });
    });
}

fn case_row(
    ui: &mut Ui,
    vm: &ViewModel,
    i: usize,
    c: &ProgramCaseItem,
    p: &Palette,
    dark: bool,
    acts: &mut ProgramActs,
) {
    let selected = vm.rewrite.program.selected_case == Some(i);
    let (rect, resp) = ui.allocate_exact_size(vec2(ui.available_width(), 24.0), Sense::click());
    if selected || resp.hovered() {
        ui.painter()
            .rect_filled(rect, 4.0, if selected { p.selection } else { p.row_hover });
    }
    let mut inner = ui.new_child(
        egui::UiBuilder::new()
            .max_rect(rect.shrink2(vec2(6.0, 0.0)))
            .layout(egui::Layout::left_to_right(egui::Align::Center)),
    );
    let s = style::status(dark);
    chip(
        &mut inner,
        if c.agree { "same" } else { "differs" },
        if c.agree { s.success } else { s.danger },
    );
    inner.label(
        RichText::new(&c.name)
            .monospace()
            .size(12.0)
            .color(if selected { p.text_strong } else { p.text }),
    );
    inner.label(RichText::new(&c.origin).size(11.0).color(p.text_dim));
    if resp.clicked() {
        acts.case = Some(i);
    }
}

fn case_detail(ui: &mut Ui, c: &ProgramCaseItem, p: &Palette, dark: bool) {
    ui.label(medium(&c.name, 13.0).color(p.text_strong));
    ui.label(
        RichText::new(c.command_line())
            .monospace()
            .size(12.0)
            .color(p.text_dim),
    );
    for d in &c.differences {
        ui.label(RichText::new(d).size(11.5).color(p.text_dim));
    }
    ui.add_space(4.0);
    let s = style::status(dark);
    // Exit status.
    ui.horizontal(|ui| {
        ui.label(medium("Exit status", 12.5).color(p.text_strong));
        if c.exit_agrees() {
            chip(ui, "same", s.success);
            ui.label(RichText::new(&c.original.exit).monospace().size(12.0));
        } else {
            chip(ui, "differs", s.danger);
            ui.label(
                RichText::new(format!(
                    "original {}, rewritten {}",
                    c.original.exit, c.rewritten.exit
                ))
                .monospace()
                .size(12.0),
            );
        }
    });
    stream(
        ui,
        "Standard output",
        "stdout",
        c.stdout_diff(),
        (c.original.stdout_bytes, c.rewritten.stdout_bytes),
        p,
        dark,
    );
    stream(
        ui,
        "Standard error",
        "stderr",
        c.stderr_diff(),
        (c.original.stderr_bytes, c.rewritten.stderr_bytes),
        p,
        dark,
    );
}

fn stream(
    ui: &mut Ui,
    title: &str,
    id: &str,
    diff: Vec<DiffLine>,
    bytes: (u64, u64),
    p: &Palette,
    dark: bool,
) {
    let s = style::status(dark);
    let same = diff.iter().all(|l| l.kind == DiffKind::Same);
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        ui.label(medium(title, 12.5).color(p.text_strong));
        if same {
            chip(ui, "same", s.success);
        } else {
            chip(ui, "differs", s.danger);
        }
        ui.label(
            RichText::new(if bytes.0 == bytes.1 {
                format!("{} bytes", bytes.0)
            } else {
                format!(
                    "{} bytes in the original, {} in the rewrite",
                    bytes.0, bytes.1
                )
            })
            .size(11.5)
            .color(p.text_dim),
        );
    });
    if diff.is_empty() {
        ui.label(RichText::new("(nothing)").size(12.0).color(p.text_dim));
        return;
    }
    Frame::new()
        .fill(p.row_hover)
        .corner_radius(6)
        .inner_margin(Margin::symmetric(8, 5))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::ScrollArea::vertical()
                .id_salt(("kraken_program_stream", id))
                .max_height(220.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    for l in &diff {
                        let (mark, color) = match l.kind {
                            DiffKind::Same => ("  ", p.text),
                            DiffKind::Original => ("- ", s.danger),
                            DiffKind::Rewritten => ("+ ", s.success),
                        };
                        let shown = if l.text.is_empty() { " " } else { &l.text };
                        ui.label(
                            RichText::new(format!("{mark}{shown}"))
                                .monospace()
                                .size(12.0)
                                .color(color),
                        )
                        .on_hover_text(match l.kind {
                            DiffKind::Same => "On both sides",
                            DiffKind::Original => "Only the original printed this line",
                            DiffKind::Rewritten => "Only the rewritten program printed this line",
                        });
                    }
                });
        });
    if !same {
        ui.label(
            RichText::new("- only the original, + only the rewritten program")
                .size(11.0)
                .color(p.text_dim),
        );
    }
}
