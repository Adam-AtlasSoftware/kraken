//! The Emulation tab (what a run or a comparison found) and the Run dialog that sets one up.

use std::sync::Mutex;

use egui::{Align2, Frame, Id, Margin, RichText, Ui, vec2};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::navtools::{
    CallDetail, EmulateMode, EmulationResult, InputRow, ParamKind, RETURN_KINDS, RunDetail,
    SideRow, side_by_side,
};
use kraken_viewmodel::rewrite::DiffLine;

use super::strings::one_line;
use crate::style::{self, chip, empty_state, medium, pal};

/// Files chosen in the file picker, waiting to become input rows.
static PICKED: Mutex<Vec<String>> = Mutex::new(Vec::new());

pub fn show(ui: &mut Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    ui.horizontal_wrapped(|ui| {
        ui.label(medium("Emulation", 14.0).color(p.text_strong));
        if vm.tools.emulation.running {
            ui.spinner();
            ui.label(
                RichText::new(&vm.tools.emulation.doing)
                    .size(12.0)
                    .color(p.text_dim),
            );
        }
    });
    ui.horizontal_wrapped(|ui| {
        let busy = vm.tools.emulation.running;
        for (mode, label, tip) in [
            (
                EmulateMode::Run,
                "Run program...",
                "Run the program in the sandboxed emulator with arguments, input and files you choose",
            ),
            (
                EmulateMode::RunPatched,
                "Run patched...",
                "Run a copy with your byte patches applied",
            ),
            (
                EmulateMode::Compare,
                "Compare original vs patched...",
                "Run both with the same input and see what the patches changed",
            ),
        ] {
            if ui
                .add_enabled(!busy, egui::Button::new(label))
                .on_hover_text(tip)
                .on_disabled_hover_text("A run is in progress")
                .clicked()
            {
                vm.begin_emulate(mode);
            }
        }
    });
    if let Some(e) = &vm.tools.emulation.error {
        ui.label(RichText::new(e).color(s.danger));
    }
    ui.separator();
    let Some(result) = vm.tools.emulation.result.clone() else {
        if !vm.tools.emulation.running {
            empty_state(
                ui,
                "Nothing has been run yet",
                "The program runs in a sandboxed emulator: no network, only its own private files, \
                 and nothing in your project changes.",
                Some(
                    "Press Run program..., or Compare original vs patched... after staging a patch.",
                ),
            );
        }
        return;
    };
    egui::ScrollArea::vertical()
        .id_salt("kraken_emulation")
        .auto_shrink([false, false])
        .show(ui, |ui| match &result {
            EmulationResult::Call(c) => call_section(ui, c),
            EmulationResult::Run {
                patched,
                given,
                run,
            } => {
                let title = if *patched {
                    "The patched program"
                } else {
                    "The program"
                };
                ui.label(
                    RichText::new(format!("{title} ran with {given}."))
                        .size(12.5)
                        .color(p.text),
                );
                ui.add_space(4.0);
                run_section(ui, "run", title, run);
            }
            EmulationResult::Compare {
                given,
                a,
                b,
                same,
                differences,
                first_divergence,
            } => {
                let (text, color) = if *same {
                    (
                        "Both runs behaved the same: exit, output and files all agree.",
                        s.warning,
                    )
                } else {
                    ("The patched program behaved differently.", s.success)
                };
                ui.label(RichText::new(text).size(13.0).strong().color(color));
                ui.label(
                    RichText::new(format!("Both ran with {given}."))
                        .size(12.0)
                        .color(p.text_dim),
                );
                if !first_divergence.is_empty() {
                    ui.label(
                        RichText::new(format!(
                            "First difference: {}",
                            one_line(first_divergence, 200)
                        ))
                        .monospace()
                        .size(12.0)
                        .color(p.text),
                    )
                    .on_hover_text("Where the two runs first stop agreeing");
                }
                for d in differences {
                    ui.horizontal_wrapped(|ui| {
                        chip(ui, &d.field, s.danger);
                        ui.label(
                            RichText::new(one_line(&d.summary, 160))
                                .monospace()
                                .size(11.5)
                                .color(p.text),
                        );
                    });
                }
                ui.add_space(6.0);
                compare_columns(ui, a, b);
            }
        });
}

fn exit_chip(ui: &mut Ui, r: &RunDetail) {
    let s = style::status(style::dark(ui));
    chip(ui, &r.exit, if r.clean { s.success } else { s.warning })
        .on_hover_text("How the program ended");
    ui.label(
        RichText::new(format!("{} instructions", r.steps))
            .size(11.5)
            .color(pal(ui).text_dim),
    );
}

fn run_section(ui: &mut Ui, id: &str, title: &str, r: &RunDetail) {
    let p = pal(ui);
    ui.horizontal_wrapped(|ui| {
        ui.label(medium(title, 12.5).color(p.text_strong));
        exit_chip(ui, r);
    });
    stream(ui, ("out", id), "Standard output", &r.stdout);
    if !r.stderr.is_empty() {
        stream(ui, ("err", id), "Standard error", &r.stderr);
    }
    files_and_notes(ui, id, r);
}

fn stream(ui: &mut Ui, id: (&str, &str), title: &str, text: &str) {
    let p = pal(ui);
    ui.label(RichText::new(title).size(11.0).color(p.text_dim));
    Frame::new()
        .fill(p.row_hover)
        .corner_radius(6)
        .inner_margin(Margin::symmetric(8, 5))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::ScrollArea::vertical()
                .id_salt(("kraken_emulation_stream", id))
                .max_height(200.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    if text.is_empty() {
                        ui.label(RichText::new("(nothing)").size(12.0).color(p.text_dim));
                    } else {
                        ui.label(RichText::new(text).monospace().size(12.0).color(p.text))
                            .on_hover_text("Program data, shown as text");
                    }
                });
        });
}

fn files_and_notes(ui: &mut Ui, id: &str, r: &RunDetail) {
    let p = pal(ui);
    if !r.files.is_empty() {
        ui.label(
            RichText::new(format!(
                "Files written: {}",
                r.files
                    .iter()
                    .map(|f| format!("{} ({} bytes)", f.name, f.size))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .size(11.5)
            .color(p.text_dim),
        );
        for f in &r.files {
            egui::CollapsingHeader::new(RichText::new(&f.name).monospace().size(12.0))
                .id_salt(("kraken_emulation_file", id, &f.name))
                .show(ui, |ui| {
                    let hint = if f.binary {
                        "hex of the first bytes"
                    } else {
                        "text"
                    };
                    ui.label(
                        RichText::new(&f.preview)
                            .monospace()
                            .size(11.5)
                            .color(p.text),
                    )
                    .on_hover_text(format!("Program data, shown as {hint}"));
                });
        }
    }
    for n in &r.notes {
        ui.label(RichText::new(n).size(11.0).color(p.text_dim));
    }
}

fn compare_columns(ui: &mut Ui, a: &RunDetail, b: &RunDetail) {
    let p = pal(ui);
    ui.columns(2, |cols| {
        for (col, title, r) in [(0, "Original", a), (1, "Patched", b)] {
            cols[col].horizontal_wrapped(|ui| {
                ui.label(medium(title, 12.5).color(p.text_strong));
                exit_chip(ui, r);
            });
        }
    });
    let (out, err) = a.diffs(b);
    side_stream(ui, "out", "Standard output", &out);
    if !err.iter().all(|l| l.text.is_empty()) {
        side_stream(ui, "err", "Standard error", &err);
    }
    ui.columns(2, |cols| {
        files_and_notes(&mut cols[0], "a", a);
        files_and_notes(&mut cols[1], "b", b);
    });
}

fn side_stream(ui: &mut Ui, id: &str, title: &str, diff: &[DiffLine]) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    let rows: Vec<SideRow> = side_by_side(diff);
    let same = rows.iter().all(|r| !r.changed);
    ui.horizontal(|ui| {
        ui.label(medium(title, 12.0).color(p.text_strong));
        if same {
            chip(ui, "same", s.success);
        } else {
            chip(ui, "differs", s.danger);
        }
    });
    Frame::new()
        .fill(p.row_hover)
        .corner_radius(6)
        .inner_margin(Margin::symmetric(8, 5))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            egui::ScrollArea::vertical()
                .id_salt(("kraken_emulation_side", id))
                .max_height(260.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    egui::Grid::new(("kraken_emulation_side_grid", id))
                        .num_columns(2)
                        .min_col_width((ui.available_width() - 16.0) / 2.0)
                        .spacing([16.0, 1.0])
                        .show(ui, |ui| {
                            for r in &rows {
                                for (side, color) in [(&r.left, s.danger), (&r.right, s.success)] {
                                    let color = if r.changed { color } else { p.text };
                                    let text = side.as_deref().unwrap_or("");
                                    let text = if text.is_empty() { " " } else { text };
                                    ui.label(
                                        RichText::new(text).monospace().size(12.0).color(color),
                                    );
                                }
                                ui.end_row();
                            }
                        });
                });
        });
}

/// The Run dialog.
pub fn dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    for path in std::mem::take(&mut *PICKED.lock().unwrap_or_else(|e| e.into_inner())) {
        if let Some(d) = vm.tools.emulate_dialog.as_mut() {
            match InputRow::from_disk(std::path::Path::new(&path)) {
                Ok(row) => d.inputs.push(row),
                Err(e) => d.error = Some(e),
            }
        }
    }
    let Some(mut d) = vm.tools.emulate_dialog.clone() else {
        return;
    };
    let dark = ctx.global_style().visuals.dark_mode;
    let p = kraken_gui_widgets::KrakenTheme { dark }.palette();
    let s = style::status(dark);
    let (enter, esc) = ctx.input_mut(|i| {
        (
            i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter),
            i.consume_key(egui::Modifiers::NONE, egui::Key::Escape),
        )
    });
    let (mut go, mut cancel, mut pick) = (false, false, false);
    let mut remove = None;
    let patches = vm.tools.patches.items.len();
    egui::Window::new(medium(d.mode.title(), 15.0))
        .id(Id::new("kraken_emulate_dialog"))
        .collapsible(false)
        .resizable(false)
        .order(egui::Order::Foreground)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, -40.0))
        .fixed_size(vec2(560.0, 0.0))
        .show(ctx, |ui| {
            let intro = match d.mode {
                EmulateMode::Run => {
                    "Runs the program in the sandboxed emulator. It never runs on this computer: \
                     no network, fixed time, files only in its own private /work."
                }
                EmulateMode::RunPatched => {
                    "Runs a copy with your staged byte patches applied. The file on disk is not \
                     changed."
                }
                EmulateMode::Compare => {
                    "Runs the original and a patched copy with exactly the same input, then shows \
                     what differs."
                }
            };
            ui.label(RichText::new(intro).color(p.text_dim));
            if d.mode != EmulateMode::Run && patches == 0 {
                ui.label(
                    RichText::new(
                        "The project has no byte patches yet; stage one in the Patches tab first.",
                    )
                    .size(12.0)
                    .color(s.warning),
                );
            }
            egui::Grid::new("kraken_emulate_grid")
                .num_columns(2)
                .spacing([10.0, 6.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Arguments").size(12.0).color(p.text_dim));
                    ui.add(
                        egui::TextEdit::singleline(&mut d.argv)
                            .id(Id::new("kraken_emulate_argv"))
                            .hint_text("-v \"two words\"")
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    )
                    .on_hover_text(
                        "Command-line arguments after the program name; quotes group words",
                    );
                    ui.end_row();
                    ui.label(RichText::new("Program name").size(12.0).color(p.text_dim));
                    ui.add(
                        egui::TextEdit::singleline(&mut d.argv0)
                            .hint_text("prog")
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    )
                    .on_hover_text("What the program sees as argv[0]");
                    ui.end_row();
                    ui.label(RichText::new("Standard input").size(12.0).color(p.text_dim));
                    ui.add(
                        egui::TextEdit::multiline(&mut d.stdin)
                            .id(Id::new("kraken_emulate_stdin"))
                            .desired_rows(3)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    )
                    .on_hover_text("Text the program reads from standard input");
                    ui.end_row();
                    ui.label(RichText::new("Environment").size(12.0).color(p.text_dim));
                    ui.add(
                        egui::TextEdit::multiline(&mut d.env)
                            .id(Id::new("kraken_emulate_env"))
                            .desired_rows(2)
                            .hint_text("NAME=value, one per line")
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    )
                    .on_hover_text("Nothing of this computer's environment is passed on");
                    ui.end_row();
                    ui.label(RichText::new("Limits").size(12.0).color(p.text_dim));
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut d.max_steps)
                                .id(Id::new("kraken_emulate_steps"))
                                .hint_text("20000000")
                                .desired_width(110.0),
                        )
                        .on_hover_text("Most instructions to run (up to 200000000)");
                        ui.label(RichText::new("steps").size(12.0).color(p.text_dim));
                        ui.add(
                            egui::TextEdit::singleline(&mut d.timeout)
                                .id(Id::new("kraken_emulate_timeout"))
                                .hint_text("20")
                                .desired_width(50.0),
                        )
                        .on_hover_text("Most seconds to run (up to 120)");
                        ui.label(RichText::new("seconds").size(12.0).color(p.text_dim));
                    });
                    ui.end_row();
                });
            ui.add_space(2.0);
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new("Input files in /work")
                        .size(12.0)
                        .color(p.text_dim),
                );
                if ui
                    .small_button("Add file...")
                    .on_hover_text(
                        "Copy a file from this computer into the program's /work (up to 1 MiB)",
                    )
                    .clicked()
                {
                    pick = true;
                }
                if ui
                    .small_button("Add empty")
                    .on_hover_text("Type a file's name and contents here")
                    .clicked()
                {
                    d.inputs.push(InputRow {
                        name: "input.txt".into(),
                        ..InputRow::default()
                    });
                }
            });
            for (i, row) in d.inputs.iter_mut().enumerate() {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut row.name)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(140.0),
                    )
                    .on_hover_text("The file's path inside /work, for example in.txt");
                    match &row.binary {
                        Some(b) => {
                            ui.label(
                                RichText::new(format!("{} bytes of binary data", b.len()))
                                    .size(12.0)
                                    .color(p.text_dim),
                            );
                        }
                        None => {
                            ui.add(
                                egui::TextEdit::singleline(&mut row.text)
                                    .font(egui::TextStyle::Monospace)
                                    .hint_text("contents")
                                    .desired_width(260.0),
                            )
                            .on_hover_text("What the file contains (text)");
                        }
                    }
                    if ui
                        .small_button("Remove")
                        .on_hover_text("Do not put this file in /work")
                        .clicked()
                    {
                        remove = Some(i);
                    }
                });
            }
            if let Some(e) = &d.error {
                ui.label(RichText::new(e).color(s.danger));
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                let r = ui
                    .add_enabled(
                        !d.running,
                        egui::Button::new(RichText::new(d.mode.button()).strong()),
                    )
                    .on_hover_text("Start the run (Ctrl+Enter)")
                    .on_disabled_hover_text("Running...");
                if r.clicked() {
                    go = true;
                }
                if ui
                    .add_enabled(!d.running, egui::Button::new("Cancel"))
                    .on_hover_text("Close without running (Esc)")
                    .on_disabled_hover_text("The run has started; wait for it to finish")
                    .clicked()
                {
                    cancel = true;
                }
                if d.running {
                    ui.spinner();
                    ui.label(
                        RichText::new("Running in the emulator...")
                            .size(12.0)
                            .color(p.text_dim),
                    );
                }
            });
        });
    if let Some(i) = remove {
        d.inputs.remove(i);
    }
    if pick {
        let ctx2 = ctx.clone();
        vm.runtime_handle().spawn(async move {
            let dialog = rfd::AsyncFileDialog::new().set_title("Choose a file to put in /work");
            if let Some(h) = dialog.pick_file().await {
                PICKED
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .push(h.path().to_string_lossy().into_owned());
                ctx2.request_repaint();
            }
        });
    }
    if let Some(live) = vm.tools.emulate_dialog.as_mut() {
        let (running, error) = (live.running, live.error.clone());
        *live = d;
        live.running = running;
        live.error = error;
    }
    if esc || cancel {
        vm.cancel_emulate();
    } else if go || enter {
        vm.submit_emulate();
    }
}

/// The "Call this function" dialog.
pub fn call_dialog(ctx: &egui::Context, vm: &mut ViewModel) {
    let Some(mut d) = vm.tools.call_dialog.clone() else {
        return;
    };
    let dark = ctx.global_style().visuals.dark_mode;
    let p = kraken_gui_widgets::KrakenTheme { dark }.palette();
    let s = style::status(dark);
    let (enter, esc) = ctx.input_mut(|i| {
        (
            i.consume_key(egui::Modifiers::COMMAND, egui::Key::Enter),
            i.consume_key(egui::Modifiers::NONE, egui::Key::Escape),
        )
    });
    let (mut go, mut cancel) = (false, false);
    egui::Window::new(medium(format!("Call {}", d.name), 15.0))
        .id(Id::new("kraken_call_dialog"))
        .collapsible(false)
        .resizable(false)
        .order(egui::Order::Foreground)
        .anchor(Align2::CENTER_CENTER, vec2(0.0, -40.0))
        .fixed_size(vec2(560.0, 0.0))
        .show(ctx, |ui| {
            ui.label(
                RichText::new(
                    "Runs only this function in the sandboxed emulator and shows what it \
                     returns and what it wrote. The rest of the program does not run.",
                )
                .color(p.text_dim),
            );
            if !d.signature.is_empty() {
                ui.label(
                    RichText::new(&d.signature)
                        .monospace()
                        .size(12.0)
                        .color(p.text),
                )
                .on_hover_text("The function's signature; the rows below are filled from it");
            }
            egui::Grid::new("kraken_call_grid")
                .num_columns(3)
                .spacing([10.0, 6.0])
                .show(ui, |ui| {
                    for (i, row) in d.params.iter_mut().enumerate() {
                        ui.label(
                            RichText::new(one_line(&row.label, 40))
                                .monospace()
                                .size(11.5)
                                .color(p.text_dim),
                        )
                        .on_hover_text(row.label.clone());
                        egui::ComboBox::from_id_salt(("kraken_call_kind", i))
                            .selected_text(row.kind.label())
                            .width(110.0)
                            .show_ui(ui, |ui| {
                                for k in ParamKind::ALL {
                                    ui.selectable_value(&mut row.kind, k, k.label())
                                        .on_hover_text(k.hint());
                                }
                            })
                            .response
                            .on_hover_text("How this argument is given");
                        ui.add(
                            egui::TextEdit::singleline(&mut row.value)
                                .id(Id::new(("kraken_call_arg", i)))
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY),
                        )
                        .on_hover_text(row.kind.hint());
                        ui.end_row();
                    }
                    if d.params.is_empty() {
                        ui.label(RichText::new("No parameters").size(12.0).color(p.text_dim));
                        ui.end_row();
                    }
                    ui.label(RichText::new("Returns").size(12.0).color(p.text_dim));
                    egui::ComboBox::from_id_salt("kraken_call_returns")
                        .selected_text(d.returns.clone())
                        .show_ui(ui, |ui| {
                            for k in RETURN_KINDS {
                                ui.selectable_value(&mut d.returns, k.to_string(), k)
                                    .on_hover_text(format!("The function returns {k}"));
                            }
                        })
                        .response
                        .on_hover_text(
                            "What the function returns: void, int (32 bits), long or ptr \
                             (pointer-sized), a narrower integer, f32 or f64",
                        );
                    ui.end_row();
                    ui.label(RichText::new("Limit").size(12.0).color(p.text_dim));
                    ui.add(
                        egui::TextEdit::singleline(&mut d.max_steps)
                            .id(Id::new("kraken_call_steps"))
                            .hint_text("10000000 steps")
                            .desired_width(130.0),
                    )
                    .on_hover_text("Most instructions to run (up to 200000000)");
                    ui.end_row();
                });
            ui.checkbox(
                &mut d.libc,
                "Start the program first (needed for libc functions)",
            )
            .on_hover_text(
                "Runs the program up to main so the C library is set up; the function can \
                 then call strlen, malloc, printf and the like",
            );
            if d.libc {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new("Stop startup at")
                            .size(12.0)
                            .color(p.text_dim),
                    );
                    ui.add(
                        egui::TextEdit::singleline(&mut d.startup)
                            .id(Id::new("kraken_call_startup"))
                            .hint_text("main (or an address, for a stripped program)")
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY),
                    )
                    .on_hover_text(
                        "Leave empty to use main; a stripped program may need main's address",
                    );
                });
            }
            if let Some(e) = &d.error {
                ui.label(RichText::new(e).color(s.danger));
            }
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        !d.running,
                        egui::Button::new(RichText::new("Call").strong()),
                    )
                    .on_hover_text("Run the function (Ctrl+Enter)")
                    .on_disabled_hover_text("Running...")
                    .clicked()
                {
                    go = true;
                }
                if ui
                    .add_enabled(!d.running, egui::Button::new("Cancel"))
                    .on_hover_text("Close without calling (Esc)")
                    .on_disabled_hover_text("The call has started; wait for it to finish")
                    .clicked()
                {
                    cancel = true;
                }
                if d.running {
                    ui.spinner();
                }
            });
        });
    if let Some(live) = vm.tools.call_dialog.as_mut() {
        let (running, error) = (live.running, live.error.clone());
        *live = d;
        live.running = running;
        live.error = error;
    }
    if esc || cancel {
        vm.cancel_call();
    } else if go || enter {
        vm.submit_call();
    }
}

fn call_section(ui: &mut Ui, c: &CallDetail) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    ui.label(
        RichText::new(format!("{} was called with {}.", c.name, c.given))
            .size(12.5)
            .color(p.text),
    );
    ui.add_space(4.0);
    ui.horizontal_wrapped(|ui| {
        chip(ui, &c.ended, if c.clean { s.success } else { s.warning })
            .on_hover_text("How the call ended");
        ui.label(
            RichText::new(format!("{} instructions", c.steps))
                .size(11.5)
                .color(p.text_dim),
        );
    });
    if let Some(v) = &c.value {
        ui.horizontal(|ui| {
            ui.label(RichText::new("Returned").size(12.0).color(p.text_dim));
            ui.label(
                RichText::new(v)
                    .monospace()
                    .size(13.0)
                    .strong()
                    .color(p.text_strong),
            )
            .on_hover_text("The value in the return register, decimal and hexadecimal");
        });
    }
    for (i, b) in c.buffers.iter().enumerate() {
        let state = if b.changed { "changed" } else { "unchanged" };
        ui.label(
            RichText::new(format!("{} ({} bytes, {state})", b.label, b.size))
                .size(11.5)
                .color(p.text_dim),
        );
        stream(ui, ("buf", &i.to_string()), "As text", &b.text);
        ui.label(
            RichText::new(&b.hex)
                .monospace()
                .size(11.0)
                .color(p.text_dim),
        )
        .on_hover_text("The first bytes as hexadecimal digits");
    }
    if !c.stdout.is_empty() {
        stream(ui, ("out", "call"), "Standard output", &c.stdout);
    }
    if !c.stderr.is_empty() {
        stream(ui, ("err", "call"), "Standard error", &c.stderr);
    }
    for n in &c.notes {
        ui.label(RichText::new(n).size(11.0).color(p.text_dim));
    }
}
