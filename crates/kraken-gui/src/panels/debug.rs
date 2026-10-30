//! The Debug tab: run the program in KRAKEN's emulator and step through it. Registers, the
//! disassembly around the program counter (the Listing follows it), a memory dump, the
//! breakpoints and what the program printed.

use egui::{RichText, Ui};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::debug::{DebugStep, MEM_ROW};

use crate::style::{self, chip, medium, pal};

pub fn show(ui: &mut Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    toolbar(ui, vm);
    if let Some(e) = vm.debug.error.clone() {
        ui.label(RichText::new(e).color(s.danger));
    }
    if !vm.debug.active() {
        start_page(ui, vm);
        return;
    }
    gdb_box(ui, vm);
    watch_box(ui, vm);
    ui.horizontal_wrapped(|ui| {
        let d = &vm.debug;
        let color = if d.finished {
            s.info
        } else if d.status.starts_with("Crashed") {
            s.danger
        } else {
            s.success
        };
        chip(ui, &d.status, color);
        ui.label(
            RichText::new(format!("{} instructions", d.instructions))
                .size(11.0)
                .color(p.text_dim),
        )
        .on_hover_text("Instructions the emulated program has executed so far");
        if d.busy {
            ui.spinner();
        }
    });
    ui.separator();
    let w = ui.available_width();
    let top_h = (ui.available_height() * 0.5).max(110.0);
    let mut view_ptr = None;
    let mut toggle = None;
    ui.allocate_ui(egui::vec2(w, top_h), |ui| {
        ui.columns(2, |cols| {
            registers(&mut cols[0], vm, &mut view_ptr);
            disassembly(&mut cols[1], vm, &mut toggle);
        });
    });
    if let Some(v) = view_ptr {
        vm.debug_view_pointer(v);
    }
    if let Some(a) = toggle {
        vm.debug_toggle_breakpoint(a);
    }
    ui.separator();
    ui.columns(2, |cols| {
        memory(&mut cols[0], vm);
        output(&mut cols[1], vm);
    });
}

fn toolbar(ui: &mut Ui, vm: &mut ViewModel) {
    let active = vm.debug.active();
    let can = vm.debug.can_step();
    let starting = vm.debug.starting;
    ui.horizontal_wrapped(|ui| {
        if !active
            && ui
                .add_enabled(!starting, egui::Button::new("Start  (F5)"))
                .on_hover_text(
                    "Run the program in the emulator, stopped before its first instruction. \
                     The program never runs on this computer",
                )
                .on_disabled_hover_text("Starting...")
                .clicked()
        {
            vm.debug_start();
        }
        if starting {
            ui.spinner();
        }
        for (label, tip, how) in [
            (
                "Step  (F11)",
                "Execute one instruction, going into calls",
                DebugStep::Into,
            ),
            (
                "Over  (F10)",
                "Execute one instruction; a call runs to its return",
                DebugStep::Over,
            ),
            (
                "Out  (Shift+F11)",
                "Run until the current function returns",
                DebugStep::Out,
            ),
            (
                "Continue  (F5)",
                "Run to the next breakpoint or the end of the program",
                DebugStep::Continue,
            ),
        ] {
            if ui
                .add_enabled(can, egui::Button::new(label))
                .on_hover_text(tip)
                .on_disabled_hover_text("Start the program first, or it has ended")
                .clicked()
            {
                vm.debug_step(how);
            }
        }
        let back = vm.debug.can_reverse();
        for (label, tip, how) in [
            (
                "Step back",
                "Go back one instruction: registers and memory return to what they were",
                DebugStep::Back,
            ),
            (
                "Reverse continue",
                "Run backwards to the previous breakpoint or watchpoint access (or the start)",
                DebugStep::ReverseContinue,
            ),
        ] {
            if ui
                .add_enabled(back, egui::Button::new(label))
                .on_hover_text(tip)
                .on_disabled_hover_text("Start the program first")
                .clicked()
            {
                vm.debug_step(how);
            }
        }
        if ui
            .add_enabled(active, egui::Button::new("Watch..."))
            .on_hover_text(
                "Stop the program when it writes or reads a range of memory; shows the \
                 watchpoints",
            )
            .on_disabled_hover_text("Start the program first")
            .clicked()
        {
            vm.debug.watch_open = !vm.debug.watch_open;
        }
        if ui
            .add_enabled(can, egui::Button::new("To main"))
            .on_hover_text("Run to the function main, where the program's own code begins")
            .on_disabled_hover_text("Start the program first, or it has ended")
            .clicked()
        {
            vm.debug_run_to_main();
        }
        if ui
            .add_enabled(active, egui::Button::new("Stop"))
            .on_hover_text("End the debugging session and discard its state")
            .on_disabled_hover_text("Nothing is running")
            .clicked()
        {
            vm.debug_stop();
        }
        if ui
            .add_enabled(active, egui::Button::new("Attach gdb..."))
            .on_hover_text(
                "Let gdb, Ghidra's debugger or IDA debug this session over the GDB remote \
                 protocol; shows the command to run",
            )
            .on_disabled_hover_text("Start the program first")
            .clicked()
        {
            vm.debug_gdb_serve();
        }
        if active {
            ui.checkbox(&mut vm.debug.follow_listing, "Follow in Listing")
                .on_hover_text("Show the instruction the program stopped at in the Listing");
        }
    });
}

fn start_page(ui: &mut Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    ui.add_space(6.0);
    ui.label(
        RichText::new(
            "Start runs the program in KRAKEN's own emulator, stopped before its first \
             instruction. Step through it, set breakpoints with F9 in the Listing (or right-click \
             an instruction), read registers and memory, and see what it prints. Nothing runs on \
             this computer and the project does not change.",
        )
        .color(p.text_dim),
    );
    ui.add_space(8.0);
    ui.label(medium("Before you start", 13.0).color(p.text_strong));
    egui::Grid::new("kraken_debug_start")
        .num_columns(2)
        .spacing([10.0, 6.0])
        .show(ui, |ui| {
            ui.label("Arguments");
            ui.add(
                egui::TextEdit::singleline(&mut vm.debug.argv)
                    .hint_text("separated by spaces")
                    .desired_width(320.0),
            )
            .on_hover_text("Command-line arguments after the program name");
            ui.end_row();
            ui.label("Input");
            ui.add(
                egui::TextEdit::singleline(&mut vm.debug.stdin)
                    .hint_text("text for standard input")
                    .desired_width(320.0),
            )
            .on_hover_text("What the program reads from standard input");
            ui.end_row();
            ui.label("");
            ui.checkbox(&mut vm.debug.patched, "Use the staged byte patches")
                .on_hover_text(
                    "Debug a copy of the program with the Patches tab's patches applied",
                );
            ui.end_row();
        });
    if !vm.debug.breakpoints.is_empty() {
        ui.label(
            RichText::new(format!(
                "{} breakpoint{} set; they are active once the program starts.",
                vm.debug.breakpoints.len(),
                if vm.debug.breakpoints.len() == 1 {
                    ""
                } else {
                    "s"
                }
            ))
            .size(12.0)
            .color(p.text_dim),
        );
    }
    for n in &vm.debug.notes {
        ui.label(RichText::new(n).size(11.0).color(p.text_dim));
    }
}

fn registers(ui: &mut Ui, vm: &ViewModel, view_ptr: &mut Option<u64>) {
    let p = pal(ui);
    ui.label(medium("Registers", 13.0).color(p.text_strong));
    egui::ScrollArea::vertical()
        .id_salt("kraken_debug_regs")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("kraken_debug_reg_grid")
                .num_columns(2)
                .spacing([10.0, 2.0])
                .show(ui, |ui| {
                    for r in &vm.debug.regs {
                        ui.label(
                            RichText::new(&r.name)
                                .monospace()
                                .size(12.0)
                                .color(p.text_dim),
                        );
                        let color = if r.changed { p.accent } else { p.text };
                        let w = if r.value > u64::from(u32::MAX) { 16 } else { 8 };
                        let text = RichText::new(format!("{:0w$x}", r.value))
                            .monospace()
                            .size(12.0)
                            .color(color);
                        let hover = if r.changed {
                            "Changed at the last stop. Click to show the memory it points at"
                        } else {
                            "Click to show the memory this value points at"
                        };
                        if ui
                            .add(egui::Button::new(text).frame(false))
                            .on_hover_text(hover)
                            .clicked()
                        {
                            *view_ptr = Some(r.value);
                        }
                        ui.end_row();
                    }
                });
        });
}

fn disassembly(ui: &mut Ui, vm: &ViewModel, toggle: &mut Option<u64>) {
    let p = pal(ui);
    let red = egui::Color32::from_rgb(222, 70, 70);
    ui.label(medium("Disassembly", 13.0).color(p.text_strong));
    egui::ScrollArea::vertical()
        .id_salt("kraken_debug_disasm")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            for i in &vm.debug.disasm {
                let on = vm.debug.has_breakpoint(i.address);
                ui.horizontal(|ui| {
                    let (rect, dot) =
                        ui.allocate_exact_size(egui::vec2(14.0, 14.0), egui::Sense::click());
                    let c = rect.center();
                    if on {
                        ui.painter().circle_filled(c, 5.0, red);
                    } else if dot.hovered() {
                        ui.painter().circle_filled(c, 5.0, red.gamma_multiply(0.35));
                    } else {
                        ui.painter()
                            .circle_stroke(c, 4.0, egui::Stroke::new(1.0, p.text_dim));
                    }
                    if dot
                        .on_hover_text(if on {
                            "Remove the breakpoint"
                        } else {
                            "Set a breakpoint here"
                        })
                        .clicked()
                    {
                        *toggle = Some(i.address);
                    }
                    let text = format!("{:08x}  {}", i.address, i.text);
                    let mut rt = RichText::new(text).monospace().size(12.0);
                    rt = if i.is_pc {
                        rt.strong().color(p.accent)
                    } else {
                        rt.color(p.text)
                    };
                    let r = ui.label(rt);
                    if i.is_pc {
                        r.on_hover_text("The program is stopped here");
                    } else {
                        r.on_hover_text(i.bytes.clone());
                    }
                });
            }
        });
}

fn memory(ui: &mut Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    ui.horizontal(|ui| {
        ui.label(medium("Memory", 13.0).color(p.text_strong));
        let r = ui
            .add(
                egui::TextEdit::singleline(&mut vm.debug.mem_input)
                    .hint_text("stack (type 0x... to look elsewhere)")
                    .desired_width(190.0)
                    .font(egui::TextStyle::Monospace),
            )
            .on_hover_text(
                "Type a hex address from the Listing to look at that memory, or leave it empty to \
             follow the stack pointer. Press Enter",
            );
        if r.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
            vm.debug_set_memory_input();
        }
    });
    egui::ScrollArea::vertical()
        .id_salt("kraken_debug_mem")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            let m = &vm.debug.memory;
            if let Some(e) = &m.error {
                ui.label(RichText::new(e).size(12.0).color(p.text_dim));
            }
            for (row, chunk) in m.bytes.chunks(MEM_ROW).enumerate() {
                let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|b| {
                        if (0x20..0x7f).contains(b) {
                            char::from(*b)
                        } else {
                            '.'
                        }
                    })
                    .collect();
                let addr = m.address.wrapping_add((row * MEM_ROW) as u64);
                ui.add(
                    egui::Label::new(
                        RichText::new(format!(
                            "{addr:08x}  {:<w$}  {ascii}",
                            hex.join(" "),
                            w = MEM_ROW * 3 - 1
                        ))
                        .monospace()
                        .size(12.0)
                        .color(p.text),
                    )
                    .extend(),
                );
            }
        });
}

fn output(ui: &mut Ui, vm: &ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    ui.label(medium("Output", 13.0).color(p.text_strong));
    egui::ScrollArea::vertical()
        .id_salt("kraken_debug_out")
        .stick_to_bottom(true)
        .auto_shrink([false, false])
        .show(ui, |ui| {
            if vm.debug.stdout.is_empty() && vm.debug.stderr.is_empty() {
                ui.label(
                    RichText::new("Nothing printed yet.")
                        .size(12.0)
                        .color(p.text_dim),
                );
            }
            if !vm.debug.stdout.is_empty() {
                ui.label(
                    RichText::new(&vm.debug.stdout)
                        .monospace()
                        .size(12.0)
                        .color(p.text),
                );
            }
            if !vm.debug.stderr.is_empty() {
                ui.label(
                    RichText::new(&vm.debug.stderr)
                        .monospace()
                        .size(12.0)
                        .color(s.danger),
                );
            }
        });
}

fn gdb_box(ui: &mut Ui, vm: &mut ViewModel) {
    let Some(g) = vm.debug.gdb.clone() else {
        return;
    };
    let p = pal(ui);
    let mut close = false;
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(medium("Attach gdb", 13.0).color(p.text_strong));
            if ui
                .small_button("Close")
                .on_hover_text("Hide this box; the gdb server keeps running until the session ends")
                .clicked()
            {
                close = true;
            }
        });
        ui.label(
            RichText::new(
                "Run one of these in a terminal. gdb sees the emulator's addresses (the \
                 Listing's plus the session's address delta for a position-independent \
                 program). Leaving gdb keeps the session where it is.",
            )
            .size(11.0)
            .color(p.text_dim),
        );
        let line = |ui: &mut Ui, what: &str, cmd: &str| {
            ui.horizontal(|ui| {
                ui.label(RichText::new(what).size(11.0).color(p.text_dim));
                ui.add(egui::Label::new(RichText::new(cmd).monospace()).selectable(true));
                if ui
                    .small_button("Copy")
                    .on_hover_text("Copy the command to the clipboard")
                    .clicked()
                {
                    ui.ctx().copy_text(cmd.to_string());
                }
            });
        };
        if let Some(t) = &g.gdb_tcp_command {
            line(ui, "TCP (127.0.0.1 only)", t);
        }
        line(ui, "Unix socket (needs socat)", &g.gdb_command);
    });
    if close {
        vm.debug.gdb = None;
    }
}

fn watch_box(ui: &mut Ui, vm: &mut ViewModel) {
    if !vm.debug.watch_open {
        return;
    }
    let p = pal(ui);
    let mut close = false;
    let mut add = false;
    let mut remove = None;
    egui::Frame::group(ui.style()).show(ui, |ui| {
        ui.horizontal(|ui| {
            ui.label(medium("Watchpoints", 13.0).color(p.text_strong));
            if ui
                .small_button("Close")
                .on_hover_text("Hide this box; the watchpoints stay set")
                .clicked()
            {
                close = true;
            }
        });
        ui.label(
            RichText::new(
                "Continue stops after the instruction that touches the range and shows the old \
                 and new bytes; Reverse continue goes back to the previous access. Runs with a \
                 watchpoint are slower.",
            )
            .size(11.0)
            .color(p.text_dim),
        );
        ui.horizontal_wrapped(|ui| {
            ui.label("Address");
            ui.add(
                egui::TextEdit::singleline(&mut vm.debug.watch_address)
                    .hint_text("0x404040")
                    .desired_width(130.0)
                    .font(egui::TextStyle::Monospace),
            )
            .on_hover_text("Hex address to watch, from the Listing (or a pointer, see below)");
            ui.label("Bytes");
            ui.add(egui::TextEdit::singleline(&mut vm.debug.watch_length).desired_width(40.0))
                .on_hover_text("How many bytes to watch (1 to 4096)");
            egui::ComboBox::from_id_salt("kraken_watch_kind")
                .selected_text(vm.debug.watch_kind.clone())
                .width(70.0)
                .show_ui(ui, |ui| {
                    for k in ["write", "read", "access"] {
                        ui.selectable_value(&mut vm.debug.watch_kind, k.to_string(), k)
                            .on_hover_text(match k {
                                "write" => "Stop when the program stores to the range",
                                "read" => "Stop when the program loads from the range",
                                _ => "Stop on any load or store",
                            });
                    }
                })
                .response
                .on_hover_text("Stop on writes, reads, or both (access)");
            ui.checkbox(&mut vm.debug.watch_emulator, "Pointer value")
                .on_hover_text(
                    "The address is a value taken from a register (a stack slot, a heap \
                     object), not a Listing address",
                );
            if ui
                .add_enabled(!vm.debug.busy, egui::Button::new("Add"))
                .on_hover_text("Set the watchpoint")
                .on_disabled_hover_text("Wait for the program to stop")
                .clicked()
            {
                add = true;
            }
        });
        for (i, w) in vm.debug.watches.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{:08x}  {} bytes  {}",
                        w.address.0, w.length, w.kind
                    ))
                    .monospace()
                    .size(12.0),
                );
                if ui
                    .small_button("Remove")
                    .on_hover_text("Delete this watchpoint")
                    .clicked()
                {
                    remove = Some(i);
                }
            });
        }
    });
    if add {
        vm.debug_watch_add();
    }
    if let Some(i) = remove {
        vm.debug_watch_remove(i);
    }
    if close {
        vm.debug.watch_open = false;
    }
}
