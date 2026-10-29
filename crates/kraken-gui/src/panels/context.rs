//! The right-click menu of the decompiler, the listing, the function list and the graph: the
//! editing and navigation items, drawn above the assistant's Explain items (see
//! `assist::menu`). Every item has hover text and its shortcut; a disabled item says why.

use egui::{RichText, Ui};
use kraken_proto::{Locator, Token, TokenKind};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::navtools::{IntentKind, NavTab};
use kraken_viewmodel::rewrite::RewriteMode;

/// What was right-clicked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    /// A function: its name in code, a function-list row, or the function being read.
    Function,
    /// An instruction (a listing row or a graph block).
    Code,
    /// A data address, such as a global in the decompiler.
    Data,
    /// A local variable or parameter in the decompiler.
    Variable,
    /// Anything else in the decompiler (a keyword, a constant).
    Other,
}

/// The thing a right-click menu acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// What it is.
    pub kind: TargetKind,
    /// Its address, when it has one.
    pub address: Option<u64>,
    /// Its name or text, when it has one.
    pub name: Option<String>,
    /// The function the click was in.
    pub function: Option<u64>,
}

/// The menu item chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavChoice {
    Rename,
    Retype,
    EditSignature,
    Comment,
    References,
    GoToDefinition,
    CopyAddress,
    CopyName,
    Bookmark,
    ToggleBreakpoint,
    RunToHere,
    CreateFunction,
    DeleteFunction,
    Rewrite,
    PatchNop,
    PatchInvert,
    PatchAlways,
    PatchNever,
    PatchReturn,
    PatchFill,
    CallFunction,
}

/// One menu row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    pub choice: NavChoice,
    pub label: String,
    pub shortcut: Option<&'static str>,
    /// What it does.
    pub hover: String,
    /// `Some(reason)` when the item cannot be used.
    pub disabled: Option<String>,
    /// The submenu the item lives in; ungrouped items are drawn in the main list.
    pub group: Option<&'static str>,
}

fn item(choice: NavChoice, label: &str, shortcut: Option<&'static str>, hover: &str) -> Item {
    Item {
        choice,
        label: label.into(),
        shortcut,
        hover: hover.into(),
        disabled: None,
        group: None,
    }
}

impl Item {
    fn in_group(mut self, group: &'static str) -> Item {
        self.group = Some(group);
        self
    }

    fn off(mut self, why: impl Into<String>) -> Item {
        self.disabled = Some(why.into());
        self
    }

    fn off_if(self, why: Option<&str>) -> Item {
        match why {
            Some(w) => self.off(w),
            None => self,
        }
    }
}

/// The target of a decompiler token.
pub fn token_target(t: &Token, text: &str, function: u64) -> Target {
    let address = match &t.target {
        Some(Locator::Native { offset, .. }) => Some(offset.0),
        Some(Locator::Managed { token, .. }) => Some(u64::from(*token)),
        _ => None,
    };
    let word = text
        .get(t.start as usize..t.end as usize)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let name = t.symbol.clone().or(word);
    let kind = match (t.kind, address) {
        (TokenKind::Function, _) => TargetKind::Function,
        (TokenKind::Variable, None) => TargetKind::Variable,
        (_, Some(_)) => TargetKind::Data,
        _ => TargetKind::Other,
    };
    let address = if kind == TargetKind::Function {
        address.or(Some(function))
    } else {
        address
    };
    Target {
        kind,
        address,
        name,
        function: Some(function),
    }
}

/// The items of the menu for `t`, in order.
pub fn items(vm: &ViewModel, t: &Target) -> Vec<Item> {
    let type_block = vm.type_edit_blocked();
    let fn_block = vm.function_edit_blocked();
    let entry =
        t.kind == TargetKind::Function || t.address.is_some_and(|a| vm.functions.find(a).is_some());
    let func = if t.kind == TargetKind::Function {
        t.address
    } else {
        t.function
    };
    let mut out = Vec::new();

    out.push(match t.kind {
        TargetKind::Function => item(
            NavChoice::Rename,
            "Rename",
            Some("N"),
            "Give this function a name that says what it does",
        ),
        TargetKind::Code | TargetKind::Data => item(
            NavChoice::Rename,
            "Rename / add label",
            Some("N"),
            "Name this address. The name shows wherever the address is used",
        ),
        TargetKind::Variable => item(
            NavChoice::Rename,
            "Rename",
            Some("N"),
            "Rename this variable",
        )
        .off("Local variables cannot be renamed yet. Only functions and labels can."),
        TargetKind::Other => item(
            NavChoice::Rename,
            "Rename",
            Some("N"),
            "Rename what is under the pointer",
        )
        .off("Only names can be renamed. Right-click a function, a label or an address."),
    });

    let retype = item(
        NavChoice::Retype,
        "Retype",
        Some("Y"),
        "Change the type of this item, such as int or char *",
    );
    out.push(match t.kind {
        _ if type_block.is_some() => retype.off_if(type_block),
        TargetKind::Function => retype,
        TargetKind::Data => retype,
        TargetKind::Code if entry => retype,
        TargetKind::Code => retype.off("This is an instruction. Retype data, or edit the function's signature."),
        TargetKind::Variable => {
            retype.off("Local variables cannot be retyped yet. Edit the function's signature to change its parameters.")
        }
        TargetKind::Other => retype.off("Right-click a function or a data address to retype it."),
    });

    let sig = item(
        NavChoice::EditSignature,
        "Edit function signature...",
        None,
        "Change the return type and parameters, written as a C prototype",
    );
    out.push(match func {
        None => sig.off("This is not inside a known function."),
        Some(_) => sig.off_if(type_block),
    });

    let comment = item(
        NavChoice::Comment,
        "Comment",
        Some(";"),
        "Leave a note at this address. It is saved with the project",
    );
    out.push(if t.address.or(func).is_some() {
        comment
    } else {
        comment.off("There is no address here to attach a comment to.")
    });

    let refs = item(
        NavChoice::References,
        "Show references",
        Some("X"),
        "List everything in the program that uses this address",
    );
    out.push(match (t.kind, t.address) {
        (TargetKind::Variable, _) => refs.off("References to local variables are not tracked yet."),
        (_, Some(_)) => refs,
        (_, None) => refs.off("There is no address here."),
    });

    let current = vm.current.as_ref().map(|c| c.address);
    let def = item(
        NavChoice::GoToDefinition,
        "Go to definition",
        None,
        "Jump to where this function or data item is",
    );
    out.push(match (t.kind, t.address) {
        (TargetKind::Function | TargetKind::Data, Some(a)) if Some(a) != current => def,
        (TargetKind::Function, Some(_)) => def.off("You are already reading this function."),
        _ => def.off("Right-click a call or a data name to follow it."),
    });

    let copy_addr = item(
        NavChoice::CopyAddress,
        "Copy address",
        None,
        "Copy the address as 0x... to the clipboard",
    );
    out.push(match t.address {
        Some(_) => copy_addr,
        None => copy_addr.off("There is no address here."),
    });
    let copy_name = item(
        NavChoice::CopyName,
        "Copy name",
        None,
        "Copy the name to the clipboard",
    );
    out.push(match &t.name {
        Some(_) => copy_name,
        None => copy_name.off("There is no name here."),
    });

    let mark = item(
        NavChoice::Bookmark,
        "Add bookmark",
        Some("Ctrl+D"),
        "Mark this address to come back to; see the Bookmarks tab",
    );
    out.push(match t.address.or(func) {
        Some(_) => mark,
        None => mark.off("There is no address here to bookmark."),
    });

    if t.kind == TargetKind::Code {
        let on = t.address.is_some_and(|a| vm.debug.has_breakpoint(a));
        let brk = item(
            NavChoice::ToggleBreakpoint,
            if on {
                "Remove breakpoint"
            } else {
                "Set breakpoint"
            },
            Some("F9"),
            "Stop the emulated program here; see the Debug tab",
        );
        out.push(match t.address {
            Some(_) => brk,
            None => brk.off("There is no address here."),
        });
        let run_to = item(
            NavChoice::RunToHere,
            "Run to here",
            None,
            "Run the emulated program until it reaches this instruction",
        );
        out.push(match t.address {
            None => run_to.off("There is no address here."),
            Some(_) if !vm.debug.active() => {
                run_to.off("Start the program in the Debug tab first.")
            }
            Some(_) => run_to.off_if(if vm.debug.can_step() {
                None
            } else {
                Some("The program is running or has ended.")
            }),
        });
    }

    if entry {
        out.push(
            item(
                NavChoice::DeleteFunction,
                "Delete function...",
                None,
                "Remove this function if the analysis got it wrong. The code stays",
            )
            .off_if(fn_block),
        );
    } else {
        let create = item(
            NavChoice::CreateFunction,
            "Create function here",
            Some("P"),
            "Tell KRAKEN the code at this address is the start of a function",
        );
        out.push(match t.kind {
            TargetKind::Code | TargetKind::Data => create.off_if(fn_block),
            _ => {
                create.off("Right-click an instruction in the listing to create a function there.")
            }
        });
    }

    let call = item(
        NavChoice::CallFunction,
        "Call this function...",
        None,
        "Run just this function in the emulator with arguments you choose; see the Emulation tab",
    );
    out.push(match func {
        None => call.off("This is not inside a known function."),
        Some(_) => call,
    });

    let rewrite = item(
        NavChoice::Rewrite,
        "Rewrite this function in Rust",
        None,
        "Translate the function to Rust and check it against the original; see the Rewrite tab",
    );
    out.push(match func {
        None => rewrite.off("This is not inside a known function."),
        Some(_) => rewrite.off_if(vm.rewrite.blocked_note()),
    });

    const PATCH: &str = "Patch";
    let code = t.kind == TargetKind::Code && t.address.is_some();
    let on_code = |it: Item| {
        it.in_group(PATCH)
            .off_if((!code).then_some("Right-click an instruction in the Listing to patch it."))
    };
    out.push(on_code(item(
        NavChoice::PatchNop,
        "NOP this",
        None,
        "Replace this instruction with NOPs for this processor. You see the new bytes first",
    )));
    out.push(on_code(item(
        NavChoice::PatchInvert,
        "Invert branch",
        None,
        "Make a conditional branch go the other way",
    )));
    out.push(on_code(item(
        NavChoice::PatchAlways,
        "Always take branch",
        None,
        "Turn a conditional branch into a jump to the same place",
    )));
    out.push(on_code(item(
        NavChoice::PatchNever,
        "Never take branch",
        None,
        "Remove a conditional branch: execution falls through",
    )));
    let entry_addr = if t.kind == TargetKind::Function {
        t.address
    } else {
        t.function
    };
    out.push(
        item(
            NavChoice::PatchReturn,
            "Make function return...",
            None,
            "Make the function return a number straight away",
        )
        .in_group(PATCH)
        .off_if(
            entry_addr
                .is_none()
                .then_some("This is not inside a known function."),
        ),
    );
    out.push(
        item(
            NavChoice::PatchFill,
            "Fill...",
            None,
            "Overwrite a range of bytes starting here with a repeated pattern",
        )
        .in_group(PATCH)
        .off_if(
            t.address
                .is_none()
                .then_some("There is no address here to fill from."),
        ),
    );
    out
}

/// Draws the items; a click sets `choice`.
pub fn draw(ui: &mut Ui, items: &[Item], choice: &mut Option<NavChoice>) {
    let mut groups: Vec<&'static str> = Vec::new();
    for it in items {
        if let Some(g) = it.group {
            if !groups.contains(&g) {
                groups.push(g);
            }
            continue;
        }
        draw_item(ui, it, choice);
    }
    for g in groups {
        ui.menu_button(g, |ui| {
            for it in items.iter().filter(|i| i.group == Some(g)) {
                draw_item(ui, it, choice);
            }
        })
        .response
        .on_hover_text("Change the program's bytes here. You see the result first and can undo it");
    }
}

fn draw_item(ui: &mut Ui, it: &Item, choice: &mut Option<NavChoice>) {
    {
        let text = match it.shortcut {
            Some(s) => format!("{}    ({s})", it.label),
            None => it.label.clone(),
        };
        let r = ui
            .add_enabled(it.disabled.is_none(), egui::Button::new(text).frame(false))
            .on_hover_text(&it.hover);
        let r = match &it.disabled {
            Some(why) => r.on_disabled_hover_text(why),
            None => r,
        };
        super::remember_rect(ui.ctx(), ("menu", it.label.as_str()), r.rect);
        if r.clicked() {
            *choice = Some(it.choice);
            ui.close();
        }
    }
}

/// Section title above the items.
pub fn heading(ui: &mut Ui, t: &Target, dim: egui::Color32) {
    let what = match (&t.name, t.address) {
        (Some(n), _) => n.clone(),
        (None, Some(a)) => format!("{a:#x}"),
        (None, None) => "Here".into(),
    };
    let what: String = what.chars().take(40).collect();
    ui.label(RichText::new(what).size(11.0).color(dim));
}

/// Carries out `choice` on `t`.
pub fn run(ctx: &egui::Context, vm: &mut ViewModel, t: &Target, choice: NavChoice) {
    let func = if t.kind == TargetKind::Function {
        t.address
    } else {
        t.function
    };
    match choice {
        NavChoice::Rename => {
            if let Some(a) = t.address {
                let hint = (t.kind == TargetKind::Function)
                    .then(|| t.name.clone())
                    .flatten();
                vm.begin_rename(a, hint.as_deref());
            }
        }
        NavChoice::Retype => {
            if let Some(a) = t.address {
                vm.begin_retype(a);
            }
        }
        NavChoice::EditSignature => {
            if let Some(f) = func {
                vm.begin_edit_signature(f);
            }
        }
        NavChoice::Comment => {
            if let Some(a) = t.address.or(func) {
                let kind = if vm.functions.find(a).is_some() {
                    kraken_proto::CommentKind::Plate
                } else {
                    kraken_proto::CommentKind::Eol
                };
                vm.begin_comment(a, kind);
            }
        }
        NavChoice::References => {
            if let Some(a) = t.address {
                vm.show_references(a, t.name.clone());
            }
        }
        NavChoice::GoToDefinition => {
            if let Some(a) = t.address {
                vm.goto(a);
            }
        }
        NavChoice::CopyAddress => {
            if let Some(a) = t.address {
                ctx.copy_text(format!("{a:#x}"));
            }
        }
        NavChoice::CopyName => {
            if let Some(n) = &t.name {
                ctx.copy_text(n.clone());
            }
        }
        NavChoice::Bookmark => {
            if let Some(a) = t.address.or(func) {
                vm.ensure_bookmarks();
                vm.begin_bookmark(a);
            }
        }
        NavChoice::ToggleBreakpoint => {
            if let Some(a) = t.address {
                vm.debug_toggle_breakpoint(a);
            }
        }
        NavChoice::RunToHere => {
            if let Some(a) = t.address {
                vm.debug_run_to(a);
                vm.show_debug();
            }
        }
        NavChoice::CreateFunction => {
            if let Some(a) = t.address {
                vm.begin_create_function(a);
            }
        }
        NavChoice::DeleteFunction => {
            if let Some(a) = t.address {
                vm.begin_delete_function(a);
            }
        }
        NavChoice::PatchNop => {
            if let Some(a) = t.address {
                vm.begin_intent(IntentKind::Nop, a);
            }
        }
        NavChoice::PatchInvert => {
            if let Some(a) = t.address {
                vm.begin_intent(IntentKind::BranchInvert, a);
            }
        }
        NavChoice::PatchAlways => {
            if let Some(a) = t.address {
                vm.begin_intent(IntentKind::BranchAlways, a);
            }
        }
        NavChoice::PatchNever => {
            if let Some(a) = t.address {
                vm.begin_intent(IntentKind::BranchNever, a);
            }
        }
        NavChoice::PatchReturn => {
            if let Some(f) = func {
                vm.begin_intent(IntentKind::Return, f);
            }
        }
        NavChoice::PatchFill => {
            if let Some(a) = t.address {
                vm.begin_intent(IntentKind::Fill, a);
            }
        }
        NavChoice::CallFunction => {
            if let Some(f) = func {
                vm.begin_call(f);
            }
        }
        NavChoice::Rewrite => {
            if let Some(f) = func {
                vm.rewrite_select(f);
                vm.rewrite_run(f, RewriteMode::Incremental);
                vm.tools.request_tab(NavTab::Rewrite);
            }
        }
    }
}
