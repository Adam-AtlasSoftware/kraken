//! The help window: a list of topics on the left and a readable page on the right.
//!
//! Topics are the first steps, one page per panel, the keyboard shortcuts, the glossary, a page
//! about the AI features and one about rewriting in Rust. F1 opens the page of the panel you are
//! in. The text describes the flow, not exact numbers, so it stays true as features grow.

use egui::{Align2, Key, Modifiers, RichText, ScrollArea, Ui};
use kraken_viewmodel::assist::panel_help;
use kraken_viewmodel::{AppAction, SHORTCUTS, ViewModel};

use crate::menu::{MenuEnv, VIEW_TABS, disabled_reason};
use crate::style::{medium, pal};
use crate::workspace::Tab;

/// A help page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Topic {
    /// The whole flow, step by step.
    Start,
    /// What one panel shows and how to use it.
    Panel(Tab),
    /// Every keyboard shortcut.
    Shortcuts,
    /// Reverse-engineering words in plain language.
    Glossary,
    /// The assistant, local models, terminal agents, MCP and privacy.
    Ai,
    /// The rewrite flow and the sandbox.
    Rewriting,
}

impl Topic {
    /// The name in the topic list.
    pub fn title(self) -> &'static str {
        match self {
            Topic::Start => "Getting started",
            Topic::Panel(t) => t.title(),
            Topic::Shortcuts => "Keyboard shortcuts",
            Topic::Glossary => "Glossary",
            Topic::Ai => "Using AI",
            Topic::Rewriting => "Rewriting in Rust",
        }
    }

    /// One sentence for the topic's hover text.
    fn hint(self) -> String {
        match self {
            Topic::Start => "The whole flow from opening a program to a Rust project".into(),
            Topic::Panel(t) => format!("What the {} panel shows and how to use it", t.title()),
            Topic::Shortcuts => "Every keyboard shortcut, generated from the real list".into(),
            Topic::Glossary => "Reverse-engineering words in plain language. Searchable".into(),
            Topic::Ai => {
                "The assistant, local models, terminal agents, what costs money, MCP and privacy"
                    .into()
            }
            Topic::Rewriting => "Plan, translate, verify, accept, export and build".into(),
        }
    }
}

/// Something a "Do it" button asks the window to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelpDo {
    /// Run an app action.
    Action(AppAction),
    /// Bring a tab to the front.
    ShowTab(Tab),
}

struct Step {
    title: &'static str,
    text: &'static str,
    /// Buttons: label, what they do, hover text.
    doit: &'static [(&'static str, HelpDo, &'static str)],
}

const STEPS: &[Step] = &[
    Step {
        title: "Open a program",
        text: "Use File > Open program, press Ctrl+O, or drop an executable or library on the window. KRAKEN looks at the file and shows what it found, then you press Import. Linux and Windows programs open, and so do their libraries: shared libraries (.so, .dll), static libraries (.a, .lib, with all their objects loaded together), object files (.o, .obj) and import libraries (a list of what a DLL offers). .NET assemblies open in the .NET engine. If a file cannot be opened, the dialog says why. A big program can take minutes the first time: a progress screen shows each stage and how far it is, and Cancel stops it. The next time it opens in seconds. No file at hand? Try the demo project on the start screen.",
        doit: &[(
            "Open a program...",
            HelpDo::Action(AppAction::NewProject),
            "Choose an executable or library to import",
        )],
    },
    Step {
        title: "Analyse it",
        text: "Analysis finds the functions. It can take a while on a big program, and you can keep reading while it runs. The status bar at the bottom shows how far it is, and you can cancel it.",
        doit: &[(
            "Analyse",
            HelpDo::Action(AppAction::Analyze),
            "Let the engine find and name functions",
        )],
    },
    Step {
        title: "Find main",
        text: "Most programs start in a function called main. Go there first. A library has no main: look at the Imports / Exports tab for the functions it offers.",
        doit: &[
            (
                "Go to main",
                HelpDo::Action(AppAction::GoToMain),
                "Open main, or where the program starts",
            ),
            (
                "Show exports",
                HelpDo::ShowTab(Tab::Symbols),
                "See what the program imports and exports",
            ),
        ],
    },
    Step {
        title: "Read the decompiler",
        text: "The Decompiler shows the function as C-like code. Click a name to follow it everywhere it is used, click a call to jump to the called function, and press Alt+Left to come back. It is a guess at the original source, so check odd details in the Listing.",
        doit: &[(
            "Show the Decompiler",
            HelpDo::ShowTab(Tab::Decompiler),
            "Bring the Decompiler to the front",
        )],
    },
    Step {
        title: "Rename and retype",
        text: "As you work out what a function does, give it a real name: select it and press N. Press Y to change the type of the item at the cursor, and ; to leave a comment. In the Decompiler, double-click a variable (or right-click it) to rename or retype it. Every change goes in the History tab, and Ctrl+Z undoes it.",
        doit: &[
            (
                "Rename this function",
                HelpDo::Action(AppAction::RenameCurrent),
                "Give the function you are reading a better name",
            ),
            (
                "Change type",
                HelpDo::Action(AppAction::Retype),
                "Set the type of the item at the cursor",
            ),
        ],
    },
    Step {
        title: "Search and bookmarks",
        text: "Press Ctrl+Shift+F to search names, strings, bytes or instructions, and G to go to an address or a name. Press Ctrl+D to bookmark a place you want to come back to. Right-click in the code for more.",
        doit: &[
            (
                "Search",
                HelpDo::Action(AppAction::Search),
                "Find names, strings, bytes or instructions anywhere",
            ),
            (
                "Go to",
                HelpDo::Action(AppAction::GoTo),
                "Jump to an address, a function or a symbol",
            ),
            (
                "Bookmarks",
                HelpDo::Action(AppAction::ShowBookmarks),
                "See every bookmark",
            ),
        ],
    },
    Step {
        title: "Ask the assistant, or let it automate",
        text: "The assistant explains code in plain words and suggests names. Automate lets it work through the whole flow while you watch. It asks before it overwrites anything you wrote. Read the Using AI page first to choose a model and to see what is sent where.",
        doit: &[
            (
                "Explain this program",
                HelpDo::Action(AppAction::ExplainProgram),
                "Ask the assistant what this program does",
            ),
            (
                "Automate...",
                HelpDo::Action(AppAction::Automate),
                "Let the assistant understand, name and rewrite the program step by step",
            ),
        ],
    },
    Step {
        title: "Rewrite in Rust",
        text: "The rewrite wizard walks you through turning functions into Rust and checking each one against the original program. See the Rewriting in Rust page for what each step does.",
        doit: &[(
            "Rewrite in Rust...",
            HelpDo::Action(AppAction::RewriteWizard),
            "Turn the program into Rust step by step, checked against the original",
        )],
    },
    Step {
        title: "Export and build",
        text: "Accept the functions you trust, export them as a Rust project, and build it. The build runs in a sandbox. The last wizard steps do this for you, and the Rewrite tab has the same buttons.",
        doit: &[(
            "Show the Rewrite tab",
            HelpDo::ShowTab(Tab::Rewrite),
            "Review, accept, export and build",
        )],
    },
];

/// The topics in the list, in order.
pub fn topics() -> Vec<Topic> {
    let mut v = vec![Topic::Start];
    v.extend(VIEW_TABS.iter().map(|t| Topic::Panel(*t)));
    v.extend([
        Topic::Shortcuts,
        Topic::Glossary,
        Topic::Ai,
        Topic::Rewriting,
    ]);
    v
}

/// What the window needs to know about the program, to enable the "Do it" buttons.
pub struct HelpEnv<'a> {
    pub menu: &'a MenuEnv<'a>,
    /// The open project, when there is one (for the glossary).
    pub vm: Option<&'a ViewModel>,
}

/// State of the help window.
pub struct HelpUi {
    open: bool,
    topic: Topic,
    query: String,
    /// The page should scroll back to the top.
    reset_scroll: bool,
}

impl Default for HelpUi {
    fn default() -> Self {
        HelpUi {
            open: false,
            topic: Topic::Start,
            query: String::new(),
            reset_scroll: false,
        }
    }
}

impl HelpUi {
    /// Whether the window is showing.
    pub fn is_open(&self) -> bool {
        self.open
    }

    /// The topic on the page.
    #[cfg(test)]
    pub fn topic(&self) -> Topic {
        self.topic
    }

    /// Opens the window on `topic`.
    pub fn show_topic(&mut self, topic: Topic) {
        self.open = true;
        if self.topic != topic {
            self.topic = topic;
            self.reset_scroll = true;
        }
    }

    /// Draws the window. Returns what a "Do it" button asked for.
    pub fn window(&mut self, ctx: &egui::Context, env: &HelpEnv<'_>) -> Option<HelpDo> {
        if !self.open {
            return None;
        }
        if ctx.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape)) {
            self.open = false;
            return None;
        }
        let mut open = true;
        let mut out = None;
        let height = (ctx.content_rect().height() - 140.0).clamp(240.0, 640.0);
        egui::Window::new("Help")
            .open(&mut open)
            .collapsible(false)
            .default_width(820.0)
            .min_width(560.0)
            .anchor(Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.horizontal_top(|ui| {
                    ui.vertical(|ui| {
                        ui.set_width(170.0);
                        ScrollArea::vertical()
                            .id_salt("kraken_help_topics")
                            .max_height(height)
                            .min_scrolled_height(height)
                            .auto_shrink([false, false])
                            .show(ui, |ui| self.topic_list(ui));
                    });
                    ui.separator();
                    ui.vertical(|ui| {
                        let mut area = ScrollArea::vertical()
                            .id_salt("kraken_help_page")
                            .max_height(height)
                            .min_scrolled_height(height)
                            .auto_shrink([false, false]);
                        if std::mem::take(&mut self.reset_scroll) {
                            area = area.vertical_scroll_offset(0.0);
                        }
                        area.show(ui, |ui| out = self.page(ui, env));
                    });
                });
            });
        if !open {
            self.open = false;
        }
        out
    }

    fn topic_list(&mut self, ui: &mut Ui) {
        let p = pal(ui);
        // Compact, so every topic fits on a laptop screen without scrolling.
        ui.spacing_mut().item_spacing.y = 1.0;
        let mut picked = None;
        for (i, t) in topics().into_iter().enumerate() {
            if i == 1 {
                ui.add_space(6.0);
                ui.label(RichText::new("Panels").size(11.5).color(p.text_dim));
            }
            if t == Topic::Shortcuts {
                ui.add_space(6.0);
                ui.label(RichText::new("Reference").size(11.5).color(p.text_dim));
            }
            if ui
                .selectable_label(self.topic == t, t.title())
                .on_hover_text(t.hint())
                .clicked()
            {
                picked = Some(t);
            }
        }
        if let Some(t) = picked {
            self.show_topic(t);
        }
    }

    fn page(&mut self, ui: &mut Ui, env: &HelpEnv<'_>) -> Option<HelpDo> {
        let p = pal(ui);
        ui.set_min_width(ui.available_width());
        ui.label(medium(self.topic.title(), 20.0).color(p.text_strong));
        ui.add_space(6.0);
        match self.topic {
            Topic::Start => start_page(ui, env),
            Topic::Panel(t) => {
                panel_page(ui, t, env);
                None
            }
            Topic::Shortcuts => {
                shortcuts_page(ui);
                None
            }
            Topic::Glossary => {
                glossary_page(ui, &mut self.query, env);
                None
            }
            Topic::Ai => {
                ai_page(ui);
                None
            }
            Topic::Rewriting => {
                rewriting_page(ui);
                None
            }
        }
    }
}

fn body(ui: &mut Ui, text: &str) {
    let p = pal(ui);
    ui.label(RichText::new(text).size(13.5).color(p.text));
    ui.add_space(6.0);
}

fn heading(ui: &mut Ui, text: &str) {
    let p = pal(ui);
    ui.add_space(6.0);
    ui.label(medium(text, 15.0).color(p.text_strong));
    ui.add_space(2.0);
}

fn bullets(ui: &mut Ui, items: &[&str]) {
    let p = pal(ui);
    for i in items {
        ui.horizontal_wrapped(|ui| {
            ui.label(RichText::new("\u{2022}").color(p.accent));
            ui.label(RichText::new(*i).size(13.5).color(p.text));
        });
    }
    ui.add_space(6.0);
}

fn start_page(ui: &mut Ui, env: &HelpEnv<'_>) -> Option<HelpDo> {
    let p = pal(ui);
    body(
        ui,
        "This is the whole flow, from a program you know nothing about to a Rust project. You do not have to do it in order, and each step has a button that does it for you.",
    );
    let mut out = None;
    for (i, s) in STEPS.iter().enumerate() {
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            ui.label(medium(format!("{}.", i + 1), 15.0).color(p.accent));
            ui.label(medium(s.title, 15.0).color(p.text_strong));
        });
        body(ui, s.text);
        ui.horizontal_wrapped(|ui| {
            for (label, what, hint) in s.doit {
                let reason = do_blocker(*what, env);
                let r = ui
                    .add_enabled(
                        reason.is_none(),
                        egui::Button::new(format!("Do it: {label}")),
                    )
                    .on_hover_text(*hint)
                    .on_disabled_hover_text(reason.unwrap_or_default());
                if r.clicked() {
                    out = Some(*what);
                }
            }
        });
    }
    out
}

/// Why a "Do it" button cannot run now.
pub fn do_blocker(what: HelpDo, env: &HelpEnv<'_>) -> Option<&'static str> {
    match what {
        HelpDo::Action(a) => disabled_reason(a, env.menu),
        HelpDo::ShowTab(_) if !env.menu.project => Some("Open a project first."),
        HelpDo::ShowTab(_) => None,
    }
}

fn panel_page(ui: &mut Ui, tab: Tab, env: &HelpEnv<'_>) {
    let p = pal(ui);
    let Some(h) = panel_help(tab.title()) else {
        body(ui, tab.tooltip());
        return;
    };
    ui.label(RichText::new(h.short).italics().color(p.text_dim));
    ui.add_space(6.0);
    body(ui, h.text);
    heading(ui, "How to use it");
    bullets(ui, h.how);
    if !h.keys.is_empty() {
        heading(ui, "Shortcuts");
        egui::Grid::new("kraken_help_panel_keys")
            .num_columns(2)
            .spacing([18.0, 4.0])
            .show(ui, |ui| {
                for k in h.keys {
                    if let Some(s) = SHORTCUTS.iter().find(|s| s.keys == *k) {
                        ui.monospace(s.keys);
                        ui.label(s.what);
                        ui.end_row();
                    }
                }
            });
    }
    if let Some(vm) = env.vm {
        let terms: Vec<_> = h.terms.iter().filter_map(|t| vm.assist.term(t)).collect();
        if !terms.is_empty() {
            heading(ui, "Words used here");
            for e in terms {
                ui.horizontal_wrapped(|ui| {
                    ui.label(medium(&e.term, 13.0).color(p.accent));
                    ui.label(RichText::new(&e.short).size(13.0).color(p.text_dim));
                });
            }
        }
    }
}

fn shortcuts_page(ui: &mut Ui) {
    body(
        ui,
        "Single-letter keys do nothing while a text box has the focus.",
    );
    egui::Grid::new("kraken_help_shortcuts")
        .num_columns(3)
        .striped(true)
        .spacing([18.0, 6.0])
        .show(ui, |ui| {
            ui.strong("Keys");
            ui.strong("What it does");
            ui.strong("Where");
            ui.end_row();
            for s in SHORTCUTS {
                ui.monospace(s.keys);
                ui.label(s.what);
                ui.weak(s.place);
                ui.end_row();
            }
        });
}

fn glossary_page(ui: &mut Ui, query: &mut String, env: &HelpEnv<'_>) {
    let p = pal(ui);
    ui.add(
        egui::TextEdit::singleline(query)
            .hint_text("Search the glossary")
            .desired_width(f32::INFINITY),
    )
    .on_hover_text("Type a word to find. A near miss still finds it");
    ui.add_space(6.0);
    let Some(vm) = env.vm else {
        body(
            ui,
            "The glossary opens with a project. Open the demo project to look words up.",
        );
        return;
    };
    let terms = vm.assist.glossary_terms(query);
    if terms.is_empty() {
        body(ui, "No word matches. Try a shorter search.");
    }
    for e in terms {
        ui.add_space(3.0);
        ui.label(medium(&e.term, 14.0).color(p.accent));
        ui.label(RichText::new(&e.short).size(13.0).color(p.text));
        if let Some(n) = &e.note {
            ui.label(RichText::new(n).size(12.5).color(p.text_dim));
        }
    }
}

fn ai_page(ui: &mut Ui) {
    body(
        ui,
        "KRAKEN has an assistant that reads the program with the same tools you use. It can explain code, suggest names, answer questions and, with Automate, work through the whole flow. You stay in charge: every change is logged in History and can be undone.",
    );
    heading(ui, "Choose what answers");
    bullets(
        ui,
        &[
            "An AI service (the API): Anthropic, OpenAI, Gemini or any service that speaks the same protocol. It needs a key.",
            "A local model: Ollama, LM Studio or llama-server on your computer. Nothing leaves your machine. KRAKEN can also start one for you.",
            "A terminal agent: Claude Code, Codex or Gemini CLI. It signs in by itself and brings its own tools, which KRAKEN cannot sandbox or undo.",
        ],
    );
    body(
        ui,
        "Pick one in Settings (Ctrl+,), on the AI page, and press Test connection.",
    );
    heading(ui, "What the assistant can do");
    bullets(
        ui,
        &[
            "Explain a function or the whole program in plain language.",
            "Suggest names for functions that still have generated names, and let you review them.",
            "Add names, comments, types and bookmarks. Changes that only add something are applied. Changes that would overwrite your work become proposals that wait for you.",
            "Translate functions to Rust and test them. Only you can accept a rewrite.",
        ],
    );
    heading(ui, "What it cannot do");
    bullets(
        ui,
        &[
            "It cannot be sure. It can be wrong, so check what matters.",
            "It cannot overwrite your work without asking, and it cannot accept a rewrite.",
            "It cannot run the program or the Rust it wrote outside the sandbox.",
        ],
    );
    heading(ui, "The Automate dialog");
    body(
        ui,
        "AI > Automate lets the assistant go through the steps for you: look at the program, name functions and, if you ask, rewrite it in Rust. It shows each step and you can stop it at any time.",
    );
    heading(ui, "Other agents: MCP and kraken auto");
    body(
        ui,
        "Any MCP client can use KRAKEN as a set of tools: run kraken mcp and point the client at it. From a terminal, kraken auto <program> opens, analyses, names and rewrites a program in one go. Both use the same commands and the same safety rules as this window.",
    );
    heading(ui, "What costs money");
    body(
        ui,
        "Cloud models are billed per token by their provider. KRAKEN calls a model only when you (or an agent you started) ask for AI work, and it shows an estimate first.",
    );
    bullets(
        ui,
        &[
            "When KRAKEN calls a model: every chat message, explanation and overview, Suggest names, every step of Automate, and in the Rust rewrite every translation, spec, test fix and repair. Rewriting a whole program takes about 3 requests per function, plus repair rounds: often around 60.",
            "Before it starts: rewrite runs, Suggest names, explanations and Automate show how many model calls they can make at most, which model, and the cost range. Local models are free and never ask. Terminal agents are billed by their own subscription.",
            "While it runs: a chip in the top bar and the status bar shows the feature, the model, the calls so far and the estimated cost. Click it for the AI Activity tab.",
            "Stopping: press Stop in the AI Activity tab. What was finished is kept. Closing the project or quitting while AI work runs asks whether to stop it or leave it running in the background engine, where it keeps costing until it ends.",
            "Limits: Settings > AI has a most-calls and most-cost limit per run, a daily budget, and the amount under which KRAKEN starts without asking. A run that reaches a limit stops cleanly and keeps what it finished; the daily budget refuses new AI work until the next day (UTC).",
            "A separate rewrite model: Settings > AI > Rewriting can give the rewrite its own model, for example a cheaper or a local one, and the rewrite wizard can change it for one run.",
            "Money is always an estimate from list prices (correct them in the [pricing] table of config.toml). Your provider's bill is what counts. The command ai_usage and the AI Activity tab show what was spent.",
        ],
    );
    heading(ui, "Privacy: what is sent where");
    bullets(
        ui,
        &[
            "A local model: nothing leaves your computer.",
            "An AI service in the cloud: the decompiled code, names and questions the assistant reads are sent to that service. Pick one you are comfortable with.",
            "A terminal agent: what it reads goes to that agent's vendor, and it can also read and change files on your computer.",
            "Keys are never written to the main settings file. Use an environment variable, or a key saved with owner-only permissions.",
            "KRAKEN itself sends nothing anywhere else.",
        ],
    );
}

fn rewriting_page(ui: &mut Ui) {
    body(
        ui,
        "KRAKEN can rewrite functions, or the whole program, as Rust and check the Rust against the original before you rely on it. Start the wizard with Rewrite > Rewrite in Rust.",
    );
    heading(ui, "The steps");
    bullets(
        ui,
        &[
            "Plan: list the functions, with the ones that call nothing else first. A function is rewritten after the ones it calls.",
            "Translate: the assistant reads the decompiled code and writes Rust. If it does not build, the assistant gets the error and tries again a few times.",
            "Verify: KRAKEN runs the original and the Rust on the same inputs and compares the results. Verified means they agreed on the cases tried. That is evidence, not proof.",
            "Accept: you mark the versions you trust. Assistants cannot do this step.",
            "Export: the accepted functions are written as a Rust project in a folder you choose.",
            "Build: the project is compiled and its tests are run, so you see that it works.",
        ],
    );
    heading(ui, "One function, the plan or the whole program");
    body(
        ui,
        "Start with one function to see how it looks. The plan does every function in turn. The whole program mode writes one standalone Rust program and compares it with the original program run on the same inputs.",
    );
    heading(ui, "What it costs");
    body(
        ui,
        "Every translation, spec and repair is a request to a model. Before a run starts, KRAKEN shows the most requests it can make, the model and the cost range, and waits for you. The chip in the top bar shows the running total, and the AI Activity tab has a Stop button. The rewrite can use its own model (Settings > AI > Rewriting), and the wizard's Check step can change it for one run.",
    );
    heading(ui, "The sandbox");
    body(
        ui,
        "The Rust comes from a model, so KRAKEN treats it as untrusted. It is built and run only in a confined process: files are read-only except a private scratch folder, there is no network, and time and memory are limited. Code that uses files, the network or processes is refused before it is built. If your computer cannot do this, the buttons that would build or run code are off and say why. The sandbox shares your kernel, so use a virtual machine for malware.",
    );
}

/// The topic of the panel with the focus, for F1.
pub fn topic_for_tab(tab: Option<Tab>) -> Topic {
    match tab {
        Some(t) if panel_help(t.title()).is_some() => Topic::Panel(t),
        _ => Topic::Start,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_panel_has_a_topic_and_a_help_page() {
        for t in VIEW_TABS {
            assert!(topics().contains(&Topic::Panel(t)));
            assert!(panel_help(t.title()).is_some(), "no help for {}", t.title());
        }
        assert_eq!(kraken_viewmodel::assist::PANEL_HELP.len(), VIEW_TABS.len());
    }

    #[test]
    fn f1_picks_the_panel_or_the_start() {
        assert_eq!(
            topic_for_tab(Some(Tab::Decompiler)),
            Topic::Panel(Tab::Decompiler)
        );
        assert_eq!(topic_for_tab(None), Topic::Start);
    }

    #[test]
    fn every_step_button_names_an_action_that_exists() {
        for s in STEPS {
            assert!(!s.doit.is_empty(), "{} has no button", s.title);
            for (_, what, hint) in s.doit {
                assert!(!hint.is_empty());
                if let HelpDo::Action(a) = what {
                    assert!(AppAction::ALL.contains(a));
                }
            }
        }
    }
}
