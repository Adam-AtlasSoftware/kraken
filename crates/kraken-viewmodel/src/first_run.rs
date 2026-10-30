//! The first-run wizard: engine, assistant, keyboard shortcuts, look, and what to do first. The
//! flow keeps the choices; the window (`kraken-gui`'s `first_run.rs`) draws the steps and, on
//! Finish, saves them (`ui.keymap`, `ui.first_run_done`, the theme and the zoom) and starts what
//! was chosen.

use crate::wizard::WizardFlow;

/// The steps, in order.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FirstRunStep {
    /// Is an engine ready; set the native one up.
    Engine,
    /// How the assistant is reached.
    Assistant,
    /// A keyboard shortcut preset.
    Keymap,
    /// Theme and text size.
    Look,
    /// What to do first.
    Done,
}

/// How the person wants to reach an assistant.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AssistantChoice {
    /// A coding agent installed on this computer (Claude Code, Codex, Gemini CLI).
    TerminalAgent,
    /// A model reached over the internet with an API key.
    ModelApi,
    /// A model that runs on this computer.
    LocalModel,
    /// No assistant for now; everything else works without one.
    NoneForNow,
}

impl AssistantChoice {
    /// Every choice, in the order shown.
    pub const ALL: [AssistantChoice; 4] = [
        AssistantChoice::TerminalAgent,
        AssistantChoice::ModelApi,
        AssistantChoice::LocalModel,
        AssistantChoice::NoneForNow,
    ];

    /// The choice's short title.
    pub fn title(self) -> &'static str {
        match self {
            AssistantChoice::TerminalAgent => "A coding agent on this computer",
            AssistantChoice::ModelApi => "A model over the internet (API key)",
            AssistantChoice::LocalModel => "A model on this computer",
            AssistantChoice::NoneForNow => "None for now",
        }
    }

    /// What it means, in a sentence.
    pub fn blurb(self) -> &'static str {
        match self {
            AssistantChoice::TerminalAgent => {
                "Uses Claude Code, Codex or Gemini CLI if you have one installed. Opens Settings after this wizard."
            }
            AssistantChoice::ModelApi => {
                "Paste an API key for a provider. Paid work always asks first. Opens Settings after this wizard."
            }
            AssistantChoice::LocalModel => {
                "Download a model that fits this computer and run it here; nothing leaves the machine. Starts the model setup after this wizard."
            }
            AssistantChoice::NoneForNow => {
                "Reading, renaming, patching and running programs work without one. Choose later in Settings."
            }
        }
    }
}

/// What to do when the wizard closes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum AfterFirstRun {
    /// Go to the start screen.
    #[default]
    Nothing,
    /// Start the short tour of the window.
    Tour,
    /// Open the small built-in demo project.
    Demo,
}

/// Where the engine stands, as the window learnt it from `setup_status`.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub enum EngineState {
    /// Not asked yet, or the daemon is not reachable.
    #[default]
    Unknown,
    /// The native engine is installed and ready.
    Ready,
    /// Not installed; the window offers Set up.
    Missing,
    /// An install job is running.
    Installing,
}

/// Text size steps, as percent of the normal size.
pub const ZOOM_STEPS: [u32; 4] = [90, 100, 115, 130];

/// The wizard's state.
#[derive(Debug, Clone)]
pub struct FirstRun {
    step: FirstRunStep,
    /// What the engine step shows.
    pub engine: EngineState,
    /// The assistant choice; the step cannot be left before one is made.
    pub assistant: Option<AssistantChoice>,
    /// The keymap preset id.
    pub keymap: String,
    /// Dark theme.
    pub dark: bool,
    /// Text size in percent (one of [`ZOOM_STEPS`]).
    pub zoom: u32,
    /// What to do after Finish.
    pub after: AfterFirstRun,
}

impl FirstRun {
    /// Starts with the settings in force now. `assistant_configured` means a provider is already
    /// set, which lets the assistant step pass untouched.
    pub fn new(keymap: &str, dark: bool, zoom: u32, assistant_configured: bool) -> Self {
        FirstRun {
            step: FirstRunStep::Engine,
            engine: EngineState::Unknown,
            assistant: assistant_configured.then_some(AssistantChoice::NoneForNow),
            keymap: keymap.to_string(),
            dark,
            zoom: ZOOM_STEPS
                .into_iter()
                .min_by_key(|z| z.abs_diff(zoom))
                .unwrap_or(100),
            after: AfterFirstRun::default(),
        }
    }

    /// The step on show.
    pub fn step(&self) -> FirstRunStep {
        self.step
    }
}

impl WizardFlow for FirstRun {
    type Step = FirstRunStep;
    const ID: &'static str = "first_run";

    fn steps(&self) -> Vec<FirstRunStep> {
        vec![
            FirstRunStep::Engine,
            FirstRunStep::Assistant,
            FirstRunStep::Keymap,
            FirstRunStep::Look,
            FirstRunStep::Done,
        ]
    }

    fn current(&self) -> FirstRunStep {
        self.step
    }

    fn set_current(&mut self, step: FirstRunStep) {
        self.step = step;
    }

    fn title(&self, step: FirstRunStep) -> &'static str {
        match step {
            FirstRunStep::Engine => "Engine",
            FirstRunStep::Assistant => "Assistant",
            FirstRunStep::Keymap => "Keys",
            FirstRunStep::Look => "Look",
            FirstRunStep::Done => "Start",
        }
    }

    fn explain(&self, step: FirstRunStep) -> &'static str {
        match step {
            FirstRunStep::Engine => {
                "The engine reads programs and turns machine code into C-like code. KRAKEN's own engine needs a one-time download of its processor descriptions."
            }
            FirstRunStep::Assistant => {
                "An assistant can explain functions, suggest names and help rewrite a program in Rust. It is optional, and you can change this in Settings at any time."
            }
            FirstRunStep::Keymap => {
                "Pick the keyboard shortcuts you know. Every preset keeps the same actions; only the keys differ. You can change it later in Settings."
            }
            FirstRunStep::Look => "Choose the theme and the size of the text.",
            FirstRunStep::Done => "That is everything. What would you like to do first?",
        }
    }

    fn blocker(&self) -> Option<String> {
        match self.step {
            FirstRunStep::Assistant if self.assistant.is_none() => Some(
                "Choose one of the options above; the last one skips the assistant".to_string(),
            ),
            _ => None,
        }
    }

    fn finish_label(&self) -> &'static str {
        match self.after {
            AfterFirstRun::Nothing => "Finish",
            AfterFirstRun::Tour => "Finish and take the tour",
            AfterFirstRun::Demo => "Finish and open the demo",
        }
    }

    fn commands(&self) -> Vec<String> {
        let mut c = vec![
            format!("kraken config set ui.keymap {}", self.keymap),
            format!("kraken config set ui.zoom_percent {}", self.zoom),
            "kraken config set ui.first_run_done true".to_string(),
        ];
        if self.engine == EngineState::Missing {
            c.insert(0, "kraken setup --native".to_string());
        }
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wizard::{self, WizardNav};

    #[test]
    fn the_flow_walks_from_engine_to_start_and_finishes() {
        let mut w = FirstRun::new("kraken", true, 100, false);
        assert_eq!(wizard::position(&w), (1, 5));
        assert!(!wizard::can_back(&w));
        assert_eq!(wizard::next(&mut w), WizardNav::Moved);
        assert_eq!(w.step(), FirstRunStep::Assistant);
        assert!(matches!(wizard::next(&mut w), WizardNav::Blocked(_)));
        w.assistant = Some(AssistantChoice::NoneForNow);
        assert_eq!(wizard::next(&mut w), WizardNav::Moved);
        w.keymap = "classic".into();
        assert_eq!(wizard::next(&mut w), WizardNav::Moved);
        w.dark = false;
        w.zoom = 115;
        assert_eq!(wizard::next(&mut w), WizardNav::Moved);
        assert!(wizard::is_last(&w));
        w.after = AfterFirstRun::Demo;
        assert_eq!(w.finish_label(), "Finish and open the demo");
        assert_eq!(wizard::next(&mut w), WizardNav::Finish);
        assert_eq!(w.keymap, "classic");
        assert!(
            w.commands()
                .iter()
                .any(|c| c.ends_with("ui.keymap classic"))
        );
        assert!(wizard::back(&mut w));
        assert_eq!(w.step(), FirstRunStep::Look);
    }

    #[test]
    fn a_configured_assistant_lets_the_step_pass_and_zoom_snaps_to_a_step() {
        let w = FirstRun::new("kraken", true, 107, true);
        assert_eq!(w.zoom, 100);
        assert!(w.assistant.is_some());
        let w = FirstRun::new("kraken", true, 140, false);
        assert_eq!(w.zoom, 130);
        assert!(w.assistant.is_none());
    }

    #[test]
    fn the_engine_command_is_listed_only_when_it_is_missing() {
        let mut w = FirstRun::new("kraken", true, 100, false);
        assert!(!w.commands().iter().any(|c| c.contains("setup")));
        w.engine = EngineState::Missing;
        assert_eq!(w.commands()[0], "kraken setup --native");
    }

    #[test]
    fn every_assistant_choice_explains_itself() {
        for c in AssistantChoice::ALL {
            assert!(!c.title().is_empty() && c.blurb().ends_with('.'));
        }
    }
}
