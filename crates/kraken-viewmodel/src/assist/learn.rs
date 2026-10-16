//! Learn mode: what each panel is for, and which glossary terms it uses.

/// Help for one panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanelHelp {
    /// The panel's title.
    pub panel: &'static str,
    /// What the panel is for, in plain words.
    pub text: &'static str,
    /// Glossary terms to link from the help.
    pub terms: &'static [&'static str],
}

/// Help for every panel, shown by the "?" next to its title.
pub const PANEL_HELP: &[PanelHelp] = &[
    PanelHelp {
        panel: "Functions",
        text: "A function is a named chunk of code that does one job. This list holds every function KRAKEN found. Names like FUN_00401340 are placeholders: nobody has named them yet, so renaming them as you understand them is the heart of the work.",
        terms: &["function", "default name", "symbol"],
    },
    PanelHelp {
        panel: "Decompiler",
        text: "The decompiler guesses what the original source code looked like and shows it as C-like pseudocode. It is easier to read than assembly, but it is a reconstruction, so treat odd-looking details with suspicion.",
        terms: &["decompiler", "pseudocode", "pointer"],
    },
    PanelHelp {
        panel: "Hex",
        text: "The raw bytes of the program, shown as hexadecimal numbers with their text on the right. Useful for spotting strings and data that the decompiler does not explain.",
        terms: &["byte", "hexadecimal", "endianness"],
    },
    PanelHelp {
        panel: "Listing",
        text: "The machine instructions behind the code, one per line. Each line is a mnemonic (what to do) and operands (what to do it to). Hover a mnemonic in learn mode for a plain explanation.",
        terms: &["assembly", "instruction", "mnemonic", "register"],
    },
    PanelHelp {
        panel: "History",
        text: "A log of every change to this project: who made it, when, and a way to undo it. Nothing the assistant does is permanent.",
        terms: &["annotation", "undo"],
    },
    PanelHelp {
        panel: "Proposals",
        text: "When the assistant wants to change something you or someone else already set, it asks first. Proposals wait here until you accept or reject them.",
        terms: &["proposal", "annotation"],
    },
    PanelHelp {
        panel: "Assistant",
        text: "Ask questions about this program in plain language. The assistant reads the code through the same tools you use, shows each step, and asks before overwriting your work.",
        terms: &["reverse engineering", "cross-reference", "caller"],
    },
];

/// The help for the panel titled `panel`.
pub fn panel_help(panel: &str) -> Option<&'static PanelHelp> {
    PANEL_HELP.iter().find(|h| h.panel == panel)
}
