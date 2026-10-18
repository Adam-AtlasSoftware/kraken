//! Learn mode and help: what each panel is for, how to use it, and which glossary terms it uses.

/// Help for one panel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PanelHelp {
    /// The panel's title, as its tab shows it.
    pub panel: &'static str,
    /// One plain sentence: what the panel is. Shown in the tab tooltip.
    pub short: &'static str,
    /// What the panel is for, in a few plain sentences. Shown in learn mode and in the help.
    pub text: &'static str,
    /// How to use it, one step per entry.
    pub how: &'static [&'static str],
    /// Keys from the shortcut list (`Shortcut::keys`) that work in this panel.
    pub keys: &'static [&'static str],
    /// Glossary terms to link from the help.
    pub terms: &'static [&'static str],
}

/// Help for every panel, shown in the tab tooltips, by learn mode and in the help window.
pub const PANEL_HELP: &[PanelHelp] = &[
    PanelHelp {
        panel: "Functions",
        short: "Every function KRAKEN found in the program. Click one to read it.",
        text: "A function is a named chunk of code that does one job. This list holds every function KRAKEN found. Names like FUN_00401340 are placeholders: nobody has named them yet, so renaming them as you understand them is the heart of the work.",
        how: &[
            "Click a function to open it in the Decompiler, the Listing and the Graph.",
            "Type in the filter box to narrow the list. Press Escape to clear it.",
            "Tick \"Hide library stubs\" to leave out the small jump entries for imported functions.",
            "Select a function and press N to rename it.",
        ],
        keys: &["Ctrl+L", "N", "Up / Down, Enter"],
        terms: &["function", "default name", "symbol"],
    },
    PanelHelp {
        panel: "Decompiler",
        short: "The selected function rewritten as readable C-like code. Click a call to follow it.",
        text: "The decompiler guesses what the original source code looked like and shows it as C-like pseudocode. It is easier to read than assembly, but it is a reconstruction, so treat odd-looking details with suspicion.",
        how: &[
            "Click a name to highlight every place it is used.",
            "Click a call to follow it. Use Alt+Left to come back.",
            "Press N on a name to rename it, Y to change its type and ; to add a comment.",
            "Right-click for more: references, bookmarks, ask the assistant.",
        ],
        keys: &["N", "Y", ";", "X", "Ctrl+D", "Alt+Left", "Alt+Right"],
        terms: &["decompiler", "pseudocode", "pointer"],
    },
    PanelHelp {
        panel: "Hex",
        short: "The raw bytes of the program, as hexadecimal numbers and text.",
        text: "The raw bytes of the program, shown as hexadecimal numbers with their text on the right. Useful for spotting strings and data that the decompiler does not explain.",
        how: &[
            "Scroll to move through memory. The view follows the function you open.",
            "Click a byte to select it. The selection is shown at the top right.",
            "Use the Show box to jump to a section, such as the code or the data.",
        ],
        keys: &["G", "Ctrl+D"],
        terms: &["byte", "hexadecimal", "endianness"],
    },
    PanelHelp {
        panel: "Listing",
        short: "The machine instructions behind the code, one per line.",
        text: "The machine instructions behind the code, one per line. Each line is a mnemonic (what to do) and operands (what to do it to). Hover a mnemonic in learn mode for a plain explanation.",
        how: &[
            "Click a line to put the cursor on it. Double-click a jump or call to follow it.",
            "Press Space to swap with the Graph.",
            "Press N, Y, ; or X on a line to rename, retype, comment or list references.",
        ],
        keys: &["Space", "N", "Y", ";", "X", "P", "Ctrl+D"],
        terms: &["assembly", "instruction", "mnemonic", "register"],
    },
    PanelHelp {
        panel: "Graph",
        short: "The same code as boxes joined by arrows. Space swaps it with the listing.",
        text: "The same function drawn as boxes of instructions joined by arrows. Each box runs from top to bottom without a decision; the arrows are the decisions and jumps. Loops and if-else shapes are easier to see here than in a long list.",
        how: &[
            "Scroll to move around the graph.",
            "Press F to fit the whole graph in the panel.",
            "Click a box to put the cursor in it.",
        ],
        keys: &["F", "Space"],
        terms: &["basic block", "control flow graph", "branch", "loop"],
    },
    PanelHelp {
        panel: "Xrefs",
        short: "Who calls this function, what it calls, and what refers to any address.",
        text: "Cross-references show how pieces of the program connect. For the function you are reading you see its callers (who uses it) and its callees (what it uses). For any address you can list everything that points at it.",
        how: &[
            "Switch between callers and callees with the buttons at the top.",
            "Click a row to jump to it.",
            "Press X on a name or an address in the code to list what refers to it.",
        ],
        keys: &["X", "Alt+Left"],
        terms: &["cross-reference", "caller", "callee", "call graph"],
    },
    PanelHelp {
        panel: "Strings",
        short: "Text found inside the program. Double-click one to see what uses it.",
        text: "Readable text found inside the program: messages, file names, URLs, format strings. Strings are often the quickest clue to what a function does.",
        how: &[
            "Type in the filter box to find a word.",
            "Double-click a string to see which code refers to it.",
            "Use Up and Down to move through the list.",
        ],
        keys: &["Up / Down, Enter"],
        terms: &["string", "wide string", "cross-reference"],
    },
    PanelHelp {
        panel: "Imports / Exports",
        short: "What the program borrows from libraries, and what it makes available.",
        text: "Imports are the functions the program borrows from system libraries, such as file, network and memory functions. They tell you what the program can do. Exports are the functions it offers to others, which is how a library is used.",
        how: &[
            "Type in the filter box to find a name.",
            "Double-click a row to see the code that uses it.",
            "Look at the exports first when you open a library (a .dll or .so).",
        ],
        keys: &["Up / Down, Enter"],
        terms: &["import", "export", "shared library", "dynamic linking"],
    },
    PanelHelp {
        panel: "Search",
        short: "Find names, strings, byte patterns or instructions anywhere in the program. Ctrl+Shift+F.",
        text: "Search looks through the whole program, not only the function you are reading. Pick what to look for (names, strings, bytes or instructions), type, and press Enter. Each result is a place you can jump to.",
        how: &[
            "Press Ctrl+Shift+F to open the tab.",
            "Choose the kind of search, then type and press Enter or click Search.",
            "Click a result to go there.",
        ],
        keys: &["Ctrl+Shift+F", "G"],
        terms: &["symbol", "string", "byte"],
    },
    PanelHelp {
        panel: "Bookmarks",
        short: "Places you or an agent marked to come back to, with notes. Ctrl+D adds one.",
        text: "Bookmarks are places you want to remember, each with an optional note. You and the assistant can both add them. They are saved in the project.",
        how: &[
            "Press Ctrl+D on a line to bookmark it.",
            "Click a bookmark to go there.",
            "Remove one you no longer need. The program itself is not changed.",
        ],
        keys: &["Ctrl+D"],
        terms: &["annotation", "comment", "address"],
    },
    PanelHelp {
        panel: "History",
        short: "Every change made to this project, who made it, and a way to undo it.",
        text: "A log of every change to this project: who made it, when, and a way to undo it. Nothing the assistant does is permanent.",
        how: &[
            "Each row says what changed and who did it (you or an agent run).",
            "Use Undo on a row to reverse that change.",
            "Press Ctrl+Z to undo your last change without opening this tab.",
        ],
        keys: &["Ctrl+Z"],
        terms: &["annotation", "undo"],
    },
    PanelHelp {
        panel: "Proposals",
        short: "Changes suggested by AI assistants that wait for your approval.",
        text: "When the assistant wants to change something you or someone else already set, it asks first. Proposals wait here until you accept or reject them.",
        how: &[
            "Read the old value and the suggested one.",
            "Accept to apply it, or reject to throw it away.",
        ],
        keys: &[],
        terms: &["proposal", "annotation"],
    },
    PanelHelp {
        panel: "Assistant",
        short: "Ask the assistant (an AI model or a terminal agent) about this program in plain language.",
        text: "Ask questions about this program in plain language. The assistant reads the code through the same tools you use, shows each step, and asks before overwriting your work.",
        how: &[
            "Type a question and press Enter.",
            "Watch the steps it takes. Each one is a command you could run yourself.",
            "Use AI > Automate to let it work through the whole flow.",
        ],
        keys: &[],
        terms: &["reverse engineering", "cross-reference", "caller"],
    },
    PanelHelp {
        panel: "Rewrite",
        short: "Rewrite functions in Rust, check each against the original, and export what you accept.",
        text: "The Rewrite tab turns functions into Rust and checks every result against the original program. A rewrite is only accepted when it behaves like the original on the tests. Accepted code can be exported as a Rust project.",
        how: &[
            "Open Rewrite > Rewrite in Rust to start the step-by-step wizard.",
            "Review each function's plan, translation and test result in this tab.",
            "Accept the ones you trust, then export and build.",
        ],
        keys: &[],
        terms: &["function", "decompiler", "calling convention"],
    },
    PanelHelp {
        panel: "AI Activity",
        short: "Which AI work runs, on which model, what it has cost so far, and a Stop button for each.",
        text: "Every piece of AI work on this project shows here: rewrite jobs started from this window, from the command line or by an agent, and the assistant's runs in this window. Each row says which model it asks, who started it, how many model calls it made and an estimate of the cost. Terminal agents are billed by their own subscription; local models are free.",
        how: &[
            "Press Stop on a row to end that work. What it finished is kept.",
            "Click the AI chip in the top bar to come here while work runs.",
            "Set limits and a daily budget in Settings > AI.",
        ],
        keys: &[],
        terms: &[],
    },
];

/// The help for the panel titled `panel`.
pub fn panel_help(panel: &str) -> Option<&'static PanelHelp> {
    PANEL_HELP.iter().find(|h| h.panel == panel)
}
