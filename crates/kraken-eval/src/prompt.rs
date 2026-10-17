//! The words of a task: what the model is asked and how it must answer.
//!
//! Everything here is written by the harness. Nothing derived from a binary is put in a prompt
//! (the question texts describe behaviour; the addresses are numbers). The user message starts
//! with `<kraken-eval id="...">` so a test double can tell which task it is answering.

use crate::suite::{Expected, Kind, TaskDef};

/// Opens and closes the answer block a model ends its reply with.
pub const ANSWER_OPEN: &str = "<kraken-answer>";
/// Closes the answer block.
pub const ANSWER_CLOSE: &str = "</kraken-answer>";

fn header(def: &TaskDef) -> String {
    format!(
        "<kraken-eval id=\"{}\" kind=\"{}\">",
        def.id,
        def.kind.as_str()
    )
}

/// The user message of a task.
pub fn goal(def: &TaskDef, expected: &Expected) -> String {
    let head = header(def);
    match (def.kind, expected) {
        (Kind::NameFunctions, Expected::Names { functions }) => {
            let addresses: Vec<String> = functions
                .iter()
                .map(|f| format!("{:#x}", f.address))
                .collect();
            format!(
                "{head}\nThe open project is a program with its symbols stripped, so its \
                 functions have default names. Give each function listed below a short \
                 snake_case name that says what it does, the way its developer would have named \
                 it.\n\nFunctions (entry addresses): {}\n\nRead them with the tools (decompile, \
                 callers, callees, strings, imports). Do not change the project; only report \
                 names.",
                addresses.join(", ")
            )
        }
        (Kind::FindFunction, _) => format!(
            "{head}\n{}\nAnswer with the entry address of that function. Use the tools to look; \
             do not change the project.",
            def.question.as_deref().unwrap_or_default()
        ),
        _ => format!(
            "{head}\n{}\nUse the tools to look; do not change the project.",
            def.question.as_deref().unwrap_or_default()
        ),
    }
}

/// The trusted instructions appended to the system prompt: the fixed answer format.
pub fn instructions(expected: &Expected) -> String {
    let shape = match expected {
        Expected::Names { .. } => {
            "{\"names\": {\"0x101159\": \"snake_case_name\", \"0x101194\": \"another_name\"}}. Use \
             every listed address as a key and give your best guess where you are unsure"
        }
        Expected::Function { .. } => "{\"address\": \"0x101159\"}",
        Expected::YesNo { .. } => "{\"answer\": \"yes\"} or {\"answer\": \"no\"}",
        Expected::Set { .. } => "{\"items\": [\"name_one\", \"name_two\"]}, each name once",
        Expected::Text { .. } => "{\"text\": \"the exact text\"}",
    };
    format!(
        "This is a measured test with a fixed answer format. Do not rename or edit anything in \
         the project. Finish your reply with exactly one answer block and nothing after it:\n\
         {ANSWER_OPEN}{shape}{ANSWER_CLOSE}"
    )
}
