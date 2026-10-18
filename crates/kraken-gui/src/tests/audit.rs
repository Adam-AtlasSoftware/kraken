//! Keeps the tooltip rule true: every widget a person can click has hover text, and a widget that
//! can be switched off says why.
//!
//! This is a scan of the source, not of a running window, so it also covers dialogs and
//! screens that no test opens. It finds each line that builds a button, checkbox, radio,
//! selectable, combo box, drag value, text field or the shared primary button, reads the whole
//! statement (up to the matching closing parenthesis and `;` or `{`) and wants `hover` in it.
//! A statement that only binds the widget (`let r = ...`) may add the text in the next few
//! lines. Every `add_enabled(` call wants `disabled_hover` the same way, because egui shows
//! `on_hover_text` only on enabled widgets. Click areas (`Sense::click`) want hover text within
//! a few lines.
//!
//! Where hover text is added in a way the scan cannot see, the place is in [`ALLOWED`] with the
//! reason. A new entry there should be rare.

use std::path::{Path, PathBuf};

const WIDGETS: &[&str] = &[
    ".button(",
    ".small_button(",
    ".checkbox(",
    ".selectable_label(",
    ".selectable_value(",
    ".radio(",
    ".radio_value(",
    ".toggle_value(",
    ".menu_button(",
    ".link(",
    "ComboBox::from",
    "DragValue::new",
    "TextEdit::singleline",
    "TextEdit::multiline",
    "Button::new",
    "Checkbox::new",
    "primary_button(",
];

/// (file, text of the line, why it is fine). The line is matched as a substring.
const ALLOWED: &[(&str, &str, &str)] = &[
    (
        "import.rs",
        "ui.radio_value(&mut self.engine",
        "the hover text is added to the response a few lines below, with the reason it is off",
    ),
    (
        "menu.rs",
        "Button::new(\"Open recent\")",
        "the hover text is on the sub-menu button's response after its closure",
    ),
    (
        "style.rs",
        "egui::Button::new(label)",
        "this is the shared primary button; every caller adds its own hover text",
    ),
    (
        "overlays.rs",
        "allocate_exact_size(screen.size(), Sense::click())",
        "the dimmed backdrop behind the palette; clicking outside closes it",
    ),
    (
        "overlays.rs",
        "allocate_exact_size(vec2(ui.available_width(), 42.0), Sense::click())",
        "a palette row; it shows its own title, description and shortcut",
    ),
    (
        "graph_view.rs",
        "allocate_exact_size(size, Sense::click_and_drag())",
        "the graph itself; the Graph tab tooltip and help explain it, and its boxes show the code",
    ),
    (
        "token_text.rs",
        "allocate_exact_size(Vec2::new(width, row_h), Sense::click())",
        "a line of code; every name in it has its own tooltip",
    ),
    (
        "hex_view.rs",
        "Sense::click_and_drag()",
        "the bytes themselves; the Hex tab tooltip and help explain them",
    ),
];

fn allowed(file: &str, line: &str) -> bool {
    ALLOWED
        .iter()
        .any(|(f, l, _)| file.ends_with(f) && line.contains(l))
}

fn sources(dir: &Path, out: &mut Vec<(PathBuf, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for e in entries.flatten() {
        let path = e.path();
        let name = e.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if name != "tests" {
                sources(&path, out);
            }
        } else if name.ends_with(".rs")
            && name != "tests.rs"
            && let Ok(text) = std::fs::read_to_string(&path)
        {
            out.push((path, text));
        }
    }
}

/// Every source file of the GUI and its widgets, without test code.
fn all_sources() -> Vec<(PathBuf, Vec<String>)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut files = Vec::new();
    sources(&root.join("src"), &mut files);
    sources(&root.join("../kraken-gui-widgets/src"), &mut files);
    assert!(files.len() > 20, "found only {} source files", files.len());
    files
        .into_iter()
        .map(|(p, t)| {
            let mut lines: Vec<String> = t.lines().map(str::to_string).collect();
            if let Some(i) = lines.iter().position(|l| l.starts_with("#[cfg(test)]")) {
                lines.truncate(i);
            }
            (p, lines)
        })
        .collect()
}

/// The statement that starts at line `i`: up to where the parentheses balance and the line ends
/// with `;`, `{` or `},`. Returns its text and the index of its last line.
fn statement(lines: &[String], i: usize) -> (String, usize) {
    let mut text = lines[i].clone();
    let mut depth = lines[i].matches('(').count() as i64 - lines[i].matches(')').count() as i64;
    let mut j = i;
    loop {
        let s = lines[j].trim_end();
        if depth <= 0 && (s.ends_with(';') || s.ends_with('{') || s.ends_with("},")) {
            break;
        }
        if j + 1 >= lines.len() || j > i + 30 {
            break;
        }
        j += 1;
        text.push('\n');
        text.push_str(&lines[j]);
        depth += lines[j].matches('(').count() as i64 - lines[j].matches(')').count() as i64;
    }
    (text, j)
}

/// Lines (1-based, with their text) that match one of `patterns` but whose statement, or the
/// `after` lines following it, lacks `needle`.
fn missing(
    file: &str,
    lines: &[String],
    patterns: &[&str],
    needle: &str,
    after: usize,
) -> Vec<String> {
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if t.starts_with("//") || t.contains("fn primary_button") {
            continue;
        }
        if !patterns.iter().any(|p| line.contains(p)) || allowed(file, line) {
            continue;
        }
        let (text, end) = statement(lines, i);
        if text.contains(needle) {
            continue;
        }
        let binds = t.starts_with("let ")
            || t.starts_with("egui::")
            || t.starts_with("ui.add_enabled(")
            || t.starts_with('.');
        let next = lines[end + 1..lines.len().min(end + 1 + after)].join("\n");
        if binds && next.contains(needle) {
            continue;
        }
        out.push(format!("{file}:{}: {}", i + 1, t.trim_end()));
    }
    out
}

/// Click areas: hover text must be within a few lines before or after.
fn click_areas_without_hover(file: &str, lines: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if t.starts_with("//") || !(line.contains("Sense::click") || line.contains(".sense(")) {
            continue;
        }
        if allowed(file, line) {
            continue;
        }
        let from = i.saturating_sub(8);
        let to = lines.len().min(i + 26);
        if !lines[from..to].iter().any(|l| l.contains("hover")) {
            out.push(format!("{file}:{}: {}", i + 1, t.trim_end()));
        }
    }
    out
}

fn report(rule: &str, found: Vec<String>) {
    assert!(
        found.is_empty(),
        "{rule}\n{}\n\nAdd the hover text, or list the place in ALLOWED in tests/audit.rs with the reason.",
        found.join("\n")
    );
}

#[test]
fn every_widget_a_person_can_click_has_hover_text() {
    let mut found = Vec::new();
    for (path, lines) in all_sources() {
        let file = path.to_string_lossy().into_owned();
        found.extend(missing(&file, &lines, WIDGETS, "hover", 8));
        found.extend(click_areas_without_hover(&file, &lines));
    }
    report("These widgets have no hover text:", found);
}

#[test]
fn every_widget_that_can_be_off_says_why() {
    let mut found = Vec::new();
    for (path, lines) in all_sources() {
        let file = path.to_string_lossy().into_owned();
        found.extend(missing(
            &file,
            &lines,
            &[".add_enabled("],
            "disabled_hover",
            6,
        ));
    }
    report(
        "These widgets can be disabled but give no reason (use on_disabled_hover_text):",
        found,
    );
}

#[test]
fn the_scan_notices_a_button_without_hover_text() {
    let lines: Vec<String> = [
        "fn f(ui: &mut Ui) {",
        "    if ui.button(\"Save\").clicked() {",
        "        save();",
        "    }",
        "    if ui",
        "        .button(\"Load\")",
        "        .on_hover_text(\"Load it\")",
        "        .clicked()",
        "    {",
        "        load();",
        "    }",
        "    let r = ui.checkbox(&mut on, \"Wrap\");",
        "    r.on_hover_text(\"Wrap long lines\");",
        "}",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    let found = missing("x.rs", &lines, WIDGETS, "hover", 8);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].contains("Save"));
}
