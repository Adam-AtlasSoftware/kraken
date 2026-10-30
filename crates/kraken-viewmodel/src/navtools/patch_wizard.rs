//! "Change what this code does...": a guided way to patch. Five steps on the wizard framework:
//! where (an instruction or decompiler line), what to do (skip a call, always or never take a
//! branch, return a value, change a constant, or write assembly), a preview (the instructions and
//! the decompiled C before and after, with the patch checks), an optional test run with inputs,
//! and Save into a named patch set with an optional exported copy or patch file.
//!
//! The commands behind the preview need the patch staged, so the wizard stages one draft patch
//! when the preview opens and takes it out again on Back or Cancel; Save keeps it and moves it
//! into the set. Nothing reaches the disk before the export checkboxes of the last step.

use kraken_proto::FlowKind;
use serde::Deserialize;
use serde_json::{Value, json};

use super::patch_intents::{IntentPreview, parse_number};
use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, hex};
use crate::wizard::WizardFlow;

/// The steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchStep {
    /// Where.
    Pick,
    /// What to do there.
    Intent,
    /// What it would look like.
    Preview,
    /// Optional test run.
    Test,
    /// Name the set and export.
    Save,
}

/// What the person wants the code to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardIntent {
    /// NOP the call instruction.
    SkipCall,
    /// The conditional branch always jumps.
    AlwaysTake,
    /// The conditional branch never jumps.
    NeverTake,
    /// The function returns a number at once.
    ReturnValue,
    /// The immediate operand of the instruction changes.
    ChangeConstant,
    /// The instructions are replaced by assembly.
    Assembly,
}

impl WizardIntent {
    /// Every intent, in the order the cards show.
    pub const ALL: [WizardIntent; 6] = [
        WizardIntent::SkipCall,
        WizardIntent::AlwaysTake,
        WizardIntent::NeverTake,
        WizardIntent::ReturnValue,
        WizardIntent::ChangeConstant,
        WizardIntent::Assembly,
    ];

    /// The card's title.
    pub fn title(self) -> &'static str {
        match self {
            WizardIntent::SkipCall => "Skip this call",
            WizardIntent::AlwaysTake => "Always take this branch",
            WizardIntent::NeverTake => "Never take this branch",
            WizardIntent::ReturnValue => "Return a value",
            WizardIntent::ChangeConstant => "Change this constant",
            WizardIntent::Assembly => "Write assembly",
        }
    }

    /// One line on what it does.
    pub fn blurb(self) -> &'static str {
        match self {
            WizardIntent::SkipCall => "The call does nothing: the instruction is replaced by NOPs.",
            WizardIntent::AlwaysTake => "The check always passes the same way: it becomes a jump.",
            WizardIntent::NeverTake => "The branch is removed: execution always falls through.",
            WizardIntent::ReturnValue => {
                "The function returns a number as soon as it is called (the function entry is patched)."
            }
            WizardIntent::ChangeConstant => "The number inside this instruction becomes another.",
            WizardIntent::Assembly => "Type the new instructions yourself.",
        }
    }

    /// Whether it asks for a number.
    pub fn takes_value(self) -> bool {
        matches!(
            self,
            WizardIntent::ReturnValue | WizardIntent::ChangeConstant
        )
    }

    fn cli_name(self) -> &'static str {
        match self {
            WizardIntent::SkipCall => "patch-nop",
            WizardIntent::AlwaysTake | WizardIntent::NeverTake => "patch-branch",
            WizardIntent::ReturnValue => "patch-return",
            WizardIntent::ChangeConstant => "patch-constant",
            WizardIntent::Assembly => "patch-asm",
        }
    }
}

/// The instruction the person picked, as far as the Listing knows it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pick {
    /// Its address.
    pub address: u64,
    /// `mnemonic operands`, when the Listing has the row.
    pub text: Option<String>,
    /// Its bytes, spaced hex.
    pub bytes: Option<String>,
    /// How control leaves it.
    pub flow: Option<FlowKind>,
    /// The function around it: entry and name.
    pub function: Option<(u64, String)>,
}

/// Where the draft patch stands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Draft {
    /// No draft is staged.
    None,
    /// Being staged.
    Staging,
    /// Staged at this address.
    Staged(u64),
    /// Staging failed; the reason.
    Failed(String),
}

/// Decompiled text on one side of the preview.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CText {
    /// Not asked for.
    #[default]
    Idle,
    /// Being decompiled.
    Loading,
    /// The text.
    Ready(String),
    /// Why there is none.
    Failed(String),
}

/// One patch-check finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LintLine {
    /// `warning` or `info`.
    pub severity: String,
    /// What it means.
    pub message: String,
}

/// The test step.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TestPanel {
    /// Command-line arguments, separated by spaces.
    pub argv: String,
    /// Standard input.
    pub stdin: String,
    /// A run is going.
    pub running: bool,
    /// The last result: did both programs behave the same, and the first difference.
    pub result: Option<(bool, String)>,
    /// Why the run failed.
    pub error: Option<String>,
}

#[derive(Debug)]
enum Todo {
    Stage,
    Discard(u64),
    Verify,
    Save,
}

/// The wizard's state.
#[derive(Debug)]
pub struct PatchWizard {
    step: PatchStep,
    /// The address as typed on the first step.
    pub address_text: String,
    /// What is known about it.
    pub pick: Option<Pick>,
    /// The chosen intent.
    pub intent: Option<WizardIntent>,
    /// The number of Return a value and Change this constant, as typed.
    pub value: String,
    /// The assembly, as typed.
    pub asm: String,
    /// The draft patch.
    pub draft: Draft,
    /// What the backend says the draft writes.
    pub preview: Option<IntentPreview>,
    /// The function's C as it is.
    pub c_before: CText,
    /// The function's C with the patch.
    pub c_after: CText,
    /// What `patch_lint` found; `None` while it is running.
    pub lint: Option<Vec<LintLine>>,
    /// The test step.
    pub test: TestPanel,
    /// The patch set to save into.
    pub set_name: String,
    /// What the set is for.
    pub set_note: String,
    /// Also write a patched copy of the program.
    pub export_binary: bool,
    /// Where the copy goes.
    pub binary_path: String,
    /// Also write a patch file.
    pub export_diff: bool,
    /// Where the patch file goes; its extension picks the format.
    pub diff_path: String,
    /// Save is running.
    pub saving: bool,
    /// Why the last save failed.
    pub error: Option<String>,
    name_touched: bool,
    discarding: u32,
    taken: Vec<u64>,
    todo: Vec<Todo>,
    seq: u64,
}

impl PatchWizard {
    fn new(address: Option<u64>) -> Self {
        PatchWizard {
            step: PatchStep::Pick,
            address_text: address.map(hex).unwrap_or_default(),
            pick: None,
            intent: None,
            value: "0".into(),
            asm: String::new(),
            draft: Draft::None,
            preview: None,
            c_before: CText::Idle,
            c_after: CText::Idle,
            lint: None,
            test: TestPanel::default(),
            set_name: String::new(),
            set_note: String::new(),
            export_binary: false,
            binary_path: String::new(),
            export_diff: false,
            diff_path: String::new(),
            saving: false,
            error: None,
            name_touched: false,
            discarding: 0,
            taken: Vec::new(),
            todo: Vec::new(),
            seq: 0,
        }
    }

    /// Why `intent` cannot be used on the picked instruction, when that is clear.
    pub fn unavailable(&self, intent: WizardIntent) -> Option<&'static str> {
        let pick = self.pick.as_ref()?;
        match intent {
            WizardIntent::SkipCall => match pick.flow {
                Some(FlowKind::Call) | None => None,
                Some(_) => Some("This instruction is not a call."),
            },
            WizardIntent::AlwaysTake | WizardIntent::NeverTake => match pick.flow {
                Some(FlowKind::ConditionalJump) | None => None,
                Some(_) => Some("This instruction is not a conditional branch."),
            },
            WizardIntent::ReturnValue => pick
                .function
                .is_none()
                .then_some("This address is not inside a known function."),
            WizardIntent::ChangeConstant | WizardIntent::Assembly => None,
        }
    }

    /// The address the patch is written at: the function entry for Return a value.
    pub fn target(&self) -> Option<u64> {
        let pick = self.pick.as_ref()?;
        match self.intent? {
            WizardIntent::ReturnValue => pick.function.as_ref().map(|f| f.0),
            _ => Some(pick.address),
        }
    }

    fn request(&self, preview: bool) -> Result<(&'static str, Value), String> {
        let intent = self.intent.ok_or("Choose what the code should do.")?;
        let at = hex(self.target().ok_or("Pick an instruction first.")?);
        let number = || {
            parse_number(self.value.trim())
                .ok_or_else(|| "The value is a number such as 0, 1, -1 or 0x10.".to_string())
        };
        let note = "changed with the Change what this code does wizard";
        Ok(match intent {
            WizardIntent::SkipCall => (
                "patch_nop",
                json!({"address": at, "count": 1, "note": note, "preview": preview}),
            ),
            WizardIntent::AlwaysTake | WizardIntent::NeverTake => (
                "patch_branch",
                json!({
                    "address": at,
                    "mode": if intent == WizardIntent::AlwaysTake { "always" } else { "never" },
                    "note": note,
                    "preview": preview
                }),
            ),
            WizardIntent::ReturnValue => (
                "patch_return",
                json!({"address": at, "value": number()?, "note": note, "preview": preview}),
            ),
            WizardIntent::ChangeConstant => (
                "patch_constant",
                json!({"address": at, "value": number()?, "note": note, "preview": preview}),
            ),
            WizardIntent::Assembly => {
                let text = self.asm.trim();
                if text.is_empty() {
                    return Err("Type at least one instruction.".into());
                }
                (
                    "patch_asm",
                    json!({"address": at, "text": text, "note": note, "preview": preview}),
                )
            }
        })
    }

    fn function_address(&self) -> Option<u64> {
        let p = self.pick.as_ref()?;
        Some(p.function.as_ref().map_or(p.address, |f| f.0))
    }

    fn default_name(&self) -> String {
        let (Some(i), Some(p)) = (self.intent, self.pick.as_ref()) else {
            return "My patch".into();
        };
        match &p.function {
            Some((_, n)) => format!("{} in {n}", i.title()),
            None => format!("{} at {}", i.title(), hex(p.address)),
        }
    }

    fn order(step: PatchStep) -> u8 {
        match step {
            PatchStep::Pick => 0,
            PatchStep::Intent => 1,
            PatchStep::Preview => 2,
            PatchStep::Test => 3,
            PatchStep::Save => 4,
        }
    }

    /// Takes the draft out when the person goes back before the preview.
    fn drop_draft(&mut self) {
        match std::mem::replace(&mut self.draft, Draft::None) {
            Draft::Staged(a) => self.todo.push(Todo::Discard(a)),
            Draft::Staging => {}
            _ => {}
        }
        self.seq += 1;
        self.preview = None;
        self.c_before = CText::Idle;
        self.c_after = CText::Idle;
        self.lint = None;
        self.test = TestPanel {
            argv: std::mem::take(&mut self.test.argv),
            stdin: std::mem::take(&mut self.test.stdin),
            ..TestPanel::default()
        };
    }
}

impl WizardFlow for PatchWizard {
    type Step = PatchStep;
    const ID: &'static str = "patch";

    fn steps(&self) -> Vec<PatchStep> {
        vec![
            PatchStep::Pick,
            PatchStep::Intent,
            PatchStep::Preview,
            PatchStep::Test,
            PatchStep::Save,
        ]
    }

    fn current(&self) -> PatchStep {
        self.step
    }

    fn set_current(&mut self, step: PatchStep) {
        if Self::order(step) < Self::order(PatchStep::Preview)
            && Self::order(self.step) >= Self::order(PatchStep::Preview)
        {
            self.drop_draft();
        }
        self.step = step;
    }

    fn title(&self, step: PatchStep) -> &'static str {
        match step {
            PatchStep::Pick => "Where",
            PatchStep::Intent => "What",
            PatchStep::Preview => "Preview",
            PatchStep::Test => "Test",
            PatchStep::Save => "Save",
        }
    }

    fn explain(&self, step: PatchStep) -> &'static str {
        match step {
            PatchStep::Pick => {
                "Which instruction to change. It comes from your selection in the Listing or the Decompiler; you can also type an address."
            }
            PatchStep::Intent => "What the code should do instead. Nothing is changed yet.",
            PatchStep::Preview => {
                "The instructions and the C before and after, and what the patch checks found. A draft patch is staged for this and removed again if you go back or cancel."
            }
            PatchStep::Test => {
                "Optional: run the original and the patched program in the emulator on the same input and compare."
            }
            PatchStep::Save => {
                "Keep the patch in a named set. You can also write a patched copy of the program or a patch file now."
            }
        }
    }

    fn blocker(&self) -> Option<String> {
        if self.saving {
            return Some("Saving...".into());
        }
        if self.discarding > 0 {
            return Some("Taking the draft patch out...".into());
        }
        match self.step {
            PatchStep::Pick => match &self.pick {
                None => {
                    Some("Type an address such as 0x401136, or pick an instruction first.".into())
                }
                Some(p) if self.taken.contains(&p.address) => Some(
                    "There is already a patch at this address. Remove it in the Patches tab first."
                        .into(),
                ),
                Some(_) => None,
            },
            PatchStep::Intent => {
                let Some(i) = self.intent else {
                    return Some("Choose what the code should do.".into());
                };
                if let Some(why) = self.unavailable(i) {
                    return Some(why.into());
                }
                if let Some(t) = self.target().filter(|t| self.taken.contains(t)) {
                    return Some(format!(
                        "There is already a patch at {}. Remove it in the Patches tab first.",
                        hex(t)
                    ));
                }
                self.request(true).err()
            }
            PatchStep::Preview => match &self.draft {
                Draft::Staged(_) => None,
                Draft::Failed(e) => Some(format!("The patch could not be made: {e}")),
                _ => Some("Working out the patch...".into()),
            },
            PatchStep::Test => self.test.running.then(|| "The test is running...".into()),
            PatchStep::Save => {
                let n = self.set_name.trim();
                if n.is_empty() || n.chars().count() > 60 {
                    Some("Give the set a name of up to 60 characters.".into())
                } else if self.export_binary && self.binary_path.trim().is_empty() {
                    Some("Type where to write the patched copy, or switch that off.".into())
                } else if self.export_diff && self.diff_path.trim().is_empty() {
                    Some("Type where to write the patch file, or switch that off.".into())
                } else {
                    None
                }
            }
        }
    }

    fn leave(&mut self, step: PatchStep) {
        match step {
            PatchStep::Intent => {
                self.todo.push(Todo::Stage);
                self.draft = Draft::Staging;
                if !self.name_touched {
                    self.set_name = self.default_name();
                }
            }
            PatchStep::Save => self.todo.push(Todo::Save),
            _ => {}
        }
    }

    fn finish_label(&self) -> &'static str {
        "Save"
    }

    fn commands(&self) -> Vec<String> {
        let (Some(i), Ok((_, args))) = (self.intent, self.request(false)) else {
            return Vec::new();
        };
        let mut flags = String::new();
        if let Some(o) = args.as_object() {
            for (k, v) in o {
                if matches!(k.as_str(), "preview" | "note") {
                    continue;
                }
                let v = match v {
                    Value::String(s) => format!("{s:?}"),
                    other => other.to_string(),
                };
                flags.push_str(&format!(" --{} {v}", k.replace('_', "-")));
            }
        }
        let name = self.set_name.trim();
        let mut out = vec![format!("kraken {}{flags}", i.cli_name())];
        if let Some(t) = self.target() {
            out.push(format!("kraken patch-group-set --name {name:?}"));
            out.push(format!(
                "kraken patch-group-assign --group {name:?} --addresses '[\"{}\"]'",
                hex(t)
            ));
        }
        if self.export_binary {
            out.push(format!(
                "kraken patch-export --output-path {:?} --group {name:?}",
                self.binary_path.trim()
            ));
        }
        if self.export_diff {
            out.push(format!(
                "kraken patch-export-diff --output-path {:?} --group {name:?}",
                self.diff_path.trim()
            ));
        }
        out
    }
}

/// Plain text of a wire value: a string, or the `value` of an untrusted wrapper.
fn text_of(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other
            .get("value")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string(),
    }
}

#[derive(Deserialize)]
struct LintWire {
    #[serde(default)]
    findings: Vec<Value>,
}

impl ViewModel {
    /// Opens the wizard on `address`; without one it takes the selected Listing row, or the
    /// function on show.
    pub fn begin_patch_wizard(&mut self, address: Option<u64>) {
        let address = address
            .or_else(|| self.views.listing.selected_row().map(|r| r.address))
            .or_else(|| self.current.as_ref().map(|c| c.address));
        self.ensure_patches();
        self.tools.patch_wizard = Some(PatchWizard::new(address));
        self.drive_patch_wizard();
    }

    /// Moves to the next step (or saves on the last), then does the work the step asks for.
    pub fn patch_wizard_next(&mut self) -> crate::wizard::WizardNav {
        self.drive_patch_wizard();
        let Some(w) = self.tools.patch_wizard.as_mut() else {
            return crate::wizard::WizardNav::Blocked("The wizard is not open.".into());
        };
        let nav = crate::wizard::next(w);
        self.drive_patch_wizard();
        nav
    }

    /// Goes back one step; leaving the preview takes the draft patch out.
    pub fn patch_wizard_back(&mut self) {
        if let Some(w) = self.tools.patch_wizard.as_mut() {
            crate::wizard::back(w);
        }
        self.drive_patch_wizard();
    }

    /// Closes the wizard and removes the draft patch.
    pub fn cancel_patch_wizard(&mut self) {
        if let Some(mut w) = self.tools.patch_wizard.take() {
            w.drop_draft();
            for t in w.todo.drain(..) {
                if let Todo::Discard(a) = t {
                    self.discard_draft(a);
                }
            }
        }
    }

    /// Reads the wizard's address and does the work its steps asked for. The window calls it
    /// every frame.
    pub fn drive_patch_wizard(&mut self) {
        let items: Vec<u64> = self.tools.patches.items.iter().map(|p| p.address).collect();
        let Some(w) = self.tools.patch_wizard.as_mut() else {
            return;
        };
        let draft = match &w.draft {
            Draft::Staged(a) => Some(*a),
            _ => None,
        };
        w.taken = items.into_iter().filter(|a| Some(*a) != draft).collect();
        let typed = super::parse_address(&w.address_text);
        if typed != w.pick.as_ref().map(|p| p.address) {
            let pick = typed.map(|a| self.resolve_pick(a));
            if let Some(w) = self.tools.patch_wizard.as_mut() {
                w.pick = pick;
            }
        }
        let Some(w) = self.tools.patch_wizard.as_mut() else {
            return;
        };
        let todo = std::mem::take(&mut w.todo);
        for t in todo {
            match t {
                Todo::Stage => self.wizard_stage(),
                Todo::Discard(a) => {
                    if let Some(w) = self.tools.patch_wizard.as_mut() {
                        w.discarding += 1;
                    }
                    self.discard_draft(a);
                }
                Todo::Verify => self.wizard_verify(),
                Todo::Save => self.wizard_save(),
            }
        }
    }

    /// Starts the test run of step four.
    pub fn patch_wizard_run_test(&mut self) {
        if let Some(w) = self.tools.patch_wizard.as_mut() {
            w.todo.push(Todo::Verify);
        }
        self.drive_patch_wizard();
    }

    fn resolve_pick(&self, address: u64) -> Pick {
        let row = self
            .views
            .listing
            .rows
            .iter()
            .find(|r| r.address == address);
        Pick {
            address,
            text: row.map(|r| {
                let ops: String = r.operands.iter().map(|o| o.text.as_str()).collect();
                format!("{} {ops}", r.mnemonic).trim().to_string()
            }),
            bytes: row.map(|r| super::spaced_hex(&r.bytes)),
            flow: row.map(|r| r.flow),
            function: self
                .functions
                .containing(address)
                .map(|f| (f.address, f.name.clone())),
        }
    }

    fn discard_draft(&mut self, address: u64) {
        self.call(
            "patch_remove",
            json!({"address": hex(address)}),
            |vm, res| {
                if let Some(w) = vm.tools.patch_wizard.as_mut() {
                    w.discarding = w.discarding.saturating_sub(1);
                }
                if let Err(e) = res {
                    vm.toast_error(&e);
                }
                vm.refresh_patches();
                vm.refresh_history();
            },
        );
    }

    fn wizard_stage(&mut self) {
        let Some(w) = self.tools.patch_wizard.as_mut() else {
            return;
        };
        let (cmd, args) = match w.request(false) {
            Ok(r) => r,
            Err(e) => {
                w.draft = Draft::Failed(e);
                return;
            }
        };
        w.seq += 1;
        let seq = w.seq;
        w.draft = Draft::Staging;
        w.c_before = CText::Loading;
        w.c_after = CText::Loading;
        w.lint = None;
        let function = w.function_address();
        self.call(cmd, args, move |vm, res| {
            let staged = res.and_then(|v| {
                let at = v
                    .get("address")
                    .and_then(Value::as_str)
                    .and_then(super::parse_address)
                    .ok_or_else(|| {
                        kraken_proto::ProtoError::new(
                            kraken_proto::ErrorCode::Internal,
                            "the patch command did not say where it wrote",
                        )
                    })?;
                let pv = serde_json::from_value::<IntentPreview>(v).ok();
                Ok((at, pv))
            });
            let live = vm.tools.patch_wizard.as_ref().is_some_and(|w| w.seq == seq);
            match staged {
                Ok((at, _)) if !live => vm.discard_draft(at),
                Ok((at, pv)) => {
                    if let Some(w) = vm.tools.patch_wizard.as_mut() {
                        w.draft = Draft::Staged(at);
                        w.preview = pv;
                    }
                    vm.refresh_patches();
                    vm.refresh_history();
                    vm.wizard_after_stage(seq, function);
                }
                Err(e) => {
                    if let Some(w) = vm.tools.patch_wizard.as_mut().filter(|w| w.seq == seq) {
                        w.draft = Draft::Failed(plain_error(&e));
                        w.c_before = CText::Idle;
                        w.c_after = CText::Idle;
                    }
                }
            }
        });
    }

    /// The draft is in: the C before and after, and the patch checks.
    fn wizard_after_stage(&mut self, seq: u64, function: Option<u64>) {
        let mut texts = vec![("decompile", false), ("decompile_patched", true)];
        let f = match function {
            Some(f) => f,
            None => {
                if let Some(w) = self.tools.patch_wizard.as_mut() {
                    let none = CText::Failed("This address is not inside a known function.".into());
                    (w.c_before, w.c_after) = (none.clone(), none);
                }
                texts.clear();
                0
            }
        };
        for (cmd, after) in texts {
            self.call(cmd, json!({"address": hex(f)}), move |vm, res| {
                let Some(w) = vm.tools.patch_wizard.as_mut().filter(|w| w.seq == seq) else {
                    return;
                };
                let t = match res {
                    Ok(v) => CText::Ready(v.get("text").map(text_of).unwrap_or_default()),
                    Err(e) => CText::Failed(plain_error(&e)),
                };
                if after {
                    w.c_after = t;
                } else {
                    w.c_before = t;
                }
            });
        }
        self.call("patch_lint", json!({}), move |vm, res| {
            let Some(w) = vm.tools.patch_wizard.as_mut().filter(|w| w.seq == seq) else {
                return;
            };
            w.lint = Some(match res.and_then(crate::vm::parse::<LintWire>) {
                Ok(l) => l
                    .findings
                    .iter()
                    .map(|f| LintLine {
                        severity: f
                            .get("severity")
                            .and_then(Value::as_str)
                            .unwrap_or("info")
                            .to_string(),
                        message: f
                            .get("message")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_string(),
                    })
                    .collect(),
                Err(e) => vec![LintLine {
                    severity: "info".into(),
                    message: format!("The patch check did not run: {}", plain_error(&e)),
                }],
            });
        });
    }

    fn wizard_verify(&mut self) {
        let Some(w) = self.tools.patch_wizard.as_mut() else {
            return;
        };
        if w.test.running {
            return;
        }
        w.test.running = true;
        w.test.result = None;
        w.test.error = None;
        let seq = w.seq;
        let argv: Vec<&str> = w.test.argv.split_whitespace().collect();
        let args = json!({"argv": argv, "stdin": w.test.stdin});
        self.call("patch_verify", args, move |vm, res| {
            let Some(w) = vm.tools.patch_wizard.as_mut().filter(|w| w.seq == seq) else {
                return;
            };
            w.test.running = false;
            match res {
                Ok(v) => {
                    let same = v.get("same").and_then(Value::as_bool).unwrap_or(false);
                    let first = v.get("first_divergence").map(text_of).unwrap_or_default();
                    w.test.result = Some((same, first));
                }
                Err(e) => w.test.error = Some(plain_error(&e)),
            }
        });
    }

    fn wizard_save(&mut self) {
        let Some(w) = self.tools.patch_wizard.as_mut() else {
            return;
        };
        let Draft::Staged(at) = w.draft else {
            return;
        };
        w.saving = true;
        w.error = None;
        let name = w.set_name.trim().to_string();
        let mut set = json!({"name": name});
        if !w.set_note.trim().is_empty() {
            set["description"] = json!(w.set_note.trim());
        }
        let mut steps = vec![
            ("patch_group_set", set),
            (
                "patch_group_assign",
                json!({"group": name, "addresses": [hex(at)]}),
            ),
        ];
        if w.export_binary {
            steps.push((
                "patch_export",
                json!({"output_path": w.binary_path.trim(), "group": name}),
            ));
        }
        if w.export_diff {
            steps.push((
                "patch_export_diff",
                json!({"output_path": w.diff_path.trim(), "group": name}),
            ));
        }
        let seq = w.seq;
        self.wizard_chain(seq, steps, name);
    }

    /// Runs the save commands one after the other; the first failure stops with its reason.
    fn wizard_chain(&mut self, seq: u64, mut steps: Vec<(&'static str, Value)>, name: String) {
        if steps.is_empty() {
            self.tools.patch_wizard = None;
            self.toast(
                ToastLevel::Success,
                format!("Saved the patch set \"{name}\". Undo it from the History."),
            );
            self.refresh_patches();
            self.refresh_history();
            return;
        }
        let (cmd, args) = steps.remove(0);
        self.call(cmd, args, move |vm, res| {
            if !vm.tools.patch_wizard.as_ref().is_some_and(|w| w.seq == seq) {
                return;
            }
            match res {
                Ok(_) => vm.wizard_chain(seq, steps, name),
                Err(e) => {
                    if let Some(w) = vm.tools.patch_wizard.as_mut() {
                        w.saving = false;
                        w.error = Some(format!("{cmd} failed: {}", plain_error(&e)));
                    }
                    vm.refresh_patches();
                }
            }
        });
    }
}

impl PatchWizard {
    /// Asks for the test run of step four; the window's next frame starts it.
    pub fn request_test(&mut self) {
        self.todo.push(Todo::Verify);
    }

    /// Marks the set name as typed by the person, so a new intent does not overwrite it.
    pub fn touch_name(&mut self) {
        self.name_touched = true;
    }
}
