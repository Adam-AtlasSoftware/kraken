//! AI work in the window: the chip in the top bar and the status bar while it runs, the AI
//! Activity tab with a Stop button per piece of work, and the question asked before AI work
//! starts.

use egui::{Id, RichText, Sense, Ui};
use kraken_proto::{AiJobStatus, AiJobView, AiOrigin, AiProviderKind, money, short_count};
use kraken_viewmodel::ViewModel;
use kraken_viewmodel::ai::{AiChip, AiConfirm};

use crate::style::{self, chip, medium, pal};
use crate::workspace::{Tab, UiState};

const OPEN_ACTIVITY: &str = "kraken_ai_open_activity";

/// What the confirmation question remembers between frames.
#[derive(Debug, Clone, Default)]
pub struct ConfirmUi {
    /// "Do not ask again for runs under ..." is ticked.
    pub skip: bool,
    /// The amount typed for it.
    pub amount: String,
}

/// The hover text of the chip.
pub fn chip_hover(c: &AiChip) -> String {
    let mut t = format!(
        "AI work is running: {}. It asks {} and has made {} model call{} so far ({}). ",
        c.feature,
        if c.model.is_empty() {
            "a model that has not said its name yet".to_string()
        } else {
            c.model.clone()
        },
        c.calls,
        if c.calls == 1 { "" } else { "s" },
        c.cost
    );
    if c.running > 1 {
        t.push_str(&format!("{} pieces of AI work run at once. ", c.running));
    }
    t.push_str("Click to see all AI work and stop it.");
    t
}

fn draw_chip(ui: &mut Ui, vm: &ViewModel, compact: bool) {
    let Some(c) = vm.ai_chip() else {
        return;
    };
    ui.ctx()
        .request_repaint_after(std::time::Duration::from_millis(700));
    let s = style::status(style::dark(ui));
    let color = if c.cost.contains('$') {
        s.warning
    } else {
        s.info
    };
    let text = if compact {
        format!(
            "AI: {} call{}",
            c.calls,
            if c.calls == 1 { "" } else { "s" }
        )
    } else {
        c.text()
    };
    let response = chip(ui, &text, color)
        .interact(Sense::click())
        .on_hover_text(chip_hover(&c))
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    if response.clicked() {
        ui.ctx()
            .data_mut(|d| d.insert_temp(Id::new(OPEN_ACTIVITY), true));
    }
}

/// The chip in the top bar ("AI: Rust rewrite, claude-sonnet-5-5, 12 calls, about $0.31");
/// nothing when no AI work runs.
pub fn top_chip(ui: &mut Ui, vm: &ViewModel) {
    draw_chip(ui, vm, false);
}

/// The short chip in the status bar ("AI: 12 calls").
pub fn status_chip(ui: &mut Ui, vm: &ViewModel) {
    draw_chip(ui, vm, true);
}

/// Brings the AI Activity tab forward after a chip click, a toast button or the menu.
pub fn apply_requests(ctx: &egui::Context, vm: &mut ViewModel, state: &mut UiState) {
    let clicked = ctx.data_mut(|d| d.remove_temp::<bool>(Id::new(OPEN_ACTIVITY)));
    if clicked == Some(true) || std::mem::take(&mut vm.ai.show_requested) {
        vm.ai_refresh();
        state.bring_to_front = Some(Tab::AiActivity);
    }
}

fn who(j: &AiJobView) -> String {
    match j.origin {
        AiOrigin::Gui => "you".into(),
        AiOrigin::Cli => "you, from the command line".into(),
        AiOrigin::Agent if j.started_by.is_empty() => "an agent".into(),
        AiOrigin::Agent => format!("agent {}", j.started_by),
        AiOrigin::Other => "KRAKEN".into(),
    }
}

fn place(k: AiProviderKind) -> &'static str {
    match k {
        AiProviderKind::Api => "cloud API",
        AiProviderKind::Local => "on this computer",
        AiProviderKind::TerminalAgent => "terminal agent",
    }
}

fn elapsed(j: &AiJobView) -> String {
    let end = j.ended_ms.unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(j.started_ms)
    });
    let secs = (end - j.started_ms).max(0) / 1000;
    match secs {
        0..=59 => format!("{secs} s"),
        60..=3599 => format!("{} min", secs / 60),
        _ => format!("{} h {} min", secs / 3600, (secs % 3600) / 60),
    }
}

/// The AI Activity tab.
pub fn panel(ui: &mut Ui, vm: &mut ViewModel) {
    let p = pal(ui);
    let s = style::status(style::dark(ui));
    ui.add_space(4.0);
    ui.label(
        RichText::new(
            "Every piece of AI work on this project: rewrite jobs (started here, from the command line or by an agent) and the assistant's runs in this window. Money is an estimate.",
        )
        .size(12.0)
        .color(p.text_dim),
    );
    ui.horizontal_wrapped(|ui| {
        let today = vm.ai.today();
        let budget = vm.ai.policy.limits.daily_budget;
        let line = match budget {
            Some(b) => format!(
                "Today, all projects: {} of your {} daily budget.",
                today.cost_text(),
                money(b)
            ),
            None => format!("Today, all projects: {}.", today.line()),
        };
        ui.label(RichText::new(line).size(12.0).color(p.text))
            .on_hover_text(
                "Estimated from the tokens each provider reported and the price table. Set a daily budget in Settings > AI.",
            );
        if ui
            .small_button("Refresh")
            .on_hover_text("Ask the engine for the latest AI work now")
            .clicked()
        {
            vm.ai_refresh();
        }
    });
    let models = vm.ai.policy.models_line();
    ui.label(RichText::new(models).size(11.5).color(p.text_dim));
    ui.add_space(6.0);

    let rows = vm.ai_rows();
    if rows.is_empty() {
        style::empty_state(
            ui,
            "No AI work yet",
            "Rewrite jobs, Suggest names, explanations and Automate runs show here with their model and cost while they run.",
            Some("Nothing is sent to a model until you start AI work, and KRAKEN asks first."),
        );
        return;
    }
    let mut stop: Option<String> = None;
    egui::ScrollArea::vertical()
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("kraken_ai_activity")
                .num_columns(8)
                .striped(true)
                .spacing([12.0, 6.0])
                .show(ui, |ui| {
                    for h in ["What", "Model", "Started by", "Status", "Calls", "Tokens", "Cost", ""] {
                        ui.label(RichText::new(h).size(11.5).strong().color(p.text_dim));
                    }
                    ui.end_row();
                    for j in &rows {
                        let running = !j.status.is_terminal();
                        ui.horizontal(|ui| {
                            if running {
                                ui.spinner();
                            }
                            ui.label(medium(j.feature.label(), 12.5).color(p.text_strong));
                            ui.label(RichText::new(&j.label).size(12.0).color(p.text));
                        });
                        ui.label(RichText::new(j.model_label()).size(12.0).monospace())
                            .on_hover_text(format!("{} ({})", j.provider, place(j.provider_kind)));
                        ui.label(RichText::new(who(j)).size(12.0));
                        let (word, color) = match j.status {
                            AiJobStatus::Running => ("running", s.info),
                            AiJobStatus::Succeeded => ("finished", s.success),
                            AiJobStatus::Failed => ("failed", s.danger),
                            AiJobStatus::Cancelled => ("stopped", p.text_dim),
                            AiJobStatus::Limited => ("stopped at limit", s.warning),
                        };
                        let r = chip(ui, &format!("{word}, {}", elapsed(j)), color);
                        if let Some(m) = &j.message {
                            r.on_hover_text(m);
                        }
                        ui.label(j.usage.calls.to_string());
                        let tokens = j.usage.input_tokens + j.usage.output_tokens;
                        ui.label(if tokens == 0 && j.provider_kind == AiProviderKind::TerminalAgent {
                            "not reported".to_string()
                        } else {
                            short_count(tokens)
                        });
                        ui.label(j.usage.cost_text());
                        let r = ui
                            .add_enabled(running, egui::Button::new("Stop"))
                            .on_hover_text(
                                "Stop this AI work. What it finished is kept; nothing more is sent to the model.",
                            )
                            .on_disabled_hover_text("This work has already ended.");
                        if r.clicked() {
                            stop = Some(j.id.clone());
                        }
                        ui.end_row();
                    }
                });
        });
    if let Some(id) = stop {
        vm.ai_stop(&id);
    }
}

/// What the person answered.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ConfirmAnswer {
    /// Start; and when set, stop asking for runs estimated below this many dollars.
    Start(Option<f64>),
    /// Do not start.
    Cancel,
}

/// The lines of the question.
pub fn confirm_lines(c: &AiConfirm) -> Vec<String> {
    let e = &c.estimate;
    let mut v = vec![
        format!(
            "Up to {} model call{}.",
            e.max_calls,
            if e.max_calls == 1 { "" } else { "s" }
        ),
        format!("Model: {}.", e.model_label()),
        format!("Cost: {}.", e.cost_text()),
    ];
    v.extend(c.notes.iter().cloned());
    v
}

/// The question asked before AI work starts; draws nothing when none waits.
pub fn confirm_dialog(
    ctx: &egui::Context,
    vm: &mut ViewModel,
    st: &mut ConfirmUi,
) -> Option<ConfirmAnswer> {
    let c = vm.ai.confirm.clone()?;
    let mut answer = None;
    let modal = egui::Modal::new(Id::new("kraken_ai_confirm")).show(ctx, |ui| {
        ui.set_width(460.0);
        ui.heading(c.action.title());
        ui.add_space(4.0);
        for line in confirm_lines(&c) {
            ui.label(RichText::new(line).size(13.0));
        }
        ui.add_space(6.0);
        if st.amount.is_empty() {
            st.amount = "0.10".into();
        }
        ui.horizontal(|ui| {
            ui.checkbox(&mut st.skip, "Do not ask again for runs under $")
                .on_hover_text(
                    "Start AI work without this question when its estimate stays below this amount. Saved in your KRAKEN config file (skip_confirm_under). Free local models never ask.",
                );
            ui.add_enabled(
                st.skip,
                egui::TextEdit::singleline(&mut st.amount).desired_width(60.0),
            )
            .on_hover_text("Amount in US dollars, for example 0.10")
            .on_disabled_hover_text("Tick the box to set an amount");
        });
        let amount = st.amount.trim().parse::<f64>().ok().filter(|a| *a >= 0.0);
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let can = !st.skip || amount.is_some();
            if ui
                .add_enabled(can, egui::Button::new("Start"))
                .on_hover_text("Start the AI work now")
                .on_disabled_hover_text("Type a valid amount, or untick the box")
                .clicked()
            {
                answer = Some(ConfirmAnswer::Start(if st.skip { amount } else { None }));
            }
            if ui
                .button("Cancel")
                .on_hover_text("Do not start anything")
                .clicked()
            {
                answer = Some(ConfirmAnswer::Cancel);
            }
        });
    });
    if answer.is_none() && modal.should_close() {
        answer = Some(ConfirmAnswer::Cancel);
    }
    match answer {
        Some(ConfirmAnswer::Start(_)) => vm.ai_confirm_yes(),
        Some(ConfirmAnswer::Cancel) => vm.ai_confirm_no(),
        None => {}
    }
    if answer.is_some() {
        st.skip = false;
    }
    answer
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use egui::{Context, Event, Modifiers, PointerButton, RawInput, Rect, Shape, pos2};
    use kraken_viewmodel::testing::FakeBackend;
    use kraken_viewmodel::{Connection, ViewModel};
    use serde_json::{Value, json};

    use super::*;

    const WAIT: Duration = Duration::from_secs(10);

    #[test]
    fn the_chip_says_what_runs_and_how_to_stop_it() {
        let c = AiChip {
            running: 2,
            feature: "Rust rewrite".into(),
            model: "claude-sonnet-5-5".into(),
            calls: 12,
            cost: "about $0.31 (estimate)".into(),
        };
        assert_eq!(
            c.text(),
            "AI: Rust rewrite (+1 more), claude-sonnet-5-5, 12 calls, about $0.31"
        );
        let h = chip_hover(&c);
        assert!(h.contains("12 model calls") && h.contains("stop"), "{h}");
    }

    fn project_json() -> Value {
        json!({
            "project_dir": "/work/proj", "binary_path": "/bin/demo", "binary_sha256": "00",
            "program": {"arch": "x86:LE:64", "format": "elf", "base": "0x400000", "sha256": "00", "size": 4096},
            "engine_build": "fake", "capabilities": [], "epoch": {}, "epoch_stale": false,
            "stale_fields": [], "analysis": {"phase": "complete", "function_count": 3},
            "pending_entries": 0, "log_entries": 0, "open_proposals": 0,
        })
    }

    fn running_job() -> Value {
        json!({"jobs": [{
            "id": "ai-1", "job_id": "job-7", "feature": "rewrite",
            "label": "Rewriting the whole program", "provider_kind": "api",
            "provider": "anthropic", "model": "claude-sonnet-5-5", "origin": "agent",
            "started_by": "claude-code", "status": "running", "started_ms": 1,
            "usage": {"calls": 3, "input_tokens": 12000, "output_tokens": 3000,
                      "wall_ms": 900, "cost_usd": 0.12}
        }], "running": 1})
    }

    struct Rig {
        ctx: Context,
        vm: ViewModel,
        backend: Arc<FakeBackend>,
        confirm: ConfirmUi,
        _rt: tokio::runtime::Runtime,
    }

    impl Rig {
        fn new() -> Rig {
            let rt = tokio::runtime::Runtime::new().expect("runtime");
            let backend = Arc::new(
                FakeBackend::new()
                    .reply("project_open", project_json())
                    .reply("project_info", project_json())
                    .reply("list_functions", json!({"items": []}))
                    .reply("history", json!({"items": []}))
                    .reply("proposals_list", json!({"items": []}))
                    .reply("ai_jobs", running_job())
                    .reply("job_cancel", json!({"job_id": "job-7", "command": "rewrite_program", "status": "running"})),
            );
            let mut vm = ViewModel::new(backend.clone(), rt.handle().clone());
            vm.open_project("/work/proj");
            assert!(vm.block_until_idle(WAIT));
            assert_eq!(vm.connection, Connection::Open);
            let ctx = Context::default();
            crate::fonts::install(&ctx);
            Rig {
                ctx,
                vm,
                backend,
                confirm: ConfirmUi::default(),
                _rt: rt,
            }
        }

        /// One frame of the top chip and the AI Activity tab; the text drawn and where.
        fn frame(&mut self, events: Vec<Event>) -> Vec<(String, egui::Pos2)> {
            self.vm.poll();
            let input = RawInput {
                screen_rect: Some(Rect::from_min_max(pos2(0.0, 0.0), pos2(1400.0, 800.0))),
                events,
                ..Default::default()
            };
            let (vm, confirm) = (&mut self.vm, &mut self.confirm);
            let mut out = self.ctx.run_ui(input, |root| {
                egui::Panel::top("top").show(root, |ui| top_chip(ui, vm));
                egui::CentralPanel::default().show(root, |ui| panel(ui, vm));
                confirm_dialog(root.ctx(), vm, confirm);
            });
            out.textures_delta.clear();
            let mut texts = Vec::new();
            fn walk(s: &Shape, out: &mut Vec<(String, egui::Pos2)>) {
                match s {
                    Shape::Text(t) => out.push((
                        t.galley.text().to_string(),
                        t.pos + t.galley.rect.center().to_vec2(),
                    )),
                    Shape::Vec(v) => v.iter().for_each(|s| walk(s, out)),
                    _ => {}
                }
            }
            for s in &out.shapes {
                walk(&s.shape, &mut texts);
            }
            texts
        }
    }

    #[test]
    fn the_chip_shows_running_ai_work_and_stop_in_the_activity_tab_cancels_its_job() {
        let mut r = Rig::new();
        // Nothing runs: no chip.
        assert!(r.vm.ai_chip().is_none());
        let t = r.frame(vec![]);
        assert!(!t.iter().any(|(s, _)| s.starts_with("AI: ")), "{t:?}");

        // An agent's rewrite job is running in the daemon.
        r.vm.ai_show_activity();
        assert!(r.vm.block_until(WAIT, |vm| !vm.ai.jobs.is_empty()));
        let t = r.frame(vec![]);
        let chip = t.iter().find(|(s, _)| s.starts_with("AI: ")).expect("chip");
        assert!(chip.0.contains("Rust rewrite"), "{}", chip.0);
        assert!(chip.0.contains("claude-sonnet-5-5"), "{}", chip.0);
        assert!(chip.0.contains("3 calls"), "{}", chip.0);
        assert!(chip.0.contains("$0.12"), "{}", chip.0);
        assert!(
            t.iter().any(|(s, _)| s.contains("agent claude-code")),
            "{t:?}"
        );
        let stop = t.iter().find(|(s, _)| s == "Stop").expect("Stop button").1;

        r.frame(vec![Event::PointerMoved(stop)]);
        for pressed in [true, false] {
            r.frame(vec![Event::PointerButton {
                pos: stop,
                button: PointerButton::Primary,
                pressed,
                modifiers: Modifiers::NONE,
            }]);
        }
        assert!(r.vm.block_until_idle(WAIT));
        let cancels = r.backend.calls_to("job_cancel");
        assert_eq!(cancels.len(), 1, "{:?}", r.backend.calls());
        assert_eq!(cancels[0]["job_id"], "job-7");

        // The daemon reports the end: the chip goes and a notice gives the totals.
        let mut done: kraken_proto::AiJobView =
            serde_json::from_value(running_job()["jobs"][0].clone()).expect("view");
        done.status = kraken_proto::AiJobStatus::Cancelled;
        done.ended_ms = Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_millis() as i64,
        );
        r.vm.on_event(kraken_viewmodel::BackendEvent::Ai(Box::new(done)));
        assert!(r.vm.ai_chip().is_none());
        assert!(
            r.vm.toasts
                .iter()
                .any(|t| t.text.contains("was stopped") && t.text.contains("3 calls")),
            "{:?}",
            r.vm.toasts
        );
    }

    fn click(r: &mut Rig, at: egui::Pos2) {
        r.frame(vec![Event::PointerMoved(at)]);
        for pressed in [true, false] {
            r.frame(vec![Event::PointerButton {
                pos: at,
                button: PointerButton::Primary,
                pressed,
                modifiers: Modifiers::NONE,
            }]);
        }
    }

    fn paid_policy() -> kraken_assist::AiPolicy {
        let cfg = kraken_agent::ProviderConfig::Anthropic {
            model: Some("claude-sonnet-5-5".into()),
            api_key: kraken_agent::SecretRef::Env("K".into()),
            base_url: None,
            max_tokens: None,
            context_window: None,
        };
        let choice = kraken_assist::ModelChoice::new(cfg, kraken_assist::ModelSource::Assistant);
        kraken_assist::AiPolicy {
            assistant: Some(choice.clone()),
            rewrite: Some(choice),
            ..kraken_assist::AiPolicy::default()
        }
    }

    #[test]
    fn the_question_shows_before_a_rewrite_run_and_cancel_starts_nothing() {
        use kraken_viewmodel::rewrite::{Availability, RewriteMode};
        let mut r = Rig::new();
        r.vm.ai.policy = paid_policy();
        r.vm.rewrite.availability = Availability::Unknown;
        r.vm.rewrite_run(0x401000, RewriteMode::Incremental);
        assert!(r.vm.ai.confirm.is_some());
        r.frame(vec![]);
        let t = r.frame(vec![]);
        let has = |s: &str| t.iter().any(|(x, _)| x.contains(s));
        assert!(has("Rewrite this function in Rust?"), "{t:?}");
        assert!(has("Up to 3 model calls."), "{t:?}");
        assert!(has("Model: claude-sonnet-5-5"), "{t:?}");
        assert!(has("(estimate)"), "{t:?}");
        let cancel = t.iter().find(|(x, _)| x == "Cancel").expect("Cancel").1;
        click(&mut r, cancel);
        assert!(r.vm.ai.confirm.is_none(), "Cancel closes the question");
        assert!(r.vm.block_until_idle(WAIT));
        assert!(r.backend.calls_to("rewrite_function").is_empty());
        assert!(r.vm.rewrite.jobs.is_empty(), "nothing started");

        // Start runs it.
        r.vm.rewrite_run(0x401000, RewriteMode::Incremental);
        r.frame(vec![]);
        let t = r.frame(vec![]);
        let start = t.iter().find(|(x, _)| x == "Start").expect("Start").1;
        click(&mut r, start);
        assert!(r.vm.block_until_idle(WAIT));
        assert_eq!(r.backend.calls_to("rewrite_function").len(), 1);
    }
}
