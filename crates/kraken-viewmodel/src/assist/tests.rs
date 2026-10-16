//! Assistant tests: scripted models (no network) over the real registry and the fake engine.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use kraken_agent::{AgentError, ChatProvider, ChatRequest, ChatStream, ProviderInfo, StreamEvent};
use serde_json::{Value, json};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

use super::script::{answer, say, scripted_provider, tool_call};
use super::*;
use crate::backend::{Backend, CallAs};
use crate::demo::{demo_fixture, demo_project_with};
use crate::state::{AnalysisPhase, Connection};
use crate::testing::FakeBackend;
use crate::vm::ViewModel;

const WAIT: Duration = Duration::from_secs(20);

struct Rig {
    _rt: Runtime,
    vm: ViewModel,
}

fn project_rig() -> Rig {
    let rt = Runtime::new().expect("runtime");
    let d = demo_project_with(demo_fixture(), Duration::from_millis(1)).expect("demo");
    let mut vm = ViewModel::new(d.backend.clone(), rt.handle().clone());
    vm.create_project(
        d.binary.to_string_lossy().into_owned(),
        d.project_dir.to_string_lossy().into_owned(),
    );
    assert!(vm.block_until_idle(WAIT));
    assert_eq!(vm.connection, Connection::Open);
    vm.start_analysis();
    assert!(vm.block_until(WAIT, |vm| {
        vm.analysis.phase == AnalysisPhase::Complete && !vm.busy()
    }));
    Rig { _rt: rt, vm }
}

fn rig(script: Vec<Vec<StreamEvent>>) -> Rig {
    let mut r = project_rig();
    let (p, badge) = scripted_provider(script, "test-model");
    r.vm.assist.set_provider(p, badge);
    r
}

impl Rig {
    fn settle(&mut self) {
        assert!(
            self.vm
                .block_until(WAIT, |vm| !vm.assist.busy() && !vm.busy()),
            "assistant did not finish: {:?}",
            self.vm.assist.items
        );
    }

    fn name_of(&self, addr: u64) -> String {
        self.vm
            .functions
            .find(addr)
            .map(|f| f.name.clone())
            .unwrap_or_default()
    }

    fn history_for(&mut self, op: &str) -> Vec<crate::state::HistoryEntry> {
        self.vm.refresh_history();
        assert!(self.vm.block_until_idle(WAIT));
        self.vm
            .history
            .entries
            .iter()
            .filter(|e| e.op == op)
            .cloned()
            .collect()
    }

    fn tools(&self) -> Vec<&ToolChip> {
        self.vm
            .assist
            .items
            .iter()
            .filter_map(|i| match i {
                ChatItem::Tool(c) => Some(c),
                _ => None,
            })
            .collect()
    }
}

fn explain_json() -> Value {
    json!({
        "summary": "It prints an out-of-memory message and then ends the program.",
        "key_behaviours": ["logs the message", "exits with the given code"],
        "suggested_names": [{"name": "fatal_out_of_memory", "reason": "it only runs when memory runs out"}],
        "caveats": ["I did not see who calls it"]
    })
}

// ------------------------------------------------------------------ chat

#[test]
fn chat_streams_text_and_shows_tool_chips_with_results() {
    let mut r = rig(vec![
        tool_call("c1", "get_function", json!({"address": "0x401340"})),
        say("That function reports an allocation failure and exits."),
    ]);
    r.vm.assist_send("What does 0x401340 do?");
    assert!(r.vm.assist.busy());
    r.settle();

    let items = &r.vm.assist.items;
    assert_eq!(items[0], ChatItem::User("What does 0x401340 do?".into()));
    let chip = r.tools()[0].clone();
    assert_eq!(chip.name, "get_function");
    assert!(chip.args_short.contains("0x401340"), "{}", chip.args_short);
    assert!(chip.summary.is_some() && !chip.is_error, "{chip:?}");
    let ChatItem::Assistant { text, streaming } = items.last().expect("an answer") else {
        panic!("last item should be the answer: {items:?}");
    };
    assert!(text.contains("allocation failure"));
    assert!(!streaming);
    assert!(r.vm.assist.usage.total() > 0, "usage is counted");
    assert_eq!(
        r.vm.assist.provider.as_ref().expect("provider").badge.model,
        "test-model"
    );
    // The conversation is remembered for the next question.
    assert_eq!(r.vm.assist.history.len(), 2);
    assert!(
        r.history_for("rename").is_empty(),
        "reading changes nothing"
    );
}

#[test]
fn chat_edits_are_logged_as_the_assistant_not_the_person() {
    let mut r = rig(vec![
        tool_call(
            "c1",
            "rename_symbol",
            json!({"address": "0x401340", "new_name": "fatal_out_of_memory"}),
        ),
        say("Done."),
    ]);
    r.vm.assist_send("Please name 0x401340");
    r.settle();
    assert_eq!(r.name_of(0x401340), "fatal_out_of_memory");
    let renames = r.history_for("rename");
    assert_eq!(renames.len(), 1);
    assert!(renames[0].by_agent, "the assistant made this edit");
    assert!(renames[0].run_id.is_some());
    assert_eq!(renames[0].who, kraken_assist::ASSISTANT_ID);
}

#[test]
fn a_proposal_is_shown_inline_and_accepting_it_is_the_persons_edit() {
    let mut r = rig(vec![
        tool_call(
            "c1",
            "rename_symbol",
            json!({"address": "0x401340", "new_name": "assistant_guess"}),
        ),
        say("I proposed a better name; please review it."),
        tool_call(
            "c2",
            "rename_symbol",
            json!({"address": "0x401440", "new_name": "other_guess"}),
        ),
        say("Proposed another."),
    ]);
    // The person named both functions first, so the assistant may only propose.
    for (addr, name) in [(0x401340, "my_name"), (0x401440, "my_other")] {
        r.vm.begin_rename(addr, None);
        assert!(r.vm.block_until_idle(WAIT));
        r.vm.set_rename_input(name);
        r.vm.submit_rename();
        assert!(r.vm.block_until_idle(WAIT));
    }
    r.vm.assist_send("Rename 0x401340");
    r.settle();
    let card =
        r.vm.assist
            .items
            .iter()
            .find_map(|i| match i {
                ChatItem::Proposal(c) => Some(c.clone()),
                _ => None,
            })
            .expect("a proposal card");
    assert_eq!(card.state, ProposalState::Waiting);
    assert!(card.proposal_id.is_some());
    assert!(card.what.contains("assistant_guess"), "{}", card.what);
    assert_eq!(r.name_of(0x401340), "my_name", "nothing applied yet");
    assert_eq!(
        r.vm.proposals.items.len(),
        1,
        "the Proposals tab sees it too"
    );

    r.vm.assist_decide_proposal(&card.call_id, true);
    assert!(r.vm.block_until(WAIT, |vm| {
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Proposal(c) if c.state == ProposalState::Accepted))
    }));
    r.settle();
    assert_eq!(r.name_of(0x401340), "assistant_guess");
    let renames = r.history_for("rename");
    assert!(
        !renames[0].by_agent && renames[0].who == "you",
        "an accepted proposal is applied as the person: {:?}",
        renames[0]
    );

    // A second proposal can be rejected.
    r.vm.assist_send("And 0x401440");
    r.settle();
    let second =
        r.vm.assist
            .items
            .iter()
            .rev()
            .find_map(|i| match i {
                ChatItem::Proposal(c) if c.state == ProposalState::Waiting => Some(c.clone()),
                _ => None,
            })
            .expect("second proposal");
    r.vm.assist_decide_proposal(&second.call_id, false);
    assert!(r.vm.block_until(WAIT, |vm| {
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Proposal(c) if c.state == ProposalState::Rejected))
    }));
    r.settle();
    assert_eq!(r.name_of(0x401440), "my_other");
}

struct Hang;

#[async_trait]
impl ChatProvider for Hang {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: "hang".into(),
            model: "never".into(),
            supports_tools: true,
            context_window: None,
        }
    }

    async fn complete(
        &self,
        _req: ChatRequest,
        cancel: CancellationToken,
    ) -> Result<ChatStream, AgentError> {
        cancel.cancelled().await;
        Err(AgentError::Cancelled)
    }
}

#[test]
fn stop_cancels_a_run_that_is_waiting_for_the_model() {
    let mut r = project_rig();
    r.vm.assist.set_provider(
        Arc::new(Hang),
        ProviderBadge {
            service: "Hang".into(),
            model: "never".into(),
            local: true,
        },
    );
    r.vm.assist_send("Anything?");
    assert!(r.vm.assist.busy());
    r.vm.assist_stop();
    assert!(r.vm.assist.stopping());
    r.settle();
    assert!(!r.vm.assist.busy());
    assert!(
        r.vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Notice(n) if n == "Stopped.")),
        "{:?}",
        r.vm.assist.items
    );
    // The unanswered question is not kept as history.
    assert!(r.vm.assist.history.is_empty());

    // A task can be stopped too.
    r.vm.assist_explain_function(0x401340);
    r.vm.assist_stop();
    r.settle();
    assert!(!r.vm.assist.busy());
}

struct Broken;

#[async_trait]
impl ChatProvider for Broken {
    fn info(&self) -> ProviderInfo {
        ProviderInfo {
            id: "broken".into(),
            model: "m".into(),
            supports_tools: true,
            context_window: None,
        }
    }

    async fn complete(
        &self,
        _req: ChatRequest,
        _cancel: CancellationToken,
    ) -> Result<ChatStream, AgentError> {
        Err(AgentError::Http {
            status: 401,
            body: "bad key".into(),
        })
    }
}

#[test]
fn model_failures_are_explained_not_hidden() {
    let mut r = project_rig();
    r.vm.assist.set_provider(
        Arc::new(Broken),
        ProviderBadge {
            service: "Broken".into(),
            model: "m".into(),
            local: false,
        },
    );
    r.vm.assist_send("hello");
    r.settle();
    assert!(
        r.vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Error(e) if e.contains("Settings"))),
        "{:?}",
        r.vm.assist.items
    );
    // Explain failures are reported the same way.
    r.vm.assist_explain_function(0x401340);
    r.settle();
    assert!(matches!(r.vm.assist.items.last(), Some(ChatItem::Error(_))));
}

#[test]
fn without_a_provider_the_assistant_says_how_to_set_one_up() {
    let mut r = project_rig();
    r.vm.assist_send("hi");
    assert!(!r.vm.assist.busy());
    assert!(r.vm.assist.show_requested);
    assert!(matches!(
        r.vm.assist.items.last(),
        Some(ChatItem::Notice(n)) if n.contains("Settings > AI")
    ));
}

#[test]
fn a_backend_that_cannot_attribute_calls_refuses_agent_writes() {
    let rt = Runtime::new().expect("runtime");
    let b = FakeBackend::new();
    let who = CallAs {
        agent: true,
        id: "kraken-assistant".into(),
        run_id: Some("run-1".into()),
    };
    let res = rt.block_on(b.call_as(&who, "rename_symbol", json!({})));
    assert!(res.is_err(), "no silent fallback to the person's identity");
}

// ------------------------------------------------------------------ explain

#[test]
fn explain_function_becomes_a_card_linked_to_the_address() {
    let mut r = rig(vec![
        tool_call("c1", "get_function", json!({"address": "0x401340"})),
        tool_call("c2", "decompile", json!({"address": "0x401340"})),
        answer(
            "It stops the program when memory runs out.",
            &explain_json(),
        ),
    ]);
    r.vm.assist_explain_function(0x401340);
    assert!(r.vm.assist.show_requested);
    r.settle();

    let items = &r.vm.assist.items;
    let ChatItem::Explanation(card) = items.last().expect("a card") else {
        panic!("expected a card: {items:?}");
    };
    assert_eq!(card.address, Some(0x401340));
    assert!(card.summary.contains("out-of-memory"));
    assert_eq!(card.key_behaviours.len(), 2);
    assert_eq!(card.suggested_names[0].0, "fatal_out_of_memory");
    assert_eq!(card.caveats.len(), 1);
    // Tool chips came first; the raw prose and the machine-readable block are not shown.
    assert_eq!(r.tools().len(), 2);
    assert!(
        !items
            .iter()
            .any(|i| matches!(i, ChatItem::Assistant { .. }))
    );
    let shown = format!("{items:?}");
    assert!(!shown.contains("kraken-result"));
    assert!(r.history_for("rename").is_empty(), "explaining never edits");
}

#[test]
fn explain_selection_passes_the_text_as_data() {
    let mut r = rig(vec![answer(
        "It adds one to the counter.",
        &json!({"summary": "It adds one to the counter.", "key_behaviours": ["increments i"]}),
    )]);
    r.vm.assist_explain_selection(SelectionKind::Decompile, "i = i + 1;", Some(0x401240));
    r.settle();
    let Some(ChatItem::Explanation(card)) = r.vm.assist.items.last() else {
        panic!("{:?}", r.vm.assist.items);
    };
    assert_eq!(card.title, "Selected code");
    assert_eq!(card.address, Some(0x401240));
    assert!(matches!(&r.vm.assist.items[0], ChatItem::User(u) if u.contains("i = i + 1;")));
    // An empty selection is refused before any model call.
    r.vm.assist_explain_selection(SelectionKind::Decompile, "   ", None);
    assert!(!r.vm.assist.busy());
}

// ------------------------------------------------------------------ overview

#[test]
fn the_overview_is_offered_once_after_analysis_and_rendered_as_a_card() {
    let mut r = rig(vec![
        tool_call("c1", "project_info", json!({})),
        tool_call("c2", "list_functions", json!({"limit": 50})),
        answer(
            "A small command-line tool.",
            &json!({
                "what_it_is": "A small tool that reads a file and checks its packets.",
                "components": [{"name": "Packet checking", "description": "verifies each packet"}],
                "interesting_functions": [
                    {"address": "0x4011a0", "name": "process_packet", "reason": "it validates input"},
                    {"address": "nonsense", "reason": "dropped"}
                ],
                "next_steps": ["Open process_packet", "Rename the FUN_ functions"]
            }),
        ),
    ]);
    assert_eq!(
        r.vm.assist.overview_offer,
        OverviewOffer::Offered,
        "analysis finished in the rig"
    );
    r.vm.assist_dismiss_offer();
    assert_eq!(r.vm.assist.overview_offer, OverviewOffer::Hidden);
    r.vm.assist_overview();
    r.settle();
    let Some(ChatItem::Overview(o)) = r.vm.assist.items.last() else {
        panic!("{:?}", r.vm.assist.items);
    };
    assert!(o.what_it_is.contains("small tool"));
    assert_eq!(o.components.len(), 1);
    assert_eq!(
        o.interesting.len(),
        1,
        "a row without a valid address is dropped"
    );
    assert_eq!(o.interesting[0].address, Some(0x4011a0));
    assert_eq!(o.next_steps.len(), 2);
    // Re-analysis does not offer it again.
    r.vm.assist_analysis_finished();
    assert_eq!(r.vm.assist.overview_offer, OverviewOffer::Hidden);
}

// ------------------------------------------------------------------ auto-name

fn autoname_script() -> Vec<Vec<StreamEvent>> {
    vec![
        tool_call("c1", "list_functions", json!({"name_filter": "FUN_"})),
        tool_call("c2", "decompile", json!({"address": "0x401340"})),
        answer(
            "Here are my suggestions.",
            &json!({"suggestions": [
                {
                    "address": "0x401340", "current_name": "FUN_00401340",
                    "new_name": "fatal_out_of_memory",
                    "comment": "Reports an allocation failure and exits.",
                    "evidence": [
                        {"kind": "string", "detail": "\"out of memory\""},
                        {"kind": "import", "detail": "exit"},
                        {"kind": "caller", "detail": "called when malloc returns NULL"}
                    ]
                },
                {
                    "address": "0x401440", "current_name": "FUN_00401440",
                    "new_name": "xor_first_word",
                    "evidence": [{"kind": "decompile", "detail": "xors a value with the length"}]
                },
                {
                    "address": "0x401300", "current_name": "FUN_00401300",
                    "new_name": "alloc_with_header",
                    "evidence": [
                        {"kind": "import", "detail": "malloc"},
                        {"kind": "caller", "detail": "init_session"}
                    ]
                }
            ]}),
        ),
    ]
}

fn review(vm: &ViewModel) -> &AutoNameReview {
    match &vm.assist.autoname {
        AutoNameState::Review(r) => r,
        other => panic!("expected a review, got {other:?}"),
    }
}

#[test]
fn auto_name_reviews_first_then_applies_as_the_person_and_can_be_undone() {
    let mut r = rig(autoname_script());
    r.vm.assist_auto_name(10);
    assert_eq!(r.vm.assist.autoname, AutoNameState::Running);
    r.settle();

    // Dry run: nothing changed, the rows carry old name, new name, evidence and a label.
    assert!(r.history_for("rename").is_empty());
    let rev = review(&r.vm);
    assert_eq!(rev.rows.len(), 3);
    let row = &rev.rows[0];
    assert_eq!(row.address, 0x401340);
    assert_eq!(row.old_name, "FUN_00401340");
    assert_eq!(row.new_name.as_deref(), Some("fatal_out_of_memory"));
    assert_eq!(row.confidence, Confidence::High);
    assert!(row.evidence.iter().any(|e| e.starts_with("Uses the text")));
    assert!(row.selected, "strong suggestions start ticked");
    // Strongest evidence first.
    assert_eq!(rev.rows[1].address, 0x401300);
    assert_eq!(rev.rows[1].confidence, Confidence::Medium);
    assert_eq!(rev.rows[2].address, 0x401440);
    assert_eq!(rev.rows[2].confidence, Confidence::Low);
    assert!(!rev.rows[2].selected, "weak ones start unticked");

    r.vm.autoname_apply(ApplyWhich::Selected);
    assert!(r.vm.block_until(WAIT, |vm| !review(vm).busy));
    r.settle();
    assert_eq!(r.name_of(0x401340), "fatal_out_of_memory");
    assert_eq!(r.name_of(0x401300), "alloc_with_header");
    assert_eq!(
        r.name_of(0x401440),
        "FUN_00401440",
        "unticked row untouched"
    );
    let rev = review(&r.vm);
    assert_eq!(rev.rows[0].status, RowStatus::Applied);
    assert_eq!(rev.rows[2].status, RowStatus::Pending);
    assert_eq!(rev.undoable, 3, "two renames and one comment");
    let renames = r.history_for("rename");
    assert_eq!(renames.len(), 2);
    assert!(renames.iter().all(|e| !e.by_agent && e.who == "you"));
    assert_eq!(r.history_for("set_comment").len(), 1);

    // Apply all picks up the rest.
    r.vm.autoname_apply(ApplyWhich::All);
    assert!(r.vm.block_until(WAIT, |vm| !review(vm).busy));
    r.settle();
    assert_eq!(r.name_of(0x401440), "xor_first_word");

    // Undo puts everything back.
    r.vm.autoname_undo();
    assert!(r.vm.block_until(WAIT, |vm| !review(vm).busy));
    r.settle();
    assert_eq!(r.name_of(0x401340), "FUN_00401340");
    assert_eq!(r.name_of(0x401300), "FUN_00401300");
    assert_eq!(r.name_of(0x401440), "FUN_00401440");
    let rev = review(&r.vm);
    assert!(rev.rows.iter().all(|row| row.status == RowStatus::Undone));
    assert_eq!(rev.undoable, 0);

    r.vm.autoname_close();
    assert_eq!(r.vm.assist.autoname, AutoNameState::Idle);
}

#[test]
fn auto_name_skips_a_function_someone_renamed_meanwhile() {
    let mut r = rig(autoname_script());
    r.vm.assist_auto_name(10);
    r.settle();
    r.vm.begin_rename(0x401340, None);
    assert!(r.vm.block_until_idle(WAIT));
    r.vm.set_rename_input("person_chose_this");
    r.vm.submit_rename();
    assert!(r.vm.block_until_idle(WAIT));

    r.vm.autoname_apply(ApplyWhich::All);
    assert!(r.vm.block_until(WAIT, |vm| !review(vm).busy));
    r.settle();
    assert_eq!(
        r.name_of(0x401340),
        "person_chose_this",
        "never overwritten"
    );
    assert!(matches!(
        &review(&r.vm).rows[0].status,
        RowStatus::Failed(why) if why.contains("person_chose_this")
    ));
    assert_eq!(
        r.name_of(0x401300),
        "alloc_with_header",
        "the others still applied"
    );
}

// ------------------------------------------------------------------ learn mode

#[test]
fn learn_mode_has_help_for_every_panel_and_finds_mnemonics() {
    let r = project_rig();
    for h in PANEL_HELP {
        assert!(!h.text.is_empty());
        for t in h.terms {
            assert!(
                r.vm.assist.term(t).is_some(),
                "{} mentions unknown term {t}",
                h.panel
            );
        }
    }
    assert!(panel_help("Functions").is_some());
    assert!(panel_help("Nope").is_none());
    let jne =
        r.vm.assist
            .mnemonic("x86:LE:64:default", "jne")
            .expect("jne");
    assert!(!jne.short.is_empty());
    assert!(
        r.vm.assist
            .mnemonic("x86:LE:64:default", "notamnemonic")
            .is_none()
    );
    assert!(r.vm.assist.mnemonic("unknown-arch", "jne").is_none());
    assert!(
        r.vm.assist.term("Stack Frame").is_some(),
        "lookup ignores case"
    );
}

// ------------------------------------------------------------------ provider settings

fn temp_store() -> (tempfile::TempDir, ProviderStore) {
    let dir = tempfile::Builder::new()
        .prefix("kraken-assist-settings")
        .tempdir()
        .expect("temp dir");
    let path = dir.path().join("kraken/config.toml");
    (dir, ProviderStore::new(Some(path)))
}

#[test]
fn provider_settings_round_trip_through_config_toml_and_keep_other_keys() {
    let (_dir, store) = temp_store();
    let path = store.config_path.clone().expect("path");
    std::fs::create_dir_all(path.parent().expect("dir")).expect("mkdir");
    std::fs::write(&path, "per_run_cap = 9\n").expect("seed");
    assert_eq!(store.load().expect("load"), None, "nothing configured yet");

    for kind in ProviderKind::ALL {
        let mut d = ProviderDraft::preset(kind);
        if d.model.is_empty() {
            d.model = "some-model".into();
        }
        if d.base_url.is_empty() && kind.needs_url() {
            d.base_url = "http://10.0.0.5:9000/v1".into();
        }
        if kind.needs_key() {
            d.key_env = "MY_KEY_VAR".into();
        }
        let out = store.save(&d).unwrap_or_else(|e| panic!("{kind:?}: {e}"));
        let loaded = store.load().expect("load").expect("configured");
        assert_eq!(loaded, out.config, "{kind:?}");
        let back = ProviderDraft::from_config(&loaded);
        assert_eq!(back.model, d.model, "{kind:?}");
        let b = badge_of(&loaded);
        assert!(!b.model.is_empty(), "{kind:?}");
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(
            text.contains("per_run_cap = 9"),
            "{kind:?}: other keys survive\n{text}"
        );
        assert!(!text.contains("null"), "{text}");
    }

    // The CLI reads the same file.
    let cli = kraken_assist::load_provider_config(Some(&path)).expect("cli load");
    assert_eq!(Some(cli), store.load().expect("load"));

    store.clear().expect("clear");
    assert_eq!(store.load().expect("load"), None);
    assert!(
        std::fs::read_to_string(&path)
            .expect("read")
            .contains("per_run_cap")
    );
}

#[test]
fn presets_fill_in_urls_models_and_the_local_badge() {
    let d = ProviderDraft::preset(ProviderKind::Ollama);
    assert_eq!(d.base_url, "http://localhost:11434/v1");
    let (_dir, store) = temp_store();
    let out = store.configure(&d).expect("configure");
    let b = badge_of(&out.config);
    assert!(b.local);
    assert_eq!(b.service, "Ollama");
    assert!(b.privacy().contains("not sent anywhere"));
    let cloud = store
        .configure(&{
            let mut d = ProviderDraft::preset(ProviderKind::Anthropic);
            d.key_env = "ANTHROPIC_API_KEY".into();
            d
        })
        .expect("anthropic");
    let b = badge_of(&cloud.config);
    assert!(!b.local);
    assert!(b.privacy().contains("sent to this provider"));
    assert!(is_local_url("http://127.0.0.1:8080/v1"));
    assert!(is_local_url("http://[::1]:8080/v1"));
    assert!(!is_local_url("https://localhost.evil.example/v1"));
    // Reading an Ollama config back picks the right preset.
    assert_eq!(
        ProviderDraft::from_config(&out.config).kind,
        ProviderKind::Ollama
    );
}

#[test]
fn bad_input_gets_a_plain_message() {
    let (_dir, store) = temp_store();
    let mut d = ProviderDraft::preset(ProviderKind::OpenAiCompatible);
    assert!(store.configure(&d).unwrap_err().contains("server address"));
    d.base_url = "localhost:1234".into();
    assert!(store.configure(&d).unwrap_err().contains("http://"));
    d.base_url = "http://localhost:1234/v1".into();
    assert!(store.configure(&d).unwrap_err().contains("model name"));
    let a = ProviderDraft::preset(ProviderKind::Anthropic);
    let mut a2 = a.clone();
    a2.key_env.clear();
    assert!(store.configure(&a2).unwrap_err().contains("API key"));
    assert!(
        ProviderStore::new(None)
            .save(&a)
            .unwrap_err()
            .contains("HOME")
    );
}

#[cfg(unix)]
#[test]
fn a_pasted_key_goes_to_a_private_file_never_to_config_toml() {
    use std::os::unix::fs::PermissionsExt;
    let (_dir, store) = temp_store();
    let secret = "sk-ant-THIS-MUST-NEVER-APPEAR-IN-CONFIG";
    let mut d = ProviderDraft::preset(ProviderKind::Anthropic);
    d.key_paste = secret.into();
    let out = store.save(&d).expect("save");
    assert!(
        !out.notes.is_empty(),
        "the person is told where the key went"
    );

    let config =
        std::fs::read_to_string(store.config_path.as_ref().expect("path")).expect("config");
    assert!(!config.contains(secret), "{config}");
    assert!(
        config.contains(SECRETS_SERVICE),
        "config points at the secrets file: {config}"
    );
    let secrets = store.secrets().expect("secrets file");
    let mode = std::fs::metadata(secrets.path())
        .expect("meta")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "secrets file is private, got {mode:o}");
    assert_eq!(
        secrets.get_secret("anthropic").expect("read").as_deref(),
        Some(secret)
    );

    // The reference resolves, so the provider can be built without the key in the environment.
    let provider = store.build(&out.config).expect("build");
    assert!(!provider.info().id.is_empty());

    // A key typed into the variable-name box is treated as a key, not written as a name.
    let (_dir2, store2) = temp_store();
    let mut d2 = ProviderDraft::preset(ProviderKind::OpenAi);
    d2.key_env = "sk-proj-abc-def-ghi".into();
    let out2 = store2.save(&d2).expect("save");
    let config2 =
        std::fs::read_to_string(store2.config_path.as_ref().expect("path")).expect("config");
    assert!(!config2.contains("sk-proj"), "{config2}");
    assert!(
        out2.notes
            .iter()
            .any(|n| n.contains("looked like an API key"))
    );
    let mode2 = std::fs::metadata(store2.secrets().expect("s").path())
        .expect("meta")
        .permissions()
        .mode();
    assert_eq!(mode2 & 0o777, 0o600);

    // A world-readable file is tightened the next time it is read.
    std::fs::set_permissions(secrets.path(), std::fs::Permissions::from_mode(0o644))
        .expect("chmod");
    secrets.get_secret("anthropic").expect("read");
    let mode = std::fs::metadata(secrets.path())
        .expect("meta")
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600);

    // Saving again keeps the reference when nothing new is typed.
    let again = ProviderDraft::from_config(&out.config);
    assert!(again.uses_secrets_file());
    let out3 = store.save(&again).expect("save again");
    assert_eq!(out3.config, out.config);
}

#[test]
fn test_connection_reports_success_and_failure_in_plain_words() {
    let rt = Runtime::new().expect("runtime");
    let (ok, _) = scripted_provider(vec![say("ready")], "tiny");
    let report = rt.block_on(test_connection(ok)).expect("works");
    assert_eq!(report.reply, "ready");
    assert_eq!(report.model, "tiny");

    let err = rt.block_on(test_connection(Arc::new(Broken))).unwrap_err();
    assert!(err.contains("refused the API key"), "{err}");
    for (e, needle) in [
        (
            AgentError::Transport("connection refused".into()),
            "Is it running",
        ),
        (
            AgentError::Http {
                status: 404,
                body: "model not found".into(),
            },
            "model name",
        ),
        (
            AgentError::Http {
                status: 429,
                body: String::new(),
            },
            "quota",
        ),
        (
            AgentError::MissingKey("variable X is not set".into()),
            "No API key",
        ),
    ] {
        assert!(plain_agent_error(&e).contains(needle), "{e}");
    }
}

#[cfg(unix)]
#[test]
fn testing_a_pasted_key_does_not_save_it() {
    let (_dir, store) = temp_store();
    let mut d = ProviderDraft::preset(ProviderKind::Anthropic);
    d.key_paste = "sk-ant-only-in-memory".into();
    store.build_unsaved(&d).expect("builds from the pasted key");
    assert!(
        !store.secrets().expect("secrets").path().exists(),
        "nothing was written by a test"
    );
    assert!(!store.config_path.as_ref().expect("path").exists());
}
