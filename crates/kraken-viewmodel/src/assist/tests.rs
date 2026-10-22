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
    assert_eq!(r.vm.assist.badge().expect("backend").model, "test-model");
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
            terminal_agent: false,
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

fn endless_tool_calls(then: Option<Vec<StreamEvent>>) -> Vec<Vec<StreamEvent>> {
    // One question allows 12 model steps.
    let mut script: Vec<_> = (0..12)
        .map(|i| {
            tool_call(
                &format!("c{i}"),
                "get_function",
                json!({"address": "0x401340"}),
            )
        })
        .collect();
    script.extend(then);
    script
}

fn notices(r: &Rig) -> Vec<String> {
    r.vm.assist
        .items
        .iter()
        .filter_map(|i| match i {
            ChatItem::Notice(n) => Some(n.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn a_local_model_goes_on_by_itself_after_the_limit_and_the_note_is_not_a_user_bubble() {
    let mut r = rig(endless_tool_calls(Some(say("All done."))));
    r.vm.assist.auto_continue_override = Some(5);
    r.vm.assist_send("Explain everything");
    r.settle();
    assert!(notices(&r).contains(&"Continuing automatically (1 of 5)...".to_string()));
    let users: Vec<_> =
        r.vm.assist
            .items
            .iter()
            .filter(|i| matches!(i, ChatItem::User(_)))
            .collect();
    assert_eq!(users.len(), 1, "{:?}", r.vm.assist.items);
    assert!(matches!(
        r.vm.assist.items.last(),
        Some(ChatItem::Assistant { text, .. }) if text.contains("All done")
    ));
    // Question, what it said at the limit, the hidden prompt, the answer.
    assert_eq!(r.vm.assist.history.len(), 4);
    assert!(r.vm.assist.last_input_tokens > 0);
}

#[test]
fn automatic_continuation_stops_at_the_setting_and_then_says_so() {
    let mut r = rig(endless_tool_calls(None));
    r.vm.assist.auto_continue_override = Some(2);
    r.vm.assist_send("Explain everything");
    r.settle();
    let n = notices(&r);
    assert!(
        n.contains(&"Continuing automatically (2 of 2)...".to_string()),
        "{n:?}"
    );
    assert!(!n.iter().any(|t| t.contains("3 of 2")));
    assert!(
        n.last()
            .is_some_and(|t| t.contains("went on by itself 2 times")),
        "{n:?}"
    );
}

#[test]
fn zero_and_paid_models_ask_each_time() {
    let mut r = rig(endless_tool_calls(None));
    r.vm.assist.auto_continue_override = Some(0);
    r.vm.assist_send("Explain everything");
    r.settle();
    let n = notices(&r);
    assert!(!n.iter().any(|t| t.starts_with("Continuing automatically")));
    assert!(
        n.last()
            .is_some_and(|t| t.contains("Ask again to continue"))
    );

    let mut r = project_rig();
    let (p, mut badge) = scripted_provider(endless_tool_calls(None), "paid");
    badge.local = false;
    r.vm.assist.set_provider(p, badge);
    r.vm.assist.auto_continue_override = Some(5);
    r.vm.assist_send("Explain everything");
    r.settle();
    assert!(
        !notices(&r)
            .iter()
            .any(|t| t.starts_with("Continuing automatically"))
    );
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
            terminal_agent: false,
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
        assert!(!h.text.is_empty() && !h.short.is_empty() && !h.how.is_empty());
        for k in h.keys {
            assert!(
                crate::SHORTCUTS.iter().any(|s| s.keys == *k),
                "{} mentions unknown shortcut {k}",
                h.panel
            );
        }
        for t in h.terms {
            assert!(
                r.vm.assist.term(t).is_some(),
                "{} mentions unknown term {t}",
                h.panel
            );
        }
    }
    assert!(panel_help("Functions").is_some());
    for title in [
        "Functions",
        "Decompiler",
        "Hex",
        "Listing",
        "Graph",
        "Xrefs",
        "Strings",
        "Imports / Exports",
        "Search",
        "Bookmarks",
        "History",
        "Proposals",
        "Assistant",
        "Rewrite",
    ] {
        assert!(panel_help(title).is_some(), "no help for {title}");
    }
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
fn a_terminal_agent_is_saved_in_the_same_table_and_the_cli_reads_it() {
    let (_dir, store) = temp_store();
    let path = store.config_path.clone().expect("path");
    std::fs::create_dir_all(path.parent().expect("dir")).expect("mkdir");
    std::fs::write(&path, "per_run_cap = 9\n").expect("seed");

    let mut d = ProviderDraft::for_agent("codex");
    d.model = "gpt-5".into();
    d.agent_args = "--flag  value".into();
    let out = store.save(&d).expect("save");
    assert_eq!(
        out.config,
        kraken_agent::ProviderConfig::TerminalAgent {
            agent: "codex".into(),
            model: Some("gpt-5".into()),
            args: vec!["--flag".into(), "value".into()],
        }
    );
    let text = std::fs::read_to_string(&path).expect("read");
    assert!(text.contains("kind = \"terminal_agent\""), "{text}");
    assert!(text.contains("agent = \"codex\""), "{text}");
    assert!(
        text.contains("per_run_cap = 9"),
        "other keys survive\n{text}"
    );
    assert!(
        !text.contains("api_key") && !text.contains("null"),
        "{text}"
    );

    // The CLI reads the same table, and the form comes back as it was.
    let cli = kraken_assist::load_provider_config(Some(&path)).expect("cli load");
    assert_eq!(cli, out.config);
    let back = ProviderDraft::from_config(&cli);
    assert_eq!(back.kind, ProviderKind::TerminalAgent);
    assert_eq!(back.agent, "codex");
    assert_eq!(back.model, "gpt-5");
    assert_eq!(back.agent_args, "--flag value");

    // It is a backend choice, not a chat model, and its badge says so.
    match store.choice(&out.config).expect("choice") {
        BackendChoice::Agent(a) => assert_eq!(a.agent, "codex"),
        BackendChoice::Api(_) => panic!("an agent is not a model API"),
    }
    let b = badge_of(&out.config);
    assert!(b.terminal_agent && !b.local);
    assert_eq!(b.service, "Codex");
    assert!(b.privacy().contains("outside KRAKEN's safety net"));
    assert!(store.build(&out.config).is_err());

    // Nothing to choose, nothing to save.
    let mut empty = ProviderDraft::for_agent("");
    empty.agent = "  ".into();
    assert!(store.configure(&empty).is_err());

    // Switching back to a model API replaces the table.
    let api = store
        .save(&ProviderDraft::preset(ProviderKind::Ollama))
        .expect("save api");
    assert!(matches!(
        api.config,
        kraken_agent::ProviderConfig::OpenaiCompatible { .. }
    ));
    let text = std::fs::read_to_string(&path).expect("read");
    assert!(!text.contains("terminal_agent"), "{text}");
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

// ------------------------------------------------------------------ automate

#[test]
fn automate_runs_the_flow_with_bulk_edits_and_never_accepts_for_the_person() {
    let mut r = rig(vec![
        tool_call("a1", "project_info", json!({})),
        tool_call(
            "a2",
            "apply_edits",
            json!({"edits": [
                {"op": "rename", "address": "0x401300", "name": "alloc_with_header"},
                {"op": "comment", "address": "0x401300", "text": "Allocates a block with a header"}
            ]}),
        ),
        tool_call("a3", "rewrite_accept", json!({})),
        say("I named one function. Review it in the History tab."),
    ]);
    assert_eq!(r.name_of(0x401300), "FUN_00401300");
    r.vm.assist_automate(kraken_assist::AutomateGoal::Understand);
    assert!(r.vm.assist.busy());
    r.settle();
    assert_eq!(r.name_of(0x401300), "alloc_with_header");
    let chips = r.tools();
    let apply = chips
        .iter()
        .find(|c| c.name == "apply_edits")
        .expect("chip");
    assert!(!apply.is_error, "{apply:?}");
    assert!(
        chips
            .iter()
            .filter(|c| c.name == "rewrite_accept")
            .all(|c| c.is_error),
        "the person's step is not offered"
    );
    assert!(r.vm.assist.items.iter().any(|i| matches!(
        i,
        ChatItem::Notice(n) if n.starts_with("Automation finished")
    )));
    let entries = r.history_for("rename");
    assert!(entries[0].by_agent);
}

// ------------------------------------------------------------------ the shell tool

fn shell_rig(command: &str) -> Option<Rig> {
    if !kraken_assist::ShellHost::available() {
        eprintln!("skipped: this host cannot confine");
        return None;
    }
    let mut r = rig(vec![
        tool_call("s1", "shell", json!({ "command": command })),
        say("Done."),
    ]);
    r.vm.assist.shell_config_override = Some(kraken_host::ShellConfig::default());
    Some(r)
}

fn permission_card(r: &Rig) -> Option<PermissionCard> {
    r.vm.assist.items.iter().find_map(|i| match i {
        ChatItem::Permission(c) => Some(c.clone()),
        _ => None,
    })
}

fn project_dir(r: &Rig) -> std::path::PathBuf {
    r.vm.project
        .as_ref()
        .expect("project")
        .project_dir
        .clone()
        .into()
}

#[test]
fn a_harmless_shell_command_runs_without_a_card() {
    let Some(mut r) = shell_rig("echo '2^64-1' | bc") else {
        return;
    };
    r.vm.assist_send("What is 2^64-1?");
    r.settle();
    assert!(permission_card(&r).is_none());
    let chip = r
        .tools()
        .into_iter()
        .find(|c| c.name == "shell")
        .expect("chip");
    assert!(
        chip.summary
            .as_deref()
            .is_some_and(|s| s.contains("18446744073709551615")),
        "{chip:?}"
    );
    assert!(!chip.is_error);
}

#[test]
fn an_unknown_shell_command_asks_with_the_exact_text_and_a_reason() {
    let Some(mut r) = shell_rig("ls -la") else {
        return;
    };
    r.vm.assist_send("List your scratch directory");
    assert!(r.vm.block_until(WAIT, |vm| {
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Permission(_)))
    }));
    let card = permission_card(&r).expect("card");
    assert_eq!(card.title, "shell");
    assert_eq!(card.command.as_deref(), Some("ls -la"));
    assert!(
        card.ask_reason
            .as_deref()
            .is_some_and(|w| w.contains("`ls`")),
        "{card:?}"
    );
    assert_eq!(card.allow_program.as_deref(), Some("ls"));
    assert_eq!(card.state, PermissionState::Waiting);
    // Nothing ran yet.
    assert!(r.tools().iter().all(|c| c.summary.is_none()));
    r.vm.assist_answer_permission(&card.id, true);
    r.settle();
    let chip = r
        .tools()
        .into_iter()
        .find(|c| c.name == "shell")
        .expect("chip");
    assert!(!chip.is_error, "{chip:?}");
    assert!(!project_dir(&r).join("assistant-shell.toml").exists());
}

#[test]
fn denying_the_card_refuses_the_command() {
    let Some(mut r) = shell_rig("ls") else {
        return;
    };
    r.vm.assist_send("List");
    assert!(r.vm.block_until(WAIT, |vm| {
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Permission(_)))
    }));
    let card = permission_card(&r).expect("card");
    r.vm.assist_answer_permission(&card.id, false);
    r.settle();
    assert!(r.tools().is_empty(), "a denied command never started");
    assert!(
        r.vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Permission(c) if c.state == PermissionState::Denied))
    );
}

#[test]
fn always_allow_approves_and_remembers_the_program_for_the_project() {
    let Some(mut r) = shell_rig("ls -la") else {
        return;
    };
    r.vm.assist_send("List");
    assert!(r.vm.block_until(WAIT, |vm| {
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Permission(_)))
    }));
    let card = permission_card(&r).expect("card");
    r.vm.assist_always_allow_shell(&card.id);
    r.settle();
    let chip = r
        .tools()
        .into_iter()
        .find(|c| c.name == "shell")
        .expect("chip");
    assert!(!chip.is_error, "{chip:?}");
    let file = std::fs::read_to_string(project_dir(&r).join("assistant-shell.toml")).expect("file");
    assert!(file.contains("allow = [\"ls\"]"), "{file}");
    // The next ls runs without a card.
    let (p, badge) = scripted_provider(
        vec![
            tool_call("s2", "shell", json!({"command": "ls"})),
            say("Again."),
        ],
        "test-model",
    );
    r.vm.assist.set_provider(p, badge);
    r.vm.assist.items.clear();
    r.vm.assist_send("List again");
    r.settle();
    assert!(permission_card(&r).is_none());
}

#[test]
fn a_command_that_cannot_be_remembered_has_no_always_button_and_is_still_approved_once() {
    let Some(mut r) = shell_rig("echo a; ls") else {
        return;
    };
    r.vm.assist_send("Two things");
    assert!(r.vm.block_until(WAIT, |vm| {
        vm.assist
            .items
            .iter()
            .any(|i| matches!(i, ChatItem::Permission(_)))
    }));
    let card = permission_card(&r).expect("card");
    assert_eq!(card.command.as_deref(), Some("echo a; ls"));
    assert!(
        card.ask_reason
            .as_deref()
            .is_some_and(|w| w.contains("`;`")),
        "{card:?}"
    );
    assert_eq!(card.allow_program, None);
    r.vm.assist_always_allow_shell(&card.id);
    r.settle();
    assert!(!project_dir(&r).join("assistant-shell.toml").exists());
    let chip = r
        .tools()
        .into_iter()
        .find(|c| c.name == "shell")
        .expect("chip");
    assert!(!chip.is_error, "{chip:?}");
}

#[test]
fn a_refused_shell_command_fails_with_the_reason_and_no_card() {
    let Some(mut r) = shell_rig("./a.out") else {
        return;
    };
    r.vm.assist_send("Run it");
    r.settle();
    assert!(permission_card(&r).is_none());
    let chip = r
        .tools()
        .into_iter()
        .find(|c| c.name == "shell")
        .expect("chip");
    assert!(chip.is_error, "{chip:?}");
    assert!(
        chip.summary
            .as_deref()
            .is_some_and(|s| s.contains("emulate_run")),
        "{chip:?}"
    );
}

#[test]
fn the_shell_tool_is_one_short_entry_in_low_context_mode() {
    if !kraken_assist::ShellHost::available() {
        return;
    }
    let host = kraken_assist::ShellHost::new(
        Arc::new(kraken_assist::RegistryToolHost::new(
            Arc::new(kraken_registry::Registry::standard()),
            Arc::new(VmCommands::new(Arc::new(FakeBackend::new()))),
            kraken_assist::HostOptions::default(),
        )),
        Arc::new(kraken_assist::ShellSession::new()),
        kraken_host::ShellConfig::default(),
        None,
        None,
    );
    let low = kraken_agent::LowContextHost::new(Arc::new(host));
    use kraken_agent::ToolHost;
    let tools = low.tools();
    let shell = tools.iter().find(|t| t.name == "shell").expect("listed");
    assert!(
        shell.description.chars().count() <= 111,
        "{}",
        shell.description
    );
    assert!(!shell.description.contains('\n'));
}

#[test]
fn danger_mode_is_used_at_once_and_saved_with_the_rest_of_the_config() {
    let mut r = project_rig();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("config.toml");
    std::fs::write(&path, "per_run_cap = 3\n").expect("config");
    r.vm.assist_set_danger_mode(kraken_host::DangerMode::Yolo, Some(&path))
        .expect("saved");
    assert_eq!(r.vm.assist_danger_mode(), kraken_host::DangerMode::Yolo);
    let cfg = kraken_host::KrakenConfig::from_file(&path).expect("read back");
    assert_eq!(cfg.danger_mode, kraken_host::DangerMode::Yolo);
    assert_eq!(cfg.per_run_cap, Some(3), "other keys survive");
}
