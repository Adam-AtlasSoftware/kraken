//! Scripted assistant answers for the demo project's screenshots: deterministic and offline.

use std::sync::Arc;

use kraken_agent::{ChatProvider, StreamEvent};
use kraken_viewmodel::assist::ProviderBadge;
use kraken_viewmodel::assist::script::{answer, say, scripted_provider, tool_call};
use serde_json::json;

use crate::args::Scene;

/// What the screenshot asks the assistant.
pub const CHAT_QUESTION: &str = "What does process_packet do, and is anything in it suspicious?";

fn chat() -> Vec<Vec<StreamEvent>> {
    vec![
        tool_call("call-1", "decompile", json!({"address": "0x4011a0"})),
        tool_call(
            "call-2",
            "rename_symbol",
            json!({"address": "0x401340", "new_name": "alloc_failure_exit"}),
        ),
        say(
            "`process_packet` (0x4011a0) checks a network packet before the program trusts it. It rejects packets shorter than 12 bytes, compares a checksum (0x401240) with the one stored in the packet, and only then passes the rest to `handle_hello` (0x401380). Nothing in it looks harmful.\n\n\
             I also suggested a clearer name for 0x401340; you named it yourself, so it waits for your OK.",
        ),
    ]
}

fn explain() -> Vec<Vec<StreamEvent>> {
    vec![
        tool_call("call-1", "get_function", json!({"address": "0x4011a0"})),
        tool_call("call-2", "decompile", json!({"address": "0x4011a0"})),
        answer(
            "It checks a packet before the program trusts it.",
            &json!({
                "summary": "`process_packet` checks that a network packet is long enough and that its checksum matches, then passes the rest of the packet on. Think of it as the program's front door guard: anything that fails a check is turned away and logged.",
                "key_behaviours": [
                    "Rejects empty or very short packets (under 12 bytes) and logs \"short packet\".",
                    "Adds up all the bytes with `checksum` (0x401240) and compares the total with the number stored in the first four bytes.",
                    "On a mismatch it logs \"bad checksum\" and returns -3.",
                    "On success it hands everything after the 12-byte header to `handle_hello` (0x401380)."
                ],
                "suggested_names": [
                    {"name": "validate_and_dispatch_packet", "reason": "it validates first, then hands the packet on"}
                ],
                "caveats": [
                    "I did not look at `handle_hello`, so I cannot say what happens to a valid packet."
                ]
            }),
        ),
    ]
}

fn autoname() -> Vec<Vec<StreamEvent>> {
    vec![
        tool_call("call-1", "list_functions", json!({"name_filter": "FUN_"})),
        tool_call("call-2", "decompile", json!({"address": "0x401340"})),
        tool_call("call-3", "decompile", json!({"address": "0x401300"})),
        answer(
            "Here are my suggestions.",
            &json!({"suggestions": [
                {
                    "address": "0x401340", "current_name": "FUN_00401340",
                    "new_name": "fatal_out_of_memory",
                    "comment": "Logs an out-of-memory error and ends the program.",
                    "evidence": [
                        {"kind": "string", "detail": "\"out of memory\""},
                        {"kind": "import", "detail": "exit"},
                        {"kind": "caller", "detail": "called when malloc returns NULL in FUN_00401300"}
                    ]
                },
                {
                    "address": "0x401300", "current_name": "FUN_00401300",
                    "new_name": "alloc_with_header",
                    "evidence": [
                        {"kind": "import", "detail": "malloc"},
                        {"kind": "caller", "detail": "init_session uses the result as its buffer"}
                    ]
                },
                {
                    "address": "0x401440", "current_name": "FUN_00401440",
                    "new_name": "xor_first_word_with_length",
                    "evidence": [
                        {"kind": "decompile", "detail": "XORs the first four bytes with the length"}
                    ]
                }
            ]}),
        ),
    ]
}

/// The scripted model for a screenshot scene, if the scene needs one.
pub fn provider_for(scene: Scene) -> Option<(Arc<dyn ChatProvider>, ProviderBadge)> {
    let script = match scene {
        Scene::Assistant => chat(),
        Scene::Explain => explain(),
        Scene::AutoName => autoname(),
        _ => return None,
    };
    Some(scripted_provider(script, "demo-model"))
}
