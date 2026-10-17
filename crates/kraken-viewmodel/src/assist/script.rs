//! Scripted model answers for tests and the demo: no network, fully deterministic.

use std::sync::Arc;

use kraken_agent::{ChatProvider, FinishReason, ProviderInfo, ReplayProvider, StreamEvent, Usage};
use serde_json::Value;

use super::ProviderBadge;

/// A model turn that calls one tool.
pub fn tool_call(id: &str, name: &str, args: Value) -> Vec<StreamEvent> {
    vec![
        StreamEvent::ToolCallDelta {
            index: 0,
            id: Some(id.to_string()),
            name: Some(name.to_string()),
            arguments: args.to_string(),
        },
        StreamEvent::Usage(Usage {
            input_tokens: 400,
            output_tokens: 24,
        }),
        StreamEvent::Finish {
            reason: FinishReason::ToolCalls,
        },
    ]
}

/// A model turn that says `text` (in a few chunks, like a stream) and stops.
pub fn say(text: &str) -> Vec<StreamEvent> {
    let mut events = Vec::new();
    let mut chunk = String::new();
    for word in text.split_inclusive(' ') {
        chunk.push_str(word);
        if chunk.len() >= 24 {
            events.push(StreamEvent::TextDelta {
                text: std::mem::take(&mut chunk),
            });
        }
    }
    if !chunk.is_empty() {
        events.push(StreamEvent::TextDelta { text: chunk });
    }
    events.push(StreamEvent::Usage(Usage {
        input_tokens: 900,
        output_tokens: u64::try_from(text.len() / 4).unwrap_or(0).max(1),
    }));
    events.push(StreamEvent::Finish {
        reason: FinishReason::Stop,
    });
    events
}

/// A final answer: `prose`, then the machine-readable `<kraken-result>` block `result`.
pub fn answer(prose: &str, result: &Value) -> Vec<StreamEvent> {
    say(&format!("{prose}\n<kraken-result>{result}</kraken-result>"))
}

/// A provider that plays `responses` in order (the last repeats), labelled as a demo.
pub fn scripted_provider(
    responses: Vec<Vec<StreamEvent>>,
    model: &str,
) -> (Arc<dyn ChatProvider>, ProviderBadge) {
    let provider = ReplayProvider::scripted(responses).with_info(ProviderInfo {
        id: "demo-script".to_string(),
        model: model.to_string(),
        supports_tools: true,
        context_window: None,
    });
    (
        Arc::new(provider),
        ProviderBadge {
            service: "Demo script (offline)".to_string(),
            model: model.to_string(),
            local: true,
            terminal_agent: false,
        },
    )
}
