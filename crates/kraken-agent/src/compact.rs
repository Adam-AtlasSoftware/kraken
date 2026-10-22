//! Keeping a conversation inside the model's context window.
//!
//! Old tool results are the bulk of a long run and the cheapest thing to give up: the model
//! can call the tool again. The functions here are pure so they can be tested without a model.

use crate::types::Message;

/// Appended to every stub so the model knows the result was shortened on purpose.
pub const ELIDED_NOTE: &str =
    "[earlier result left out to save space; call the tool again if you need it]";

/// Compaction starts when the next request would fill more than this share of the window.
const HIGH_WATER_PERCENT: u64 = 85;
/// Compaction stops once the prompt is under this share of the window.
const LOW_WATER_PERCENT: u64 = 60;
/// The newest tool results are never elided by the normal pass.
pub const KEEP_RECENT: usize = 4;
/// The newest tool results kept by the emergency pass after the provider refused a request.
pub const KEEP_RECENT_EMERGENCY: usize = 2;
const STUB_HEAD_CHARS: usize = 120;
const BYTES_PER_TOKEN: usize = 3;

/// A rough token count for `bytes` of text.
pub fn estimate_tokens(bytes: usize) -> u64 {
    (bytes / BYTES_PER_TOKEN) as u64
}

/// The size in bytes of what a message adds to a prompt.
pub fn message_bytes(m: &Message) -> usize {
    match m {
        Message::User { content } => content.len(),
        Message::Assistant {
            content,
            tool_calls,
        } => {
            content.len()
                + tool_calls
                    .iter()
                    .map(|c| c.name.len() + c.arguments.to_string().len())
                    .sum::<usize>()
        }
        Message::ToolResult { name, content, .. } => name.len() + content.len(),
    }
}

pub fn total_bytes(messages: &[Message]) -> usize {
    messages.iter().map(message_bytes).sum()
}

/// True when a request of about `estimate` prompt tokens plus `reserve` for the answer would
/// fill more than the high-water share of `window`.
pub fn needs_room(estimate: u64, reserve: u64, window: u32) -> bool {
    estimate.saturating_add(reserve).saturating_mul(100) > u64::from(window) * HIGH_WATER_PERCENT
}

fn under_low_water(estimate: u64, window: u32) -> bool {
    estimate.saturating_mul(100) < u64::from(window) * LOW_WATER_PERCENT
}

fn is_elided(content: &str) -> bool {
    content.contains(ELIDED_NOTE)
}

/// The stub that replaces a tool result: the tool name, the start of the result and the note.
pub fn stub_for(call_id: &str, name: &str, content: &str) -> String {
    let body = content
        .split_once('\n')
        .map(|(_, rest)| rest.strip_suffix("\n</tool_result>").unwrap_or(rest))
        .unwrap_or(content);
    let mut head: String = body.chars().take(STUB_HEAD_CHARS).collect();
    if body.chars().count() > STUB_HEAD_CHARS {
        head.push('…');
    }
    let safe = |s: &str| -> String {
        s.chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | ':'))
            .collect()
    };
    format!(
        "<tool_result untrusted=\"true\" tool=\"{}\" id=\"{}\">\n{head} {ELIDED_NOTE}\n</tool_result>",
        safe(name),
        safe(call_id)
    )
}

/// Elides the oldest tool results, leaving the newest `keep` alone, until the estimated prompt
/// (`estimate` tokens) is under the low-water mark of `window` or nothing is left to elide.
/// Returns how many results were elided and the new estimate.
pub fn elide_oldest(
    messages: &mut [Message],
    mut estimate: u64,
    window: u32,
    keep: usize,
) -> (usize, u64) {
    let candidates = candidates(messages);
    let upto = candidates.len().saturating_sub(keep);
    let mut elided = 0;
    for &i in &candidates[..upto] {
        if under_low_water(estimate, window) {
            break;
        }
        estimate = estimate.saturating_sub(shrink(&mut messages[i]));
        elided += 1;
    }
    (elided, estimate)
}

/// Elides every tool result except the newest `keep`. Returns how many were elided.
pub fn elide_all_but(messages: &mut [Message], keep: usize) -> usize {
    let candidates = candidates(messages);
    let upto = candidates.len().saturating_sub(keep);
    for &i in &candidates[..upto] {
        shrink(&mut messages[i]);
    }
    upto
}

/// Indices of tool results that are not stubs yet, oldest first.
fn candidates(messages: &[Message]) -> Vec<usize> {
    messages
        .iter()
        .enumerate()
        .filter(|(_, m)| matches!(m, Message::ToolResult { content, .. } if !is_elided(content)))
        .map(|(i, _)| i)
        .collect()
}

/// Replaces the body of a tool result with its stub; returns the tokens saved.
fn shrink(m: &mut Message) -> u64 {
    let Message::ToolResult {
        tool_call_id,
        name,
        content,
        ..
    } = m
    else {
        return 0;
    };
    let before = content.len();
    *content = stub_for(tool_call_id, name, content);
    estimate_tokens(before.saturating_sub(content.len()))
}

/// True when a provider error says the request did not fit the window.
pub fn is_context_overflow(error_text: &str) -> bool {
    error_text.to_ascii_lowercase().contains("context window")
}
