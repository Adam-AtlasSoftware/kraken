//! Output conventions applied by every surface so that CLI, MCP and the daemon agree.

use serde_json::{Value, json};

/// Applies the surface conventions to a command result:
///
/// - a result with `"status": "proposed"` gets a top-level `"proposal"` object
///   (`{id, key, reason}`), the field `kraken-agent` looks for to raise proposal events.
pub fn finalize_output(mut out: Value) -> Value {
    if let Some(obj) = out.as_object_mut()
        && obj.get("status").and_then(Value::as_str) == Some("proposed")
        && !obj.contains_key("proposal")
    {
        let proposal = json!({
            "id": obj.get("proposal_id").cloned().unwrap_or(Value::Null),
            "key": obj.get("key").cloned().unwrap_or(Value::Null),
            "reason": obj.get("reason").cloned().unwrap_or(Value::Null),
        });
        obj.insert("proposal".into(), proposal);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proposed_results_get_a_proposal_field() {
        let v = finalize_output(json!({
            "status": "proposed", "proposal_id": 4, "key": "name@0x1", "versions": {}, "reason": "overwrite"
        }));
        assert_eq!(v["proposal"]["id"], 4);
        assert_eq!(v["proposal"]["reason"], "overwrite");
        assert_eq!(v["proposal_id"], 4);
    }

    #[test]
    fn other_results_are_untouched() {
        let applied = json!({"status": "applied", "entry_id": 1});
        assert_eq!(finalize_output(applied.clone()), applied);
        assert_eq!(finalize_output(json!([1, 2])), json!([1, 2]));
    }
}
