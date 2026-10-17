//! Registry entries as MCP tool definitions.

use kraken_registry::{Entry, Permission, Registry};
use rmcp::model::{JsonObject, Tool, ToolAnnotations};
use serde_json::Value;

fn object_schema(v: &Value) -> Option<JsonObject> {
    match v {
        Value::Object(m) if m.get("type").and_then(Value::as_str) == Some("object") => {
            Some(m.clone())
        }
        _ => None,
    }
}

/// The tool definition of one command.
pub fn tool_for(entry: &Entry) -> Tool {
    let spec = entry.spec();
    let description = spec.tool_description();
    let input = object_schema(entry.args_schema()).unwrap_or_else(|| {
        let mut m = JsonObject::new();
        m.insert("type".into(), Value::String("object".into()));
        m
    });
    let annotations = match spec.permission {
        Permission::Safe => ToolAnnotations::new().read_only(true),
        Permission::Mutating => ToolAnnotations::new().read_only(false).destructive(false),
        Permission::Dangerous => ToolAnnotations::new().read_only(false).destructive(true),
    }
    .open_world(false);
    let mut tool = Tool::new(spec.name.clone(), description, input).annotate(annotations);
    if let Some(out) = object_schema(entry.output_schema()) {
        tool = tool.with_raw_output_schema(out.into());
    }
    tool
}

/// Tool definitions for every command, sorted by name.
pub fn tools_for(registry: &Registry) -> Vec<Tool> {
    registry.iter().map(tool_for).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_standard_command_becomes_a_tool_with_schemas() {
        let r = Registry::standard();
        let tools = tools_for(&r);
        assert_eq!(tools.len(), r.len());
        for t in &tools {
            assert_eq!(
                t.input_schema.get("type").and_then(Value::as_str),
                Some("object"),
                "{}",
                t.name
            );
            assert!(t.output_schema.is_some(), "{} has an output schema", t.name);
            assert!(t.description.as_deref().is_some_and(|d| !d.is_empty()));
        }
    }

    #[test]
    fn annotations_follow_the_permission() {
        let r = Registry::standard();
        let list = tool_for(r.get("list_functions").expect("list_functions"));
        assert_eq!(list.annotations.and_then(|a| a.read_only_hint), Some(true));
        let rename = tool_for(r.get("rename_symbol").expect("rename_symbol"));
        let a = rename.annotations.expect("annotations");
        assert_eq!(a.read_only_hint, Some(false));
        assert_eq!(a.destructive_hint, Some(false));
    }
}
