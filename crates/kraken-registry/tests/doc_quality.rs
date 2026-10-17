//! Tool descriptions are what a model reads before it calls a command, so they are held to a
//! standard: a short summary, a doc that says how to call it with an example, and a described,
//! bounded argument list. The registry is the single source of these texts (the CLI help, the
//! MCP tool list and the generated reference all come from it).

use kraken_registry::Registry;
use serde_json::Value;

const MAX_SUMMARY: usize = 110;
const MAX_ARG_DOC: usize = 240;
const MAX_DOC: usize = 800;

fn resolve(v: &Value, defs: &Value) -> Value {
    if let Some(r) = v.get("$ref").and_then(Value::as_str)
        && let Some(name) = r.strip_prefix("#/$defs/")
        && let Some(d) = defs.get(name)
    {
        let mut d = d.clone();
        if let (Some(o), Some(desc)) = (d.as_object_mut(), v.get("description")) {
            o.insert("description".into(), desc.clone());
        }
        return d;
    }
    v.clone()
}

fn properties(schema: &Value) -> Vec<(String, Value)> {
    let defs = schema.get("$defs").cloned().unwrap_or(Value::Null);
    schema
        .get("properties")
        .and_then(Value::as_object)
        .map(|props| {
            props
                .iter()
                .map(|(k, v)| (k.clone(), resolve(v, &defs)))
                .collect()
        })
        .unwrap_or_default()
}

fn has_description(v: &Value) -> bool {
    v.get("description")
        .and_then(Value::as_str)
        .is_some_and(|d| !d.trim().is_empty())
        || ["allOf", "anyOf"].iter().any(|k| {
            v.get(*k)
                .and_then(Value::as_array)
                .is_some_and(|a| a.iter().any(has_description))
        })
}

fn description_len(v: &Value) -> usize {
    v.get("description")
        .and_then(Value::as_str)
        .map_or(0, |d| d.chars().count())
}

/// The doc ends with `Example: <command> <JSON arguments>`; the arguments must be real: valid
/// JSON, only known properties, every required one present.
fn check_example(entry: &kraken_registry::Entry, problems: &mut Vec<String>) {
    let spec = entry.spec();
    let name = &spec.name;
    let Some(line) = spec
        .doc
        .lines()
        .find_map(|l| l.trim().strip_prefix("Example: "))
    else {
        problems.push(format!("{name}: doc has no `Example:` line"));
        return;
    };
    let Some(json) = line.strip_prefix(name.as_str()).map(str::trim) else {
        problems.push(format!(
            "{name}: example does not start with the command name"
        ));
        return;
    };
    let args: Value = match serde_json::from_str(json) {
        Ok(v) => v,
        Err(e) => {
            problems.push(format!("{name}: example arguments are not JSON ({e})"));
            return;
        }
    };
    let schema = entry.args_schema();
    let known: Vec<String> = properties(schema).into_iter().map(|(k, _)| k).collect();
    let obj = args.as_object().cloned().unwrap_or_default();
    for k in obj.keys() {
        if !known.contains(k) {
            problems.push(format!("{name}: example uses unknown argument `{k}`"));
        }
    }
    if let Some(req) = schema.get("required").and_then(Value::as_array) {
        for r in req.iter().filter_map(Value::as_str) {
            if !obj.contains_key(r) {
                problems.push(format!("{name}: example misses required argument `{r}`"));
            }
        }
    }
}

#[test]
fn every_command_reads_well_to_a_model() {
    let registry = Registry::standard();
    let mut problems = Vec::new();
    for entry in registry.iter() {
        let spec = entry.spec();
        let name = &spec.name;
        if spec.summary.chars().count() > MAX_SUMMARY {
            problems.push(format!("{name}: summary is over {MAX_SUMMARY} characters"));
        }
        if spec.summary.trim_end().ends_with('.') {
            problems.push(format!("{name}: summary ends with a full stop"));
        }
        if spec.doc.chars().count() > MAX_DOC {
            problems.push(format!("{name}: doc is over {MAX_DOC} characters"));
        }
        check_example(entry, &mut problems);
        for (arg, schema) in properties(entry.args_schema()) {
            if !has_description(&schema) {
                problems.push(format!("{name}.{arg}: argument has no description"));
            } else if description_len(&schema) > MAX_ARG_DOC {
                problems.push(format!(
                    "{name}.{arg}: argument doc is over {MAX_ARG_DOC} characters"
                ));
            }
        }
    }
    assert!(
        problems.is_empty(),
        "{} problems:\n{}",
        problems.len(),
        problems.join("\n")
    );
}
