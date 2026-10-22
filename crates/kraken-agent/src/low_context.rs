//! Low context mode: a tool host that tells the model what tools exist without sending every
//! tool's full description and parameter schema.
//!
//! A small local model may have a window of 32k or 64k tokens, and the full list of KRAKEN's
//! tools is most of that. This wrapper offers every tool of the host it wraps with its name and
//! a one-line description, and adds [`TOOL_HELP`]: the model asks for the complete description
//! and schema of the tools it wants to use and gets them as a tool result. Tool calls still go
//! to the wrapped host unchanged, so permissions, approvals and limits work as before. A call
//! with bad arguments fails with the tool's schema in the message, so the model can fix it
//! without asking first.
//!
//! Tool results fill a small window as much as the tool list does, so the mode also asks for
//! small pages (a list tool that takes `limit` gets [`LIST_LIMIT`] items unless the model asks
//! for more, up to [`MAX_LIMIT`]) and shortens any other result above [`RESULT_MAX_CHARS`] with
//! a note on how to ask for less.

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::{Value, json};

use crate::tool::{Decision, Permission, ToolCtx, ToolError, ToolHost, ToolSpec};

/// The name of the tool that returns the full description and parameters of other tools.
pub const TOOL_HELP: &str = "tool_help";

/// Items per page of a list tool when the model does not ask for a size.
pub const LIST_LIMIT: u64 = 20;
/// Most items per page the model may ask for.
pub const MAX_LIMIT: u64 = 50;
/// Longest tool result passed on whole, in characters of JSON.
pub const RESULT_MAX_CHARS: usize = 12_000;
/// Longest one-line description, in characters.
const BRIEF_CHARS: usize = 110;
/// Most tools one `tool_help` call describes.
const HELP_MAX: usize = 8;
/// Most matches a `tool_help` search lists.
const SEARCH_MAX: usize = 12;

/// Wraps a [`ToolHost`] so only a short description of each tool is sent up front.
pub struct LowContextHost {
    inner: Arc<dyn ToolHost>,
    specs: Vec<ToolSpec>,
}

impl LowContextHost {
    /// A low context view of `inner`.
    pub fn new(inner: Arc<dyn ToolHost>) -> Self {
        let specs = inner.tools();
        LowContextHost { inner, specs }
    }

    /// Gives a list tool a small page unless the model chose one, and keeps a chosen one in range.
    fn small_page(&self, name: &str, mut args: Value) -> Value {
        let takes_limit = self
            .specs
            .iter()
            .find(|t| t.name == name)
            .is_some_and(|t| t.input_schema["properties"].get("limit").is_some());
        if !takes_limit {
            return args;
        }
        if let Some(obj) = args.as_object_mut() {
            let limit = obj
                .get("limit")
                .and_then(Value::as_u64)
                .map_or(LIST_LIMIT, |l| l.clamp(1, MAX_LIMIT));
            obj.insert("limit".into(), json!(limit));
        }
        args
    }

    fn help_spec() -> ToolSpec {
        ToolSpec {
            name: TOOL_HELP.into(),
            description: "Tool parameters are not listed to save space. Before using a tool for \
                          the first time, call this with its name to get its full description \
                          and parameters: {\"names\": [\"decompile\"]}. To find a tool, pass a \
                          word: {\"query\": \"rename\"}. Lists come in small pages: ask for \
                          more with the cursor the last page gave (next_cursor)."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "names": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Tools to describe in full."
                    },
                    "query": {
                        "type": "string",
                        "description": "A word to look for in tool names and descriptions."
                    }
                }
            }),
            permission: Permission::Safe,
        }
    }

    fn help(&self, args: &Value) -> Result<Value, ToolError> {
        let tools = &self.specs;
        let mut names: Vec<String> = match args.get("names") {
            Some(Value::Array(a)) => a
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect(),
            Some(Value::String(s)) => vec![s.clone()],
            _ => Vec::new(),
        };
        if let Some(n) = args.get("name").and_then(Value::as_str) {
            names.push(n.to_string());
        }
        let query = args.get("query").and_then(Value::as_str).map(str::trim);
        if names.is_empty() && query.is_none_or(str::is_empty) {
            return Err(ToolError::InvalidArgs(
                "pass {\"names\": [...]} to describe tools or {\"query\": \"word\"} to search"
                    .into(),
            ));
        }
        let mut out = serde_json::Map::new();
        if !names.is_empty() {
            let mut found = Vec::new();
            let mut missing = Vec::new();
            for n in names.iter().take(HELP_MAX) {
                match tools.iter().find(|t| &t.name == n) {
                    Some(t) => found.push(json!({
                        "name": t.name,
                        "description": t.description,
                        "input_schema": t.input_schema,
                    })),
                    None => missing.push(n.clone()),
                }
            }
            out.insert("tools".into(), Value::Array(found));
            if !missing.is_empty() {
                out.insert("not_found".into(), json!(missing));
            }
            if names.len() > HELP_MAX {
                out.insert(
                    "note".into(),
                    json!(format!(
                        "only the first {HELP_MAX} names were described; ask again for the rest"
                    )),
                );
            }
        }
        if let Some(q) = query.filter(|q| !q.is_empty()) {
            let q = q.to_lowercase();
            let matches: Vec<Value> = tools
                .iter()
                .filter(|t| {
                    t.name.to_lowercase().contains(&q) || t.description.to_lowercase().contains(&q)
                })
                .take(SEARCH_MAX)
                .map(|t| json!({"name": t.name, "description": brief(&t.description)}))
                .collect();
            out.insert("matches".into(), Value::Array(matches));
        }
        Ok(Value::Object(out))
    }
}

/// `result` as it is when it is small enough, else a preview with a note.
fn shrink(result: Value) -> Value {
    let text = result.to_string();
    let chars = text.chars().count();
    if chars <= RESULT_MAX_CHARS {
        return result;
    }
    json!({
        "truncated": true,
        "original_chars": chars,
        "note": "This result is too large for low context mode and was cut. Ask for less: a \
                 smaller limit, a filter, or one address or name instead of a list.",
        "preview": text.chars().take(RESULT_MAX_CHARS).collect::<String>(),
    })
}

/// The first sentence of `description`, at most [`BRIEF_CHARS`] characters.
pub fn brief(description: &str) -> String {
    let first = description.trim().lines().next().unwrap_or("").trim();
    let sentence = match first.find(". ") {
        Some(i) => &first[..=i],
        None => first,
    };
    if sentence.chars().count() <= BRIEF_CHARS {
        return sentence.to_string();
    }
    let cut: String = sentence.chars().take(BRIEF_CHARS - 1).collect();
    format!("{}\u{2026}", cut.trim_end())
}

#[async_trait]
impl ToolHost for LowContextHost {
    fn tools(&self) -> Vec<ToolSpec> {
        let mut specs: Vec<ToolSpec> = self
            .specs
            .iter()
            .cloned()
            .map(|t| ToolSpec {
                description: brief(&t.description),
                input_schema: json!({"type": "object", "additionalProperties": true}),
                ..t
            })
            .collect();
        specs.push(Self::help_spec());
        specs
    }

    fn decide(&self, name: &str, args: &Value) -> Decision {
        if name == TOOL_HELP {
            return Decision::Allow;
        }
        self.inner.decide(name, args)
    }

    async fn call(&self, name: &str, args: Value, ctx: &ToolCtx) -> Result<Value, ToolError> {
        if name == TOOL_HELP {
            return self.help(&args);
        }
        let args = self.small_page(name, args);
        match self.inner.call(name, args, ctx).await {
            Ok(v) => Ok(shrink(v)),
            Err(ToolError::InvalidArgs(why)) => {
                let schema = self
                    .specs
                    .iter()
                    .find(|t| t.name == name)
                    .map(|t| t.input_schema.to_string());
                Err(ToolError::InvalidArgs(match schema {
                    Some(s) => format!("{why}. The parameters of `{name}` are: {s}"),
                    None => why,
                }))
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use tokio_util::sync::CancellationToken;

    use super::*;

    struct Host {
        calls: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl ToolHost for Host {
        fn tools(&self) -> Vec<ToolSpec> {
            vec![
                ToolSpec {
                    name: "decompile".into(),
                    description:
                        "Decompile one function to C. Pass its address or name.\\n\\nExample: {...}"
                            .replace("\\n", "\n"),
                    input_schema: json!({"type": "object", "properties": {"address": {"type": "string"}}, "required": ["address"]}),
                    permission: Permission::Safe,
                },
                ToolSpec {
                    name: "rename_function".into(),
                    description: "Rename a function.".into(),
                    input_schema: json!({"type": "object", "properties": {"address": {"type": "string"}, "name": {"type": "string"}}}),
                    permission: Permission::Mutating,
                },
            ]
        }

        async fn call(&self, name: &str, args: Value, _: &ToolCtx) -> Result<Value, ToolError> {
            self.calls.lock().unwrap().push(name.into());
            match (name, args.get("address")) {
                ("decompile", Some(_)) => Ok(json!({"c": "int main(){}"})),
                ("decompile", None) => {
                    Err(ToolError::InvalidArgs("missing field `address`".into()))
                }
                _ => Err(ToolError::NotFound(name.into())),
            }
        }
    }

    fn ctx() -> ToolCtx {
        ToolCtx {
            run_id: "r".into(),
            call_id: "c".into(),
            cancel: CancellationToken::new(),
        }
    }

    fn host() -> (Arc<Host>, LowContextHost) {
        let h = Arc::new(Host {
            calls: Mutex::new(Vec::new()),
        });
        (h.clone(), LowContextHost::new(h))
    }

    #[test]
    fn every_tool_is_listed_with_a_short_description_and_no_parameters() {
        let (_, low) = host();
        let tools = low.tools();
        let names: Vec<&str> = tools.iter().map(|t| t.name.as_str()).collect();
        assert_eq!(names, ["decompile", "rename_function", TOOL_HELP]);
        assert_eq!(tools[0].description, "Decompile one function to C.");
        assert_eq!(tools[0].input_schema["additionalProperties"], true);
        assert!(tools[0].input_schema.get("properties").is_none());
        assert_eq!(
            tools[1].permission,
            Permission::Mutating,
            "permissions are kept"
        );
        assert_eq!(tools[2].permission, Permission::Safe);
    }

    #[test]
    fn brief_takes_the_first_sentence_and_cuts_long_ones() {
        assert_eq!(brief("One. Two."), "One.");
        assert_eq!(brief("  A line\nsecond line"), "A line");
        let long = "x".repeat(300);
        let b = brief(&long);
        assert_eq!(b.chars().count(), BRIEF_CHARS);
        assert!(b.ends_with('\u{2026}'));
        assert_eq!(brief(""), "");
    }

    #[tokio::test]
    async fn tool_help_returns_the_full_description_and_schema() {
        let (inner, low) = host();
        let r = low
            .call(TOOL_HELP, json!({"names": ["decompile", "nope"]}), &ctx())
            .await
            .unwrap();
        assert_eq!(r["tools"][0]["name"], "decompile");
        assert!(
            r["tools"][0]["description"]
                .as_str()
                .unwrap()
                .contains("Example")
        );
        assert_eq!(r["tools"][0]["input_schema"]["required"][0], "address");
        assert_eq!(r["not_found"], json!(["nope"]));
        assert!(
            inner.calls.lock().unwrap().is_empty(),
            "help never reaches the host"
        );
    }

    #[tokio::test]
    async fn tool_help_searches_and_rejects_an_empty_request() {
        let (_, low) = host();
        let r = low
            .call(TOOL_HELP, json!({"query": "RENAME"}), &ctx())
            .await
            .unwrap();
        assert_eq!(r["matches"].as_array().unwrap().len(), 1);
        assert_eq!(r["matches"][0]["name"], "rename_function");
        let e = low.call(TOOL_HELP, json!({}), &ctx()).await.unwrap_err();
        assert!(matches!(e, ToolError::InvalidArgs(_)));
        let one = low
            .call(TOOL_HELP, json!({"name": "rename_function"}), &ctx())
            .await
            .unwrap();
        assert_eq!(one["tools"][0]["name"], "rename_function");
    }

    #[tokio::test]
    async fn real_tools_are_called_unchanged_and_bad_arguments_carry_the_schema() {
        let (inner, low) = host();
        let ok = low
            .call("decompile", json!({"address": "0x401000"}), &ctx())
            .await
            .unwrap();
        assert_eq!(ok["c"], "int main(){}");
        let e = low.call("decompile", json!({}), &ctx()).await.unwrap_err();
        let ToolError::InvalidArgs(msg) = e else {
            panic!("{e:?}")
        };
        assert!(
            msg.contains("missing field `address`") && msg.contains("\"required\""),
            "{msg}"
        );
        let e = low.call("nothing", json!({}), &ctx()).await.unwrap_err();
        assert!(matches!(e, ToolError::NotFound(_)));
        assert_eq!(inner.calls.lock().unwrap().len(), 3);
    }

    struct Lists {
        seen: Mutex<Vec<Value>>,
        big: bool,
    }

    #[async_trait]
    impl ToolHost for Lists {
        fn tools(&self) -> Vec<ToolSpec> {
            let spec = |name: &str, props: Value| ToolSpec {
                name: name.into(),
                description: format!("{name} list"),
                input_schema: json!({"type": "object", "properties": props}),
                permission: Permission::Safe,
            };
            vec![
                spec(
                    "functions",
                    json!({"limit": {"type": "integer"}, "cursor": {"type": "string"}}),
                ),
                spec("whoami", json!({})),
            ]
        }

        async fn call(&self, name: &str, args: Value, _: &ToolCtx) -> Result<Value, ToolError> {
            self.seen.lock().unwrap().push(args);
            if self.big {
                return Ok(json!({"c": "x".repeat(RESULT_MAX_CHARS * 2)}));
            }
            Ok(json!({"tool": name}))
        }
    }

    #[tokio::test]
    async fn list_tools_get_small_pages_and_a_chosen_page_stays_in_range() {
        let inner = Arc::new(Lists {
            seen: Mutex::new(Vec::new()),
            big: false,
        });
        let low = LowContextHost::new(inner.clone());
        low.call("functions", json!({}), &ctx()).await.unwrap();
        low.call("functions", json!({"limit": 500, "cursor": "n"}), &ctx())
            .await
            .unwrap();
        low.call("functions", json!({"limit": 5}), &ctx())
            .await
            .unwrap();
        low.call("whoami", json!({}), &ctx()).await.unwrap();
        let seen = inner.seen.lock().unwrap();
        assert_eq!(seen[0]["limit"], LIST_LIMIT);
        assert_eq!(
            (seen[1]["limit"].as_u64(), seen[1]["cursor"].as_str()),
            (Some(MAX_LIMIT), Some("n"))
        );
        assert_eq!(seen[2]["limit"], 5);
        assert!(
            seen[3].get("limit").is_none(),
            "a tool without a limit is left alone"
        );
    }

    #[tokio::test]
    async fn an_oversized_result_is_cut_with_a_note_and_a_small_one_is_not() {
        let big = LowContextHost::new(Arc::new(Lists {
            seen: Mutex::new(Vec::new()),
            big: true,
        }));
        let r = big.call("whoami", json!({}), &ctx()).await.unwrap();
        assert_eq!(r["truncated"], true);
        assert!(r["note"].as_str().unwrap().contains("Ask for less"));
        assert_eq!(
            r["preview"].as_str().unwrap().chars().count(),
            RESULT_MAX_CHARS
        );
        let small = LowContextHost::new(Arc::new(Lists {
            seen: Mutex::new(Vec::new()),
            big: false,
        }));
        let r = small.call("whoami", json!({}), &ctx()).await.unwrap();
        assert_eq!(r, json!({"tool": "whoami"}));
    }
}
