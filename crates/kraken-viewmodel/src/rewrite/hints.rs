//! Hints that steer the translation of one function, edited in the Rewrite tab: the text form
//! the person types, its conversion to and from the `rewrite_hint_*` JSON, and the actions.

use std::collections::{HashMap, HashSet};

use serde_json::{Value, json};

use crate::errors::plain_error;
use crate::state::ToastLevel;
use crate::vm::{ViewModel, hex};

/// What the hints editor holds for one function, as the person types it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HintsDraft {
    /// Free text for the model.
    pub notes: String,
    /// One `name -> new_name` per line.
    pub renames: String,
    /// One `variable: Rust type` per line.
    pub types: String,
    /// One `std::...` path per line.
    pub uses: String,
    /// Keep `unsafe` to dereferencing the given pointers.
    pub forbid_unsafe: bool,
}

impl HintsDraft {
    /// True when nothing is typed.
    pub fn is_empty(&self) -> bool {
        self.notes.trim().is_empty()
            && self.renames.trim().is_empty()
            && self.types.trim().is_empty()
            && self.uses.trim().is_empty()
            && !self.forbid_unsafe
    }

    /// The `hints` argument of `rewrite_hint_set`; the error says which line is wrong.
    pub fn to_json(&self) -> Result<Value, String> {
        let mut renames = Vec::new();
        for line in lines(&self.renames) {
            let Some((from, to)) = line.split_once("->").or_else(|| line.split_once('=')) else {
                return Err(format!(
                    "Rename line \"{line}\" needs an arrow: local_10 -> count"
                ));
            };
            renames.push(json!({"from": from.trim(), "to": to.trim()}));
        }
        let mut types = Vec::new();
        for line in lines(&self.types) {
            let Some((target, ty)) = line.split_once(':') else {
                return Err(format!(
                    "Type line \"{line}\" needs a colon: a0: &mut [u32]"
                ));
            };
            types.push(json!({"target": target.trim(), "rust_type": ty.trim()}));
        }
        let uses: Vec<String> = lines(&self.uses)
            .map(|l| {
                l.trim_start_matches("use ")
                    .trim_end_matches(';')
                    .trim()
                    .to_string()
            })
            .collect();
        Ok(json!({
            "notes": self.notes.trim(),
            "rename_vars": renames,
            "types": types,
            "uses": uses,
            "forbid_unsafe": self.forbid_unsafe,
        }))
    }

    /// The editor text for the `hints` of a `rewrite_hint_get` answer.
    pub fn from_json(v: &Value) -> HintsDraft {
        let list = |key: &str| {
            v.get(key)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default()
        };
        let s = |x: &Value, k: &str| x.get(k).and_then(Value::as_str).unwrap_or("").to_string();
        HintsDraft {
            notes: s(v, "notes"),
            renames: list("rename_vars")
                .iter()
                .map(|r| format!("{} -> {}", s(r, "from"), s(r, "to")))
                .collect::<Vec<_>>()
                .join("\n"),
            types: list("types")
                .iter()
                .map(|t| format!("{}: {}", s(t, "target"), s(t, "rust_type")))
                .collect::<Vec<_>>()
                .join("\n"),
            uses: list("uses")
                .iter()
                .filter_map(|u| u.as_str().map(str::to_string))
                .collect::<Vec<_>>()
                .join("\n"),
            forbid_unsafe: v
                .get("forbid_unsafe")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        }
    }
}

fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().map(str::trim).filter(|l| !l.is_empty())
}

/// The stored hints the tab has heard of.
#[derive(Debug, Clone, Default)]
pub struct HintsState {
    /// What the daemon holds, by function address.
    pub stored: HashMap<u64, HintsDraft>,
    /// Who stored them last, by function address.
    pub updated_by: HashMap<u64, String>,
    /// Functions whose hints were asked for.
    pub(crate) requested: HashSet<u64>,
    /// Hints that go with the next translation of a function.
    pub(crate) pending: HashMap<u64, Value>,
}

impl ViewModel {
    /// Asks for the stored hints of a function, once.
    pub fn rewrite_hints_load(&mut self, address: u64) {
        if !self.rewrite.hints.requested.insert(address) {
            return;
        }
        self.call(
            "rewrite_hint_get",
            json!({ "address": hex(address) }),
            move |vm, res| {
                // An older daemon has no hints; the editor then starts empty.
                let Ok(v) = res else { return };
                vm.rewrite_hints_stored(address, &v);
            },
        );
    }

    fn rewrite_hints_stored(&mut self, address: u64, answer: &Value) {
        let draft = answer
            .get("hints")
            .map(HintsDraft::from_json)
            .unwrap_or_default();
        self.rewrite.hints.stored.insert(address, draft);
        match answer.get("updated_by").and_then(Value::as_str) {
            Some(who) => self
                .rewrite
                .hints
                .updated_by
                .insert(address, who.to_string()),
            None => self.rewrite.hints.updated_by.remove(&address),
        };
    }

    /// Stores the hints for the function (no model call).
    pub fn rewrite_hints_save(&mut self, address: u64, draft: &HintsDraft) -> Result<(), String> {
        let hints = draft.to_json()?;
        let name = self.rewrite_name(address);
        self.call(
            "rewrite_hint_set",
            json!({ "address": hex(address), "hints": hints }),
            move |vm, res| match res {
                Ok(v) => {
                    vm.rewrite_hints_stored(address, &v);
                    let text = if vm
                        .rewrite
                        .hints
                        .stored
                        .get(&address)
                        .is_some_and(|d| d.is_empty())
                    {
                        format!("Removed the hints of {name}.")
                    } else {
                        format!("Saved the hints of {name}. The next translation uses them.")
                    };
                    vm.toast(ToastLevel::Success, text);
                }
                Err(e) => vm.toast(ToastLevel::Error, plain_error(&e)),
            },
        );
        Ok(())
    }

    /// Translates the function again with these hints (they are stored with the request); a job
    /// that asks the model, so the usual cost question comes first.
    pub fn rewrite_retranslate_with_hints(
        &mut self,
        address: u64,
        draft: &HintsDraft,
    ) -> Result<(), String> {
        let hints = draft.to_json()?;
        self.rewrite.hints.pending.insert(address, hints);
        self.rewrite.hints.stored.insert(address, draft.clone());
        self.rewrite_retry(address);
        Ok(())
    }

    /// The hints that go with the translation now starting, once.
    pub(super) fn rewrite_take_pending_hints(&mut self, address: u64) -> Option<Value> {
        self.rewrite.hints.pending.remove(&address)
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{base, opened};
    use super::*;

    #[test]
    fn hints_load_once_save_and_travel_with_the_retranslation() {
        let b = base()
            .reply(
                "rewrite_hint_get",
                json!({"address": "0x401240", "updated_by": "adam",
                       "hints": {"notes": "stored note", "forbid_unsafe": true}}),
            )
            .reply(
                "rewrite_hint_set",
                json!({"address": "0x401240", "updated_by": "adam",
                       "hints": {"notes": "typed", "rename_vars": [{"from": "a", "to": "b"}]}}),
            )
            .reply("rewrite_function", json!({"job_id": "job-9"}))
            .reply("rewrite_unit", json!({"versions": []}));
        let mut r = opened(b);
        r.vm.rewrite_refresh();
        r.idle();
        r.vm.rewrite_select(0x401240);
        r.idle();

        // The stored hints are read once, however often the editor asks.
        r.vm.rewrite_hints_load(0x401240);
        r.vm.rewrite_hints_load(0x401240);
        r.idle();
        assert_eq!(r.backend.calls_to("rewrite_hint_get").len(), 1);
        let stored = &r.vm.rewrite.hints.stored[&0x401240];
        assert_eq!(stored.notes, "stored note");
        assert!(stored.forbid_unsafe);
        assert_eq!(r.vm.rewrite.hints.updated_by[&0x401240], "adam");

        // A line the person got wrong is explained and nothing is sent.
        let bad = HintsDraft {
            renames: "a b".into(),
            ..HintsDraft::default()
        };
        assert!(r.vm.rewrite_hints_save(0x401240, &bad).is_err());
        assert!(r.backend.calls_to("rewrite_hint_set").is_empty());

        // Saving sends the typed hints.
        let draft = HintsDraft {
            notes: "typed".into(),
            renames: "a -> b".into(),
            ..HintsDraft::default()
        };
        r.vm.rewrite_hints_save(0x401240, &draft).expect("valid");
        r.idle();
        let set = &r.backend.calls_to("rewrite_hint_set")[0];
        assert_eq!(set["address"], "0x401240");
        assert_eq!(set["hints"]["rename_vars"][0]["to"], "b");
        assert_eq!(r.vm.rewrite.hints.stored[&0x401240].renames, "a -> b");

        // Retranslating runs the function with the hints in the request.
        r.vm.rewrite_retranslate_with_hints(0x401240, &draft)
            .expect("valid");
        r.idle();
        let call = &r.backend.calls_to("rewrite_function")[0];
        assert_eq!(call["hints"]["notes"], "typed");
        assert_eq!(call["address"], "0x401240");
        // They go with that one request only.
        assert!(r.vm.rewrite.hints.pending.is_empty());
    }

    #[test]
    fn typed_lines_become_hints_and_back() {
        let d = HintsDraft {
            notes: " keep the loop ".into(),
            renames: "local_10 -> count\nparam_1=left".into(),
            types: "a0: &mut [u32]\n\nlocal_8: usize".into(),
            uses: "use std::cmp::Ordering;\nstd::mem".into(),
            forbid_unsafe: true,
        };
        let j = d.to_json().expect("valid");
        assert_eq!(j["notes"], "keep the loop");
        assert_eq!(
            j["rename_vars"][1],
            json!({"from": "param_1", "to": "left"})
        );
        assert_eq!(j["types"][0]["rust_type"], "&mut [u32]");
        assert_eq!(j["uses"], json!(["std::cmp::Ordering", "std::mem"]));
        let back = HintsDraft::from_json(&j);
        assert_eq!(back.renames, "local_10 -> count\nparam_1 -> left");
        assert_eq!(back.types, "a0: &mut [u32]\nlocal_8: usize");
        assert!(back.forbid_unsafe);
    }

    #[test]
    fn a_line_without_its_separator_says_what_to_write() {
        let d = HintsDraft {
            renames: "local_10 count".into(),
            ..HintsDraft::default()
        };
        assert!(d.to_json().is_err_and(|e| e.contains("arrow")));
        let d = HintsDraft {
            types: "a0 u32".into(),
            ..HintsDraft::default()
        };
        assert!(d.to_json().is_err_and(|e| e.contains("colon")));
        assert!(HintsDraft::default().is_empty());
    }
}
