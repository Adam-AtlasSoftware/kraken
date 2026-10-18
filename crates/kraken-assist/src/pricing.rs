//! Model prices, for cost estimates.
//!
//! Every number here is an estimate: list prices in US dollars per million tokens as published
//! by the providers, without discounts, caching, batch rates or long-context surcharges. They go
//! stale. The `[pricing]` table of `config.toml` overrides and extends them:
//!
//! ```toml
//! [pricing]
//! "claude-sonnet-5-5" = { input = 3.0, output = 15.0 }
//! "my-finetune" = { input = 0.5, output = 1.5 }
//! ```
//!
//! A model is looked up by its exact name first, then by the longest known name it starts with
//! (`claude-sonnet-4-5-20250929` finds `claude-sonnet`).

use std::collections::BTreeMap;
use std::path::Path;

use kraken_proto::{AiBilling, AiProviderKind};
use serde::{Deserialize, Serialize};

/// The price of one model, US dollars per million tokens.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Price {
    /// Per million input tokens.
    pub input: f64,
    /// Per million output tokens.
    pub output: f64,
}

impl Price {
    /// The cost of `input` and `output` tokens.
    pub fn cost(&self, input: u64, output: u64) -> f64 {
        (input as f64 * self.input + output as f64 * self.output) / 1_000_000.0
    }
}

/// Built-in prices (estimates; USD per million input / output tokens). Keys are model names or
/// name prefixes. Keep this the only list of prices in the code base.
pub const DEFAULT_PRICES: &[(&str, f64, f64)] = &[
    // Anthropic
    ("claude-opus-4-0", 15.0, 75.0),
    ("claude-opus-4-1", 15.0, 75.0),
    ("claude-opus-4-2025", 15.0, 75.0),
    ("claude-3-opus", 15.0, 75.0),
    ("claude-opus", 5.0, 25.0),
    ("claude-sonnet", 3.0, 15.0),
    ("claude-3-5-sonnet", 3.0, 15.0),
    ("claude-3-7-sonnet", 3.0, 15.0),
    ("claude-haiku", 1.0, 5.0),
    ("claude-3-5-haiku", 0.8, 4.0),
    ("claude-3-haiku", 0.25, 1.25),
    // OpenAI
    ("gpt-5", 1.25, 10.0),
    ("gpt-5-mini", 0.25, 2.0),
    ("gpt-5-nano", 0.05, 0.4),
    ("gpt-4.1", 2.0, 8.0),
    ("gpt-4.1-mini", 0.4, 1.6),
    ("gpt-4.1-nano", 0.1, 0.4),
    ("gpt-4o", 2.5, 10.0),
    ("gpt-4o-mini", 0.15, 0.6),
    ("o1", 15.0, 60.0),
    ("o3", 2.0, 8.0),
    ("o3-mini", 1.1, 4.4),
    ("o4-mini", 1.1, 4.4),
    // Google Gemini
    ("gemini-3-pro", 2.0, 12.0),
    ("gemini-2.5-pro", 1.25, 10.0),
    ("gemini-2.5-flash", 0.3, 2.5),
    ("gemini-2.5-flash-lite", 0.1, 0.4),
    ("gemini-2.0-flash", 0.1, 0.4),
];

/// The price table: the built-in estimates with the `[pricing]` table on top.
#[derive(Debug, Clone, PartialEq)]
pub struct Pricing {
    prices: BTreeMap<String, Price>,
}

impl Default for Pricing {
    fn default() -> Self {
        Pricing {
            prices: DEFAULT_PRICES
                .iter()
                .map(|(m, i, o)| {
                    (
                        (*m).to_string(),
                        Price {
                            input: *i,
                            output: *o,
                        },
                    )
                })
                .collect(),
        }
    }
}

impl Pricing {
    /// A table with no prices (tests).
    pub fn empty() -> Self {
        Pricing {
            prices: BTreeMap::new(),
        }
    }

    /// Adds or replaces the price of `model`.
    pub fn set(&mut self, model: &str, price: Price) {
        self.prices.insert(model.to_ascii_lowercase(), price);
    }

    /// The built-in table with the `[pricing]` table of `text` (a whole `config.toml`) applied.
    /// Entries that do not parse are skipped and named in the second value.
    pub fn from_config_text(text: &str) -> (Self, Vec<String>) {
        let mut p = Pricing::default();
        let mut bad = Vec::new();
        let Ok(table) = text.parse::<toml::Table>() else {
            return (p, bad);
        };
        if let Some(toml::Value::Table(t)) = table.get("pricing") {
            for (model, v) in t {
                match v.clone().try_into::<Price>() {
                    Ok(price) if price.input >= 0.0 && price.output >= 0.0 => p.set(model, price),
                    _ => bad.push(model.clone()),
                }
            }
        }
        (p, bad)
    }

    /// The table for the config file at `path` (the built-in one when there is none).
    pub fn load(path: Option<&Path>) -> Self {
        path.and_then(|p| std::fs::read_to_string(p).ok())
            .map(|t| Self::from_config_text(&t).0)
            .unwrap_or_default()
    }

    /// The price of `model`: exact name, else the longest known prefix.
    pub fn price_of(&self, model: &str) -> Option<Price> {
        let m = model.trim().to_ascii_lowercase();
        if m.is_empty() {
            return None;
        }
        if let Some(p) = self.prices.get(&m) {
            return Some(*p);
        }
        // Providers prefix names (`anthropic/claude-...`, `models/gemini-...`).
        let bare = m.rsplit('/').next().unwrap_or(&m);
        self.prices
            .iter()
            .filter(|(k, _)| bare.starts_with(k.as_str()))
            .max_by_key(|(k, _)| k.len())
            .map(|(_, p)| *p)
    }

    /// How a call to `model` on `kind` is paid for, and its price when metered.
    pub fn billing(&self, kind: AiProviderKind, model: &str) -> (AiBilling, Option<Price>) {
        match kind {
            AiProviderKind::Local => (AiBilling::Free, None),
            AiProviderKind::TerminalAgent => (AiBilling::Subscription, None),
            AiProviderKind::Api => match self.price_of(model) {
                Some(p) => (AiBilling::Metered, Some(p)),
                None => (AiBilling::Unpriced, None),
            },
        }
    }

    /// Every entry, sorted by name (for the settings and the docs).
    pub fn entries(&self) -> impl Iterator<Item = (&str, Price)> {
        self.prices.iter().map(|(k, v)| (k.as_str(), *v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_wins_and_config_overrides() {
        let p = Pricing::default();
        assert_eq!(p.price_of("claude-sonnet-4-5-20250929").unwrap().input, 3.0);
        assert_eq!(p.price_of("claude-opus-4-1-2025").unwrap().input, 15.0);
        assert_eq!(p.price_of("claude-opus-4-5").unwrap().input, 5.0);
        assert_eq!(p.price_of("gpt-4.1-mini").unwrap().input, 0.4);
        assert_eq!(p.price_of("models/gemini-2.5-flash").unwrap().output, 2.5);
        assert!(p.price_of("qwen3:14b").is_none());
        let (c, bad) = Pricing::from_config_text(
            "[pricing]\n\"qwen3:14b\" = { input = 0.1, output = 0.2 }\n\"claude-sonnet\" = { input = 1.0, output = 2.0 }\nbroken = 3\n",
        );
        assert_eq!(c.price_of("qwen3:14b").unwrap().output, 0.2);
        assert_eq!(c.price_of("claude-sonnet-5-5").unwrap().input, 1.0);
        assert_eq!(bad, vec!["broken".to_string()]);
        let price = c.price_of("qwen3:14b").unwrap();
        assert!((price.cost(1_000_000, 500_000) - 0.2).abs() < 1e-9);
    }

    #[test]
    fn local_and_agents_are_not_metered() {
        let p = Pricing::default();
        assert_eq!(
            p.billing(AiProviderKind::Local, "claude-opus").0,
            AiBilling::Free
        );
        assert_eq!(
            p.billing(AiProviderKind::TerminalAgent, "opus").0,
            AiBilling::Subscription
        );
        assert_eq!(
            p.billing(AiProviderKind::Api, "who-knows").0,
            AiBilling::Unpriced
        );
    }
}
