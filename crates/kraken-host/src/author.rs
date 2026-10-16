//! Who is calling: the OS user for the CLI, the MCP client for agents, and run ids.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use kraken_proto::sanitize;

/// The user id for CLI edits: `$USER`, else `$LOGNAME`, else `user`.
pub fn user_id() -> String {
    user_id_with(&|k| std::env::var(k).ok())
}

/// [`user_id`] with an injectable environment.
pub fn user_id_with(env: &dyn Fn(&str) -> Option<String>) -> String {
    ["USER", "LOGNAME"]
        .iter()
        .find_map(|k| env(k).filter(|v| !v.trim().is_empty()))
        .map(|v| clean_id(&v))
        .unwrap_or_else(|| "user".into())
}

/// The agent id for an MCP client: its `clientInfo.name`, cleaned, or `mcp-client` when absent.
pub fn agent_id_from_client(client_name: Option<&str>) -> String {
    match client_name.map(clean_id) {
        Some(n) if !n.is_empty() => n,
        _ => "mcp-client".into(),
    }
}

fn clean_id(raw: &str) -> String {
    let s = sanitize(raw);
    let s: String = s
        .chars()
        .map(|c| if c.is_whitespace() { '-' } else { c })
        .take(64)
        .collect();
    s.trim().to_string()
}

/// Generates run ids that are unique per process start (`run-<unix ms hex>-<pid>-<n>`).
#[derive(Debug, Default)]
pub struct RunIdGen {
    next: AtomicU64,
}

impl RunIdGen {
    /// A generator.
    pub fn new() -> Self {
        Self::default()
    }

    /// The next run id.
    pub fn next_id(&self) -> String {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        let n = self.next.fetch_add(1, Ordering::Relaxed);
        format!("run-{ms:x}-{}-{n}", std::process::id())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_comes_from_the_environment() {
        assert_eq!(
            user_id_with(&|k| (k == "USER").then(|| "adam".into())),
            "adam"
        );
        assert_eq!(
            user_id_with(&|k| (k == "LOGNAME").then(|| "bob".into())),
            "bob"
        );
        assert_eq!(user_id_with(&|_| None), "user");
        assert_eq!(user_id_with(&|_| Some("  ".into())), "user");
    }

    #[test]
    fn agent_ids_are_cleaned() {
        assert_eq!(agent_id_from_client(Some("claude code")), "claude-code");
        assert_eq!(agent_id_from_client(Some("")), "mcp-client");
        assert_eq!(agent_id_from_client(None), "mcp-client");
        assert_eq!(agent_id_from_client(Some(&"x".repeat(200))).len(), 64);
    }

    #[test]
    fn run_ids_differ() {
        let g = RunIdGen::new();
        assert_ne!(g.next_id(), g.next_id());
    }
}
