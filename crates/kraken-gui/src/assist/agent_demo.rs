//! The scripted terminal agent behind the `assistant-agent` screenshot.
//!
//! The window can play the part of an ACP agent itself (`kraken-gui --fake-acp-agent`, a hidden
//! flag): it runs the same fake agent the tests use, so the screenshot is deterministic and needs
//! no installed agent, no network and no account.

use kraken_acp::{AgentPaths, AgentProfile, Platform, Resolver};
use kraken_viewmodel::agents::AgentsConfig;
use kraken_viewmodel::assist::{AgentChoice, BackendChoice, ProviderBadge};

/// The hidden flag that turns this executable into the fake ACP agent.
pub const FAKE_AGENT_FLAG: &str = "--fake-acp-agent";

/// The question the screenshot asks.
pub const SCENE_PROMPT: &str =
    "Find the function that prints an error and exits, and give it a clear name.";

/// The id of the scripted agent.
pub const DEMO_AGENT: &str = "demo";

/// Serves the fake agent on stdin/stdout. Returns the process exit code.
pub fn run_fake_agent() -> i32 {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    match kraken_acp::fake_agent::serve(stdin.lock(), stdout.lock()) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("kraken-gui: fake agent: {e}");
            5
        }
    }
}

/// An agents configuration with one scripted "Demo agent" and nothing else on the computer
/// involved: a scratch data directory, no config directory (the notice counts as read), and the
/// built-in agents shown as not installed.
pub fn scene_config() -> Option<AgentsConfig> {
    let exe = std::env::current_exe().ok()?;
    let dir = std::env::temp_dir().join("kraken-gui-agents-scene");
    let resolver = Resolver {
        paths: AgentPaths::in_data_dir(&dir),
        platform: Platform::current(),
        path_env: Some(dir.as_os_str().to_owned()),
    };
    let mut cfg = AgentsConfig::new(resolver, None);
    cfg.kraken_exe = Some(exe.clone());
    cfg.parent_env = Some(vec![]);
    cfg.extra_profiles = vec![
        AgentProfile::custom(
            DEMO_AGENT,
            "Demo agent",
            exe.to_string_lossy().into_owned(),
            vec![FAKE_AGENT_FLAG.to_string()],
        )
        .with_env("FAKE_ACP_SCRIPT", "kraken"),
    ];
    Some(cfg)
}

/// The scripted agent as the assistant's backend.
pub fn scene_backend() -> (BackendChoice, ProviderBadge) {
    (
        BackendChoice::Agent(AgentChoice {
            agent: DEMO_AGENT.to_string(),
            model: None,
            args: Vec::new(),
        }),
        ProviderBadge {
            service: "Demo agent".to_string(),
            model: String::new(),
            local: false,
            terminal_agent: true,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scene_offers_one_scripted_agent() {
        let cfg = scene_config().expect("config");
        assert_eq!(cfg.extra_profiles.len(), 1);
        assert_eq!(cfg.extra_profiles[0].args, [FAKE_AGENT_FLAG]);
        assert!(cfg.config_dir.is_none());
        let (choice, badge) = scene_backend();
        assert!(matches!(choice, BackendChoice::Agent(a) if a.agent == DEMO_AGENT));
        assert!(badge.terminal_agent);
    }
}
