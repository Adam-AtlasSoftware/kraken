//! Which platforms can run terminal agents (decisions 35 and 69).

use serde::Serialize;

/// An operating system and CPU architecture, as `std::env::consts` names them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Platform {
    /// `linux`, `macos`, `windows`, ...
    pub os: String,
    /// `x86_64`, `aarch64`, `riscv64`, ...
    pub arch: String,
}

impl Platform {
    /// The platform this binary runs on.
    pub fn current() -> Self {
        Platform::new(std::env::consts::OS, std::env::consts::ARCH)
    }

    /// A platform by name (tests).
    pub fn new(os: impl Into<String>, arch: impl Into<String>) -> Self {
        Platform {
            os: os.into(),
            arch: arch.into(),
        }
    }

    /// `linux-x86_64` style label.
    pub fn label(&self) -> String {
        format!("{}-{}", self.os, self.arch)
    }

    /// Whether the agent adapters can run here. The adapters ship native helpers (the Claude and
    /// Codex SDK binaries) only for x86-64 and arm64 on Linux, macOS and Windows; riscv64 and
    /// everything else is unsupported (decision 69).
    pub fn supports_agents(&self) -> Result<(), String> {
        let os_ok = matches!(self.os.as_str(), "linux" | "macos" | "windows");
        let arch_ok = matches!(self.arch.as_str(), "x86_64" | "aarch64");
        if os_ok && arch_ok {
            Ok(())
        } else {
            Err(format!(
                "terminal agents are not supported on {}: their adapters ship binaries only for \
                 x86-64 and arm64 on Linux, macOS and Windows",
                self.label()
            ))
        }
    }

    /// Whether KRAKEN can download a pinned Node.js for this platform. Elsewhere install Node.js
    /// yourself and KRAKEN will find it on `PATH`.
    pub fn can_provision_node(&self) -> bool {
        crate::node::node_download_for(self).is_some()
    }
}

/// What a platform can do with agents (the "capability descriptor").
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PlatformReport {
    /// The platform label.
    pub platform: String,
    /// Whether agents run at all.
    pub agents_supported: bool,
    /// Why not, when unsupported.
    pub unsupported_reason: Option<String>,
    /// Whether KRAKEN can download Node.js here.
    pub can_download_node: bool,
}

impl Platform {
    /// The capability descriptor for this platform.
    pub fn report(&self) -> PlatformReport {
        let support = self.supports_agents();
        PlatformReport {
            platform: self.label(),
            agents_supported: support.is_ok(),
            unsupported_reason: support.err(),
            can_download_node: self.supports_agents().is_ok() && self.can_provision_node(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn riscv64_is_unsupported() {
        let p = Platform::new("linux", "riscv64");
        assert!(p.supports_agents().is_err());
        let r = p.report();
        assert!(!r.agents_supported);
        assert!(!r.can_download_node);
        assert!(r.unsupported_reason.is_some_and(|m| m.contains("riscv64")));
    }

    #[test]
    fn tier_one_platforms_are_supported() {
        for (os, arch) in [
            ("linux", "x86_64"),
            ("linux", "aarch64"),
            ("macos", "aarch64"),
            ("windows", "x86_64"),
        ] {
            assert!(Platform::new(os, arch).supports_agents().is_ok());
        }
    }

    #[test]
    fn node_download_only_where_pinned() {
        assert!(Platform::new("linux", "x86_64").report().can_download_node);
        assert!(Platform::new("macos", "aarch64").report().can_download_node);
        assert!(
            Platform::new("windows", "x86_64")
                .report()
                .can_download_node
        );
        let arm = Platform::new("linux", "aarch64").report();
        assert!(arm.agents_supported);
        assert!(!arm.can_download_node);
    }
}
