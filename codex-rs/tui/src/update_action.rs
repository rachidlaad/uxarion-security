use crate::version::CODEX_CLI_VERSION;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

const UXARION_UPDATE_REPO_ENV_VAR: &str = "UXARION_UPDATE_REPO";
const UXARION_UPDATE_REMOTE_ENV_VAR: &str = "UXARION_UPDATE_REMOTE";
const UXARION_UPDATE_BRANCH_ENV_VAR: &str = "UXARION_UPDATE_BRANCH";
const UXARION_UPDATE_REPO_URL_ENV_VAR: &str = "UXARION_UPDATE_REPO_URL";
const UXARION_MANAGED_BY_NPM_ENV_VAR: &str = "UXARION_MANAGED_BY_NPM";
const UXARION_MANAGED_BY_BUN_ENV_VAR: &str = "UXARION_MANAGED_BY_BUN";
pub(crate) const DEFAULT_UXARION_UPDATE_REMOTE: &str = "uxarion";
pub(crate) const DEFAULT_UXARION_UPDATE_BRANCH: &str = "main";
pub(crate) const DEFAULT_UXARION_UPDATE_REPO_URL: &str =
    "https://github.com/rachidlaad/uxarion-security";

/// Update action the CLI should perform after the TUI exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateAction {
    /// Update from the configured Uxarion Git checkout.
    UxarionGitCheckout,
    /// Update via the Uxarion distribution channel.
    NpmGlobalLatest,
    /// Update via the Uxarion distribution channel.
    BunGlobalLatest,
    /// Update via the Uxarion distribution channel.
    BrewUpgrade,
}

impl UpdateAction {
    /// Returns the list of command-line arguments for invoking the update.
    pub fn command_args(self) -> (&'static str, &'static [&'static str]) {
        match self {
            UpdateAction::UxarionGitCheckout => ("uxarion", &["update"]),
            UpdateAction::NpmGlobalLatest => ("npm", &["install", "-g", "uxarion@latest"]),
            UpdateAction::BunGlobalLatest => ("bun", &["install", "-g", "uxarion@latest"]),
            UpdateAction::BrewUpgrade => ("brew", &["upgrade", "uxarion"]),
        }
    }

    /// Returns string representation of the command-line arguments for invoking the update.
    pub fn command_str(self) -> String {
        let (command, args) = self.command_args();
        shlex::try_join(std::iter::once(command).chain(args.iter().copied()))
            .unwrap_or_else(|_| format!("{command} {}", args.join(" ")))
    }

    pub(crate) fn current_version_value(self) -> String {
        match self {
            UpdateAction::UxarionGitCheckout => {
                current_checkout_revision().unwrap_or_else(|| CODEX_CLI_VERSION.to_string())
            }
            UpdateAction::NpmGlobalLatest
            | UpdateAction::BunGlobalLatest
            | UpdateAction::BrewUpgrade => CODEX_CLI_VERSION.to_string(),
        }
    }

    pub fn current_version_label(self) -> String {
        let current_version = self.current_version_value();
        match self {
            UpdateAction::UxarionGitCheckout => display_revision(&current_version),
            UpdateAction::NpmGlobalLatest
            | UpdateAction::BunGlobalLatest
            | UpdateAction::BrewUpgrade => current_version,
        }
    }

    pub fn format_latest_version(self, latest_version: &str) -> String {
        match self {
            UpdateAction::UxarionGitCheckout => display_revision(latest_version),
            UpdateAction::NpmGlobalLatest
            | UpdateAction::BunGlobalLatest
            | UpdateAction::BrewUpgrade => latest_version.to_string(),
        }
    }

    pub fn source_label(self) -> String {
        match self {
            UpdateAction::UxarionGitCheckout => std::env::var(UXARION_UPDATE_REPO_URL_ENV_VAR)
                .unwrap_or_else(|_| DEFAULT_UXARION_UPDATE_REPO_URL.to_string()),
            UpdateAction::NpmGlobalLatest
            | UpdateAction::BunGlobalLatest
            | UpdateAction::BrewUpgrade => DEFAULT_UXARION_UPDATE_REPO_URL.to_string(),
        }
    }
}

pub(crate) fn get_update_action() -> Option<UpdateAction> {
    let current_exe = std::env::current_exe().ok()?;
    detect_update_action(
        cfg!(target_os = "macos"),
        current_exe.as_path(),
        std::env::var_os(UXARION_MANAGED_BY_NPM_ENV_VAR).is_some()
            || std::env::var_os("npm_config_user_agent").is_some(),
        std::env::var_os(UXARION_MANAGED_BY_BUN_ENV_VAR).is_some()
            || std::env::var_os("BUN_INSTALL").is_some(),
        std::env::var_os(UXARION_UPDATE_REPO_ENV_VAR).is_some(),
    )
}

pub(crate) fn update_repo_root() -> Option<PathBuf> {
    std::env::var_os(UXARION_UPDATE_REPO_ENV_VAR).map(PathBuf::from)
}

pub(crate) fn update_repo_remote() -> String {
    std::env::var(UXARION_UPDATE_REMOTE_ENV_VAR)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_UXARION_UPDATE_REMOTE.to_string())
}

pub(crate) fn update_repo_branch() -> String {
    std::env::var(UXARION_UPDATE_BRANCH_ENV_VAR)
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_UXARION_UPDATE_BRANCH.to_string())
}

fn detect_update_action(
    is_macos: bool,
    current_exe: &Path,
    managed_by_npm: bool,
    managed_by_bun: bool,
    managed_by_uxarion_repo: bool,
) -> Option<UpdateAction> {
    if managed_by_uxarion_repo {
        Some(UpdateAction::UxarionGitCheckout)
    } else if managed_by_npm {
        Some(UpdateAction::NpmGlobalLatest)
    } else if managed_by_bun {
        Some(UpdateAction::BunGlobalLatest)
    } else if is_macos
        && (current_exe.starts_with("/opt/homebrew") || current_exe.starts_with("/usr/local"))
    {
        Some(UpdateAction::BrewUpgrade)
    } else {
        None
    }
}

fn current_checkout_revision() -> Option<String> {
    let repo_root = update_repo_root()?;
    git_stdout(repo_root.as_path(), &["rev-parse", "HEAD"])
}

fn git_stdout(repo_root: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(args)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let trimmed = stdout.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn display_revision(revision: &str) -> String {
    revision.chars().take(7).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_update_action_without_env_mutation() {
        assert_eq!(
            detect_update_action(
                false,
                std::path::Path::new("/any/path"),
                false,
                false,
                false
            ),
            None
        );
        assert_eq!(
            detect_update_action(false, std::path::Path::new("/any/path"), false, false, true),
            Some(UpdateAction::UxarionGitCheckout)
        );
        assert_eq!(
            detect_update_action(false, std::path::Path::new("/any/path"), true, false, false),
            Some(UpdateAction::NpmGlobalLatest)
        );
        assert_eq!(
            detect_update_action(false, std::path::Path::new("/any/path"), false, true, false),
            Some(UpdateAction::BunGlobalLatest)
        );
        assert_eq!(
            detect_update_action(
                true,
                std::path::Path::new("/opt/homebrew/bin/codex"),
                false,
                false,
                false
            ),
            Some(UpdateAction::BrewUpgrade)
        );
        assert_eq!(
            detect_update_action(
                true,
                std::path::Path::new("/usr/local/bin/codex"),
                false,
                false,
                false
            ),
            Some(UpdateAction::BrewUpgrade)
        );
    }

    #[test]
    fn formats_git_revisions_for_display() {
        assert_eq!(display_revision("1234567890abcdef"), "1234567");
    }

    #[test]
    fn update_commands_match_distribution_channels() {
        assert_eq!(
            UpdateAction::UxarionGitCheckout.command_str(),
            "uxarion update"
        );
        assert_eq!(
            UpdateAction::NpmGlobalLatest.command_str(),
            "npm install -g uxarion@latest"
        );
        assert_eq!(
            UpdateAction::BunGlobalLatest.command_str(),
            "bun install -g uxarion@latest"
        );
        assert_eq!(
            UpdateAction::BrewUpgrade.command_str(),
            "brew upgrade uxarion"
        );
    }
}
