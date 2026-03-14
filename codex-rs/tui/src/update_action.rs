/// Update action the CLI should perform after the TUI exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdateAction {
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
            UpdateAction::NpmGlobalLatest
            | UpdateAction::BunGlobalLatest
            | UpdateAction::BrewUpgrade => ("uxarion", &["update"]),
        }
    }

    /// Returns string representation of the command-line arguments for invoking the update.
    pub fn command_str(self) -> String {
        let (command, args) = self.command_args();
        shlex::try_join(std::iter::once(command).chain(args.iter().copied()))
            .unwrap_or_else(|_| format!("{command} {}", args.join(" ")))
    }
}

#[cfg(not(debug_assertions))]
pub(crate) fn get_update_action() -> Option<UpdateAction> {
    None
}

#[cfg(any(not(debug_assertions), test))]
fn detect_update_action(
    is_macos: bool,
    current_exe: &std::path::Path,
    managed_by_npm: bool,
    managed_by_bun: bool,
) -> Option<UpdateAction> {
    if managed_by_npm {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_update_action_without_env_mutation() {
        assert_eq!(
            detect_update_action(false, std::path::Path::new("/any/path"), false, false),
            None
        );
        assert_eq!(
            detect_update_action(false, std::path::Path::new("/any/path"), true, false),
            Some(UpdateAction::NpmGlobalLatest)
        );
        assert_eq!(
            detect_update_action(false, std::path::Path::new("/any/path"), false, true),
            Some(UpdateAction::BunGlobalLatest)
        );
        assert_eq!(
            detect_update_action(
                true,
                std::path::Path::new("/opt/homebrew/bin/codex"),
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
                false
            ),
            Some(UpdateAction::BrewUpgrade)
        );
    }
}
