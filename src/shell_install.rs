//! Managed shell integration install/uninstall for ambient capture.
//!
//! Blocks are delimited so re-enable is idempotent and uninstall is safe.

use std::path::{Path, PathBuf};

use crate::maybe_run::{shell_snippet_bash, shell_snippet_fish};

pub const BEGIN_MARKER: &str = "# >>> blackbox >>>";
pub const END_MARKER: &str = "# <<< blackbox <<<";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShellKind {
    Fish,
    Bash,
    Zsh,
}

impl ShellKind {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "fish" => Some(Self::Fish),
            "bash" => Some(Self::Bash),
            "zsh" => Some(Self::Zsh),
            _ => None,
        }
    }

    pub fn detect() -> Self {
        let shell = std::env::var("SHELL").unwrap_or_default();
        if shell.contains("fish") {
            Self::Fish
        } else if shell.contains("zsh") {
            Self::Zsh
        } else {
            Self::Bash
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Fish => "fish",
            Self::Bash => "bash",
            Self::Zsh => "zsh",
        }
    }
}

#[derive(Debug, Clone)]
pub struct InstallResult {
    pub shell: ShellKind,
    pub path: PathBuf,
    pub action: &'static str, // "installed" | "updated" | "unchanged"
}

/// Resolve the rc / conf.d path for a shell (respects HOME).
pub fn rc_path(shell: ShellKind, home: &Path) -> PathBuf {
    match shell {
        ShellKind::Fish => home.join(".config/fish/conf.d/blackbox.fish"),
        ShellKind::Bash => home.join(".bashrc"),
        ShellKind::Zsh => home.join(".zshrc"),
    }
}

fn managed_block(shell: ShellKind, wrap: &[String]) -> String {
    let body = match shell {
        ShellKind::Fish => shell_snippet_fish(wrap),
        ShellKind::Bash | ShellKind::Zsh => shell_snippet_bash(wrap),
    };
    format!(
        "{BEGIN_MARKER}\n# Managed by `blackbox enable --install-shell`. Do not edit by hand.\n{body}{END_MARKER}\n"
    )
}

/// Insert or replace the managed blackbox block in `content`.
pub fn upsert_block(content: &str, block: &str) -> (String, &'static str) {
    if let Some((before, rest)) = content.split_once(BEGIN_MARKER) {
        if let Some((_old, after)) = rest.split_once(END_MARKER) {
            let after = after.strip_prefix('\n').unwrap_or(after);
            let mut out = String::with_capacity(content.len() + block.len());
            out.push_str(before.trim_end_matches('\n'));
            if !before.is_empty() && !before.ends_with('\n') {
                out.push('\n');
            }
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(block);
            if !after.is_empty() {
                if !out.ends_with('\n') {
                    out.push('\n');
                }
                out.push_str(after.trim_start_matches('\n'));
                if !out.ends_with('\n') {
                    out.push('\n');
                }
            }
            let action = if content.contains(block.trim_end()) {
                "unchanged"
            } else {
                "updated"
            };
            // Always rewrite for consistency; action is approximate.
            let _ = action;
            return (out, "updated");
        }
    }

    // No existing block — append.
    let mut out = content.to_string();
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(block);
    (out, "installed")
}

/// Remove the managed block from content. Returns None if nothing changed.
pub fn remove_block(content: &str) -> Option<String> {
    let (before, rest) = content.split_once(BEGIN_MARKER)?;
    let (_old, after) = rest.split_once(END_MARKER)?;
    let after = after.strip_prefix('\n').unwrap_or(after);
    let mut out = before.to_string();
    if !after.is_empty() {
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(after);
    }
    // Collapse triple newlines a bit
    while out.contains("\n\n\n") {
        out = out.replace("\n\n\n", "\n\n");
    }
    Some(out)
}

/// Install managed shell functions into the user's rc / conf.d.
pub fn install_shell(
    shell: ShellKind,
    wrap: &[String],
    home: &Path,
) -> anyhow::Result<InstallResult> {
    let path = rc_path(shell, home);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let existing = if path.exists() {
        std::fs::read_to_string(&path)?
    } else {
        String::new()
    };

    let block = managed_block(shell, wrap);
    let (new_content, action) = upsert_block(&existing, &block);

    if new_content == existing {
        return Ok(InstallResult {
            shell,
            path,
            action: "unchanged",
        });
    }

    // Atomic-ish write
    let tmp = path.with_extension("blackbox-tmp");
    std::fs::write(&tmp, &new_content)?;
    std::fs::rename(&tmp, &path)?;

    Ok(InstallResult {
        shell,
        path,
        action,
    })
}

/// Remove managed shell integration.
pub fn uninstall_shell(shell: ShellKind, home: &Path) -> anyhow::Result<Option<PathBuf>> {
    let path = rc_path(shell, home);
    if !path.exists() {
        return Ok(None);
    }
    let existing = std::fs::read_to_string(&path)?;
    let Some(new_content) = remove_block(&existing) else {
        return Ok(None);
    };

    // For fish conf.d file that becomes empty/only whitespace — remove file.
    if shell == ShellKind::Fish && new_content.trim().is_empty() {
        std::fs::remove_file(&path)?;
        return Ok(Some(path));
    }

    let tmp = path.with_extension("blackbox-tmp");
    std::fs::write(&tmp, &new_content)?;
    std::fs::rename(&tmp, &path)?;
    Ok(Some(path))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_installs_then_updates() {
        let wrap = vec!["claude".into(), "codex".into()];
        let block1 = managed_block(ShellKind::Bash, &wrap);
        let (c1, a1) = upsert_block("", &block1);
        assert_eq!(a1, "installed");
        assert!(c1.contains(BEGIN_MARKER));
        assert!(c1.contains("claude()"));

        let wrap2 = vec!["claude".into()];
        let block2 = managed_block(ShellKind::Bash, &wrap2);
        let (c2, a2) = upsert_block(&c1, &block2);
        assert_eq!(a2, "updated");
        assert_eq!(c2.matches(BEGIN_MARKER).count(), 1);
        assert!(c2.contains("claude()"));
        // still only one managed block
        assert_eq!(c2.matches(END_MARKER).count(), 1);
    }

    #[test]
    fn remove_block_works() {
        let wrap = vec!["claude".into()];
        let block = managed_block(ShellKind::Fish, &wrap);
        let content = format!("# header\n\n{block}\n# footer\n");
        let out = remove_block(&content).unwrap();
        assert!(!out.contains(BEGIN_MARKER));
        assert!(out.contains("# header"));
        assert!(out.contains("# footer"));
    }

    #[test]
    fn install_to_home_dir() {
        let home = tempfile::tempdir().unwrap();
        let wrap = vec!["claude".into(), "codex".into()];
        let r = install_shell(ShellKind::Bash, &wrap, home.path()).unwrap();
        assert_eq!(r.action, "installed");
        let text = std::fs::read_to_string(&r.path).unwrap();
        assert!(text.contains("maybe-run"));
        // second install is idempotent-ish
        let r2 = install_shell(ShellKind::Bash, &wrap, home.path()).unwrap();
        assert!(r2.action == "updated" || r2.action == "unchanged");
        let text2 = std::fs::read_to_string(&r2.path).unwrap();
        assert_eq!(text2.matches(BEGIN_MARKER).count(), 1);

        let removed = uninstall_shell(ShellKind::Bash, home.path()).unwrap();
        assert!(removed.is_some());
        let text3 = std::fs::read_to_string(rc_path(ShellKind::Bash, home.path())).unwrap();
        assert!(!text3.contains(BEGIN_MARKER));
    }

    #[test]
    fn fish_conf_d_removed_when_empty() {
        let home = tempfile::tempdir().unwrap();
        let wrap = vec!["claude".into()];
        install_shell(ShellKind::Fish, &wrap, home.path()).unwrap();
        let path = rc_path(ShellKind::Fish, home.path());
        assert!(path.exists());
        uninstall_shell(ShellKind::Fish, home.path()).unwrap();
        assert!(!path.exists());
    }
}
