//! Shared helpers for preparing harness launch commands.

/// True if `flag` appears as its own argv element.
pub fn has_flag(command: &[String], flag: &str) -> bool {
    command.iter().any(|a| a == flag)
}

/// True if any of the flags appear.
pub fn has_any_flag(command: &[String], flags: &[&str]) -> bool {
    flags.iter().any(|f| has_flag(command, f))
}

/// True if `--flag value` or `--flag=value` is present.
pub fn has_option(command: &[String], option: &str) -> bool {
    let eq_prefix = format!("{}=", option);
    command.iter().enumerate().any(|(i, a)| {
        a == option || a.starts_with(&eq_prefix) || {
            // previous token is the option and this is its value,
            // but only if the value itself doesn't start with '-'
            // (to avoid treating a consecutive flag as an option value)
            i > 0
                && command[i - 1] == option
                && !a.starts_with('-')
        }
    })
}

/// Insert `insert` after the binary (index 0), unless already present.
///
/// # POSIX note
/// Flags are inserted as discrete argv tokens, never concatenated into the
/// binary path or a shell string, so there is no shell injection or argument
/// mangling risk on POSIX systems. Each token maps 1:1 to an argv element.
pub fn ensure_flags(command: &[String], insert: &[&str]) -> Vec<String> {
    let out = command.to_vec();
    if out.is_empty() {
        return out;
    }
    // Walk insert pairs or singles — for simplicity insert each token if missing as a flag
    let mut to_add: Vec<String> = Vec::new();
    let mut i = 0;
    while i < insert.len() {
        let tok = insert[i];
        if tok.starts_with('-') {
            // option with optional value
            let needs_value = i + 1 < insert.len() && !insert[i + 1].starts_with('-');
            if needs_value {
                let val = insert[i + 1];
                if !has_option(&out, tok) {
                    to_add.push(tok.to_string());
                    to_add.push(val.to_string());
                }
                i += 2;
            } else {
                if !has_flag(&out, tok) {
                    to_add.push(tok.to_string());
                }
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    if to_add.is_empty() {
        return out;
    }
    // Insert after program name
    let mut result = Vec::with_capacity(out.len() + to_add.len());
    result.push(out[0].clone());
    result.extend(to_add);
    result.extend(out.into_iter().skip(1));
    result
}

/// Claude: force stream-json when in print/non-interactive mode.
///
/// Does not alter fully interactive sessions (no `-p`/`--print`) so the
/// TUI still works. Set `BLACKBOX_FORCE_JSON=1` to always inject.
pub fn prepare_claude_command(command: &[String]) -> Vec<String> {
    let force = std::env::var("BLACKBOX_FORCE_JSON")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let print_mode = has_any_flag(command, &["-p", "--print"]);
    if !force && !print_mode {
        return command.to_vec();
    }

    let mut cmd = command.to_vec();
    if !has_option(&cmd, "--output-format") {
        cmd = ensure_flags(&cmd, &["--output-format", "stream-json"]);
    }
    // Verbose helps surface tool events in some versions
    if print_mode && !has_flag(&cmd, "--verbose") && !has_flag(&cmd, "-v") {
        cmd = ensure_flags(&cmd, &["--verbose"]);
    }
    cmd
}

/// Codex: prefer JSON / quiet machine output for `exec` and non-interactive.
pub fn prepare_codex_command(command: &[String]) -> Vec<String> {
    let force = std::env::var("BLACKBOX_FORCE_JSON")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    let is_exec = command.iter().any(|a| a == "exec");
    let has_json = has_any_flag(command, &["--json", "--output-json"])
        || has_option(command, "--output-format");

    if !force && !is_exec {
        return command.to_vec();
    }
    if has_json {
        return command.to_vec();
    }

    // Prefer --json for exec; fall back to same for force
    ensure_flags(command, &["--json"])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claude_print_gets_stream_json() {
        let cmd = vec!["claude".into(), "-p".into(), "hi".into()];
        let out = prepare_claude_command(&cmd);
        assert!(has_option(&out, "--output-format"));
        assert!(out.iter().any(|a| a == "stream-json"));
        assert_eq!(out[0], "claude");
        assert!(out.iter().any(|a| a == "-p"));
    }

    #[test]
    fn claude_interactive_untouched() {
        let cmd = vec!["claude".into()];
        let out = prepare_claude_command(&cmd);
        assert_eq!(out, cmd);
    }

    #[test]
    fn claude_already_has_format() {
        let cmd = vec![
            "claude".into(),
            "-p".into(),
            "--output-format".into(),
            "json".into(),
            "hi".into(),
        ];
        let out = prepare_claude_command(&cmd);
        // should not duplicate stream-json
        let formats: Vec<_> = out
            .iter()
            .enumerate()
            .filter(|(_, a)| *a == "--output-format")
            .collect();
        assert_eq!(formats.len(), 1);
        assert!(out.iter().any(|a| a == "json"));
    }

    #[test]
    fn codex_exec_gets_json() {
        let cmd = vec!["codex".into(), "exec".into(), "do stuff".into()];
        let out = prepare_codex_command(&cmd);
        assert!(has_flag(&out, "--json"));
    }

    #[test]
    fn ensure_flags_inserts_after_binary() {
        let cmd = vec!["claude".into(), "-p".into(), "x".into()];
        let out = ensure_flags(&cmd, &["--output-format", "stream-json"]);
        assert_eq!(out[0], "claude");
        assert_eq!(out[1], "--output-format");
        assert_eq!(out[2], "stream-json");
    }
}
