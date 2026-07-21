//! Canonical lossless command metadata schema.
//!
//! Commands must not be reconstructed via whitespace splitting for replay or
//! analysis. This module stores exact argv when available, shell source when
//! reported by a harness, and an explicit fidelity marker so consumers never
//! treat display strings as exact argv.

use serde::{Deserialize, Serialize};

/// How the command representation was obtained.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum CaptureMethod {
    /// Null-separated argv from `/proc/<pid>/cmdline`.
    ProcCmdline,
    /// Poller-discovered descendant (also from `/proc`).
    ProcPoller,
    /// Harness adapter reported a structured argv array.
    AdapterArgv,
    /// Harness adapter reported a shell command string (source only).
    AdapterShell,
    /// Reconstructed from a free-form display string (lossy).
    DisplayString,
    /// Origin unknown / not classified.
    #[default]
    Unknown,
}

impl CaptureMethod {
    /// View as str.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `as_str` — see module docs for full workflow.
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ProcCmdline => "proc_cmdline",
            Self::ProcPoller => "proc_poller",
            Self::AdapterArgv => "adapter_argv",
            Self::AdapterShell => "adapter_shell",
            Self::DisplayString => "display_string",
            Self::Unknown => "unknown",
        }
    }
}

/// Fidelity of the command representation for sandbox / analysis decisions.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
pub enum CommandFidelity {
    /// Exact argv array captured from process execution or structured source.
    Exact,
    /// Reasonable reconstruction (e.g. shell with known `-c` form).
    Inferred,
    /// Whitespace-split or display-only; unsafe for automated re-execution.
    Lossy,
    /// Fidelity not established.
    #[default]
    Unknown,
}

impl CommandFidelity {
    /// View as str.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `as_str` — see module docs for full workflow.
    /// ```
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Inferred => "inferred",
            Self::Lossy => "lossy",
            Self::Unknown => "unknown",
        }
    }

    /// Whether sandbox re-execution is safe without confirmation.
    ///
    /// # Examples
    ///
    /// ```
    /// # use blackbox as _;
    /// // `is_safe_for_sandbox` — see module docs for full workflow.
    /// ```
    pub fn is_safe_for_sandbox(self) -> bool {
        matches!(self, Self::Exact | Self::Inferred)
    }
}

/// Canonical command metadata attached to process / tool events.
///
/// Example (proc-cmdline):
/// ```json
/// {
///   "executable": "/usr/bin/grep",
///   "argv": ["grep", "hello world", "file.txt"],
///   "cwd": "/project",
///   "shell_source": null,
///   "capture_method": "proc_cmdline",
///   "lossless": true,
///   "fidelity": "exact"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CommandMetadata {
    /// Absolute or relative path of the executable, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,

    /// Full argv array (argv\[0\] is the program name). Authoritative when present
    /// and `fidelity` is Exact.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub argv: Vec<String>,

    /// Working directory at capture time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,

    /// Original shell source string when the harness reports a shell command
    /// (e.g. `cat result.json | jq '.items[]'`). Never treated as exact argv.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shell_source: Option<String>,

    /// How this metadata was captured.
    #[serde(default)]
    pub capture_method: CaptureMethod,

    /// Whether `argv` is byte-faithful to process execution (no reconstruction).
    #[serde(default)]
    pub lossless: bool,

    /// Explicit fidelity for sandbox / analysis gates.
    #[serde(default)]
    pub fidelity: CommandFidelity,
}

impl CommandMetadata {
    /// Build from an exact argv array captured via `/proc` (or equivalent).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_proc_argv` — see module docs for full workflow.
    /// ```
    pub fn from_proc_argv(
        argv: Vec<String>,
        executable: Option<String>,
        cwd: Option<String>,
        method: CaptureMethod,
    ) -> Self {
        let executable = executable.or_else(|| argv.first().cloned());
        Self {
            executable,
            argv,
            cwd,
            shell_source: None,
            capture_method: method,
            lossless: true,
            fidelity: CommandFidelity::Exact,
        }
    }

    /// Build from a structured argv array reported by a harness adapter.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_adapter_argv` — see module docs for full workflow.
    /// ```
    pub fn from_adapter_argv(argv: Vec<String>, cwd: Option<String>) -> Self {
        let executable = argv.first().cloned();
        Self {
            executable,
            argv,
            cwd,
            shell_source: None,
            capture_method: CaptureMethod::AdapterArgv,
            lossless: true,
            fidelity: CommandFidelity::Exact,
        }
    }

    /// Build from a harness-reported shell command string.
    ///
    /// When the shell binary is known, argv is stored as
    /// `[shell, "-lc", source]` with fidelity Inferred (shell invocation is
    /// exact, but the source body is opaque).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_shell_source` — see module docs for full workflow.
    /// ```
    pub fn from_shell_source(shell_source: impl Into<String>, shell: Option<&str>) -> Self {
        let shell_source = shell_source.into();
        if let Some(sh) = shell {
            let argv = vec![sh.to_string(), "-lc".into(), shell_source.clone()];
            Self {
                executable: Some(sh.to_string()),
                argv,
                cwd: None,
                shell_source: Some(shell_source),
                capture_method: CaptureMethod::AdapterShell,
                lossless: true,
                fidelity: CommandFidelity::Inferred,
            }
        } else {
            Self {
                executable: None,
                argv: Vec::new(),
                cwd: None,
                shell_source: Some(shell_source),
                capture_method: CaptureMethod::AdapterShell,
                lossless: false,
                fidelity: CommandFidelity::Lossy,
            }
        }
    }

    /// Build from a free-form display string (whitespace-split). Always lossy.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_display_string` — see module docs for full workflow.
    /// ```
    pub fn from_display_string(display: &str) -> Self {
        let argv: Vec<String> = display.split_whitespace().map(String::from).collect();
        let executable = argv.first().cloned();
        Self {
            executable,
            argv,
            cwd: None,
            shell_source: Some(display.to_string()),
            capture_method: CaptureMethod::DisplayString,
            lossless: false,
            fidelity: CommandFidelity::Lossy,
        }
    }

    /// Serialize into event metadata keys (flat merge into TraceEvent.metadata).
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `to_metadata_map` — see module docs for full workflow.
    /// ```
    pub fn to_metadata_map(&self) -> std::collections::HashMap<String, serde_json::Value> {
        let mut m = std::collections::HashMap::new();
        m.insert(
            "command_meta".to_string(),
            serde_json::to_value(self).unwrap_or_default(),
        );
        // Also emit flat keys for consumers that already look for argv / etc.
        if !self.argv.is_empty() {
            m.insert("argv".to_string(), serde_json::json!(self.argv));
            // Keep `command` as array when lossless so sandbox prefers exact form.
            if self.lossless {
                m.insert("command".to_string(), serde_json::json!(self.argv));
            } else if let Some(ref src) = self.shell_source {
                m.insert("command".to_string(), serde_json::json!(src));
            }
        } else if let Some(ref src) = self.shell_source {
            m.insert("command".to_string(), serde_json::json!(src));
        }
        if let Some(ref exe) = self.executable {
            m.insert("executable".to_string(), serde_json::json!(exe));
        }
        if let Some(ref cwd) = self.cwd {
            m.insert("cwd".to_string(), serde_json::json!(cwd));
        }
        if let Some(ref src) = self.shell_source {
            m.insert("shell_source".to_string(), serde_json::json!(src));
        }
        m.insert(
            "capture_method".to_string(),
            serde_json::json!(self.capture_method.as_str()),
        );
        m.insert("lossless".to_string(), serde_json::json!(self.lossless));
        m.insert(
            "fidelity".to_string(),
            serde_json::json!(self.fidelity.as_str()),
        );
        m
    }

    /// Merge this metadata into a TraceEvent's metadata map.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `apply_to_event` — see module docs for full workflow.
    /// ```
    pub fn apply_to_event(&self, event: &mut crate::core::event::TraceEvent) {
        for (k, v) in self.to_metadata_map() {
            event.metadata.insert(k, v);
        }
    }

    /// Extract CommandMetadata from a TraceEvent, preferring structured form.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `from_event` — see module docs for full workflow.
    /// ```
    pub fn from_event(event: &crate::core::event::TraceEvent) -> Option<Self> {
        // Prefer nested command_meta object.
        if let Some(v) = event.metadata.get("command_meta") {
            if let Ok(meta) = serde_json::from_value::<CommandMetadata>(v.clone()) {
                if !meta.argv.is_empty() || meta.shell_source.is_some() {
                    return Some(meta);
                }
            }
        }

        // Prefer exact argv array.
        if let Some(arr) = event.metadata.get("argv").and_then(|v| v.as_array()) {
            let argv: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            if !argv.is_empty() {
                let method = event
                    .metadata
                    .get("capture_method")
                    .and_then(|v| v.as_str())
                    .map(parse_capture_method)
                    .unwrap_or(CaptureMethod::Unknown);
                let lossless = event
                    .metadata
                    .get("lossless")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(matches!(
                        method,
                        CaptureMethod::ProcCmdline
                            | CaptureMethod::ProcPoller
                            | CaptureMethod::AdapterArgv
                    ));
                let fidelity = event
                    .metadata
                    .get("fidelity")
                    .and_then(|v| v.as_str())
                    .map(parse_fidelity)
                    .unwrap_or(if lossless {
                        CommandFidelity::Exact
                    } else {
                        CommandFidelity::Unknown
                    });
                return Some(Self {
                    executable: event
                        .metadata
                        .get("executable")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .or_else(|| argv.first().cloned()),
                    argv,
                    cwd: event
                        .metadata
                        .get("cwd")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    shell_source: event
                        .metadata
                        .get("shell_source")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    capture_method: method,
                    lossless,
                    fidelity,
                });
            }
        }

        // command as JSON array (exact).
        if let Some(arr) = event.metadata.get("command").and_then(|v| v.as_array()) {
            let argv: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            if !argv.is_empty() {
                return Some(Self {
                    executable: argv.first().cloned(),
                    argv,
                    cwd: event
                        .metadata
                        .get("cwd")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    shell_source: None,
                    capture_method: CaptureMethod::Unknown,
                    lossless: true,
                    fidelity: CommandFidelity::Exact,
                });
            }
        }

        // shell_source only.
        if let Some(src) = event
            .metadata
            .get("shell_source")
            .and_then(|v| v.as_str())
            .or_else(|| event.metadata.get("command").and_then(|v| v.as_str()))
        {
            let mut meta = Self::from_display_string(src);
            // Prefer adapter_shell if tagged.
            if event
                .metadata
                .get("capture_method")
                .and_then(|v| v.as_str())
                == Some("adapter_shell")
            {
                meta.capture_method = CaptureMethod::AdapterShell;
            }
            return Some(meta);
        }

        None
    }

    /// Argv suitable for re-execution, if fidelity permits.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `argv_for_execution` — see module docs for full workflow.
    /// ```
    pub fn argv_for_execution(&self) -> Option<&[String]> {
        if self.fidelity.is_safe_for_sandbox() && !self.argv.is_empty() {
            Some(&self.argv)
        } else {
            None
        }
    }
}

fn parse_capture_method(s: &str) -> CaptureMethod {
    match s {
        "proc_cmdline" | "proc-cmdline" => CaptureMethod::ProcCmdline,
        "proc_poller" | "proc-poller" => CaptureMethod::ProcPoller,
        "adapter_argv" | "adapter-argv" => CaptureMethod::AdapterArgv,
        "adapter_shell" | "adapter-shell" => CaptureMethod::AdapterShell,
        "display_string" | "display-string" => CaptureMethod::DisplayString,
        _ => CaptureMethod::Unknown,
    }
}

fn parse_fidelity(s: &str) -> CommandFidelity {
    match s {
        "exact" => CommandFidelity::Exact,
        "inferred" => CommandFidelity::Inferred,
        "lossy" => CommandFidelity::Lossy,
        _ => CommandFidelity::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::event::{EventSource, TraceEvent};

    #[test]
    fn from_proc_argv_is_exact_and_lossless() {
        let meta = CommandMetadata::from_proc_argv(
            vec!["grep".into(), "hello world".into(), "file.txt".into()],
            Some("/usr/bin/grep".into()),
            Some("/project".into()),
            CaptureMethod::ProcCmdline,
        );
        assert!(meta.lossless);
        assert_eq!(meta.fidelity, CommandFidelity::Exact);
        assert_eq!(meta.argv.len(), 3);
        assert_eq!(meta.argv[1], "hello world");
        assert_eq!(meta.executable.as_deref(), Some("/usr/bin/grep"));
        assert_eq!(meta.cwd.as_deref(), Some("/project"));
    }

    #[test]
    fn quotes_and_spaces_preserved_in_argv() {
        let meta = CommandMetadata::from_proc_argv(
            vec![
                "printf".into(),
                "%s\n".into(),
                "one two".into(),
                "path with spaces/file".into(),
            ],
            None,
            None,
            CaptureMethod::ProcPoller,
        );
        assert_eq!(meta.argv[2], "one two");
        assert_eq!(meta.argv[3], "path with spaces/file");
        assert!(meta.lossless);
    }

    #[test]
    fn shell_source_with_shell_is_inferred() {
        let meta =
            CommandMetadata::from_shell_source("cat result.json | jq '.items[]'", Some("bash"));
        assert_eq!(
            meta.argv,
            vec!["bash", "-lc", "cat result.json | jq '.items[]'"]
        );
        assert_eq!(meta.fidelity, CommandFidelity::Inferred);
        assert!(meta.lossless);
        assert_eq!(
            meta.shell_source.as_deref(),
            Some("cat result.json | jq '.items[]'")
        );
    }

    #[test]
    fn shell_source_without_shell_is_lossy() {
        let meta = CommandMetadata::from_shell_source("FOO=\"a b\" bun test", None);
        assert!(meta.argv.is_empty());
        assert_eq!(meta.fidelity, CommandFidelity::Lossy);
        assert!(!meta.lossless);
    }

    #[test]
    fn display_string_is_lossy_and_splits() {
        let meta = CommandMetadata::from_display_string("grep \"hello world\" file.txt");
        assert_eq!(meta.fidelity, CommandFidelity::Lossy);
        assert!(!meta.lossless);
        // Lossy split cannot preserve quotes as a single arg.
        assert!(meta.argv.contains(&"\"hello".to_string()) || meta.argv.len() > 3);
    }

    #[test]
    fn pipes_and_redirects_in_shell_source() {
        let src = "cat result.json | jq '.items[]' > out.txt";
        let meta = CommandMetadata::from_shell_source(src, Some("/bin/bash"));
        assert_eq!(meta.shell_source.as_deref(), Some(src));
        assert_eq!(meta.argv[2], src);
        assert!(meta.fidelity.is_safe_for_sandbox());
    }

    #[test]
    fn unicode_in_argv() {
        let meta = CommandMetadata::from_proc_argv(
            vec!["echo".into(), "你好世界".into(), "café".into()],
            None,
            None,
            CaptureMethod::ProcCmdline,
        );
        assert_eq!(meta.argv[1], "你好世界");
        assert_eq!(meta.argv[2], "café");
    }

    #[test]
    fn variable_assignment_shell_source() {
        let meta = CommandMetadata::from_shell_source("FOO=\"a b\" bun test", Some("bash"));
        assert_eq!(meta.argv[2], "FOO=\"a b\" bun test");
        assert_eq!(meta.fidelity, CommandFidelity::Inferred);
    }

    #[test]
    fn apply_and_roundtrip_via_event() {
        let meta = CommandMetadata::from_proc_argv(
            vec!["ls".into(), "-la".into()],
            Some("/bin/ls".into()),
            Some("/tmp".into()),
            CaptureMethod::ProcCmdline,
        );
        let mut ev = TraceEvent::new("run-1", EventSource::Process, "process.descendant.spawned");
        meta.apply_to_event(&mut ev);

        let recovered = CommandMetadata::from_event(&ev).expect("recover");
        assert_eq!(recovered.argv, meta.argv);
        assert_eq!(recovered.fidelity, CommandFidelity::Exact);
        assert!(recovered.lossless);
        assert_eq!(recovered.cwd.as_deref(), Some("/tmp"));
        assert_eq!(recovered.executable.as_deref(), Some("/bin/ls"));
    }

    #[test]
    fn from_event_prefers_argv_array_over_string() {
        let mut ev = TraceEvent::new("run-1", EventSource::Process, "process.spawned");
        ev.metadata.insert(
            "argv".into(),
            serde_json::json!(["grep", "hello world", "f.txt"]),
        );
        ev.metadata.insert(
            "command".into(),
            serde_json::json!("grep hello world f.txt"),
        );
        ev.metadata
            .insert("capture_method".into(), serde_json::json!("proc_poller"));
        let meta = CommandMetadata::from_event(&ev).unwrap();
        assert_eq!(meta.argv[1], "hello world");
        assert_eq!(meta.fidelity, CommandFidelity::Exact);
    }

    #[test]
    fn argv_for_execution_blocks_lossy() {
        let lossy = CommandMetadata::from_display_string("echo hi");
        assert!(lossy.argv_for_execution().is_none());
        let exact = CommandMetadata::from_adapter_argv(vec!["echo".into(), "hi".into()], None);
        assert_eq!(
            exact.argv_for_execution().unwrap(),
            &["echo".to_string(), "hi".to_string()]
        );
    }

    #[test]
    fn serde_round_trip() {
        let meta = CommandMetadata::from_proc_argv(
            vec!["make".into(), "test".into()],
            None,
            Some("/proj".into()),
            CaptureMethod::ProcCmdline,
        );
        let json = serde_json::to_string(&meta).unwrap();
        let de: CommandMetadata = serde_json::from_str(&json).unwrap();
        assert_eq!(de, meta);
    }
}
