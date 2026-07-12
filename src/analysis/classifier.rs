use crate::analysis::AnalysisPass;
use crate::core::event::{EventSource, SideEffect, TraceEvent};

/// Classifies events by their side-effect profile.
///
/// Each event receives a conservative `SideEffect` label
/// that determines replay safety policies.
///
/// ## Default classification rules
///
/// | Pattern | Classification |
/// |---|---|
/// | `read_file`, `rg`, `grep`, `ls`, `cat` | `Read` |
/// | `sed -i`, `write_file`, `npm install` | `LocalWrite` |
/// | `git push`, `curl POST`, `aws deploy` | `ExternalWrite` |
/// | `rm`, `rm -rf`, `DROP TABLE`, `DELETE FROM` | `Destructive` |
/// | `echo` | `None` |
/// | Unknown commands | `Unknown` |
pub struct SideEffectClassifier;

impl SideEffectClassifier {
    pub fn new() -> Self {
        Self
    }

    /// Classify a command string into a side-effect level.
    pub fn classify_command(&self, command: &str) -> SideEffect {
        let lower = command.to_lowercase();
        let parts: Vec<&str> = lower.split_whitespace().collect();
        let base = parts.first().copied().unwrap_or("");

        // Destructive patterns first
        if (base == "rm" && (lower.contains("-rf") || lower.contains("-fr")))
            || lower.contains("drop table")
            || lower.contains("delete from")
            || lower.contains("mkfs")
            || lower.contains("dd if=")
        {
            return SideEffect::Destructive;
        }

        match base {
            "ls" | "cat" | "head" | "tail" | "grep" | "rg" | "find"
            | "read" | "which" | "file" | "stat" | "du" | "df" | "ps" | "top"
            | "pwd" | "whoami" | "id" | "env" | "printenv" | "type" | "true"
            | "false" | "test" | "wc" | "sort" | "uniq" | "diff" | "tree" => {
                SideEffect::Read
            }
            "echo" => SideEffect::None,
            "sed" | "awk" | "touch" | "mkdir" | "cp" | "mv" | "chmod"
            | "chown" | "ln" | "truncate" | "tee" => {
                SideEffect::LocalWrite
            }
            "rm" => SideEffect::Destructive,
            "curl" | "wget" | "nc" | "ssh" | "scp" | "rsync" | "npm" | "pip"
            | "cargo" | "docker" | "kubectl" | "aws" | "gcloud" | "az" => {
                if lower.contains("get") || lower.contains("list") || lower.contains("describe")
                    || lower.contains("info") || lower.contains("version") || lower.contains("help")
                {
                    SideEffect::Read
                } else if lower.contains("push")
                    || lower.contains("deploy")
                    || lower.contains("post")
                    || lower.contains("put")
                    || lower.contains("delete")
                    || lower.contains("publish")
                {
                    SideEffect::ExternalWrite
                } else {
                    SideEffect::LocalWrite
                }
            }
            "git" => {
                if lower.contains("push") || lower.contains("pull") {
                    SideEffect::ExternalWrite
                } else if lower.contains("fetch")
                    || lower.contains("status")
                    || lower.contains("log")
                    || lower.contains("diff")
                    || lower.contains("show")
                    || lower.contains("branch")
                {
                    SideEffect::Read
                } else {
                    SideEffect::LocalWrite
                }
            }
            _ => SideEffect::Unknown,
        }
    }

    /// Classify an event based on its kind, source, and metadata.
    pub fn classify_event(&self, event: &TraceEvent) -> SideEffect {
        // Already classified
        if event.side_effect != SideEffect::Unknown {
            return event.side_effect.clone();
        }

        // Source-based defaults
        match event.source {
            EventSource::Filesystem => {
                if event.kind.contains("delete") || event.kind.contains("remove") {
                    return SideEffect::Destructive;
                }
                if event.kind.contains("write")
                    || event.kind.contains("create")
                    || event.kind.contains("modify")
                {
                    return SideEffect::LocalWrite;
                }
                return SideEffect::Read;
            }
            EventSource::Git => {
                if event.kind.contains("push") || event.kind.contains("pull") {
                    return SideEffect::ExternalWrite;
                }
                if event.kind.contains("fetch")
                    || event.kind.contains("diff")
                    || event.kind.contains("commit")
                    || event.kind.contains("status")
                {
                    return SideEffect::Read;
                }
                return SideEffect::LocalWrite;
            }
            EventSource::Terminal | EventSource::Process | EventSource::Tool => {
                // Try command from metadata (string or array join)
                if let Some(cmd) = event.metadata.get("command").and_then(|v| {
                    v.as_str().map(String::from).or_else(|| {
                        v.as_array().map(|a| {
                            a.iter()
                                .filter_map(|x| x.as_str())
                                .collect::<Vec<_>>()
                                .join(" ")
                        })
                    })
                }) {
                    return self.classify_command(&cmd);
                }
                // Tool input.command for Bash-like tools
                if let Some(cmd) = event
                    .metadata
                    .get("input")
                    .and_then(|i| i.get("command").or_else(|| i.get("cmd")))
                    .and_then(|c| c.as_str())
                {
                    return self.classify_command(cmd);
                }
                if event.kind == "terminal.output" {
                    return SideEffect::None;
                }
            }
            EventSource::System => return SideEffect::None,
            EventSource::Network => return SideEffect::ExternalWrite,
            _ => {}
        }

        // Kind-based heuristics
        let kind = event.kind.to_lowercase();
        if kind.contains("read") || kind.contains("list") || kind.contains("get") {
            return SideEffect::Read;
        }
        if kind.contains("write") || kind.contains("create") || kind.contains("update") {
            return SideEffect::LocalWrite;
        }
        if kind.contains("delete") || kind.contains("destroy") || kind.contains("drop") {
            return SideEffect::Destructive;
        }

        SideEffect::Unknown
    }
}

impl Default for SideEffectClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AnalysisPass for SideEffectClassifier {
    fn name(&self) -> &'static str {
        "classifier"
    }

    async fn analyze(&self, events: &[TraceEvent]) -> anyhow::Result<Vec<TraceEvent>> {
        let mut derived = Vec::new();
        for event in events {
            // Skip bookkeeping noise and analysis events themselves
            if event.kind.starts_with("analysis.")
                || event.kind.ends_with(".started")
                || event.kind.ends_with(".stopped")
                || event.kind == "environment.captured"
                || event.kind == "terminal.recording"
            {
                continue;
            }

            let classification = self.classify_event(event);
            // Only emit for interesting reclassifications — not every Read.
            // Quiet by default: LocalWrite / ExternalWrite / Destructive only.
            let interesting = matches!(
                classification,
                SideEffect::LocalWrite | SideEffect::ExternalWrite | SideEffect::Destructive
            );
            if interesting
                && classification != SideEffect::Unknown
                && classification != event.side_effect
            {
                let mut meta = std::collections::HashMap::new();
                meta.insert(
                    "side_effect".to_string(),
                    serde_json::Value::String(format!("{:?}", classification)),
                );
                meta.insert(
                    "source_event_id".to_string(),
                    serde_json::Value::String(event.id.clone()),
                );
                meta.insert(
                    "source_kind".to_string(),
                    serde_json::Value::String(event.kind.clone()),
                );

                let mut derived_event = TraceEvent::new(
                    &event.run_id,
                    EventSource::System,
                    "analysis.side_effect",
                );
                derived_event.parent_event_id = Some(event.id.clone());
                derived_event.side_effect = classification;
                derived_event.metadata = meta;
                derived.push(derived_event);
            }
        }
        Ok(derived)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_read_commands() {
        let c = SideEffectClassifier::new();
        assert_eq!(c.classify_command("ls -la"), SideEffect::Read);
        assert_eq!(c.classify_command("cat foo.txt"), SideEffect::Read);
        assert_eq!(c.classify_command("rg pattern"), SideEffect::Read);
    }

    #[test]
    fn classify_destructive() {
        let c = SideEffectClassifier::new();
        assert_eq!(c.classify_command("rm -rf /tmp/foo"), SideEffect::Destructive);
        assert_eq!(
            c.classify_command("DROP TABLE users"),
            SideEffect::Destructive
        );
    }

    #[test]
    fn classify_git() {
        let c = SideEffectClassifier::new();
        assert_eq!(c.classify_command("git status"), SideEffect::Read);
        assert_eq!(c.classify_command("git push origin main"), SideEffect::ExternalWrite);
        assert_eq!(c.classify_command("git commit -m x"), SideEffect::LocalWrite);
    }

    #[tokio::test]
    async fn analyze_skips_read_noise() {
        let c = SideEffectClassifier::new();
        let mut ev = TraceEvent::new("run-1", EventSource::Process, "process.spawned");
        ev.metadata
            .insert("command".to_string(), serde_json::json!("ls -la"));
        let derived = c.analyze(&[ev]).await.unwrap();
        // Read reclassifications are quiet — no derived event
        assert!(derived.is_empty());
    }

    #[tokio::test]
    async fn analyze_emits_destructive() {
        let c = SideEffectClassifier::new();
        let mut ev = TraceEvent::new("run-1", EventSource::Tool, "tool.call");
        ev.side_effect = SideEffect::Unknown;
        ev.metadata
            .insert("tool_name".to_string(), serde_json::json!("Bash"));
        ev.metadata.insert(
            "input".to_string(),
            serde_json::json!({"command": "rm -rf /tmp/x"}),
        );
        // classify_event may use tool name → Unknown for Bash; put command on event
        ev.metadata
            .insert("command".to_string(), serde_json::json!("rm -rf /tmp/x"));
        let derived = c.analyze(&[ev]).await.unwrap();
        assert_eq!(derived.len(), 1);
        assert_eq!(derived[0].side_effect, SideEffect::Destructive);
    }
}
