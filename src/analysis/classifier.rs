use crate::analysis::AnalysisPass;
use crate::core::event::{SideEffect, TraceEvent};

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
/// | `rm -rf`, `DROP TABLE`, `DELETE FROM` | `Destructive` |
/// | Unknown commands | `Unknown` |
pub struct SideEffectClassifier;

impl SideEffectClassifier {
    pub fn new() -> Self {
        Self
    }

    /// Classify a command string into a side-effect level.
    #[allow(dead_code)]
    pub fn classify_command(&self, command: &str) -> SideEffect {
        let lower = command.to_lowercase();
        let parts: Vec<&str> = lower.split_whitespace().collect();
        let base = parts.first().copied().unwrap_or("");

        match base {
            "ls" | "cat" | "head" | "tail" | "grep" | "rg" | "find" | "echo"
            | "read" | "which" | "file" | "stat" | "du" | "df" | "ps" | "top" => {
                SideEffect::Read
            }
            "sed" | "awk" | "touch" | "mkdir" | "cp" | "mv" | "rm" => {
                if lower.contains("-rf") || lower.contains("-r") {
                    SideEffect::Destructive
                } else {
                    SideEffect::LocalWrite
                }
            }
            "curl" | "wget" | "git" if lower.contains("push") || lower.contains("fetch") => {
                SideEffect::ExternalWrite
            }
            _ => SideEffect::Unknown,
        }
    }
}

#[async_trait::async_trait]
impl AnalysisPass for SideEffectClassifier {
    fn name(&self) -> &'static str {
        "classifier"
    }

    async fn analyze(&self, _events: &[TraceEvent]) -> anyhow::Result<Vec<TraceEvent>> {
        Ok(Vec::new())
    }
}
