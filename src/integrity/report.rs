//! Structured fsck findings and repair plans.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// `FsckSeverity` classification.
pub enum FsckSeverity {
    /// `Info` variant.
    Info,
    /// `Warning` variant.
    Warning,
    /// `Error` variant.
    Error,
    /// `Critical` variant.
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `FsckFinding` value.
pub struct FsckFinding {
    /// Section.
    pub section: String,
    /// Severity.
    pub severity: FsckSeverity,
    /// Code.
    pub code: String,
    /// Message.
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Owning run id.
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Event id.
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Checkpoint id.
    pub checkpoint_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Field.
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Blob key.
    pub blob_key: Option<String>,
    #[serde(default)]
    /// Repairable.
    pub repairable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// `FsckReport` value.
pub struct FsckReport {
    /// Schema identifier string.
    pub schema: String,
    /// Mode.
    pub mode: String,
    /// Whether the operation succeeded.
    pub ok: bool,
    /// Findings.
    pub findings: Vec<FsckFinding>,
    /// Sections checked.
    pub sections_checked: Vec<String>,
    /// Error count.
    pub error_count: usize,
    /// Warning count.
    pub warning_count: usize,
    /// Repairable count.
    pub repairable_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Repair plan.
    pub repair_plan: Option<RepairPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Recovery artifact.
    pub recovery_artifact: Option<String>,
}

impl FsckReport {
    /// Create a new instance.
    ///
    /// # Examples
    ///
    /// ```
    /// # use blackbox as _;
    /// // `new` — see module docs for full workflow.
    /// ```
    pub fn new(mode: &str) -> Self {
        Self {
            schema: "blackbox.fsck/v1".into(),
            mode: mode.into(),
            ok: true,
            findings: Vec::new(),
            sections_checked: Vec::new(),
            error_count: 0,
            warning_count: 0,
            repairable_count: 0,
            repair_plan: None,
            recovery_artifact: None,
        }
    }

    /// Push.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `push` — see module docs for full workflow.
    /// ```
    pub fn push(&mut self, finding: FsckFinding) {
        match finding.severity {
            FsckSeverity::Error | FsckSeverity::Critical => {
                self.ok = false;
                self.error_count += 1;
            }
            FsckSeverity::Warning => self.warning_count += 1,
            FsckSeverity::Info => {}
        }
        if finding.repairable {
            self.repairable_count += 1;
        }
        self.findings.push(finding);
    }

    /// Format text.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// # use blackbox as _;
    /// // `format_text` — see module docs for full workflow.
    /// ```
    pub fn format_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!(
            "blackbox fsck ({}) — {}\n",
            self.mode,
            if self.ok { "OK" } else { "ISSUES" }
        ));
        out.push_str(&format!(
            "sections: {}\n",
            self.sections_checked.join(", ")
        ));
        out.push_str(&format!(
            "errors={} warnings={} repairable={}\n",
            self.error_count, self.warning_count, self.repairable_count
        ));
        for f in &self.findings {
            out.push_str(&format!(
                "  [{:?}] {}:{} {}\n",
                f.severity, f.section, f.code, f.message
            ));
        }
        if let Some(ref plan) = self.repair_plan {
            out.push_str(&format!(
                "repair plan: {} action(s)\n",
                plan.actions.len()
            ));
            for a in &plan.actions {
                out.push_str(&format!("  - {}: {}\n", a.kind, a.description));
            }
        }
        if let Some(ref art) = self.recovery_artifact {
            out.push_str(&format!("recovery artifact: {art}\n"));
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
/// `RepairPlan` value.
pub struct RepairPlan {
    /// Schema identifier string.
    pub schema: String,
    /// Actions.
    pub actions: Vec<RepairAction>,
    /// Creation timestamp.
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// `RepairAction` value.
pub struct RepairAction {
    /// Event or item kind string.
    pub kind: String,
    /// Human-readable description.
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Owning run id.
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// Blob key.
    pub blob_key: Option<String>,
    /// Safe to apply automatically under `--repair`.
    pub auto_safe: bool,
}
