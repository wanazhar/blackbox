//! Structured fsck findings and repair plans.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsckSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FsckFinding {
    pub section: String,
    pub severity: FsckSeverity,
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub event_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_key: Option<String>,
    #[serde(default)]
    pub repairable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FsckReport {
    pub schema: String,
    pub mode: String,
    pub ok: bool,
    pub findings: Vec<FsckFinding>,
    pub sections_checked: Vec<String>,
    pub error_count: usize,
    pub warning_count: usize,
    pub repairable_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_plan: Option<RepairPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_artifact: Option<String>,
}

impl FsckReport {
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
pub struct RepairPlan {
    pub schema: String,
    pub actions: Vec<RepairAction>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepairAction {
    pub kind: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_key: Option<String>,
    /// Safe to apply automatically under `--repair`.
    pub auto_safe: bool,
}
