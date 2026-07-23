//! Canonical action fingerprints for security decision correlation.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::protocol::canonical_hash;

/// High-level action family used in fingerprints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    /// Process / shell execution.
    ProcessExec,
    /// Filesystem write/delete.
    FileWrite,
    /// Filesystem read.
    FileRead,
    /// Network connect / HTTP.
    Network,
    /// Tool invocation (MCP / harness tool).
    Tool,
    /// Package install.
    PackageInstall,
    /// Other / opaque.
    Other,
}

impl ActionKind {
    /// Stable string form.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ProcessExec => "process_exec",
            Self::FileWrite => "file_write",
            Self::FileRead => "file_read",
            Self::Network => "network",
            Self::Tool => "tool",
            Self::PackageInstall => "package_install",
            Self::Other => "other",
        }
    }
}

/// Normalized action used for decision / execution matching.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionFingerprint {
    /// Action family.
    pub kind: ActionKind,
    /// Primary target (argv0, path, host, tool name).
    pub target: String,
    /// Normalized arguments (sorted where order is insignificant).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    /// Optional working directory.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Extra structured attributes that participate in the hash.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Value>,
}

impl ActionFingerprint {
    /// Build a process-exec fingerprint from argv.
    pub fn process_exec(argv: &[String], cwd: Option<&str>) -> Self {
        let (target, args) = if argv.is_empty() {
            (String::new(), vec![])
        } else {
            (argv[0].clone(), argv[1..].to_vec())
        };
        Self {
            kind: ActionKind::ProcessExec,
            target: normalize_target(&target),
            args: args.into_iter().map(|a| a.trim().to_string()).collect(),
            cwd: cwd.map(|c| c.to_string()),
            attributes: None,
        }
    }

    /// Build a tool fingerprint.
    pub fn tool(name: &str, input: Option<Value>) -> Self {
        Self {
            kind: ActionKind::Tool,
            target: name.trim().to_string(),
            args: vec![],
            cwd: None,
            attributes: input,
        }
    }

    /// Build a network fingerprint.
    pub fn network(destination: &str) -> Self {
        Self {
            kind: ActionKind::Network,
            target: destination.trim().to_ascii_lowercase(),
            args: vec![],
            cwd: None,
            attributes: None,
        }
    }

    /// Build a filesystem write fingerprint.
    pub fn file_write(path: &str) -> Self {
        Self {
            kind: ActionKind::FileWrite,
            target: normalize_path(path),
            args: vec![],
            cwd: None,
            attributes: None,
        }
    }

    /// Canonical JSON object used for hashing.
    pub fn canonical_value(&self) -> Value {
        json!({
            "kind": self.kind.as_str(),
            "target": self.target,
            "args": self.args,
            "cwd": self.cwd,
            "attributes": self.attributes,
        })
    }

    /// SHA-256 hex of the canonical action form.
    pub fn hash(&self) -> String {
        canonical_hash(&self.canonical_value()).unwrap_or_else(|_| {
            let mut hasher = Sha256::new();
            hasher.update(self.kind.as_str().as_bytes());
            hasher.update(self.target.as_bytes());
            hex::encode(hasher.finalize())
        })
    }

    /// Whether two fingerprints describe the same logical action.
    pub fn matches(&self, other: &ActionFingerprint) -> bool {
        self.hash() == other.hash()
    }

    /// Loose relatedness: same kind + same target (args may differ).
    pub fn same_family_target(&self, other: &ActionFingerprint) -> bool {
        self.kind == other.kind && self.target == other.target
    }
}

/// Compute action hash for a fingerprint.
pub fn action_fingerprint(fp: &ActionFingerprint) -> String {
    fp.hash()
}

fn normalize_target(s: &str) -> String {
    let t = s.trim();
    // Strip common shell path prefixes for argv0 identity.
    std::path::Path::new(t)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(t)
        .to_string()
}

fn normalize_path(p: &str) -> String {
    let p = p.trim().replace('\\', "/");
    // Collapse // and strip trailing slash (except root).
    let mut out = String::new();
    for part in p.split('/') {
        if part.is_empty() && !out.is_empty() {
            continue;
        }
        if !out.is_empty() && out != "/" {
            out.push('/');
        } else if out.is_empty() && p.starts_with('/') {
            out.push('/');
        }
        if part.is_empty() {
            continue;
        }
        if part == "." {
            continue;
        }
        out.push_str(part);
    }
    if out.is_empty() {
        p
    } else {
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_exec_hash_stable() {
        let a = ActionFingerprint::process_exec(
            &["/usr/bin/curl".into(), "https://x".into()],
            Some("/tmp"),
        );
        let b = ActionFingerprint::process_exec(
            &["curl".into(), "https://x".into()],
            Some("/tmp"),
        );
        assert_eq!(a.hash(), b.hash());
        assert_eq!(a.hash().len(), 64);
    }

    #[test]
    fn different_args_different_hash() {
        let a = ActionFingerprint::process_exec(&["rm".into(), "-rf".into(), "/".into()], None);
        let b = ActionFingerprint::process_exec(&["rm".into(), "file".into()], None);
        assert_ne!(a.hash(), b.hash());
        assert!(a.same_family_target(&b));
    }
}
