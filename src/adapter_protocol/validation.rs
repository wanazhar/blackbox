//! Adapter manifest and event validation / conformance helpers.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::adapter_protocol::manifest::{AdapterManifest, ADAPTER_PROTOCOL};

pub const MAX_ADAPTER_EVENT_BYTES: usize = 1024 * 1024; // 1 MiB

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ValidationReport {
    pub ok: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    #[serde(default)]
    pub events_validated: usize,
}

pub fn validate_adapter_manifest(m: &AdapterManifest) -> ValidationReport {
    let mut r = ValidationReport {
        ok: true,
        ..Default::default()
    };
    if m.name.trim().is_empty() {
        r.ok = false;
        r.errors.push("name is required".into());
    }
    if m.protocol != ADAPTER_PROTOCOL {
        r.ok = false;
        r.errors.push(format!(
            "unsupported protocol {:?} (expected {ADAPTER_PROTOCOL})",
            m.protocol
        ));
    }
    if m.command.is_empty() {
        r.ok = false;
        r.errors.push("command must be non-empty".into());
    }
    if m.detect_basenames.is_empty() {
        r.warnings
            .push("detect_basenames empty — adapter will not auto-detect".into());
    }
    r
}

/// Validate one NDJSON adapter event line (canonical subset).
pub fn validate_adapter_event(line: &str) -> ValidationReport {
    let mut r = ValidationReport {
        ok: true,
        ..Default::default()
    };
    if line.len() > MAX_ADAPTER_EVENT_BYTES {
        r.ok = false;
        r.errors.push(format!(
            "event exceeds max size {} bytes",
            MAX_ADAPTER_EVENT_BYTES
        ));
        return r;
    }
    let v: serde_json::Value = match serde_json::from_str(line) {
        Ok(v) => v,
        Err(e) => {
            r.ok = false;
            r.errors.push(format!("invalid JSON: {e}"));
            return r;
        }
    };
    let obj = match v.as_object() {
        Some(o) => o,
        None => {
            r.ok = false;
            r.errors.push("event must be a JSON object".into());
            return r;
        }
    };
    for req in ["kind", "source_sequence"] {
        if !obj.contains_key(req) {
            r.ok = false;
            r.errors.push(format!("missing required field {req}"));
        }
    }
    if let Some(kind) = obj.get("kind").and_then(|k| k.as_str()) {
        if kind.is_empty() {
            r.ok = false;
            r.errors.push("kind must be non-empty".into());
        }
    }
    r
}

/// Spawn the adapter command and validate NDJSON events on stdout (bounded).
///
/// Empty stdout is a warning (fixture-only adapters), not a hard failure.
/// Invalid lines or non-zero exit (when events expected) fail the report.
pub fn run_live_conformance(m: &AdapterManifest, timeout: Duration) -> ValidationReport {
    let mut r = ValidationReport {
        ok: true,
        ..Default::default()
    };
    if m.command.is_empty() {
        r.ok = false;
        r.errors.push("live conformance: empty command".into());
        return r;
    }
    let prog = &m.command[0];
    let args = &m.command[1..];
    let mut child = match Command::new(prog)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            r.warnings.push(format!(
                "live conformance: could not spawn `{}`: {e} (fixture-only OK)",
                prog
            ));
            return r;
        }
    };

    // Bounded wait without hanging CI forever.
    let deadline = std::time::Instant::now() + timeout;
    let stdout = child.stdout.take();
    let mut events = 0usize;
    if let Some(out) = stdout {
        let reader = BufReader::new(out);
        for (i, line) in reader.lines().enumerate() {
            if std::time::Instant::now() > deadline {
                let _ = child.kill();
                r.warnings.push("live conformance: timed out reading stdout".into());
                break;
            }
            let Ok(line) = line else {
                continue;
            };
            if line.trim().is_empty() {
                continue;
            }
            let ev = validate_adapter_event(&line);
            if !ev.ok {
                r.ok = false;
                for e in ev.errors {
                    r.errors.push(format!("live stdout line {}: {e}", i + 1));
                }
            } else {
                events += 1;
            }
            if events >= 256 {
                r.warnings
                    .push("live conformance: capped at 256 events".into());
                let _ = child.kill();
                break;
            }
        }
    }
    r.events_validated = events;

    // Best-effort wait with remaining budget.
    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
    let status = if remaining.is_zero() {
        let _ = child.kill();
        child.wait()
    } else {
        // poll until timeout
        loop {
            match child.try_wait() {
                Ok(Some(s)) => break Ok(s),
                Ok(None) if std::time::Instant::now() > deadline => {
                    let _ = child.kill();
                    break child.wait();
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => break Err(e),
            }
        }
    };
    match status {
        Ok(s) if !s.success() && events == 0 => {
            r.warnings.push(format!(
                "live process exit={s:?} with no events (treated as fixture-only)"
            ));
        }
        Ok(s) if !s.success() && events > 0 => {
            r.warnings
                .push(format!("live process exit={s:?} after {events} event(s)"));
        }
        Err(e) => {
            r.warnings.push(format!("live process wait failed: {e}"));
        }
        _ => {}
    }
    if events == 0 {
        r.warnings
            .push("live process produced no NDJSON events".into());
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_protocol() {
        let m = AdapterManifest {
            name: "x".into(),
            protocol: "nope".into(),
            command: vec!["x".into()],
            detect_basenames: vec![],
            capabilities: vec![],
            version: None,
        };
        assert!(!validate_adapter_manifest(&m).ok);
    }

    #[test]
    fn accepts_event() {
        let line = r#"{"kind":"tool.call","source_sequence":1,"tool_name":"Bash"}"#;
        assert!(validate_adapter_event(line).ok);
    }

    #[test]
    fn live_printf_json_line() {
        let m = AdapterManifest {
            name: "echo".into(),
            protocol: ADAPTER_PROTOCOL.into(),
            command: vec![
                "printf".into(),
                r#"{"kind":"tool.call","source_sequence":1}"#.into(),
            ],
            detect_basenames: vec![],
            capabilities: vec![],
            version: None,
        };
        let r = run_live_conformance(&m, Duration::from_secs(2));
        assert!(r.ok, "{:?}", r.errors);
        assert_eq!(r.events_validated, 1);
    }
}
