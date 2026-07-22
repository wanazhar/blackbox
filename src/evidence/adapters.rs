//! Sensor-specific NDJSON adapters (proxy + process/Falco-style).
#![allow(missing_docs)]

use chrono::Utc;
use serde_json::Value;

use super::event::{
    EvidenceAction, EvidenceIntegrity, EvidenceOutcome, ExternalEvidenceEvent, ExternalIdentity,
    EVIDENCE_EVENT_SCHEMA,
};

/// Detect and map a single JSON object from a known sensor family.
pub fn map_sensor_event(obj: &serde_json::Map<String, Value>) -> Option<ExternalEvidenceEvent> {
    if is_falco_like(obj) {
        return Some(map_falco(obj));
    }
    if is_proxy_like(obj) {
        return Some(map_proxy(obj));
    }
    if is_process_audit_like(obj) {
        return Some(map_process_audit(obj));
    }
    None
}

fn is_falco_like(obj: &serde_json::Map<String, Value>) -> bool {
    obj.contains_key("rule")
        && (obj.contains_key("output_fields")
            || obj.get("source").and_then(|v| v.as_str()) == Some("syscall")
            || obj.contains_key("priority"))
}

fn is_proxy_like(obj: &serde_json::Map<String, Value>) -> bool {
    let has_url =
        obj.contains_key("url") || obj.contains_key("request_url") || obj.contains_key("dest_host");
    let has_proxy_mark = obj.get("proxy").is_some()
        || obj.get("sensor").and_then(|v| v.as_str()) == Some("proxy")
        || obj.get("type").and_then(|v| v.as_str()) == Some("http_proxy");
    has_url && (has_proxy_mark || obj.contains_key("status_code") || obj.contains_key("action"))
}

fn is_process_audit_like(obj: &serde_json::Map<String, Value>) -> bool {
    (obj.contains_key("exe") || obj.contains_key("comm") || obj.contains_key("cmdline"))
        && (obj.contains_key("pid") || obj.contains_key("auid") || obj.contains_key("SYSCALL"))
}

fn map_falco(obj: &serde_json::Map<String, Value>) -> ExternalEvidenceEvent {
    let rule = obj
        .get("rule")
        .and_then(|v| v.as_str())
        .unwrap_or("falco_rule");
    let source_event_id = obj
        .get("uuid")
        .or_else(|| obj.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("falco-{}", rule));
    let fields = obj
        .get("output_fields")
        .and_then(|v| v.as_object())
        .cloned()
        .unwrap_or_default();
    let proc = fields
        .get("proc.name")
        .or_else(|| fields.get("proc.cmdline"))
        .and_then(|v| v.as_str())
        .unwrap_or(rule);
    let action = if rule.to_ascii_lowercase().contains("network")
        || fields.contains_key("fd.sip")
        || fields.contains_key("fd.name")
    {
        EvidenceAction::NetworkConnect
    } else if rule.to_ascii_lowercase().contains("write") {
        EvidenceAction::FileWrite
    } else {
        EvidenceAction::ProcessExec
    };
    let mut ev = ExternalEvidenceEvent::new("falco", "process", source_event_id, action);
    ev.object = Some(proc.into());
    if let Some(dest) = fields
        .get("fd.name")
        .or_else(|| fields.get("fd.sip"))
        .and_then(|v| v.as_str())
    {
        ev.destination = Some(dest.into());
    }
    if let Some(pid) = fields.get("proc.pid").and_then(|v| v.as_i64()) {
        ev.identity.pid = Some(pid);
    }
    ev.identity.host = fields
        .get("hostname")
        .and_then(|v| v.as_str())
        .map(String::from);
    ev.outcome = EvidenceOutcome::Success;
    ev.integrity = EvidenceIntegrity::Unverified;
    ev.transformations.push("mapped_from_falco".into());
    ev.attributes
        .insert("rule".into(), Value::String(rule.into()));
    ev
}

fn map_proxy(obj: &serde_json::Map<String, Value>) -> ExternalEvidenceEvent {
    let source_event_id = obj
        .get("id")
        .or_else(|| obj.get("request_id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("proxy-{}", Utc::now().timestamp_millis()));
    let dest = obj
        .get("url")
        .or_else(|| obj.get("request_url"))
        .or_else(|| obj.get("dest_host"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let action_s = obj
        .get("action")
        .or_else(|| obj.get("decision"))
        .and_then(|v| v.as_str())
        .unwrap_or("allow");
    let (action, outcome) = match action_s.to_ascii_lowercase().as_str() {
        "deny" | "block" | "blocked" | "rejected" => {
            (EvidenceAction::ProxyDeny, EvidenceOutcome::Denied)
        }
        "allow" | "allowed" | "accept" => (EvidenceAction::ProxyAllow, EvidenceOutcome::Success),
        _ => {
            let code = obj.get("status_code").and_then(|v| v.as_i64()).unwrap_or(0);
            if code == 403 || code == 407 {
                (EvidenceAction::ProxyDeny, EvidenceOutcome::Denied)
            } else {
                (EvidenceAction::HttpRequest, EvidenceOutcome::Success)
            }
        }
    };
    let mut ev = ExternalEvidenceEvent::new("http-proxy", "proxy", source_event_id, action);
    ev.destination = if dest.is_empty() { None } else { Some(dest) };
    ev.outcome = outcome;
    ev.integrity = EvidenceIntegrity::Unverified;
    ev.transformations.push("mapped_from_proxy".into());
    if let Some(run) = obj.get("run_id").and_then(|v| v.as_str()) {
        ev.identity.run_id = Some(run.into());
        ev.linked_run_id = Some(run.into());
    }
    if let Some(tid) = obj.get("trace_id").and_then(|v| v.as_str()) {
        ev.identity.trace_id = Some(tid.into());
    }
    ev
}

fn map_process_audit(obj: &serde_json::Map<String, Value>) -> ExternalEvidenceEvent {
    let source_event_id = obj
        .get("msg")
        .or_else(|| obj.get("id"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("audit-{}", Utc::now().timestamp_millis()));
    let exe = obj
        .get("exe")
        .or_else(|| obj.get("comm"))
        .or_else(|| obj.get("cmdline"))
        .and_then(|v| v.as_str())
        .unwrap_or("process")
        .to_string();
    let mut ev = ExternalEvidenceEvent::new(
        "linux-audit",
        "process",
        source_event_id,
        EvidenceAction::ProcessExec,
    );
    ev.object = Some(exe);
    if let Some(pid) = obj.get("pid").and_then(|v| v.as_i64()) {
        ev.identity.pid = Some(pid);
    }
    ev.outcome = EvidenceOutcome::Success;
    ev.integrity = EvidenceIntegrity::Unverified;
    ev.transformations.push("mapped_from_process_audit".into());
    ev.schema = EVIDENCE_EVENT_SCHEMA.into();
    let _ = ExternalIdentity::default(); // keep import stable
    ev
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_proxy_deny() {
        let v: Value = serde_json::json!({
            "proxy": true,
            "url": "https://evil.example/x",
            "action": "deny",
            "id": "p1"
        });
        let ev = map_sensor_event(v.as_object().unwrap()).unwrap();
        assert!(matches!(ev.action, EvidenceAction::ProxyDeny));
        assert_eq!(ev.destination.as_deref(), Some("https://evil.example/x"));
    }

    #[test]
    fn maps_falco_exec() {
        let v: Value = serde_json::json!({
            "rule": "Write below binary dir",
            "priority": "Warning",
            "source": "syscall",
            "uuid": "u1",
            "output_fields": { "proc.name": "bash", "proc.pid": 42 }
        });
        let ev = map_sensor_event(v.as_object().unwrap()).unwrap();
        assert_eq!(ev.source, "falco");
        assert_eq!(ev.identity.pid, Some(42));
    }
}
