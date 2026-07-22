//! Sensor-specific NDJSON adapters.
#![allow(missing_docs)]

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};

use super::event::{
    EvidenceAction, EvidenceIntegrity, EvidenceOutcome, ExternalEvidenceEvent,
    EVIDENCE_EVENT_SCHEMA,
};

/// Detect and map a single JSON object from a known sensor family.
pub fn map_sensor_event(obj: &Map<String, Value>) -> Option<ExternalEvidenceEvent> {
    if is_kubernetes_audit(obj) {
        return Some(map_kubernetes_audit(obj));
    }
    if is_aws_cloudtrail(obj) {
        return Some(map_aws_cloudtrail(obj));
    }
    if is_gcp_cloud_audit(obj) {
        return Some(map_gcp_cloud_audit(obj));
    }
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

/// Fallible adapter entrypoint for the importer. The public compatibility
/// mapper still returns an event, while ingestion preserves actionable schema
/// diagnostics for recognized malformed sensor records.
pub(super) fn map_sensor_event_checked(
    obj: &Map<String, Value>,
) -> Result<Option<ExternalEvidenceEvent>, String> {
    let Some(event) = map_sensor_event(obj) else {
        return Ok(None);
    };
    if event.source.is_empty() {
        let reason = event
            .coverage_notes
            .iter()
            .find(|note| note.starts_with("malformed sensor record:"))
            .cloned()
            .unwrap_or_else(|| "malformed recognized sensor record".into());
        return Err(reason);
    }
    Ok(Some(event))
}

fn is_kubernetes_audit(obj: &Map<String, Value>) -> bool {
    obj.get("apiVersion")
        .and_then(Value::as_str)
        .is_some_and(|v| v.starts_with("audit.k8s.io/"))
        || (obj.get("kind").and_then(Value::as_str) == Some("Event")
            && (obj.contains_key("auditID") || obj.contains_key("requestURI")))
}

fn is_aws_cloudtrail(obj: &Map<String, Value>) -> bool {
    obj.contains_key("eventVersion")
        && (obj.contains_key("eventSource")
            || obj.contains_key("eventName")
            || obj.contains_key("eventID"))
}

fn is_gcp_cloud_audit(obj: &Map<String, Value>) -> bool {
    obj.get("protoPayload")
        .and_then(Value::as_object)
        .and_then(|payload| payload.get("@type"))
        .and_then(Value::as_str)
        .is_some_and(|kind| kind.ends_with("google.cloud.audit.AuditLog"))
}

fn map_kubernetes_audit(obj: &Map<String, Value>) -> ExternalEvidenceEvent {
    let audit_id = string_at(obj, &["auditID"]);
    let mut ev = ExternalEvidenceEvent::new(
        "kubernetes-audit",
        "k8s_audit",
        audit_id.unwrap_or_default(),
        EvidenceAction::K8sAudit,
    );
    ev.integrity = EvidenceIntegrity::Unverified;
    ev.transformations
        .push("mapped_from_kubernetes_audit".into());

    let user = object_at(obj, &["user"]);
    ev.identity.principal = user.and_then(|u| string_at(u, &["username"]).map(str::to_owned));

    let object_ref = object_at(obj, &["objectRef"]);
    ev.identity.namespace = object_ref
        .and_then(|r| string_at(r, &["namespace"]))
        .map(str::to_owned);
    ev.identity.workload = annotation(obj, &["blackbox.io/workload", "blackbox.dev/workload"])
        .or_else(|| kubernetes_workload(object_ref))
        .map(str::to_owned);
    ev.identity.container =
        annotation(obj, &["blackbox.io/container", "blackbox.dev/container"]).map(str::to_owned);
    ev.identity.trace_id =
        annotation(obj, &["blackbox.io/trace-id", "blackbox.dev/trace-id"]).map(str::to_owned);
    ev.identity.run_id =
        annotation(obj, &["blackbox.io/run-id", "blackbox.dev/run-id"]).map(str::to_owned);
    ev.linked_run_id = ev.identity.run_id.clone();

    ev.destination = string_at(obj, &["requestURI"]).map(str::to_owned);
    ev.object = kubernetes_object(object_ref);
    ev.outcome = kubernetes_outcome(obj);
    set_timestamp(
        &mut ev,
        obj.get("requestReceivedTimestamp"),
        TimestampKind::Occurred,
        "requestReceivedTimestamp",
    );
    set_timestamp(
        &mut ev,
        obj.get("stageTimestamp"),
        TimestampKind::Observed,
        "stageTimestamp",
    );

    copy_string_attribute(&mut ev, "k8s.verb", obj.get("verb"));
    copy_string_attribute(&mut ev, "k8s.stage", obj.get("stage"));
    copy_string_attribute(&mut ev, "k8s.user_agent", obj.get("userAgent"));
    copy_value_attribute(&mut ev, "k8s.source_ips", obj.get("sourceIPs"));
    if let Some(code) = object_at(obj, &["responseStatus"]).and_then(|s| s.get("code")) {
        copy_value_attribute(&mut ev, "k8s.response_code", Some(code));
    }

    let mut missing = Vec::new();
    required_string(obj, "auditID", &mut missing);
    required_string(obj, "stage", &mut missing);
    required_string(obj, "requestURI", &mut missing);
    required_string(obj, "verb", &mut missing);
    required_timestamp(obj, "requestReceivedTimestamp", &mut missing);
    required_timestamp(obj, "stageTimestamp", &mut missing);
    if ev.identity.principal.is_none() {
        missing.push("user.username");
    }
    if !valid_string_array(obj.get("sourceIPs")) {
        missing.push("sourceIPs");
    }
    mark_malformed(&mut ev, &missing);
    ev
}

fn map_aws_cloudtrail(obj: &Map<String, Value>) -> ExternalEvidenceEvent {
    let event_id = string_at(obj, &["eventID"]);
    let mut ev = ExternalEvidenceEvent::new(
        "aws-cloudtrail",
        "cloud_audit",
        event_id.unwrap_or_default(),
        EvidenceAction::CloudAudit,
    );
    ev.integrity = EvidenceIntegrity::Unverified;
    ev.transformations.push("mapped_from_aws_cloudtrail".into());
    ev.identity.principal = aws_principal(obj).map(str::to_owned);
    let request = object_at(obj, &["requestParameters"]);
    ev.identity.workload = request
        .and_then(|r| first_string(r, &["workload", "podName", "task", "taskDefinition"]))
        .map(str::to_owned);
    ev.identity.container = request
        .and_then(|r| first_string(r, &["container", "containerName"]))
        .map(str::to_owned);
    ev.identity.namespace = request
        .and_then(|r| first_string(r, &["namespace", "namespaceName"]))
        .map(str::to_owned);
    ev.destination = string_at(obj, &["eventSource"]).map(str::to_owned);
    ev.object = aws_object(obj).or_else(|| string_at(obj, &["eventName"]).map(str::to_owned));
    ev.outcome = aws_outcome(obj);
    set_timestamp(
        &mut ev,
        obj.get("eventTime"),
        TimestampKind::Occurred,
        "eventTime",
    );
    copy_string_attribute(&mut ev, "cloud.action", obj.get("eventName"));
    copy_string_attribute(&mut ev, "cloud.region", obj.get("awsRegion"));
    copy_string_attribute(&mut ev, "cloud.source_ip", obj.get("sourceIPAddress"));
    copy_string_attribute(&mut ev, "cloud.user_agent", obj.get("userAgent"));
    copy_string_attribute(&mut ev, "cloud.account", obj.get("recipientAccountId"));
    copy_string_attribute(&mut ev, "cloud.error_code", obj.get("errorCode"));

    let mut missing = Vec::new();
    required_string(obj, "eventID", &mut missing);
    required_timestamp(obj, "eventTime", &mut missing);
    required_string(obj, "eventSource", &mut missing);
    required_string(obj, "eventName", &mut missing);
    if obj.contains_key("errorCode")
        && obj
            .get("errorCode")
            .and_then(Value::as_str)
            .is_none_or(str::is_empty)
    {
        missing.push("errorCode");
    }
    if ev.identity.principal.is_none() {
        missing.push("userIdentity principal");
    }
    mark_malformed(&mut ev, &missing);
    ev
}

fn map_gcp_cloud_audit(obj: &Map<String, Value>) -> ExternalEvidenceEvent {
    let payload = object_at(obj, &["protoPayload"]);
    let insert_id = string_at(obj, &["insertId"]);
    let mut ev = ExternalEvidenceEvent::new(
        "gcp-cloud-audit",
        "cloud_audit",
        insert_id.unwrap_or_default(),
        EvidenceAction::CloudAudit,
    );
    ev.integrity = EvidenceIntegrity::Unverified;
    ev.transformations
        .push("mapped_from_gcp_cloud_audit".into());
    ev.identity.principal = payload
        .and_then(|p| object_at(p, &["authenticationInfo"]))
        .and_then(|a| string_at(a, &["principalEmail"]))
        .map(str::to_owned);
    ev.identity.trace_id = string_at(obj, &["trace"]).map(str::to_owned);
    let resource_labels = object_at(obj, &["resource", "labels"]);
    ev.identity.workload = resource_labels
        .and_then(|labels| first_string(labels, &["pod_name", "workload_name", "instance_id"]))
        .map(str::to_owned);
    ev.identity.container = resource_labels
        .and_then(|labels| first_string(labels, &["container_name"]))
        .map(str::to_owned);
    ev.identity.namespace = resource_labels
        .and_then(|labels| first_string(labels, &["namespace_name"]))
        .map(str::to_owned);
    ev.destination = payload
        .and_then(|p| string_at(p, &["serviceName"]))
        .map(str::to_owned);
    ev.object = payload
        .and_then(|p| string_at(p, &["resourceName"]))
        .map(str::to_owned);
    ev.outcome = gcp_outcome(payload);
    set_timestamp(
        &mut ev,
        obj.get("timestamp").or_else(|| obj.get("receiveTimestamp")),
        TimestampKind::Occurred,
        "timestamp",
    );
    if let Some(received) = obj.get("receiveTimestamp") {
        set_timestamp(
            &mut ev,
            Some(received),
            TimestampKind::Observed,
            "receiveTimestamp",
        );
    }
    copy_string_attribute(
        &mut ev,
        "cloud.action",
        payload.and_then(|p| p.get("methodName")),
    );
    copy_string_attribute(&mut ev, "cloud.log_name", obj.get("logName"));
    copy_string_attribute(
        &mut ev,
        "cloud.source_ip",
        payload
            .and_then(|p| object_at(p, &["requestMetadata"]))
            .and_then(|m| m.get("callerIp")),
    );

    let mut missing = Vec::new();
    required_string(obj, "insertId", &mut missing);
    required_timestamp(obj, "timestamp", &mut missing);
    if payload
        .and_then(|p| string_at(p, &["methodName"]))
        .is_none()
    {
        missing.push("protoPayload.methodName");
    }
    if payload
        .and_then(|p| string_at(p, &["serviceName"]))
        .is_none()
    {
        missing.push("protoPayload.serviceName");
    }
    if ev.identity.principal.is_none() {
        missing.push("protoPayload.authenticationInfo.principalEmail");
    }
    if payload.is_some_and(|payload| !valid_gcp_status(payload.get("status"))) {
        missing.push("protoPayload.status.code");
    }
    mark_malformed(&mut ev, &missing);
    ev
}

fn is_falco_like(obj: &Map<String, Value>) -> bool {
    obj.contains_key("rule")
        && (obj.contains_key("output_fields")
            || obj.get("source").and_then(Value::as_str) == Some("syscall")
            || obj.contains_key("priority"))
}

fn is_proxy_like(obj: &Map<String, Value>) -> bool {
    let has_url =
        obj.contains_key("url") || obj.contains_key("request_url") || obj.contains_key("dest_host");
    let has_proxy_mark = obj.get("proxy").is_some()
        || obj.get("sensor").and_then(Value::as_str) == Some("proxy")
        || obj.get("type").and_then(Value::as_str) == Some("http_proxy");
    has_url && (has_proxy_mark || obj.contains_key("status_code") || obj.contains_key("action"))
}

fn is_process_audit_like(obj: &Map<String, Value>) -> bool {
    (obj.contains_key("exe") || obj.contains_key("comm") || obj.contains_key("cmdline"))
        && (obj.contains_key("pid") || obj.contains_key("auid") || obj.contains_key("SYSCALL"))
}

fn map_falco(obj: &Map<String, Value>) -> ExternalEvidenceEvent {
    let rule = obj
        .get("rule")
        .and_then(Value::as_str)
        .unwrap_or("falco_rule");
    let source_event_id = obj
        .get("uuid")
        .or_else(|| obj.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("falco-{rule}"));
    let fields = obj
        .get("output_fields")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let proc = fields
        .get("proc.name")
        .or_else(|| fields.get("proc.cmdline"))
        .and_then(Value::as_str)
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
        .and_then(Value::as_str)
    {
        ev.destination = Some(dest.into());
    }
    if let Some(pid) = fields.get("proc.pid").and_then(Value::as_i64) {
        ev.identity.pid = Some(pid);
    }
    ev.identity.host = fields
        .get("hostname")
        .and_then(Value::as_str)
        .map(String::from);
    ev.outcome = EvidenceOutcome::Success;
    ev.integrity = EvidenceIntegrity::Unverified;
    ev.transformations.push("mapped_from_falco".into());
    ev.attributes
        .insert("rule".into(), Value::String(rule.into()));
    ev
}

fn map_proxy(obj: &Map<String, Value>) -> ExternalEvidenceEvent {
    let source_event_id = obj
        .get("id")
        .or_else(|| obj.get("request_id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("proxy-{}", Utc::now().timestamp_millis()));
    let dest = obj
        .get("url")
        .or_else(|| obj.get("request_url"))
        .or_else(|| obj.get("dest_host"))
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let action_s = obj
        .get("action")
        .or_else(|| obj.get("decision"))
        .and_then(Value::as_str)
        .unwrap_or("allow");
    let (action, outcome) = match action_s.to_ascii_lowercase().as_str() {
        "deny" | "block" | "blocked" | "rejected" => {
            (EvidenceAction::ProxyDeny, EvidenceOutcome::Denied)
        }
        "allow" | "allowed" | "accept" => (EvidenceAction::ProxyAllow, EvidenceOutcome::Success),
        _ => {
            let code = obj.get("status_code").and_then(Value::as_i64).unwrap_or(0);
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
    if let Some(run) = obj.get("run_id").and_then(Value::as_str) {
        ev.identity.run_id = Some(run.into());
        ev.linked_run_id = Some(run.into());
    }
    if let Some(tid) = obj.get("trace_id").and_then(Value::as_str) {
        ev.identity.trace_id = Some(tid.into());
    }
    ev
}

fn map_process_audit(obj: &Map<String, Value>) -> ExternalEvidenceEvent {
    let source_event_id = obj
        .get("msg")
        .or_else(|| obj.get("id"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| format!("audit-{}", Utc::now().timestamp_millis()));
    let exe = obj
        .get("exe")
        .or_else(|| obj.get("comm"))
        .or_else(|| obj.get("cmdline"))
        .and_then(Value::as_str)
        .unwrap_or("process")
        .to_string();
    let mut ev = ExternalEvidenceEvent::new(
        "linux-audit",
        "process",
        source_event_id,
        EvidenceAction::ProcessExec,
    );
    ev.object = Some(exe);
    if let Some(pid) = obj.get("pid").and_then(Value::as_i64) {
        ev.identity.pid = Some(pid);
    }
    ev.outcome = EvidenceOutcome::Success;
    ev.integrity = EvidenceIntegrity::Unverified;
    ev.transformations.push("mapped_from_process_audit".into());
    ev.schema = EVIDENCE_EVENT_SCHEMA.into();
    ev
}

fn string_at<'a>(obj: &'a Map<String, Value>, path: &[&str]) -> Option<&'a str> {
    let mut value = None;
    let mut current = obj;
    for (idx, key) in path.iter().enumerate() {
        value = current.get(*key);
        if idx + 1 < path.len() {
            current = value?.as_object()?;
        }
    }
    value?.as_str().filter(|s| !s.is_empty())
}

fn object_at<'a>(obj: &'a Map<String, Value>, path: &[&str]) -> Option<&'a Map<String, Value>> {
    let mut value = None;
    let mut current = obj;
    for (idx, key) in path.iter().enumerate() {
        value = current.get(*key);
        if idx + 1 < path.len() {
            current = value?.as_object()?;
        }
    }
    value?.as_object()
}

fn annotation<'a>(obj: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    let annotations = obj.get("annotations")?.as_object()?;
    keys.iter()
        .find_map(|key| annotations.get(*key).and_then(Value::as_str))
        .filter(|s| !s.is_empty())
}

fn kubernetes_workload(object_ref: Option<&Map<String, Value>>) -> Option<&str> {
    let object_ref = object_ref?;
    match string_at(object_ref, &["resource"])? {
        "pods" | "deployments" | "statefulsets" | "daemonsets" | "jobs" | "cronjobs" => {
            string_at(object_ref, &["name"])
        }
        _ => None,
    }
}

fn kubernetes_object(object_ref: Option<&Map<String, Value>>) -> Option<String> {
    let object_ref = object_ref?;
    let resource = string_at(object_ref, &["resource"])?;
    let mut value = resource.to_owned();
    if let Some(namespace) = string_at(object_ref, &["namespace"]) {
        value.push('/');
        value.push_str(namespace);
    }
    if let Some(name) = string_at(object_ref, &["name"]) {
        value.push('/');
        value.push_str(name);
    }
    if let Some(subresource) = string_at(object_ref, &["subresource"]) {
        value.push(':');
        value.push_str(subresource);
    }
    Some(value)
}

fn kubernetes_outcome(obj: &Map<String, Value>) -> EvidenceOutcome {
    if obj.get("stage").and_then(Value::as_str) == Some("Panic") {
        return EvidenceOutcome::Failure;
    }
    let status = object_at(obj, &["responseStatus"]);
    let code = status.and_then(|s| s.get("code")).and_then(Value::as_i64);
    match code {
        Some(401 | 403) => EvidenceOutcome::Denied,
        Some(200..=399) => EvidenceOutcome::Success,
        Some(400..=599) => EvidenceOutcome::Failure,
        _ if status.and_then(|s| string_at(s, &["status"])) == Some("Success") => {
            EvidenceOutcome::Success
        }
        _ if status.and_then(|s| string_at(s, &["status"])) == Some("Failure") => {
            EvidenceOutcome::Failure
        }
        _ => EvidenceOutcome::Unknown,
    }
}

fn aws_principal(obj: &Map<String, Value>) -> Option<&str> {
    let identity = object_at(obj, &["userIdentity"])?;
    string_at(identity, &["arn"])
        .or_else(|| string_at(identity, &["principalId"]))
        .or_else(|| string_at(identity, &["userName"]))
        .or_else(|| string_at(identity, &["invokedBy"]))
        .or_else(|| {
            object_at(identity, &["sessionContext", "sessionIssuer"])
                .and_then(|issuer| string_at(issuer, &["arn"]))
        })
}

fn first_string<'a>(obj: &'a Map<String, Value>, keys: &[&str]) -> Option<&'a str> {
    keys.iter().find_map(|key| string_at(obj, &[*key]))
}

fn aws_object(obj: &Map<String, Value>) -> Option<String> {
    obj.get("resources")
        .and_then(Value::as_array)
        .and_then(|resources| resources.first())
        .and_then(Value::as_object)
        .and_then(|resource| {
            string_at(resource, &["ARN"])
                .or_else(|| string_at(resource, &["arn"]))
                .or_else(|| string_at(resource, &["resourceName"]))
        })
        .map(str::to_owned)
}

fn aws_outcome(obj: &Map<String, Value>) -> EvidenceOutcome {
    match obj.get("errorCode") {
        Some(Value::String(code))
            if code.to_ascii_lowercase().contains("accessdenied")
                || code.to_ascii_lowercase().contains("unauthorized") =>
        {
            EvidenceOutcome::Denied
        }
        Some(Value::String(code)) if !code.is_empty() => EvidenceOutcome::Failure,
        Some(_) => EvidenceOutcome::Unknown,
        None => EvidenceOutcome::Success,
    }
}

fn gcp_outcome(payload: Option<&Map<String, Value>>) -> EvidenceOutcome {
    let Some(status_value) = payload.and_then(|payload| payload.get("status")) else {
        return EvidenceOutcome::Success;
    };
    let Some(code) = status_value
        .as_object()
        .and_then(|status| status.get("code"))
        .and_then(Value::as_i64)
    else {
        return EvidenceOutcome::Unknown;
    };
    match code {
        0 => EvidenceOutcome::Success,
        7 | 16 => EvidenceOutcome::Denied,
        _ => EvidenceOutcome::Failure,
    }
}

fn valid_gcp_status(status: Option<&Value>) -> bool {
    match status {
        None => true,
        Some(status) => status
            .as_object()
            .and_then(|status| status.get("code"))
            .and_then(Value::as_i64)
            .is_some(),
    }
}

fn valid_string_array(value: Option<&Value>) -> bool {
    value.and_then(Value::as_array).is_some_and(|values| {
        !values.is_empty()
            && values
                .iter()
                .all(|value| value.as_str().is_some_and(|value| !value.is_empty()))
    })
}

fn required_string<'a>(obj: &'a Map<String, Value>, key: &'a str, missing: &mut Vec<&'a str>) {
    if string_at(obj, &[key]).is_none() {
        missing.push(key);
    }
}

fn required_timestamp<'a>(obj: &'a Map<String, Value>, key: &'a str, malformed: &mut Vec<&'a str>) {
    let valid = string_at(obj, &[key]).is_some_and(|raw| DateTime::parse_from_rfc3339(raw).is_ok());
    if !valid {
        malformed.push(key);
    }
}

fn mark_malformed(ev: &mut ExternalEvidenceEvent, missing: &[&str]) {
    if !missing.is_empty() {
        // map_sensor_event predates fallible adapters. Clearing the required
        // source field makes the existing schema validator reject a recognized
        // but malformed record instead of letting it fall through to generic
        // mapping or manufacturing required values.
        ev.source.clear();
        ev.coverage_notes.push(format!(
            "malformed sensor record: missing or invalid required fields: {}",
            missing.join(", ")
        ));
    }
}

enum TimestampKind {
    Occurred,
    Observed,
}

fn set_timestamp(
    ev: &mut ExternalEvidenceEvent,
    raw: Option<&Value>,
    kind: TimestampKind,
    field: &str,
) {
    let Some(raw) = raw else { return };
    let Some(raw) = raw.as_str() else {
        ev.coverage_notes
            .push(format!("{field} was not a string; timestamp omitted"));
        return;
    };
    match DateTime::parse_from_rfc3339(raw) {
        Ok(parsed) => match kind {
            TimestampKind::Occurred => ev.occurred_at = Some(parsed.with_timezone(&Utc)),
            TimestampKind::Observed => ev.observed_at = Some(parsed.with_timezone(&Utc)),
        },
        Err(_) => ev
            .coverage_notes
            .push(format!("{field} was invalid; timestamp omitted")),
    }
}

fn copy_string_attribute(ev: &mut ExternalEvidenceEvent, key: &str, value: Option<&Value>) {
    if let Some(value) = value.and_then(Value::as_str).filter(|s| !s.is_empty()) {
        ev.attributes
            .insert(key.into(), Value::String(value.to_owned()));
    }
}

fn copy_value_attribute(ev: &mut ExternalEvidenceEvent, key: &str, value: Option<&Value>) {
    if let Some(value) = value {
        ev.attributes.insert(key.into(), value.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_proxy_deny() {
        let v = serde_json::json!({
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
        let v = serde_json::json!({
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

    #[test]
    fn malformed_known_sensor_is_not_generic_fallback() {
        let v = serde_json::json!({
            "apiVersion": "audit.k8s.io/v1",
            "kind": "Event",
            "auditID": "only-an-id"
        });
        let ev = map_sensor_event(v.as_object().unwrap()).unwrap();
        assert!(ev.validate().is_err());
        assert!(ev.coverage_notes[0].contains("requestURI"));
    }
}
