//! Typed resource selectors for boundary authorization (1.8).
//!
//! Selectors replace free-form substring checks. Matching always returns a
//! structured [`MatchExplanation`] rather than a bare boolean.

#![allow(missing_docs)]

use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use super::normalize::{
    host_matches_exact, host_matches_suffix, ip_in_cidr, normalize_cidr, normalize_ip,
    normalize_path, normalize_port, normalize_url, observation_host, observation_ip, CanonicalHost,
    NormalizeOutcome,
};

/// Schema id for selector documents when serialized standalone.
pub const RESOURCE_SELECTOR_SCHEMA: &str = "blackbox.boundary.selector/v1";

/// Typed policy selector kinds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResourceSelector {
    /// Exact DNS hostname (canonical form).
    DomainExact { value: String },
    /// DNS suffix with label-boundary matching. Leading `.` optional.
    DomainSuffix { value: String },
    /// IPv4/IPv6 CIDR.
    Cidr { value: String },
    /// Exact IP address.
    IpExact { value: String },
    /// URL prefix: scheme + host + optional path prefix.
    UrlPrefix {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        scheme: Option<String>,
        host: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    /// TCP/UDP port number.
    Port { value: u16 },
    /// Unix domain socket path (exact after path normalization).
    UnixSocket { value: String },
    /// Exact filesystem path.
    PathExact { value: String },
    /// Filesystem path prefix (normalized; trailing `/` optional).
    PathPrefix { value: String },
    /// Identity / principal class token.
    Identity { value: String },
    /// Tool / harness capability token.
    Tool { value: String },
    /// Side-effect class token.
    Effect { value: String },
    /// Provenance / answer-source class.
    ProvenanceClass { value: String },
    /// Abstract network/class token (`public_network`, `package_proxy`, …).
    ClassToken { value: String },
}

impl ResourceSelector {
    /// Stable kind name.
    pub fn kind_name(&self) -> &'static str {
        match self {
            Self::DomainExact { .. } => "domain_exact",
            Self::DomainSuffix { .. } => "domain_suffix",
            Self::Cidr { .. } => "cidr",
            Self::IpExact { .. } => "ip_exact",
            Self::UrlPrefix { .. } => "url_prefix",
            Self::Port { .. } => "port",
            Self::UnixSocket { .. } => "unix_socket",
            Self::PathExact { .. } => "path_exact",
            Self::PathPrefix { .. } => "path_prefix",
            Self::Identity { .. } => "identity",
            Self::Tool { .. } => "tool",
            Self::Effect { .. } => "effect",
            Self::ProvenanceClass { .. } => "provenance_class",
            Self::ClassToken { .. } => "class_token",
        }
    }

    /// Token string used for disposition lookups (class / identity / tool / effect).
    pub fn disposition_token(&self) -> Option<&str> {
        match self {
            Self::ClassToken { value }
            | Self::Identity { value }
            | Self::Tool { value }
            | Self::Effect { value }
            | Self::ProvenanceClass { value } => Some(value.as_str()),
            _ => None,
        }
    }

    /// Interpret a legacy free-form network allowlist entry as a selector.
    ///
    /// - strings starting with `.` → domain_suffix
    /// - strings containing `/` that parse as CIDR → cidr
    /// - strings that look like URLs → url_prefix
    /// - pure class tokens (snake_case, no dots) → class_token
    /// - otherwise → domain_exact (never substring)
    pub fn from_legacy_network_token(token: &str) -> Self {
        let t = token.trim();
        if t.is_empty() {
            return Self::ClassToken {
                value: t.to_string(),
            };
        }
        if t.starts_with('.') {
            return Self::DomainSuffix {
                value: t.to_string(),
            };
        }
        if t.contains("://") {
            if let NormalizeOutcome::Ok(u) = normalize_url(t) {
                return Self::UrlPrefix {
                    scheme: Some(u.scheme),
                    host: u.host.0,
                    path: Some(u.path),
                };
            }
        }
        if t.contains('/') && matches!(normalize_cidr(t), NormalizeOutcome::Ok(_)) {
            return Self::Cidr {
                value: t.to_string(),
            };
        }
        // snake_case class tokens: public_network, package_proxy, local_only
        if t.chars().all(|c| c.is_ascii_lowercase() || c == '_') && t.contains('_') {
            return Self::ClassToken {
                value: t.to_string(),
            };
        }
        // Pure ASCII identifier without dots — treat as class token when it has no DNS shape.
        if !t.contains('.') && !t.contains(':') && t.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            // Heuristic: multi-word snake or known style → class; single label host → domain.
            if t.contains('_') {
                return Self::ClassToken {
                    value: t.to_string(),
                };
            }
        }
        // IP?
        if matches!(normalize_ip(t), NormalizeOutcome::Ok(_)) {
            return Self::IpExact {
                value: t.to_string(),
            };
        }
        Self::DomainExact {
            value: t.to_string(),
        }
    }
}

/// Entry in `allowed.network` (and similar) that accepts legacy strings or typed objects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResourceEntry {
    /// Legacy free-form string (interpreted via [`ResourceSelector::from_legacy_network_token`]).
    Legacy(String),
    /// Explicit typed selector.
    Typed(ResourceSelector),
}

impl ResourceEntry {
    /// Resolve to a concrete selector.
    pub fn as_selector(&self) -> ResourceSelector {
        match self {
            Self::Legacy(s) => ResourceSelector::from_legacy_network_token(s),
            Self::Typed(s) => s.clone(),
        }
    }

    /// Display / merge key.
    pub fn key(&self) -> String {
        match self {
            Self::Legacy(s) => s.clone(),
            Self::Typed(s) => serde_json::to_string(s).unwrap_or_else(|_| s.kind_name().into()),
        }
    }

    /// Token equality for prohibition removal (legacy string form or class token value).
    pub fn matches_token(&self, token: &str) -> bool {
        match self {
            Self::Legacy(s) => s == token,
            Self::Typed(s) => s.disposition_token() == Some(token),
        }
    }
}

impl From<&str> for ResourceEntry {
    fn from(s: &str) -> Self {
        Self::Legacy(s.into())
    }
}

impl From<String> for ResourceEntry {
    fn from(s: String) -> Self {
        Self::Legacy(s)
    }
}

impl From<ResourceSelector> for ResourceEntry {
    fn from(s: ResourceSelector) -> Self {
        Self::Typed(s)
    }
}

/// Structured match outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchDecision {
    /// Observation is authorized by this selector.
    Allow,
    /// Selector does not apply / does not match.
    NoMatch,
    /// Observation could not be normalized; never silently allowed.
    Unknown,
}

/// Explanation returned by every matcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchExplanation {
    pub decision: MatchDecision,
    pub selector_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canonical_observation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector_value: Option<String>,
    pub reasons: Vec<String>,
}

impl MatchExplanation {
    fn allow(
        kind: &str,
        observation: impl Into<String>,
        canonical: impl Into<String>,
        selector_value: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            decision: MatchDecision::Allow,
            selector_kind: kind.into(),
            observation: Some(observation.into()),
            canonical_observation: Some(canonical.into()),
            selector_value: Some(selector_value.into()),
            reasons: vec![reason.into()],
        }
    }

    fn no_match(
        kind: &str,
        observation: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            decision: MatchDecision::NoMatch,
            selector_kind: kind.into(),
            observation: Some(observation.into()),
            canonical_observation: None,
            selector_value: None,
            reasons: vec![reason.into()],
        }
    }

    fn unknown(kind: &str, observation: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            decision: MatchDecision::Unknown,
            selector_kind: kind.into(),
            observation: Some(observation.into()),
            canonical_observation: None,
            selector_value: None,
            reasons: vec![reason.into()],
        }
    }

    /// True when this selector authorizes the observation.
    pub fn is_allow(&self) -> bool {
        matches!(self.decision, MatchDecision::Allow)
    }
}

/// Match a network destination observation against a selector.
pub fn match_network_selector(selector: &ResourceSelector, observation: &str) -> MatchExplanation {
    match selector {
        ResourceSelector::DomainExact { value } => match_domain_exact(value, observation),
        ResourceSelector::DomainSuffix { value } => match_domain_suffix(value, observation),
        ResourceSelector::Cidr { value } => match_cidr(value, observation),
        ResourceSelector::IpExact { value } => match_ip_exact(value, observation),
        ResourceSelector::UrlPrefix {
            scheme,
            host,
            path,
        } => match_url_prefix(scheme.as_deref(), host, path.as_deref(), observation),
        ResourceSelector::Port { value } => match_port(*value, observation),
        ResourceSelector::UnixSocket { value } => match_unix_socket(value, observation),
        ResourceSelector::ClassToken { value } => {
            // Class tokens do not match raw destinations by substring.
            // They are disposition-level authorizations (e.g. public_network allowed).
            MatchExplanation {
                decision: MatchDecision::NoMatch,
                selector_kind: "class_token".into(),
                observation: Some(observation.into()),
                canonical_observation: None,
                selector_value: Some(value.clone()),
                reasons: vec![
                    "class_token_not_destination_matcher".into(),
                    format!("token={value}"),
                ],
            }
        }
        ResourceSelector::PathExact { .. }
        | ResourceSelector::PathPrefix { .. }
        | ResourceSelector::Identity { .. }
        | ResourceSelector::Tool { .. }
        | ResourceSelector::Effect { .. }
        | ResourceSelector::ProvenanceClass { .. } => MatchExplanation::no_match(
            selector.kind_name(),
            observation,
            "selector_not_applicable_to_network_destination",
        ),
    }
}

/// Match a filesystem path observation against path selectors.
pub fn match_path_selector(selector: &ResourceSelector, observation: &str) -> MatchExplanation {
    match selector {
        ResourceSelector::PathExact { value } => match_path_exact(value, observation),
        ResourceSelector::PathPrefix { value } => match_path_prefix(value, observation),
        ResourceSelector::UnixSocket { value } => match_unix_socket(value, observation),
        other => MatchExplanation::no_match(
            other.kind_name(),
            observation,
            "selector_not_applicable_to_path",
        ),
    }
}

/// Match a token observation (identity / tool / effect / class) by exact equality.
#[allow(dead_code)] // Used by future identity/tool/effect detectors (1.8 phase B/E).
pub fn match_token_selector(selector: &ResourceSelector, observation: &str) -> MatchExplanation {
    let (kind, value) = match selector {
        ResourceSelector::Identity { value } => ("identity", value.as_str()),
        ResourceSelector::Tool { value } => ("tool", value.as_str()),
        ResourceSelector::Effect { value } => ("effect", value.as_str()),
        ResourceSelector::ProvenanceClass { value } => ("provenance_class", value.as_str()),
        ResourceSelector::ClassToken { value } => ("class_token", value.as_str()),
        other => {
            return MatchExplanation::no_match(
                other.kind_name(),
                observation,
                "selector_not_applicable_to_token",
            );
        }
    };
    if observation == value {
        MatchExplanation::allow(kind, observation, observation, value, "exact_token_match")
    } else {
        MatchExplanation::no_match(kind, observation, "token_mismatch")
    }
}

/// True when any network entry allows the destination (typed match only).
///
/// Class-token entries do not authorize specific hosts. Unknown observations
/// never count as allowed.
pub fn network_entries_allow(entries: &[ResourceEntry], destination: &str) -> MatchExplanation {
    let mut first_unknown: Option<MatchExplanation> = None;
    let mut last_no = MatchExplanation::no_match("network", destination, "no_matching_selector");
    for entry in entries {
        let sel = entry.as_selector();
        // Class tokens: only allow when destination itself is that class token string.
        if let ResourceSelector::ClassToken { value } = &sel {
            if destination == value.as_str() {
                return MatchExplanation::allow(
                    "class_token",
                    destination,
                    destination,
                    value,
                    "destination_is_class_token",
                );
            }
            continue;
        }
        let expl = match_network_selector(&sel, destination);
        match expl.decision {
            MatchDecision::Allow => return expl,
            MatchDecision::Unknown => {
                if first_unknown.is_none() {
                    first_unknown = Some(expl);
                }
            }
            MatchDecision::NoMatch => last_no = expl,
        }
    }
    // Prefer reporting unknown when every attempt failed to parse the observation
    // against applicable selectors — but only if we saw an applicable selector.
    first_unknown.unwrap_or(last_no)
}

fn match_domain_exact(value: &str, observation: &str) -> MatchExplanation {
    let host = match observation_host(observation) {
        NormalizeOutcome::Ok(h) => h,
        NormalizeOutcome::Unknown { reason } => {
            return MatchExplanation::unknown("domain_exact", observation, reason);
        }
    };
    match host_matches_exact(&host, value) {
        NormalizeOutcome::Ok(true) => MatchExplanation::allow(
            "domain_exact",
            observation,
            host.as_str(),
            value,
            "canonical_host_equal",
        ),
        NormalizeOutcome::Ok(false) => MatchExplanation {
            decision: MatchDecision::NoMatch,
            selector_kind: "domain_exact".into(),
            observation: Some(observation.into()),
            canonical_observation: Some(host.0),
            selector_value: Some(value.into()),
            reasons: vec!["host_not_equal".into()],
        },
        NormalizeOutcome::Unknown { reason } => {
            MatchExplanation::unknown("domain_exact", observation, reason)
        }
    }
}

fn match_domain_suffix(value: &str, observation: &str) -> MatchExplanation {
    let host = match observation_host(observation) {
        NormalizeOutcome::Ok(h) => h,
        NormalizeOutcome::Unknown { reason } => {
            return MatchExplanation::unknown("domain_suffix", observation, reason);
        }
    };
    match host_matches_suffix(&host, value) {
        NormalizeOutcome::Ok(true) => MatchExplanation::allow(
            "domain_suffix",
            observation,
            host.as_str(),
            value,
            "label_boundary_suffix_match",
        ),
        NormalizeOutcome::Ok(false) => MatchExplanation {
            decision: MatchDecision::NoMatch,
            selector_kind: "domain_suffix".into(),
            observation: Some(observation.into()),
            canonical_observation: Some(host.0),
            selector_value: Some(value.into()),
            reasons: vec!["suffix_not_matched".into()],
        },
        NormalizeOutcome::Unknown { reason } => {
            MatchExplanation::unknown("domain_suffix", observation, reason)
        }
    }
}

fn match_cidr(value: &str, observation: &str) -> MatchExplanation {
    let net = match normalize_cidr(value) {
        NormalizeOutcome::Ok(n) => n,
        NormalizeOutcome::Unknown { reason } => {
            return MatchExplanation::unknown("cidr", observation, format!("selector_{reason}"));
        }
    };
    let ip = match observation_ip(observation) {
        NormalizeOutcome::Ok(ip) => ip,
        NormalizeOutcome::Unknown { reason } => {
            // Hostnames are NoMatch for CIDR, not Unknown (observation may be fine for domain rules).
            if reason == "malformed_ip"
                || reason == "ip_literal_not_hostname"
                || matches!(observation_host(observation), NormalizeOutcome::Ok(_))
            {
                return MatchExplanation {
                    decision: MatchDecision::NoMatch,
                    selector_kind: "cidr".into(),
                    observation: Some(observation.into()),
                    canonical_observation: None,
                    selector_value: Some(value.into()),
                    reasons: vec!["observation_not_ip".into()],
                };
            }
            return MatchExplanation::unknown("cidr", observation, reason);
        }
    };
    if ip_in_cidr(ip, net) {
        MatchExplanation::allow(
            "cidr",
            observation,
            ip.to_string(),
            value,
            "ip_in_cidr",
        )
    } else {
        MatchExplanation {
            decision: MatchDecision::NoMatch,
            selector_kind: "cidr".into(),
            observation: Some(observation.into()),
            canonical_observation: Some(ip.to_string()),
            selector_value: Some(value.into()),
            reasons: vec!["ip_outside_cidr".into()],
        }
    }
}

fn match_ip_exact(value: &str, observation: &str) -> MatchExplanation {
    let want = match normalize_ip(value) {
        NormalizeOutcome::Ok(ip) => ip,
        NormalizeOutcome::Unknown { reason } => {
            return MatchExplanation::unknown("ip_exact", observation, format!("selector_{reason}"));
        }
    };
    let got = match observation_ip(observation) {
        NormalizeOutcome::Ok(ip) => ip,
        NormalizeOutcome::Unknown { reason } => {
            if matches!(observation_host(observation), NormalizeOutcome::Ok(_)) {
                return MatchExplanation::no_match("ip_exact", observation, "observation_not_ip");
            }
            return MatchExplanation::unknown("ip_exact", observation, reason);
        }
    };
    if got == want {
        MatchExplanation::allow(
            "ip_exact",
            observation,
            got.to_string(),
            value,
            "canonical_ip_equal",
        )
    } else {
        MatchExplanation {
            decision: MatchDecision::NoMatch,
            selector_kind: "ip_exact".into(),
            observation: Some(observation.into()),
            canonical_observation: Some(got.to_string()),
            selector_value: Some(value.into()),
            reasons: vec!["ip_not_equal".into()],
        }
    }
}

fn match_url_prefix(
    scheme: Option<&str>,
    host: &str,
    path: Option<&str>,
    observation: &str,
) -> MatchExplanation {
    let obs = match normalize_url(observation) {
        NormalizeOutcome::Ok(u) => u,
        NormalizeOutcome::Unknown { reason } => {
            return MatchExplanation::unknown("url_prefix", observation, reason);
        }
    };
    if let Some(want_scheme) = scheme {
        if obs.scheme != want_scheme.to_ascii_lowercase() {
            return MatchExplanation {
                decision: MatchDecision::NoMatch,
                selector_kind: "url_prefix".into(),
                observation: Some(observation.into()),
                canonical_observation: Some(format!("{}://{}{}", obs.scheme, obs.host.as_str(), obs.path)),
                selector_value: Some(format!("{want_scheme}://{host}")),
                reasons: vec!["scheme_mismatch".into()],
            };
        }
    }
    // Host may be domain or IP.
    let host_ok = match normalize_ip(host) {
        NormalizeOutcome::Ok(want_ip) => {
            normalize_ip(obs.host.as_str()).as_ok().copied() == Some(want_ip)
        }
        NormalizeOutcome::Unknown { .. } => {
            matches!(
                host_matches_exact(&obs.host, host),
                NormalizeOutcome::Ok(true)
            )
        }
    };
    if !host_ok {
        return MatchExplanation {
            decision: MatchDecision::NoMatch,
            selector_kind: "url_prefix".into(),
            observation: Some(observation.into()),
            canonical_observation: Some(obs.host.as_str().into()),
            selector_value: Some(host.into()),
            reasons: vec!["host_mismatch".into()],
        };
    }
    if let Some(prefix) = path {
        let want_path = match normalize_path(prefix) {
            NormalizeOutcome::Ok(p) => p,
            NormalizeOutcome::Unknown { reason } => {
                return MatchExplanation::unknown(
                    "url_prefix",
                    observation,
                    format!("selector_path_{reason}"),
                );
            }
        };
        let want_path = if want_path.starts_with('/') {
            want_path
        } else {
            format!("/{want_path}")
        };
        let obs_path = &obs.path;
        let path_ok = obs_path == &want_path
            || obs_path.starts_with(&format!(
                "{}/",
                want_path.trim_end_matches('/')
            ))
            || (want_path.ends_with('/') && obs_path.starts_with(&want_path));
        if !path_ok {
            return MatchExplanation {
                decision: MatchDecision::NoMatch,
                selector_kind: "url_prefix".into(),
                observation: Some(observation.into()),
                canonical_observation: Some(obs.path.clone()),
                selector_value: Some(want_path),
                reasons: vec!["path_prefix_mismatch".into()],
            };
        }
    }
    MatchExplanation::allow(
        "url_prefix",
        observation,
        format!("{}://{}{}", obs.scheme, obs.host.as_str(), obs.path),
        format!(
            "{}://{}{}",
            scheme.unwrap_or("*"),
            host,
            path.unwrap_or("")
        ),
        "url_prefix_match",
    )
}

fn match_port(want: u16, observation: &str) -> MatchExplanation {
    match normalize_port(observation) {
        NormalizeOutcome::Ok(p) if p == want => {
            MatchExplanation::allow("port", observation, p.to_string(), want.to_string(), "port_equal")
        }
        NormalizeOutcome::Ok(p) => MatchExplanation {
            decision: MatchDecision::NoMatch,
            selector_kind: "port".into(),
            observation: Some(observation.into()),
            canonical_observation: Some(p.to_string()),
            selector_value: Some(want.to_string()),
            reasons: vec!["port_mismatch".into()],
        },
        NormalizeOutcome::Unknown { reason } => {
            MatchExplanation::unknown("port", observation, reason)
        }
    }
}

fn match_unix_socket(value: &str, observation: &str) -> MatchExplanation {
    let want = match normalize_path(value) {
        NormalizeOutcome::Ok(p) => p,
        NormalizeOutcome::Unknown { reason } => {
            return MatchExplanation::unknown("unix_socket", observation, format!("selector_{reason}"));
        }
    };
    let got = match normalize_path(observation) {
        NormalizeOutcome::Ok(p) => p,
        NormalizeOutcome::Unknown { reason } => {
            return MatchExplanation::unknown("unix_socket", observation, reason);
        }
    };
    if got == want {
        MatchExplanation::allow(
            "unix_socket",
            observation,
            got,
            want,
            "unix_socket_path_equal",
        )
    } else {
        MatchExplanation {
            decision: MatchDecision::NoMatch,
            selector_kind: "unix_socket".into(),
            observation: Some(observation.into()),
            canonical_observation: Some(got),
            selector_value: Some(want),
            reasons: vec!["unix_socket_mismatch".into()],
        }
    }
}

fn match_path_exact(value: &str, observation: &str) -> MatchExplanation {
    let want = match normalize_path(value) {
        NormalizeOutcome::Ok(p) => p,
        NormalizeOutcome::Unknown { reason } => {
            return MatchExplanation::unknown("path_exact", observation, format!("selector_{reason}"));
        }
    };
    let got = match normalize_path(observation) {
        NormalizeOutcome::Ok(p) => p,
        NormalizeOutcome::Unknown { reason } => {
            return MatchExplanation::unknown("path_exact", observation, reason);
        }
    };
    if got == want {
        MatchExplanation::allow("path_exact", observation, got, want, "path_equal")
    } else {
        MatchExplanation {
            decision: MatchDecision::NoMatch,
            selector_kind: "path_exact".into(),
            observation: Some(observation.into()),
            canonical_observation: Some(got),
            selector_value: Some(want),
            reasons: vec!["path_not_equal".into()],
        }
    }
}

fn match_path_prefix(value: &str, observation: &str) -> MatchExplanation {
    let want = match normalize_path(value) {
        NormalizeOutcome::Ok(p) => p,
        NormalizeOutcome::Unknown { reason } => {
            return MatchExplanation::unknown(
                "path_prefix",
                observation,
                format!("selector_{reason}"),
            );
        }
    };
    let got = match normalize_path(observation) {
        NormalizeOutcome::Ok(p) => p,
        NormalizeOutcome::Unknown { reason } => {
            return MatchExplanation::unknown("path_prefix", observation, reason);
        }
    };
    let want_trim = want.trim_end_matches('/');
    let ok = got == want
        || got == want_trim
        || got.starts_with(&format!("{want_trim}/"));
    if ok {
        MatchExplanation::allow("path_prefix", observation, got, want, "path_prefix_match")
    } else {
        MatchExplanation {
            decision: MatchDecision::NoMatch,
            selector_kind: "path_prefix".into(),
            observation: Some(observation.into()),
            canonical_observation: Some(got),
            selector_value: Some(want),
            reasons: vec!["path_prefix_mismatch".into()],
        }
    }
}

/// Whether a destination is clearly a public URL/host (heuristic observation class).
///
/// Used only as an *observation* signal, not as authorization.
pub fn observation_looks_public_network(dest: &str) -> bool {
    let d = dest.trim();
    if d == "public_network" {
        return true;
    }
    if d.starts_with("http://") || d.starts_with("https://") {
        // Loopback / private hosts are not "public" observations.
        if let NormalizeOutcome::Ok(host) = observation_host(d) {
            return !host_is_private_or_local(&host);
        }
        return true;
    }
    if let NormalizeOutcome::Ok(ip) = observation_ip(d) {
        return !ip_is_private_or_local(ip);
    }
    if let NormalizeOutcome::Ok(host) = observation_host(d) {
        let h = host.as_str();
        if h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local") {
            return false;
        }
        // Multi-label public-looking DNS names.
        return h.contains('.') && !host_is_private_or_local(&host);
    }
    false
}

fn host_is_private_or_local(host: &CanonicalHost) -> bool {
    let h = host.as_str();
    if h == "localhost" || h.ends_with(".localhost") || h.ends_with(".local") {
        return true;
    }
    if let Ok(ip) = h.parse::<IpAddr>() {
        return ip_is_private_or_local(ip);
    }
    false
}

fn ip_is_private_or_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.octets()[0] == 100 && (v4.octets()[1] & 0b1100_0000) == 64 // 100.64/10
        }
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xfe00) == 0xfc00,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_com_does_not_allow_attacker() {
        let sel = ResourceSelector::DomainExact {
            value: "example.com".into(),
        };
        let m = match_network_selector(&sel, "attacker-example.com");
        assert_eq!(m.decision, MatchDecision::NoMatch);
        let m2 = match_network_selector(&sel, "https://attacker-example.com/x");
        assert_eq!(m2.decision, MatchDecision::NoMatch);
        let m3 = match_network_selector(&sel, "https://example.com/x");
        assert!(m3.is_allow());
    }

    #[test]
    fn suffix_label_boundaries() {
        let sel = ResourceSelector::DomainSuffix {
            value: ".corp.example".into(),
        };
        assert!(match_network_selector(&sel, "a.corp.example").is_allow());
        assert!(match_network_selector(&sel, "corp.example").is_allow());
        assert_eq!(
            match_network_selector(&sel, "notcorp.example").decision,
            MatchDecision::NoMatch
        );
        assert_eq!(
            match_network_selector(&sel, "evil.corp.example.attacker.com").decision,
            MatchDecision::NoMatch
        );
    }

    #[test]
    fn cidr_v4_v6() {
        let sel = ResourceSelector::Cidr {
            value: "10.0.0.0/8".into(),
        };
        assert!(match_network_selector(&sel, "10.1.2.3").is_allow());
        assert_eq!(
            match_network_selector(&sel, "11.0.0.1").decision,
            MatchDecision::NoMatch
        );
        let sel6 = ResourceSelector::Cidr {
            value: "2001:db8::/32".into(),
        };
        assert!(match_network_selector(&sel6, "2001:db8::abcd").is_allow());
    }

    #[test]
    fn equivalent_canonical_forms() {
        let sel = ResourceSelector::DomainExact {
            value: "packages.internal".into(),
        };
        assert!(match_network_selector(&sel, "Packages.Internal.").is_allow());
        assert!(match_network_selector(&sel, "https://packages.internal/v1").is_allow());
    }

    #[test]
    fn malformed_observation_unknown_never_allow() {
        let sel = ResourceSelector::DomainExact {
            value: "example.com".into(),
        };
        let m = match_network_selector(&sel, " ");
        assert_eq!(m.decision, MatchDecision::Unknown);
        assert!(!m.is_allow());
    }

    #[test]
    fn legacy_string_no_substring() {
        let entries = vec![ResourceEntry::Legacy("example.com".into())];
        let expl = network_entries_allow(&entries, "attacker-example.com");
        assert!(!expl.is_allow());
        let expl2 = network_entries_allow(&entries, "https://example.com/");
        assert!(expl2.is_allow());
    }

    #[test]
    fn typed_json_roundtrip() {
        let sel = ResourceSelector::UrlPrefix {
            scheme: Some("https".into()),
            host: "api.example.com".into(),
            path: Some("/v1/".into()),
        };
        let entry = ResourceEntry::Typed(sel.clone());
        let json = serde_json::to_string(&entry).unwrap();
        let back: ResourceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_selector(), sel);
        assert!(match_network_selector(&sel, "https://api.example.com/v1/x").is_allow());
        assert_eq!(
            match_network_selector(&sel, "https://api.example.com/v2/x").decision,
            MatchDecision::NoMatch
        );
    }

    #[test]
    fn path_prefix_match() {
        let sel = ResourceSelector::PathPrefix {
            value: "/home/user/.ssh".into(),
        };
        assert!(match_path_selector(&sel, "/home/user/.ssh/id_rsa").is_allow());
        assert_eq!(
            match_path_selector(&sel, "/tmp/doc mentions .ssh here").decision,
            MatchDecision::NoMatch
        );
    }
}
