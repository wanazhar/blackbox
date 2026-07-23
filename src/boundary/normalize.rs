//! Canonical observation normalization for typed policy matching (1.8).
//!
//! Malformed inputs never become silently allowed — callers treat
//! [`NormalizeOutcome::Unknown`] as non-matching for authorization.

#![allow(missing_docs)]

use std::net::IpAddr;
use std::path::{Component, Path};
use std::str::FromStr;

use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use url::Url;

/// Result of normalizing an observation for policy comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NormalizeOutcome<T> {
    /// Successfully canonicalized value.
    Ok(T),
    /// Input was empty, malformed, or ambiguous; never treat as allowed.
    Unknown { reason: String },
}

impl<T> NormalizeOutcome<T> {
    /// Borrow the canonical value when normalization succeeded.
    pub fn as_ok(&self) -> Option<&T> {
        match self {
            Self::Ok(v) => Some(v),
            Self::Unknown { .. } => None,
        }
    }

    /// Map a successful value.
    pub fn map_ok<U>(self, f: impl FnOnce(T) -> U) -> NormalizeOutcome<U> {
        match self {
            Self::Ok(v) => NormalizeOutcome::Ok(f(v)),
            Self::Unknown { reason } => NormalizeOutcome::Unknown { reason },
        }
    }
}

/// Canonical hostname (ASCII lower-case, no trailing dot, IDNA A-label form).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CanonicalHost(pub String);

impl CanonicalHost {
    /// Borrow the host string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical URL components used by prefix / exact matchers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanonicalUrl {
    pub scheme: String,
    pub host: CanonicalHost,
    /// Port when explicit or default for the scheme.
    pub port: Option<u16>,
    /// Path with empty segments collapsed; always starts with `/` when non-empty host form.
    pub path: String,
    /// True when userinfo was present (stripped from comparison form).
    pub had_userinfo: bool,
}

/// Normalize a DNS hostname: trim, strip trailing dots, lowercase, IDNA.
///
/// IP literals are rejected here — use [`normalize_ip`].
pub fn normalize_host(raw: &str) -> NormalizeOutcome<CanonicalHost> {
    let s = raw.trim();
    if s.is_empty() {
        return NormalizeOutcome::Unknown {
            reason: "empty_host".into(),
        };
    }
    // Strip one or more trailing dots (FQDN form).
    let s = s.trim_end_matches('.');
    if s.is_empty() {
        return NormalizeOutcome::Unknown {
            reason: "empty_host_after_trailing_dot".into(),
        };
    }
    // Bracketed IPv6 is not a hostname.
    if s.starts_with('[') {
        return NormalizeOutcome::Unknown {
            reason: "ip_literal_not_hostname".into(),
        };
    }
    // Bare IPv4/IPv6 should not go through domain matchers.
    if IpAddr::from_str(s).is_ok() {
        return NormalizeOutcome::Unknown {
            reason: "ip_literal_not_hostname".into(),
        };
    }
    // Reject obvious control / whitespace inside labels.
    if s.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return NormalizeOutcome::Unknown {
            reason: "host_contains_whitespace_or_control".into(),
        };
    }
    // IDNA: encode Unicode → ASCII A-labels; also validates labels.
    let ascii = match idna_to_ascii(s) {
        Ok(a) => a,
        Err(reason) => return NormalizeOutcome::Unknown { reason },
    };
    if ascii.is_empty() || ascii.len() > 253 {
        return NormalizeOutcome::Unknown {
            reason: "host_length_invalid".into(),
        };
    }
    for label in ascii.split('.') {
        if label.is_empty() || label.len() > 63 {
            return NormalizeOutcome::Unknown {
                reason: "host_label_invalid".into(),
            };
        }
    }
    NormalizeOutcome::Ok(CanonicalHost(ascii))
}

fn idna_to_ascii(s: &str) -> Result<String, String> {
    // Use the `url` crate's IDNA via a synthetic URL when non-ASCII is present;
    // for pure ASCII, lowercase is enough and avoids dependency on idna alone.
    if s.is_ascii() {
        return Ok(s.to_ascii_lowercase());
    }
    let synthetic = format!("https://{s}/");
    let parsed = Url::parse(&synthetic).map_err(|e| format!("idna_parse_failed:{e}"))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| "idna_no_host".to_string())?
        .to_string();
    Ok(host.to_ascii_lowercase())
}

/// Normalize an IPv4 or IPv6 address string (no brackets required for v6).
pub fn normalize_ip(raw: &str) -> NormalizeOutcome<IpAddr> {
    let s = raw.trim();
    let s = s
        .strip_prefix('[')
        .and_then(|x| x.strip_suffix(']'))
        .unwrap_or(s);
    if s.is_empty() {
        return NormalizeOutcome::Unknown {
            reason: "empty_ip".into(),
        };
    }
    match IpAddr::from_str(s) {
        Ok(ip) => NormalizeOutcome::Ok(canonicalize_ip(ip)),
        Err(_) => NormalizeOutcome::Unknown {
            reason: "malformed_ip".into(),
        },
    }
}

fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        // Map IPv4-mapped IPv6 to IPv4 for consistent comparison.
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                IpAddr::V6(v6)
            }
        }
        other => other,
    }
}

/// Parse a CIDR (`10.0.0.0/8`, `2001:db8::/32`).
pub fn normalize_cidr(raw: &str) -> NormalizeOutcome<IpNet> {
    let s = raw.trim();
    if s.is_empty() {
        return NormalizeOutcome::Unknown {
            reason: "empty_cidr".into(),
        };
    }
    match IpNet::from_str(s) {
        Ok(net) => NormalizeOutcome::Ok(net),
        Err(_) => NormalizeOutcome::Unknown {
            reason: "malformed_cidr".into(),
        },
    }
}

/// Normalize a URL for prefix matching: scheme lower, host canonical, path collapsed.
pub fn normalize_url(raw: &str) -> NormalizeOutcome<CanonicalUrl> {
    let s = raw.trim();
    if s.is_empty() {
        return NormalizeOutcome::Unknown {
            reason: "empty_url".into(),
        };
    }
    let parsed = match Url::parse(s) {
        Ok(u) => u,
        Err(_) => {
            // Bare host or host/path without scheme — not a URL for url_prefix.
            return NormalizeOutcome::Unknown {
                reason: "malformed_url".into(),
            };
        }
    };
    let scheme = parsed.scheme().to_ascii_lowercase();
    if scheme.is_empty() {
        return NormalizeOutcome::Unknown {
            reason: "missing_scheme".into(),
        };
    }
    let host_raw = match parsed.host_str() {
        Some(h) => h,
        None => {
            return NormalizeOutcome::Unknown {
                reason: "url_missing_host".into(),
            };
        }
    };
    // Prefer IP form when host is an IP.
    let host = if let Ok(ip) = IpAddr::from_str(host_raw) {
        CanonicalHost(canonicalize_ip(ip).to_string())
    } else {
        match normalize_host(host_raw) {
            NormalizeOutcome::Ok(h) => h,
            NormalizeOutcome::Unknown { reason } => {
                return NormalizeOutcome::Unknown { reason };
            }
        }
    };
    let port = parsed.port_or_known_default();
    let path = normalize_url_path(parsed.path());
    let had_userinfo = !parsed.username().is_empty() || parsed.password().is_some();
    NormalizeOutcome::Ok(CanonicalUrl {
        scheme,
        host,
        port,
        path,
        had_userinfo,
    })
}

fn normalize_url_path(path: &str) -> String {
    if path.is_empty() {
        return "/".into();
    }
    let mut parts: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        if seg.is_empty() || seg == "." {
            continue;
        }
        if seg == ".." {
            parts.pop();
            continue;
        }
        parts.push(seg);
    }
    if parts.is_empty() {
        "/".into()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Normalize a filesystem path for exact/prefix matching (no symlink resolution).
///
/// Collapses `.` / `..` components, strips redundant separators. Relative paths
/// stay relative; absolute paths stay absolute.
pub fn normalize_path(raw: &str) -> NormalizeOutcome<String> {
    let s = raw.trim();
    if s.is_empty() {
        return NormalizeOutcome::Unknown {
            reason: "empty_path".into(),
        };
    }
    // Reject NULs.
    if s.contains('\0') {
        return NormalizeOutcome::Unknown {
            reason: "path_contains_nul".into(),
        };
    }
    let path = Path::new(s);
    let mut out = std::path::PathBuf::new();
    let mut absolute = false;
    for (i, c) in path.components().enumerate() {
        match c {
            Component::Prefix(p) => {
                out.push(p.as_os_str());
            }
            Component::RootDir => {
                absolute = true;
                out.push(std::path::MAIN_SEPARATOR.to_string());
            }
            Component::CurDir => {
                if i == 0 {
                    out.push(".");
                }
            }
            Component::ParentDir => {
                if !out.pop() {
                    if absolute {
                        // Above root is invalid / unknown.
                        return NormalizeOutcome::Unknown {
                            reason: "path_escapes_root".into(),
                        };
                    }
                    out.push("..");
                }
            }
            Component::Normal(p) => out.push(p),
        }
    }
    let s = out.to_string_lossy().replace('\\', "/");
    // Ensure absolute paths start with /
    let s = if absolute && !s.starts_with('/') {
        format!("/{s}")
    } else {
        s
    };
    if s.is_empty() {
        NormalizeOutcome::Ok(if absolute { "/".into() } else { ".".into() })
    } else {
        NormalizeOutcome::Ok(s)
    }
}

/// Extract a host (or IP) observation from a free-form destination string.
///
/// Accepts bare hosts, `host:port`, URLs, and bracketed IPv6.
pub fn observation_host(raw: &str) -> NormalizeOutcome<CanonicalHost> {
    let s = raw.trim();
    if s.is_empty() {
        return NormalizeOutcome::Unknown {
            reason: "empty_destination".into(),
        };
    }
    // Full URL?
    if s.contains("://") {
        return match normalize_url(s) {
            NormalizeOutcome::Ok(u) => NormalizeOutcome::Ok(u.host),
            NormalizeOutcome::Unknown { reason } => NormalizeOutcome::Unknown { reason },
        };
    }
    // Bracketed IPv6 with optional port: [2001:db8::1]:443
    if s.starts_with('[') {
        if let Some(end) = s.find(']') {
            let inner = &s[1..end];
            return match normalize_ip(inner) {
                NormalizeOutcome::Ok(ip) => NormalizeOutcome::Ok(CanonicalHost(ip.to_string())),
                NormalizeOutcome::Unknown { reason } => NormalizeOutcome::Unknown { reason },
            };
        }
        return NormalizeOutcome::Unknown {
            reason: "malformed_bracketed_host".into(),
        };
    }
    // host:port — only split on last colon when the left side is not IPv6-looking
    // (IPv6 has multiple colons). For simple host:port use first colon carefully.
    let host_part = if s.matches(':').count() == 1 {
        s.split_once(':').map(|(h, _)| h).unwrap_or(s)
    } else {
        s
    };
    // Prefer IP if it parses.
    if let NormalizeOutcome::Ok(ip) = normalize_ip(host_part) {
        return NormalizeOutcome::Ok(CanonicalHost(ip.to_string()));
    }
    normalize_host(host_part)
}

/// Extract an IP observation from a free-form destination (if it is an IP).
pub fn observation_ip(raw: &str) -> NormalizeOutcome<IpAddr> {
    match observation_host(raw) {
        NormalizeOutcome::Ok(h) => normalize_ip(h.as_str()),
        NormalizeOutcome::Unknown { reason } => NormalizeOutcome::Unknown { reason },
    }
}

/// Whether `ip` is contained in `net` (family must match).
pub fn ip_in_cidr(ip: IpAddr, net: IpNet) -> bool {
    net.contains(&ip)
}

/// Domain-suffix check with label boundaries.
///
/// `suffix` may be written with or without a leading dot. Matching requires a
/// full label boundary: `example.com` matches `a.example.com` but not
/// `attacker-example.com`.
pub fn host_matches_suffix(host: &CanonicalHost, suffix_raw: &str) -> NormalizeOutcome<bool> {
    let suffix = suffix_raw.trim().trim_start_matches('.');
    let suffix_host = match normalize_host(suffix) {
        NormalizeOutcome::Ok(h) => h,
        NormalizeOutcome::Unknown { reason } => return NormalizeOutcome::Unknown { reason },
    };
    let h = host.as_str();
    let s = suffix_host.as_str();
    if h == s {
        return NormalizeOutcome::Ok(true);
    }
    let needle = format!(".{s}");
    NormalizeOutcome::Ok(h.ends_with(&needle))
}

/// Domain exact match after canonicalization.
pub fn host_matches_exact(host: &CanonicalHost, exact_raw: &str) -> NormalizeOutcome<bool> {
    match normalize_host(exact_raw) {
        NormalizeOutcome::Ok(want) => NormalizeOutcome::Ok(host.as_str() == want.as_str()),
        // Exact domain rules never match IPs silently.
        NormalizeOutcome::Unknown { reason } => NormalizeOutcome::Unknown { reason },
    }
}

/// Parse a port observation (`443`, `:443`, `host:443`).
pub fn normalize_port(raw: &str) -> NormalizeOutcome<u16> {
    let s = raw.trim().trim_start_matches(':');
    if s.is_empty() {
        return NormalizeOutcome::Unknown {
            reason: "empty_port".into(),
        };
    }
    // host:port form
    let port_str = if s.contains(':') && !s.starts_with('[') {
        s.rsplit_once(':').map(|(_, p)| p).unwrap_or(s)
    } else if let Some(end) = s.rfind("]:") {
        &s[end + 2..]
    } else {
        s
    };
    match port_str.parse::<u16>() {
        Ok(0) => NormalizeOutcome::Unknown {
            reason: "port_zero".into(),
        },
        Ok(p) => NormalizeOutcome::Ok(p),
        Err(_) => NormalizeOutcome::Unknown {
            reason: "malformed_port".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn host_trailing_dot_and_case() {
        let a = normalize_host("Example.COM.").as_ok().unwrap().clone();
        let b = normalize_host("example.com").as_ok().unwrap().clone();
        assert_eq!(a, b);
    }

    #[test]
    fn suffix_respects_label_boundary() {
        let host = normalize_host("attacker-example.com")
            .as_ok()
            .unwrap()
            .clone();
        assert_eq!(
            host_matches_suffix(&host, "example.com").as_ok().copied(),
            Some(false)
        );
        let host2 = normalize_host("a.example.com").as_ok().unwrap().clone();
        assert_eq!(
            host_matches_suffix(&host2, ".example.com").as_ok().copied(),
            Some(true)
        );
        assert_eq!(
            host_matches_exact(&host, "example.com").as_ok().copied(),
            Some(false)
        );
    }

    #[test]
    fn exact_does_not_allow_suffix_attacker() {
        let host = normalize_host("attacker-example.com")
            .as_ok()
            .unwrap()
            .clone();
        assert_eq!(
            host_matches_exact(&host, "example.com").as_ok().copied(),
            Some(false)
        );
    }

    #[test]
    fn cidr_v4_and_v6() {
        let net = *normalize_cidr("10.0.0.0/8").as_ok().unwrap();
        let ip = *normalize_ip("10.1.2.3").as_ok().unwrap();
        assert!(ip_in_cidr(ip, net));
        let outside = *normalize_ip("11.0.0.1").as_ok().unwrap();
        assert!(!ip_in_cidr(outside, net));

        let net6 = *normalize_cidr("2001:db8::/32").as_ok().unwrap();
        let ip6 = *normalize_ip("2001:db8::1").as_ok().unwrap();
        assert!(ip_in_cidr(ip6, net6));
    }

    #[test]
    fn malformed_is_unknown() {
        assert!(matches!(
            normalize_host(""),
            NormalizeOutcome::Unknown { .. }
        ));
        assert!(matches!(
            normalize_cidr("not-a-cidr"),
            NormalizeOutcome::Unknown { .. }
        ));
        assert!(matches!(
            normalize_url("not a url"),
            NormalizeOutcome::Unknown { .. }
        ));
    }

    #[test]
    fn url_strips_userinfo_and_normalizes() {
        let u = normalize_url("HTTPS://User:Pass@API.Example.COM./v1//x/../y");
        let u = u.as_ok().unwrap();
        assert_eq!(u.scheme, "https");
        assert_eq!(u.host.as_str(), "api.example.com");
        assert!(u.had_userinfo);
        assert_eq!(u.path, "/v1/y");
    }

    #[test]
    fn observation_host_from_url_and_port() {
        let h = observation_host("https://Packages.Internal/foo");
        let h = h.as_ok().unwrap();
        assert_eq!(h.as_str(), "packages.internal");
        let h2 = observation_host("packages.internal:443");
        let h2 = h2.as_ok().unwrap();
        assert_eq!(h2.as_str(), "packages.internal");
    }

    #[test]
    fn path_collapse() {
        let p = normalize_path("/home/./user/../user/.ssh/id_rsa");
        let p = p.as_ok().unwrap();
        assert_eq!(p, "/home/user/.ssh/id_rsa");
    }

    #[test]
    fn ipv4_mapped_canonical() {
        let ip = *normalize_ip("::ffff:10.0.0.1").as_ok().unwrap();
        assert_eq!(ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
    }
}
