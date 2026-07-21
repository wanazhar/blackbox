//! Minimal JUnit XML parser for verification receipts.

use crate::verification::receipt::{
    VerificationConfidence, VerificationReceipt, VerificationStatus, VerifierType,
};

#[derive(Debug, Clone, Default)]
/// `JunitSummary` value.
pub struct JunitSummary {
    /// Tests.
    pub tests: u64,
    /// Failures.
    pub failures: u64,
    /// Error messages.
    pub errors: u64,
    /// Skipped.
    pub skipped: u64,
}

/// Parse a subset of JUnit XML (testsuite/testsuites attributes).
///
/// # Examples
///
/// ```
/// # use blackbox as _;
/// // `parse_junit_xml` — see module docs for full workflow.
/// ```
pub fn parse_junit_xml(xml: &str) -> anyhow::Result<JunitSummary> {
    let mut summary = JunitSummary::default();
    // Attribute extraction without a full XML dependency.
    for tag in ["testsuites", "testsuite"] {
        if let Some(attrs) = open_tag_attrs(xml, tag) {
            if let Some(n) = attr_u64(attrs, "tests") {
                summary.tests = summary.tests.max(n);
            }
            if let Some(n) = attr_u64(attrs, "failures") {
                summary.failures = summary.failures.saturating_add(n);
            }
            if let Some(n) = attr_u64(attrs, "errors") {
                summary.errors = summary.errors.saturating_add(n);
            }
            if let Some(n) = attr_u64(attrs, "skipped") {
                summary.skipped = summary.skipped.saturating_add(n);
            }
        }
    }
    if summary.tests == 0 {
        // Count testcase elements as fallback.
        summary.tests = xml.matches("<testcase").count() as u64;
        summary.failures = xml.matches("<failure").count() as u64;
        summary.errors = xml.matches("<error").count() as u64;
        summary.skipped = xml.matches("<skipped").count() as u64;
    }
    Ok(summary)
}

/// Receipt from junit.
///
/// # Examples
///
/// ```no_run
/// # use blackbox as _;
/// // `receipt_from_junit` — see module docs for full workflow.
/// ```
pub fn receipt_from_junit(
    run_id: &str,
    summary: &JunitSummary,
    source_path: &str,
) -> VerificationReceipt {
    let failed = summary.failures.saturating_add(summary.errors);
    let passed = summary.tests.saturating_sub(failed).saturating_sub(summary.skipped);
    let status = if summary.tests == 0 {
        VerificationStatus::Inconclusive
    } else if failed == 0 {
        VerificationStatus::Passed
    } else if passed > 0 {
        VerificationStatus::PartiallyPassed
    } else {
        VerificationStatus::Failed
    };
    let mut r = VerificationReceipt::new(run_id, VerifierType::JunitXml);
    r.tests_total = Some(summary.tests);
    r.tests_passed = Some(passed);
    r.tests_failed = Some(failed);
    r.tests_skipped = Some(summary.skipped);
    r.status = status;
    r.confidence = VerificationConfidence::Confirmed;
    r.verified_scope = Some(source_path.into());
    r.summary = Some(format!(
        "junit: {} tests, {} failed, {} skipped",
        summary.tests, failed, summary.skipped
    ));
    r
}

fn open_tag_attrs<'a>(xml: &'a str, tag: &str) -> Option<&'a str> {
    let start = format!("<{tag}");
    let i = xml.find(&start)?;
    let rest = &xml[i + start.len()..];
    let end = rest.find('>')?;
    Some(&rest[..end])
}

fn attr_u64(attrs: &str, name: &str) -> Option<u64> {
    let pat = format!("{name}=\"");
    let i = attrs.find(&pat)?;
    let rest = &attrs[i + pat.len()..];
    let end = rest.find('"')?;
    rest[..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_suite() {
        let xml = r#"<?xml version="1.0"?>
        <testsuite name="t" tests="3" failures="1" errors="0" skipped="1">
          <testcase name="a"/><testcase name="b"><failure/></testcase><testcase name="c"><skipped/></testcase>
        </testsuite>"#;
        let s = parse_junit_xml(xml).unwrap();
        assert_eq!(s.tests, 3);
        assert_eq!(s.failures, 1);
        assert_eq!(s.skipped, 1);
    }
}
