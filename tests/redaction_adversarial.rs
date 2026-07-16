//! WS7 — Adversarial redaction assurance corpus.
//!
//! Fixtures use deliberately broken / non-live credentials. Secrets must die;
//! structural identifiers (SHA, blob keys, UUIDs) must never be scarred.
//!
//! Covers chunk-boundary splits, export/scrub parity, and common secret shapes.

use blackbox::redaction::export::ExportRedactor;
use blackbox::redaction::scanner::SecretScanner;
use blackbox::redaction::stream::StreamRedactor;
use blackbox::redaction::RedactionConfig;
use serde_json::json;

fn scanner() -> SecretScanner {
    SecretScanner::new(RedactionConfig::default())
}

fn export_redactor() -> ExportRedactor {
    ExportRedactor::new(RedactionConfig::default())
}

/// Non-live adversarial secret samples (broken / example forms only).
fn adversarial_secrets() -> Vec<(&'static str, &'static str)> {
    vec![
        // Environment / config
        ("env_openai", "OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz012345"),
        ("env_anthropic", "ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz"),
        ("env_aws_key", "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"),
        (
            "env_aws_secret",
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        ),
        (
            "env_aws_session",
            "AWS_SESSION_TOKEN=FwoGZXIvYXdzEBYaDExampleSessionTokenValue1234567890",
        ),
        ("dotenv", "DATABASE_URL=postgres://user:s3cretpass@localhost:5432/db"),
        ("npmrc", "//registry.npmjs.org/:_authToken=npm_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"),
        ("pypirc", "password=pypi-AgEIcHlwaS5vcmcCJEXAMPLETOKENVALUE123456"),
        (
            "netrc",
            "machine api.github.com login user password ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12",
        ),
        // Tokens
        ("gh_classic", "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12"),
        (
            "gh_fine",
            "github_pat_11AAAAAAA0abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP",
        ),
        ("slack", concat!("xoxb-", "123456789012-ABCDEFGHabcdefghijklmnop")),
        ("stripe", concat!("sk_live_", "51AbCdEfGhIjKlMnOpQrStUvWxYz012345")),
        // Google API keys: AIza + exactly 35 [A-Za-z0-9_-] (non-live fixture)
        ("gemini", "AIzaSyA-abcdefghijklmnopqrstuvwxyz01234"),
        ("xai", "xai-abcdefghijklmnopqrstuvwxyz0123456789"),
        (
            "bearer",
            "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
        ),
        (
            "basic_auth_url",
            "https://admin:p@ssw0rd-secret@db.example.com:5432/app",
        ),
        (
            "signed_url",
            "https://s3.example.com/obj?X-Amz-Signature=abcdef0123456789deadbeef",
        ),
        (
            "cookie",
            "Set-Cookie: sessionid=abc123def456ghi789jkl012; Path=/",
        ),
        (
            "session",
            "PHPSESSID=abcdefghijklmnopqrstuvwx",
        ),
        // PEM header (material intentionally truncated / non-live)
        (
            "pem",
            "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAAExampleOnly\n-----END OPENSSH PRIVATE KEY-----",
        ),
        // JSON-escaped
        (
            "json_escaped",
            r#"{"token":"sk-abcdefghijklmnopqrstuvwxyz012345"}"#,
        ),
        // URL-encoded secret assignment still matches key= form when decoded-ish in text
        (
            "urlish",
            "callback?access_token=sk-abcdefghijklmnopqrstuvwxyz012345&state=1",
        ),
        // Unicode around secrets
        (
            "unicode",
            "密钥=sk-abcdefghijklmnopqrstuvwxyz012345 café",
        ),
        // Very long single-line payload with embedded secret
        (
            "long_line",
            "prefix_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa key=sk-abcdefghijklmnopqrstuvwxyz012345 suffix_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        ),
        ("hf_token", "hf_abcdefghijklmnopqrstuvwx"),
        (
            "sendgrid",
            "SG.abcdefghijklmnop.qrstuvwxyz0123456789ABCDEF",
        ),
        (
            "azure_key",
            "AccountKey=abcdefghijklmnopqrstuvwxyz0123456789+/==",
        ),
    ]
}

fn structural_ids() -> Vec<&'static str> {
    vec![
        "ea950d8180f520d808274579577db86bc6365a7a",
        "22c8e61f11fd0f02da754f5b2fa912f842c7ed27a056f5b38f882f820baf37d5",
        "939b2397-08b7-43c8-8850-41fedb4f001a",
        "4bc8c9f7-4600-4c7c-bf30-a39aae08448a",
        "d1a7b60df83a72fc820ce76f1883d30dc36f3980ce7570692f7fe30e98ce5b7e",
        "Succeeded",
        "terminal.output",
        "tool.call",
        "2026-07-12T14:15:01.338087081Z",
    ]
}

#[test]
fn adversarial_secrets_are_redacted() {
    let s = scanner();
    for (name, sample) in adversarial_secrets() {
        let out = s.redact(sample);
        assert!(
            out.contains("[REDACTED]") || out != sample,
            "{name}: secret must not survive unchanged: {sample} → {out}"
        );
        // Spot-check known prefixes do not leak.
        for leak in [
            "sk-abcdef",
            "ghp_ABCDEF",
            "github_pat_11AAAA",
            "AKIAIOSFODNN7",
            "xoxb-123456789012",
            "sk_live_51Ab",
            "xai-abcdef",
            "npm_ABCDEF",
            "BEGIN OPENSSH PRIVATE KEY",
        ] {
            if sample.contains(leak) {
                assert!(
                    !out.contains(leak),
                    "{name}: leak fragment {leak:?} survived in {out}"
                );
            }
        }
    }
}

#[test]
fn structural_ids_never_scarred() {
    let s = scanner();
    for sample in structural_ids() {
        assert_eq!(s.redact(sample), sample, "scarred structural: {sample}");
        assert!(
            s.scan(sample, "gate", None).is_empty(),
            "false positive on structural: {sample}"
        );
    }
}

#[test]
fn mixed_secret_and_sha_preserves_sha() {
    let s = scanner();
    let sha = "ea950d8180f520d808274579577db86bc6365a7a";
    let blob = "22c8e61f11fd0f02da754f5b2fa912f842c7ed27a056f5b38f882f820baf37d5";
    let text = format!("commit {sha} blob {blob} key=sk-abcdefghijklmnopqrstuvwxyz012345");
    let out = s.redact(&text);
    assert!(out.contains(sha), "sha scarred: {out}");
    assert!(out.contains(blob), "blob key scarred: {out}");
    assert!(!out.contains("sk-abcdef"), "secret leaked: {out}");
}

#[test]
fn chunk_boundary_openai_key() {
    let mut stream = StreamRedactor::new(scanner());
    let secret = "sk-abcdefghijklmnopqrstuvwxyz012345";
    let mid = secret.len() / 2;
    let (a, _) = stream.push(&format!("export KEY={}", &secret[..mid]));
    let (b, hits) = stream.push(&format!("{}\n", &secret[mid..]));
    assert!(hits > 0, "expected boundary detection");
    let full = format!("{a}{b}");
    assert!(
        !full.contains(secret),
        "full secret survived chunk split: {full}"
    );
    assert!(full.contains("[REDACTED]") || b.contains("[REDACTED]"));
}

#[test]
fn chunk_boundary_github_pat() {
    let mut stream = StreamRedactor::new(scanner());
    let secret = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12";
    let mid = 10;
    let (_a, _) = stream.push(&secret[..mid]);
    let (b, hits) = stream.push(&secret[mid..]);
    assert!(hits > 0);
    assert!(!b.contains(&secret[mid..]) || b.contains("[REDACTED]"));
}

#[test]
fn chunk_boundary_does_not_scar_sha() {
    let mut stream = StreamRedactor::new(scanner());
    let sha = "ea950d8180f520d808274579577db86bc6365a7a";
    let (a, h1) = stream.push(&sha[..16]);
    let (b, h2) = stream.push(&sha[16..]);
    assert_eq!(h1 + h2, 0);
    assert_eq!(format!("{a}{b}"), sha);
}

#[test]
fn ansi_adjacent_secret_redacted() {
    let s = scanner();
    // Simulate residual control sequences near a secret (normalizer usually strips CSI).
    let text = "ok key=sk-abcdefghijklmnopqrstuvwxyz012345\x1b[0m";
    let out = s.redact(text);
    assert!(!out.contains("sk-abcdef"));
    assert!(out.contains("[REDACTED]"));
}

#[test]
fn export_redacts_tool_payload_secrets() {
    let r = export_redactor();
    let mut val = json!({
        "kind": "tool.call",
        "metadata": {
            "tool_name": "Bash",
            "input": {
                "command": "echo ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh12"
            },
            "output": "AKIAIOSFODNN7EXAMPLE"
        },
        "output_blob": "22c8e61f11fd0f02da754f5b2fa912f842c7ed27a056f5b38f882f820baf37d5"
    });
    r.redact_json(&mut val);
    assert_eq!(
        val["output_blob"],
        "22c8e61f11fd0f02da754f5b2fa912f842c7ed27a056f5b38f882f820baf37d5"
    );
    let cmd = val["metadata"]["input"]["command"].as_str().unwrap();
    assert!(!cmd.contains("ghp_ABCDEF"));
    assert!(cmd.contains("[REDACTED]"));
    assert!(val["metadata"]["output"]
        .as_str()
        .unwrap()
        .contains("[REDACTED]"));
}

#[test]
fn export_preserves_structural_near_secrets() {
    let r = export_redactor();
    let sha = "ea950d8180f520d808274579577db86bc6365a7a";
    let mut val = json!({
        "git_commit": sha,
        "preview": format!("commit {sha} token=sk-abcdefghijklmnopqrstuvwxyz012345")
    });
    r.redact_json(&mut val);
    assert_eq!(val["git_commit"], sha);
    let preview = val["preview"].as_str().unwrap();
    assert!(preview.contains(sha));
    assert!(!preview.contains("sk-abcdef"));
}

#[test]
fn memory_pack_style_fields_redact() {
    // Resume/memory paths use the same scanner.redact entry point.
    let s = scanner();
    let headline = "failed with OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz012345";
    let out = s.redact(headline);
    assert!(!out.contains("sk-abcdef"));
    assert!(out.contains("[REDACTED]") || out.contains("OPENAI"));
}

#[test]
fn json_number_cannot_bypass_scanner() {
    // Numbers that look like secrets are rare; ensure recursive JSON redaction
    // still processes stringified forms in nested payloads.
    let s = scanner();
    let mut val = json!({
        "nested": {
            "token": "sk-abcdefghijklmnopqrstuvwxyz012345"
        }
    });
    s.redact_json(&mut val);
    assert!(val["nested"]["token"]
        .as_str()
        .unwrap()
        .contains("[REDACTED]"));
}

#[test]
fn pem_header_redacted_not_entire_base64_blob_keys() {
    let s = scanner();
    let blob = "22c8e61f11fd0f02da754f5b2fa912f842c7ed27a056f5b38f882f820baf37d5";
    assert_eq!(s.redact(blob), blob);
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAExampleOnly\n-----END RSA PRIVATE KEY-----";
    let out = s.redact(pem);
    assert!(out.contains("[REDACTED]"));
    assert!(!out.contains("BEGIN RSA PRIVATE KEY"));
}
