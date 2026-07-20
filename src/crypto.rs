//! Optional at-rest encryption for content-addressed blobs and sealed packs.
//!
//! When enabled, plaintext is still content-addressed by SHA-256 of the
//! **plaintext** (key = hex(sha256(plain))). On disk the file holds:
//!
//! ```text
//! b"BBEN" || version(u8=1) || nonce(12) || ciphertext+tag
//! ```
//!
//! Legacy plaintext blobs (no magic header) still load unchanged.
//! Key material lives in `.blackbox/store.key` (0600) or `BLACKBOX_STORE_KEY`
//! (64-char hex). This protects other UIDs / casual disk scrapes — not a
//! running same-UID attacker who can read the key file.
//!
//! # Sealed export packs
//!
//! Portable JSON can be wrapped as `blackbox.export.sealed/v1` with either
//! the store key or a passphrase (PBKDF2-HMAC-SHA256).

use std::path::{Path, PathBuf};

use anyhow::Context;
use base64::Engine;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"BBEN";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 4 + 1 + NONCE_LEN; // magic + ver + nonce
const PBKDF2_ITERS: u32 = 210_000;
const SEALED_FORMAT: &str = "blackbox.export.sealed/v1";

/// 32-byte ChaCha20-Poly1305 key for blob encryption.
#[derive(Clone)]
pub struct BlobCrypto {
    key: [u8; KEY_LEN],
}

impl std::fmt::Debug for BlobCrypto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BlobCrypto([redacted])")
    }
}

impl BlobCrypto {
    pub fn from_key_bytes(key: [u8; KEY_LEN]) -> Self {
        Self { key }
    }

    /// Load existing key only (env or path). Does not generate.
    pub fn load_existing(key_path: &Path) -> anyhow::Result<Option<Self>> {
        if let Ok(hex_key) = std::env::var("BLACKBOX_STORE_KEY") {
            let key = parse_hex_key(hex_key.trim())
                .context("BLACKBOX_STORE_KEY must be 64 hex characters")?;
            return Ok(Some(Self::from_key_bytes(key)));
        }
        // Also honor BLACKBOX_STORE_KEY_FILE even if caller passed project path.
        let path = if let Ok(p) = std::env::var("BLACKBOX_STORE_KEY_FILE") {
            let path = PathBuf::from(p.trim());
            if path.as_os_str().is_empty() {
                key_path.to_path_buf()
            } else {
                path
            }
        } else {
            key_path.to_path_buf()
        };
        let key_path = path.as_path();
        if !key_path.exists() {
            return Ok(None);
        }
        let raw = std::fs::read(key_path)
            .with_context(|| format!("read store key {}", key_path.display()))?;
        let key = if raw.len() == KEY_LEN {
            let mut k = [0u8; KEY_LEN];
            k.copy_from_slice(&raw);
            k
        } else {
            let s = String::from_utf8_lossy(&raw);
            parse_hex_key(s.trim()).context("store.key must be 32 raw bytes or 64 hex chars")?
        };
        crate::privacy::restrict_file(key_path);
        Ok(Some(Self::from_key_bytes(key)))
    }

    /// Load from env `BLACKBOX_STORE_KEY` (64 hex) or path; generate if missing.
    pub fn load_or_create(key_path: &Path) -> anyhow::Result<Self> {
        if let Some(c) = Self::load_existing(key_path)? {
            return Ok(c);
        }
        let key_arr = ChaCha20Poly1305::generate_key(&mut OsRng);
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(key_arr.as_slice());
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
            crate::privacy::restrict_dir(parent);
        }
        std::fs::write(key_path, key).with_context(|| format!("write {}", key_path.display()))?;
        crate::privacy::restrict_file(key_path);
        tracing::info!(
            path = %key_path.display(),
            "generated at-rest blob encryption key (store securely; loss = unreadable blobs)"
        );
        Ok(Self::from_key_bytes(key))
    }

    /// Derive a key from a passphrase (PBKDF2-HMAC-SHA256).
    pub fn from_passphrase(passphrase: &str, salt: &[u8], iterations: u32) -> anyhow::Result<Self> {
        if passphrase.is_empty() {
            anyhow::bail!("passphrase must not be empty");
        }
        if salt.len() < 8 {
            anyhow::bail!("salt too short");
        }
        let mut key = [0u8; KEY_LEN];
        pbkdf2::<Hmac<Sha256>>(passphrase.as_bytes(), salt, iterations, &mut key)
            .map_err(|e| anyhow::anyhow!("pbkdf2 failed: {e}"))?;
        Ok(Self::from_key_bytes(key))
    }

    /// Encrypt plaintext for disk storage. Returns wire format with magic header.
    pub fn seal(&self, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| anyhow::anyhow!("blob encrypt failed: {e}"))?;
        let mut out = Vec::with_capacity(HEADER_LEN + ct.len());
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    /// Decrypt wire format if encrypted; returns plaintext.
    pub fn open(&self, data: &[u8]) -> anyhow::Result<Vec<u8>> {
        if !is_encrypted_blob(data) {
            return Ok(data.to_vec());
        }
        if data.len() < HEADER_LEN + 16 {
            anyhow::bail!("encrypted blob too short");
        }
        if data[4] != VERSION {
            anyhow::bail!("unsupported blob encryption version {}", data[4]);
        }
        let nonce = Nonce::from_slice(&data[5..5 + NONCE_LEN]);
        let ct = &data[HEADER_LEN..];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        cipher
            .decrypt(nonce, ct)
            .map_err(|_| anyhow::anyhow!("blob decrypt failed (wrong key or corrupt)"))
    }
}

/// True if data has BBEN magic header.
pub fn is_encrypted_blob(data: &[u8]) -> bool {
    data.len() >= 5 && &data[..4] == MAGIC
}

/// Default key path next to the store root.
pub fn default_key_path(store_root: &Path) -> PathBuf {
    store_root.join("store.key")
}

/// Resolve where the store encryption key lives.
///
/// Priority:
/// 1. `BLACKBOX_STORE_KEY_FILE` (path; keeps key off the project tree)
/// 2. Existing XDG `~/.config/blackbox/default.key` if present
/// 3. Project `.blackbox/store.key`
///
/// Prefer (1)/(2) so a stolen project checkout without the key is useless.
pub fn resolve_key_path(store_root: &Path) -> PathBuf {
    if let Ok(p) = std::env::var("BLACKBOX_STORE_KEY_FILE") {
        let path = PathBuf::from(p.trim());
        if !path.as_os_str().is_empty() {
            return path;
        }
    }
    // Prefer existing external key (do not auto-create outside project unless env set).
    let xdg = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")));
    if let Some(cfg) = xdg {
        let external = cfg.join("blackbox").join("default.key");
        if external.is_file() {
            return external;
        }
    }
    default_key_path(store_root)
}

/// True when key material is expected to live outside the project tree.
pub fn key_is_external(store_root: &Path) -> bool {
    let p = resolve_key_path(store_root);
    !p.starts_with(store_root)
}

/// SHA-256 hex of plaintext (content-addressed key).
pub fn content_key(plaintext: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(plaintext);
    hex::encode(hasher.finalize())
}

fn parse_hex_key(s: &str) -> anyhow::Result<[u8; KEY_LEN]> {
    let bytes = hex::decode(s).context("invalid hex")?;
    if bytes.len() != KEY_LEN {
        anyhow::bail!("expected {} bytes, got {}", KEY_LEN, bytes.len());
    }
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&bytes);
    Ok(key)
}

// ── Sealed text files (state / MEMORY) ───────────────────────────

/// Write plaintext bytes; if crypto is Some, store BBEN ciphertext.
pub fn write_maybe_sealed(
    path: &Path,
    plain: &[u8],
    crypto: Option<&BlobCrypto>,
) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
        crate::privacy::restrict_dir(parent);
    }
    let data = if let Some(c) = crypto {
        c.seal(plain)?
    } else {
        plain.to_vec()
    };
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &data)?;
    crate::privacy::restrict_file(&tmp);
    std::fs::rename(&tmp, path)?;
    crate::privacy::restrict_file(path);
    Ok(())
}

/// Read file; decrypt BBEN if needed using store key next to store root.
pub fn read_maybe_sealed(path: &Path, store_root: &Path) -> anyhow::Result<Vec<u8>> {
    let data = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    if !is_encrypted_blob(&data) {
        return Ok(data);
    }
    let key_path = resolve_key_path(store_root);
    let crypto = BlobCrypto::load_existing(&key_path)?.ok_or_else(|| {
        anyhow::anyhow!(
            "{} is encrypted but no store.key / BLACKBOX_STORE_KEY / BLACKBOX_STORE_KEY_FILE found",
            path.display()
        )
    })?;
    crypto.open(&data)
}

/// Crypto for sticky files: present only when a key (or env) exists.
pub fn sticky_crypto(store_root: &Path) -> Option<BlobCrypto> {
    BlobCrypto::load_existing(&resolve_key_path(store_root))
        .ok()
        .flatten()
}

// ── Sealed export packs ──────────────────────────────────────────

/// Seal a portable (or other) export string for offline sharing.
///
/// - `passphrase = Some(...)` → PBKDF2 key with random salt
/// - `passphrase = None` → use provided `store` crypto (must be Some)
pub fn seal_export_pack(
    plaintext: &str,
    passphrase: Option<&str>,
    store: Option<&BlobCrypto>,
) -> anyhow::Result<String> {
    let (crypto, kdf, salt_b64, iterations) = if let Some(pass) = passphrase {
        let mut salt = [0u8; 16];
        use chacha20poly1305::aead::rand_core::RngCore;
        OsRng.fill_bytes(&mut salt);
        let c = BlobCrypto::from_passphrase(pass, &salt, PBKDF2_ITERS)?;
        (
            c,
            "pbkdf2-sha256",
            Some(base64::engine::general_purpose::STANDARD.encode(salt)),
            Some(PBKDF2_ITERS),
        )
    } else if let Some(c) = store {
        (c.clone(), "store_key", None, None)
    } else {
        anyhow::bail!("seal requires --passphrase or store encryption key");
    };
    let sealed = crypto.seal(plaintext.as_bytes())?;
    let body = serde_json::json!({
        "format": SEALED_FORMAT,
        "kdf": kdf,
        "salt_b64": salt_b64,
        "iterations": iterations,
        "ciphertext_b64": base64::engine::general_purpose::STANDARD.encode(sealed),
        "sealed_at": chrono::Utc::now().to_rfc3339(),
    });
    Ok(serde_json::to_string_pretty(&body)?)
}

/// Detect sealed export envelope.
pub fn is_sealed_export_pack(text: &str) -> bool {
    text.contains(SEALED_FORMAT)
        || serde_json::from_str::<serde_json::Value>(text)
            .ok()
            .and_then(|v| {
                v.get("format")
                    .and_then(|f| f.as_str())
                    .map(|s| s == SEALED_FORMAT)
            })
            .unwrap_or(false)
}

/// Open a sealed export pack to plaintext JSON.
pub fn open_export_pack(
    sealed_json: &str,
    passphrase: Option<&str>,
    store: Option<&BlobCrypto>,
) -> anyhow::Result<String> {
    let v: serde_json::Value =
        serde_json::from_str(sealed_json).context("sealed pack is not JSON")?;
    let format = v.get("format").and_then(|f| f.as_str()).unwrap_or("");
    if format != SEALED_FORMAT {
        anyhow::bail!("not a sealed export pack (format={format:?})");
    }
    let ct_b64 = v
        .get("ciphertext_b64")
        .and_then(|c| c.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing ciphertext_b64"))?;
    let ct = base64::engine::general_purpose::STANDARD
        .decode(ct_b64)
        .context("ciphertext_b64 base64 decode")?;
    let kdf = v.get("kdf").and_then(|k| k.as_str()).unwrap_or("store_key");
    let crypto = match kdf {
        "pbkdf2-sha256" => {
            let pass = passphrase.ok_or_else(|| {
                anyhow::anyhow!("this pack was sealed with a passphrase; pass --passphrase")
            })?;
            let salt_b64 = v
                .get("salt_b64")
                .and_then(|s| s.as_str())
                .ok_or_else(|| anyhow::anyhow!("missing salt_b64"))?;
            let salt = base64::engine::general_purpose::STANDARD
                .decode(salt_b64)
                .context("salt_b64 decode")?;
            // Ignore attacker-chosen iteration counts (DoS). Only the current
            // PBKDF2_ITERS policy is accepted; historical packs must match.
            let iters = v
                .get("iterations")
                .and_then(|i| i.as_u64())
                .unwrap_or(PBKDF2_ITERS as u64);
            if iters != PBKDF2_ITERS as u64 {
                anyhow::bail!(
                    "unsupported PBKDF2 iterations {iters} (expected {PBKDF2_ITERS})"
                );
            }
            BlobCrypto::from_passphrase(pass, &salt, PBKDF2_ITERS)?
        }
        "store_key" => store
            .cloned()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "this pack was sealed with the store key; enable encrypt_blobs or set BLACKBOX_STORE_KEY"
                )
            })?,
        other => anyhow::bail!("unknown kdf: {other}"),
    };
    // Sealed packs must be AEAD ciphertext (BBEN). Never reuse blob `open()`
    // plaintext passthrough — that would accept unauthenticated "sealed" packs.
    if !is_encrypted_blob(&ct) {
        anyhow::bail!("sealed pack ciphertext is not authenticated (missing BBEN header)");
    }
    let plain = crypto.open(&ct)?;
    String::from_utf8(plain).context("sealed plaintext is not UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_roundtrip() {
        let crypto = BlobCrypto::from_key_bytes([7u8; 32]);
        let plain = b"secret env payload sk-abcdefghijklmnopqrstuvwxyz012345";
        let sealed = crypto.seal(plain).unwrap();
        assert!(is_encrypted_blob(&sealed));
        assert_ne!(&sealed[..], plain.as_slice());
        let opened = crypto.open(&sealed).unwrap();
        assert_eq!(opened, plain);
    }

    #[test]
    fn open_plaintext_passthrough() {
        let crypto = BlobCrypto::from_key_bytes([1u8; 32]);
        let plain = b"legacy blob";
        assert_eq!(crypto.open(plain).unwrap(), plain);
    }

    #[test]
    fn wrong_key_fails() {
        let a = BlobCrypto::from_key_bytes([1u8; 32]);
        let b = BlobCrypto::from_key_bytes([2u8; 32]);
        let sealed = a.seal(b"hello world data").unwrap();
        assert!(b.open(&sealed).is_err());
    }

    #[test]
    fn load_or_create_persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.key");
        let c1 = BlobCrypto::load_or_create(&path).unwrap();
        let c2 = BlobCrypto::load_or_create(&path).unwrap();
        let sealed = c1.seal(b"abc").unwrap();
        assert_eq!(c2.open(&sealed).unwrap(), b"abc");
        assert!(path.exists());
    }

    #[test]
    fn passphrase_export_pack_roundtrip() {
        let plain = r#"{"version":2,"run":{"id":"x"},"events":[]}"#;
        let sealed = seal_export_pack(plain, Some("correct horse battery"), None).unwrap();
        assert!(is_sealed_export_pack(&sealed));
        assert!(!sealed.contains("\"id\":\"x\"") || sealed.contains("ciphertext"));
        let opened = open_export_pack(&sealed, Some("correct horse battery"), None).unwrap();
        assert_eq!(opened, plain);
        assert!(open_export_pack(&sealed, Some("wrong"), None).is_err());
    }

    #[test]
    fn sealed_pack_rejects_unauthenticated_ciphertext() {
        // Attacker ships sealed envelope with raw plaintext as ciphertext_b64.
        let fake = serde_json::json!({
            "format": SEALED_FORMAT,
            "kdf": "pbkdf2-sha256",
            "salt_b64": base64::engine::general_purpose::STANDARD.encode(b"0123456789abcdef"),
            "iterations": PBKDF2_ITERS,
            "ciphertext_b64": base64::engine::general_purpose::STANDARD
                .encode(br#"{"version":2,"run":{"id":"forged"},"events":[]}"#),
        });
        let err = open_export_pack(&fake.to_string(), Some("any"), None).unwrap_err();
        assert!(
            err.to_string().contains("authenticated") || err.to_string().contains("BBEN"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn sealed_pack_rejects_attacker_pbkdf2_iterations() {
        let plain = r#"{"version":2}"#;
        let sealed = seal_export_pack(plain, Some("pw"), None).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&sealed).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("iterations".into(), serde_json::json!(4_294_967_295u64));
        let err = open_export_pack(&v.to_string(), Some("pw"), None).unwrap_err();
        assert!(err.to_string().contains("iterations"), "unexpected: {err}");
    }

    #[test]
    fn store_key_export_pack() {
        let c = BlobCrypto::from_key_bytes([3u8; 32]);
        let plain = "{\"ok\":true}";
        let sealed = seal_export_pack(plain, None, Some(&c)).unwrap();
        let opened = open_export_pack(&sealed, None, Some(&c)).unwrap();
        assert_eq!(opened, plain);
    }

    #[test]
    fn write_read_maybe_sealed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let c = BlobCrypto::load_or_create(&default_key_path(dir.path())).unwrap();
        write_maybe_sealed(&path, br#"{"a":1}"#, Some(&c)).unwrap();
        let disk = std::fs::read(&path).unwrap();
        assert!(is_encrypted_blob(&disk));
        let plain = read_maybe_sealed(&path, dir.path()).unwrap();
        assert_eq!(plain, br#"{"a":1}"#);
    }
}
