//! Optional at-rest encryption for content-addressed blobs.
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

use std::path::{Path, PathBuf};

use anyhow::Context;
use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use sha2::{Digest, Sha256};

const MAGIC: &[u8; 4] = b"BBEN";
const VERSION: u8 = 1;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const HEADER_LEN: usize = 4 + 1 + NONCE_LEN; // magic + ver + nonce

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

    /// Load from env `BLACKBOX_STORE_KEY` (64 hex) or path; generate if missing.
    pub fn load_or_create(key_path: &Path) -> anyhow::Result<Self> {
        if let Ok(hex_key) = std::env::var("BLACKBOX_STORE_KEY") {
            let key = parse_hex_key(hex_key.trim())
                .context("BLACKBOX_STORE_KEY must be 64 hex characters")?;
            return Ok(Self::from_key_bytes(key));
        }
        if key_path.exists() {
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
            return Ok(Self::from_key_bytes(key));
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
}
