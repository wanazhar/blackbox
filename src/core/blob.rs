use serde::{Deserialize, Serialize};

/// A reference to content stored in the content-addressed blob store.
///
/// The key is the SHA-256 hash of the (optionally compressed) content.
/// Blobs are deduplicated: identical content produces the same key
/// and is stored once.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlobReference {
    /// SHA-256 hex digest of the content
    pub key: String,

    /// Uncompressed size in bytes
    pub size: u64,

    /// Whether the blob is stored with Zstandard compression
    pub compressed: bool,

    /// MIME type hint, if known
    pub content_type: Option<String>,
}

impl BlobReference {
    /// Create a new blob reference.
    ///
    /// # Panics
    ///
    /// Panics if `key` is not a valid 64-character lowercase hex SHA-256 digest.
    /// This prevents path traversal attacks via malformed blob keys.
    pub fn new(key: String, size: u64) -> Self {
        assert!(
            is_valid_blob_key(&key),
            "BlobReference key must be a 64-char hex SHA-256 digest, got: {:?}",
            key
        );
        Self {
            key,
            size,
            compressed: false,
            content_type: None,
        }
    }

    /// Try to create a new blob reference, returning None if the key is invalid.
    pub fn try_new(key: String, size: u64) -> Option<Self> {
        if is_valid_blob_key(&key) {
            Some(Self {
                key,
                size,
                compressed: false,
                content_type: None,
            })
        } else {
            None
        }
    }

    /// Mark this blob as Zstandard-compressed.
    pub fn compressed(mut self) -> Self {
        self.compressed = true;
        self
    }

    /// Set the MIME content type hint.
    pub fn with_content_type(mut self, content_type: &str) -> Self {
        self.content_type = Some(content_type.to_string());
        self
    }
}

/// Check if a string is a valid blob key (64 **lowercase** hex chars = SHA-256).
pub fn is_valid_blob_key(key: &str) -> bool {
    key.len() == 64
        && key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_sha256_key() {
        let key = "a".repeat(64);
        let r = BlobReference::new(key.clone(), 100);
        assert_eq!(r.key, key);
        assert_eq!(r.size, 100);
        assert!(!r.compressed);
        assert!(r.content_type.is_none());
    }

    #[test]
    #[should_panic(expected = "must be a 64-char hex")]
    fn rejects_short_key() {
        BlobReference::new("abc".into(), 100);
    }

    #[test]
    #[should_panic(expected = "must be a 64-char hex")]
    fn rejects_path_traversal() {
        BlobReference::new("../../etc/passwd".into(), 100);
    }

    #[test]
    #[should_panic(expected = "must be a 64-char hex")]
    fn rejects_non_hex() {
        let key = "g".repeat(64);
        BlobReference::new(key, 100);
    }

    #[test]
    fn try_new_valid() {
        let key = "0".repeat(64);
        assert!(BlobReference::try_new(key, 100).is_some());
    }

    #[test]
    fn try_new_invalid() {
        assert!(BlobReference::try_new("short".into(), 100).is_none());
    }

    #[test]
    fn compressed_builder() {
        let key = "a".repeat(64);
        let r = BlobReference::new(key, 100).compressed();
        assert!(r.compressed);
    }

    #[test]
    fn with_content_type_builder() {
        let key = "a".repeat(64);
        let r = BlobReference::new(key, 100).with_content_type("text/plain");
        assert_eq!(r.content_type.as_deref(), Some("text/plain"));
    }

    #[test]
    fn is_valid_blob_key_cases() {
        assert!(is_valid_blob_key(&"0".repeat(64)));
        assert!(is_valid_blob_key(&"a".repeat(64)));
        assert!(is_valid_blob_key(&"f".repeat(64)));
        assert!(!is_valid_blob_key(&"g".repeat(64)));
        assert!(!is_valid_blob_key(&"A".repeat(64))); // uppercase refused
        assert!(!is_valid_blob_key("short"));
        assert!(!is_valid_blob_key(&"a".repeat(63)));
        assert!(!is_valid_blob_key(&"a".repeat(65)));
        assert!(!is_valid_blob_key("../../etc/passwd"));
    }
}
