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
    pub fn new(key: String, size: u64) -> Self {
        Self {
            key,
            size,
            compressed: false,
            content_type: None,
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
