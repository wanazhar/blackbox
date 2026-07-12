/// Searchable terminal transcript index.
///
/// Builds an index over normalized terminal output for
/// full-text search, event correlation, and context retrieval.
pub struct TranscriptIndexer;

impl TranscriptIndexer {
    pub fn new() -> Self {
        Self
    }

    /// Index a segment of normalized terminal text.
    ///
    /// Associates the text with the originating event so
    /// users can search transcripts and jump to context.
    pub fn index(&mut self, _event_id: &str, _text: &str) {
        // Stub: will tokenize and build a search index
        // using FTS5 (SQLite) or an in-memory trie.
    }

    /// Search the transcript index for matching text.
    ///
    /// Returns event IDs whose transcript content matches
    /// the query, ranked by relevance.
    pub fn search(&self, _query: &str) -> Vec<String> {
        Vec::new()
    }
}
