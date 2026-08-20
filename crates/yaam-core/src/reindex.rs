//! Rebuilding the index from the tree.
//!
//! This is the operation that proves the index is derived. It must reproduce every row from the
//! Markdown tree plus local cold manifests — and then replay tombstones, or a rebuild would
//! resurrect structure that was erased.

/// What a rebuild produced.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReindexReport {
    /// Records indexed from the live tree.
    pub from_tree: usize,
    /// Records indexed from cold manifests.
    pub from_manifests: usize,
    /// Files skipped because their frontmatter would not parse.
    pub skipped: usize,
    /// Erasures re-applied from the tombstone log.
    pub tombstones_replayed: usize,
}

/// Rebuilds the index in place.
pub fn reindex_all(_pipeline: &mut crate::Pipeline) -> crate::Result<ReindexReport> {
    todo!("truncate derived, walk tree + manifests, replay tombstones")
}
