//! Where a deployment's three pieces of state live.
//!
//! One type, because the three are configured together and mean nothing apart: the tree is
//! authoritative, the index is derived from it, and the key store is what makes the sealed half of
//! the tree readable. A process holding a tree from one deployment and an index from another cannot
//! be told it is wrong — every read simply answers about records it has never seen.
//!
//! The index and the key store default to sitting under the root, which is what makes a store a
//! single directory to move or back up. Naming them separately is for the deployment that wants the
//! disposable half on faster or more local storage than the authoritative half — and it has to be
//! *possible*, not merely documented: the same paths have to reach the writer, the reader and the
//! erasure verifier, or one of the three quietly works against a different file.

use std::path::PathBuf;

use crate::layout;

/// The paths one pipeline works over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    /// Root of the memory tree: the authoritative half, and where `spec/` is read from.
    pub root: PathBuf,
    /// The derived index. Disposable — deleting it is recoverable by a rebuild.
    pub index: PathBuf,
    /// Root of the per-subject key store.
    pub key_store: PathBuf,
}

impl Paths {
    /// The default layout: everything under one root.
    #[must_use]
    pub fn under(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self {
            index: root.join(layout::INDEX_FILE),
            key_store: root.join(layout::KEYSTORE_DIR),
            root,
        }
    }

    /// Puts the index somewhere other than under the root.
    #[must_use]
    pub fn with_index(mut self, index: impl Into<PathBuf>) -> Self {
        self.index = index.into();
        self
    }

    /// Puts the key store somewhere other than under the root.
    ///
    /// Choose it before the first record is written. Keys already on disk stay where they were, so
    /// moving this over live key material hides them rather than migrating them — and a hidden key
    /// is a body nobody can read again.
    #[must_use]
    pub fn with_key_store(mut self, key_store: impl Into<PathBuf>) -> Self {
        self.key_store = key_store.into();
        self
    }

    /// Whether the index sits where [`Paths::under`] would have put it.
    ///
    /// What a startup log needs: a relocated index is worth saying out loud, and a default one is
    /// noise.
    #[must_use]
    pub fn index_is_default(&self) -> bool {
        self.index == self.root.join(layout::INDEX_FILE)
    }

    /// Whether the key store sits where [`Paths::under`] would have put it.
    #[must_use]
    pub fn key_store_is_default(&self) -> bool {
        self.key_store == self.root.join(layout::KEYSTORE_DIR)
    }
}

#[cfg(test)]
mod tests {
    use super::Paths;

    #[test]
    fn the_default_layout_puts_everything_under_the_root() {
        let paths = Paths::under("/srv/memory");
        assert_eq!(
            paths.index,
            std::path::Path::new("/srv/memory/index.sqlite")
        );
        assert_eq!(
            paths.key_store,
            std::path::Path::new("/srv/memory/keystore")
        );
        assert!(paths.index_is_default());
        assert!(paths.key_store_is_default());
    }

    #[test]
    fn a_relocated_path_says_so() {
        let paths = Paths::under("/srv/memory")
            .with_index("/fast/index.sqlite")
            .with_key_store("/secrets/keys");
        assert!(!paths.index_is_default());
        assert!(!paths.key_store_is_default());
    }
}
