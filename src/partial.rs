//! Cleanup for files that are only partially written.

use std::path::{Path, PathBuf};

use crate::dest::Destination;

/// Removes a destination file unless its write is committed.
///
/// Extraction creates the output file before the entry's data has been read.
/// Corruption (bad CRC32, size mismatch) is only detected while or after the
/// data streams, so on any error the guard deletes the file instead of leaving
/// truncated or unverified bytes under the entry's name.
///
/// With `Overwrite`, the original file was already removed when the new one
/// was created, so removing it on failure loses nothing that was still intact.
pub(crate) struct PartialFile<'a> {
    dest: &'a Destination,
    rel: Option<PathBuf>,
}

impl<'a> PartialFile<'a> {
    /// Track `rel`, a path relative to `dest`.
    pub(crate) fn new(dest: &'a Destination, rel: &Path) -> Self {
        Self {
            dest,
            rel: Some(rel.to_path_buf()),
        }
    }

    /// Keep the file: everything was written and verified.
    pub(crate) fn commit(mut self) {
        self.rel = None;
    }
}

impl Drop for PartialFile<'_> {
    fn drop(&mut self) {
        if let Some(rel) = self.rel.take() {
            // remove_file unlinks a symlink rather than following it.
            let _ = self.dest.remove_file(&rel);
        }
    }
}
