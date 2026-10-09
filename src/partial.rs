//! Cleanup for files that are only partially written.

use std::fs;
use std::path::{Path, PathBuf};

/// Removes a destination file unless its write is committed.
///
/// Extraction creates the output file before the entry's data has been read.
/// Corruption (bad CRC32, size mismatch) is only detected while or after the
/// data streams, so on any error the guard deletes the file instead of leaving
/// truncated or unverified bytes under the entry's name.
///
/// With `Overwrite`, the original file was already truncated when it was
/// opened, so removing it on failure loses nothing that was still intact.
pub(crate) struct PartialFile {
    path: Option<PathBuf>,
}

impl PartialFile {
    pub(crate) fn new(path: &Path) -> Self {
        Self {
            path: Some(path.to_path_buf()),
        }
    }

    /// Keep the file: everything was written and verified.
    pub(crate) fn commit(mut self) {
        self.path = None;
    }
}

impl Drop for PartialFile {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            // remove_file unlinks a symlink rather than following it.
            let _ = fs::remove_file(path);
        }
    }
}
