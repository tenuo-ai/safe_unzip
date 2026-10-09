//! ZIP archive adapter.

use std::fs::File;
use std::io::{BufReader, Read, Seek, Write};
use std::path::Path;

use crate::copy::copy_entry;
use crate::entry::{EntryInfo, EntryKind};
use crate::error::Error;

/// Adapter for ZIP archives.
///
/// Wraps the `zip` crate and provides a format-agnostic interface for extraction.
pub struct ZipAdapter<R> {
    archive: zip::ZipArchive<R>,
}

impl<R: Read + Seek> ZipAdapter<R> {
    /// Create a new ZipAdapter from a reader.
    pub fn new(reader: R) -> Result<Self, Error> {
        let archive = zip::ZipArchive::new(reader)?;
        Ok(Self { archive })
    }

    /// Returns the number of entries in the archive.
    pub fn len(&self) -> usize {
        self.archive.len()
    }

    /// Returns true if the archive is empty.
    pub fn is_empty(&self) -> bool {
        self.archive.is_empty()
    }

    /// Get all entry metadata without decompressing (for validation).
    ///
    /// Uses `by_index_raw()` to read only headers, not content.
    ///
    /// # Errors
    ///
    /// Returns `Error::EncryptedEntry` if any entry is encrypted.
    pub fn entries_metadata(&mut self) -> Result<Vec<EntryInfo>, Error> {
        let mut entries = Vec::with_capacity(self.archive.len());

        for i in 0..self.archive.len() {
            let entry = self.archive.by_index_raw(i)?;
            let name = entry.name().to_string();

            // Reject encrypted entries
            if entry.encrypted() {
                return Err(Error::EncryptedEntry { entry: name });
            }

            let kind = if entry.is_dir() {
                EntryKind::Directory
            } else if entry.is_symlink() {
                EntryKind::Symlink {
                    target: String::new(), // Can't read target without decompressing
                }
            } else {
                EntryKind::File
            };

            entries.push(EntryInfo {
                name,
                size: entry.size(),
                kind,
                mode: entry.unix_mode(),
            });
        }

        Ok(entries)
    }

    /// Process each entry with a callback.
    ///
    /// This design works around the zip crate's lifetime constraints by
    /// processing entries one at a time through a callback.
    ///
    /// The callback receives:
    /// - `info`: Entry metadata for policy decisions
    /// - `reader`: A reader to access the entry's content (only for files)
    ///
    /// Return `Ok(true)` to continue, `Ok(false)` to stop, or `Err` to abort.
    ///
    /// # Errors
    ///
    /// Returns `Error::EncryptedEntry` if any entry is encrypted.
    pub fn for_each<F>(&mut self, mut callback: F) -> Result<(), Error>
    where
        F: FnMut(EntryInfo, Option<&mut dyn Read>) -> Result<bool, Error>,
    {
        for i in 0..self.archive.len() {
            let mut entry = self.archive.by_index(i)?;
            let name = entry.name().to_string();

            // Reject encrypted entries
            if entry.encrypted() {
                return Err(Error::EncryptedEntry { entry: name });
            }

            // Determine entry kind and read symlink target if applicable
            let kind = if entry.is_dir() {
                EntryKind::Directory
            } else if entry.is_symlink() {
                let mut target = String::new();
                entry.read_to_string(&mut target)?;
                EntryKind::Symlink { target }
            } else {
                EntryKind::File
            };

            let info = EntryInfo {
                name,
                size: entry.size(),
                kind: kind.clone(),
                mode: entry.unix_mode(),
            };

            // For files, provide the reader; for dirs/symlinks, no reader needed
            let continue_extraction = if matches!(kind, EntryKind::File) {
                callback(info, Some(&mut entry))?
            } else {
                callback(info, None)?
            };

            if !continue_extraction {
                break;
            }
        }

        Ok(())
    }

    /// Extract a single entry by index, writing to the provided writer.
    ///
    /// Returns the entry info and number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns `Error::EncryptedEntry` if the entry is encrypted.
    pub fn extract_to<W: Write>(
        &mut self,
        index: usize,
        writer: &mut W,
        limit: u64,
    ) -> Result<(EntryInfo, u64), Error> {
        let mut entry = self.archive.by_index(index)?;
        let name = entry.name().to_string();

        // Reject encrypted entries
        if entry.encrypted() {
            return Err(Error::EncryptedEntry { entry: name });
        }

        let kind = if entry.is_dir() {
            EntryKind::Directory
        } else if entry.is_symlink() {
            let mut target = String::new();
            entry.read_to_string(&mut target)?;
            EntryKind::Symlink { target }
        } else {
            EntryKind::File
        };

        let info = EntryInfo {
            name,
            size: entry.size(),
            kind: kind.clone(),
            mode: entry.unix_mode(),
        };

        let bytes_written = if matches!(kind, EntryKind::File) {
            // Never write past the declared size: anything beyond it means the
            // header lied (possible zip bomb).
            let cap = limit.min(info.size);
            let copied = copy_entry(&mut entry, writer, cap, &info.name)?;
            if copied.overflow {
                return Err(if cap < info.size {
                    Error::FileTooLarge {
                        entry: info.name.clone(),
                        limit,
                        size: info.size,
                    }
                } else {
                    Error::SizeMismatch {
                        entry: info.name.clone(),
                        declared: info.size,
                        actual: copied.written + 1,
                    }
                });
            }
            if copied.written != info.size {
                return Err(if cap < info.size {
                    Error::FileTooLarge {
                        entry: info.name.clone(),
                        limit,
                        size: info.size,
                    }
                } else {
                    Error::SizeMismatch {
                        entry: info.name.clone(),
                        declared: info.size,
                        actual: copied.written,
                    }
                });
            }
            copied.written
        } else {
            0
        };

        Ok((info, bytes_written))
    }

    /// Decompress a file entry without writing it, checking its CRC32.
    ///
    /// Returns the number of bytes decompressed. Directories and symlinks
    /// are skipped and return 0.
    ///
    /// # Errors
    ///
    /// Returns an error if the entry is encrypted, fails its CRC32 check, or
    /// decompresses to more than its declared size.
    pub fn verify_entry(&mut self, index: usize) -> Result<u64, Error> {
        let mut entry = self.archive.by_index(index)?;
        let name = entry.name().to_string();

        if entry.encrypted() {
            return Err(Error::EncryptedEntry { entry: name });
        }
        if entry.is_dir() || entry.is_symlink() {
            return Ok(0);
        }

        let declared = entry.size();
        drain_checked(&mut entry, &name, declared)
    }

    /// Get entry info by index without reading content.
    ///
    /// # Errors
    ///
    /// Returns `Error::EncryptedEntry` if the entry is encrypted.
    pub fn entry_info(&mut self, index: usize) -> Result<EntryInfo, Error> {
        let entry = self.archive.by_index_raw(index)?;
        let name = entry.name().to_string();

        // Reject encrypted entries
        if entry.encrypted() {
            return Err(Error::EncryptedEntry { entry: name });
        }

        let kind = if entry.is_dir() {
            EntryKind::Directory
        } else if entry.is_symlink() {
            EntryKind::Symlink {
                target: String::new(),
            }
        } else {
            EntryKind::File
        };

        Ok(EntryInfo {
            name,
            size: entry.size(),
            kind,
            mode: entry.unix_mode(),
        })
    }
}

impl ZipAdapter<BufReader<File>> {
    /// Open a ZIP file from a path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Self::new(reader)
    }
}

/// Read an entry to EOF without storing it, so the zip crate checks its CRC32.
///
/// Reads at most `declared + 1` bytes: one byte past the declared size is
/// enough to detect a lying header without decompressing a bomb.
pub(crate) fn drain_checked<R: Read>(
    entry: &mut R,
    name: &str,
    declared: u64,
) -> Result<u64, Error> {
    let copied = copy_entry(entry, &mut std::io::sink(), declared, name)?;
    if copied.overflow {
        return Err(Error::SizeMismatch {
            entry: name.to_string(),
            declared,
            actual: copied.written + 1,
        });
    }
    if copied.written != declared {
        return Err(Error::SizeMismatch {
            entry: name.to_string(),
            declared,
            actual: copied.written,
        });
    }
    Ok(copied.written)
}
