//! TAR archive adapter.

use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::Path;

use flate2::read::GzDecoder;

use crate::entry::{EntryInfo, EntryKind};
use crate::error::Error;

/// Adapter for TAR archives.
///
/// Supports both plain `.tar` and gzip-compressed `.tar.gz` / `.tgz` files.
///
/// Unlike ZIP, TAR is a sequential format without a central directory.
/// This means:
/// - Entries must be read in order
/// - `ValidateFirst` mode requires reading the entire archive twice
/// - Random access to entries is not supported
pub struct TarAdapter<R: Read> {
    archive: tar::Archive<R>,
    /// Cached entries for validation mode (read once, extract later)
    cached_entries: Option<Vec<CachedEntry>>,
}

/// Cached entry data for two-pass extraction.
struct CachedEntry {
    info: EntryInfo,
    data: Vec<u8>,
}

impl<R: Read> TarAdapter<R> {
    /// Create a new TarAdapter from a reader.
    ///
    /// For `.tar.gz` files, wrap the reader in `GzDecoder` first,
    /// or use `TarAdapter::open_gz()`.
    pub fn new(reader: R) -> Self {
        Self {
            archive: tar::Archive::new(reader),
            cached_entries: None,
        }
    }

    /// Process each entry with a callback.
    ///
    /// TAR is sequential, so entries are processed in order.
    /// The callback receives entry info and a reader for the content.
    ///
    /// Return `Ok(true)` to continue, `Ok(false)` to stop, or `Err` to abort.
    pub fn for_each<F>(&mut self, mut callback: F) -> Result<(), Error>
    where
        F: FnMut(EntryInfo, Option<&mut dyn Read>) -> Result<bool, Error>,
    {
        let entries = self.archive.entries()?;

        for entry_result in entries {
            let mut entry = entry_result?;
            let header = entry.header();

            let name = entry.path()?.to_string_lossy().into_owned();

            let entry_type = header.entry_type();
            let kind = match entry_type {
                tar::EntryType::Regular | tar::EntryType::Continuous => EntryKind::File,
                tar::EntryType::Directory => EntryKind::Directory,
                tar::EntryType::Symlink | tar::EntryType::Link => {
                    let target = entry
                        .link_name()?
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    EntryKind::Symlink { target }
                }
                // Reject device files, fifos, etc. - these are security risks
                other => {
                    return Err(Error::UnsupportedEntryType {
                        entry: name,
                        entry_type: entry_type_name(other),
                    });
                }
            };

            let info = EntryInfo {
                name,
                size: header.size()?,
                kind: kind.clone(),
                mode: header.mode().ok(),
            };

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

    /// Read all entries into memory for validation.
    ///
    /// This is used by `ValidateFirst` mode to check all entries
    /// before extracting any. The data is cached for later extraction.
    pub fn cache_all(&mut self) -> Result<Vec<EntryInfo>, Error> {
        let mut entries = Vec::new();
        let mut cached = Vec::new();

        let tar_entries = self.archive.entries()?;

        for entry_result in tar_entries {
            let mut entry = entry_result?;
            let header = entry.header();

            let name = entry.path()?.to_string_lossy().into_owned();

            let entry_type = header.entry_type();
            let kind = match entry_type {
                tar::EntryType::Regular | tar::EntryType::Continuous => EntryKind::File,
                tar::EntryType::Directory => EntryKind::Directory,
                tar::EntryType::Symlink | tar::EntryType::Link => {
                    let target = entry
                        .link_name()?
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    EntryKind::Symlink { target }
                }
                // Reject device files, fifos, etc. - these are security risks
                other => {
                    return Err(Error::UnsupportedEntryType {
                        entry: name,
                        entry_type: entry_type_name(other),
                    });
                }
            };

            let info = EntryInfo {
                name: name.clone(),
                size: header.size()?,
                kind: kind.clone(),
                mode: header.mode().ok(),
            };

            // Read file content into memory
            let mut data = Vec::new();
            if matches!(kind, EntryKind::File) {
                entry.read_to_end(&mut data)?;
            }

            entries.push(info.clone());
            cached.push(CachedEntry { info, data });
        }

        self.cached_entries = Some(cached);
        Ok(entries)
    }

    /// Extract cached entries (after cache_all was called).
    pub fn extract_cached<F>(&mut self, mut callback: F) -> Result<(), Error>
    where
        F: FnMut(EntryInfo, Option<&[u8]>) -> Result<bool, Error>,
    {
        let cached = self.cached_entries.take().ok_or_else(|| {
            Error::Io(std::io::Error::other(
                "no cached entries (call cache_all first)",
            ))
        })?;

        for entry in cached {
            let data = if matches!(entry.info.kind, EntryKind::File) {
                Some(entry.data.as_slice())
            } else {
                None
            };

            if !callback(entry.info, data)? {
                break;
            }
        }

        Ok(())
    }
}

impl TarAdapter<BufReader<File>> {
    /// Open a plain TAR file from a path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        Ok(Self::new(reader))
    }
}

impl TarAdapter<GzDecoder<BufReader<File>>> {
    /// Open a gzip-compressed TAR file (.tar.gz, .tgz) from a path.
    pub fn open_gz<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let decoder = GzDecoder::new(reader);
        Ok(Self::new(decoder))
    }
}

/// Helper to copy with a byte limit.
pub fn copy_limited<R: Read + ?Sized, W: Write>(
    reader: &mut R,
    writer: &mut W,
    limit: u64,
) -> Result<u64, Error> {
    let mut total = 0u64;
    let mut buf = [0u8; 8192];

    loop {
        let remaining = limit.saturating_sub(total);
        if remaining == 0 {
            break;
        }

        let to_read = buf.len().min(remaining as usize);
        let n = reader.read(&mut buf[..to_read])?;
        if n == 0 {
            break;
        }

        writer.write_all(&buf[..n])?;
        total += n as u64;
    }

    Ok(total)
}

/// Convert TAR entry type to a human-readable name.
fn entry_type_name(entry_type: tar::EntryType) -> String {
    match entry_type {
        tar::EntryType::Regular => "regular file".into(),
        tar::EntryType::Link => "hard link".into(),
        tar::EntryType::Symlink => "symbolic link".into(),
        tar::EntryType::Char => "character device".into(),
        tar::EntryType::Block => "block device".into(),
        tar::EntryType::Directory => "directory".into(),
        tar::EntryType::Fifo => "fifo (named pipe)".into(),
        tar::EntryType::Continuous => "continuous file".into(),
        tar::EntryType::GNULongName => "GNU long name".into(),
        tar::EntryType::GNULongLink => "GNU long link".into(),
        tar::EntryType::GNUSparse => "GNU sparse file".into(),
        _ => format!("unknown (0x{:02x})", entry_type.as_byte()),
    }
}
