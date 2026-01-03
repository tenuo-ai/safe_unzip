//! 7z archive adapter.
//!
//! Provides read-only extraction of 7z archives with the same security
//! guarantees as ZIP and TAR.

use std::io::Write;
use std::path::Path;

use crate::entry::{EntryInfo, EntryKind};
use crate::error::Error;

/// Adapter for 7z archives.
///
/// Uses the `sevenz-rust` crate for decompression. Note that 7z archives
/// are fully decompressed into memory before extraction, so very large
/// archives may use significant RAM.
///
/// # Example
///
/// ```ignore
/// use safe_unzip::{Driver, SevenZAdapter};
///
/// let adapter = SevenZAdapter::open("archive.7z")?;
/// let report = Driver::new("/tmp/out")?.extract_7z(adapter)?;
/// ```
pub struct SevenZAdapter {
    /// Cached entries (7z requires full decompression)
    entries: Vec<SevenZEntry>,
}

struct SevenZEntry {
    info: EntryInfo,
    data: Vec<u8>,
}

impl SevenZAdapter {
    /// Open a 7z file from a path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        let path = path.as_ref();
        let entries = Self::decompress_all(path)?;
        Ok(Self { entries })
    }

    /// Open a 7z file from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        // sevenz-rust requires a file path, so we write to a temp file
        let mut temp = tempfile::NamedTempFile::new()?;
        temp.write_all(data)?;
        temp.flush()?;
        Self::open(temp.path())
    }

    fn decompress_all(path: &Path) -> Result<Vec<SevenZEntry>, Error> {
        let mut entries = Vec::new();

        // Use the lower-level API to iterate entries
        let mut archive = sevenz_rust::SevenZReader::open(path, sevenz_rust::Password::empty())
            .map_err(|e| Error::Io(std::io::Error::other(format!("7z open error: {}", e))))?;

        // Iterate through all entries
        archive
            .for_each_entries(|entry, reader| {
                let name = entry.name().to_string();

                // Determine entry kind
                let kind = if entry.is_directory() {
                    EntryKind::Directory
                } else {
                    EntryKind::File
                };

                // Read content for files
                let mut data = Vec::new();
                if matches!(kind, EntryKind::File) {
                    reader.read_to_end(&mut data)?;
                }

                let info = EntryInfo {
                    name,
                    size: data.len() as u64,
                    kind,
                    mode: None, // 7z doesn't preserve Unix permissions
                };

                entries.push(SevenZEntry { info, data });
                Ok(true)
            })
            .map_err(|e| Error::Io(std::io::Error::other(format!("7z read error: {}", e))))?;

        Ok(entries)
    }

    /// Get all entry metadata.
    pub fn entries_metadata(&self) -> Vec<EntryInfo> {
        self.entries.iter().map(|e| e.info.clone()).collect()
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the archive is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Process each entry with a callback.
    pub fn for_each<F>(&self, mut callback: F) -> Result<(), Error>
    where
        F: FnMut(&EntryInfo, Option<&[u8]>) -> Result<bool, Error>,
    {
        for entry in &self.entries {
            let data = if matches!(entry.info.kind, EntryKind::File) {
                Some(entry.data.as_slice())
            } else {
                None
            };

            if !callback(&entry.info, data)? {
                break;
            }
        }
        Ok(())
    }
}
