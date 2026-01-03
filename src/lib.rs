mod error;
mod extractor;
mod limits;

// New architecture modules (v0.2)
pub mod adapter;
mod driver;
pub mod entry;
pub mod policy;

// Async API (requires `async` feature)
#[cfg(feature = "async")]
mod async_extractor;

/// Async extraction API.
///
/// This module provides async versions of the extraction functions. Requires the
/// `async` feature to be enabled.
///
/// ```toml
/// [dependencies]
/// safe_unzip = { version = "0.1", features = ["async"] }
/// ```
///
/// # Example
///
/// ```no_run
/// use safe_unzip::r#async::{extract_file, AsyncExtractor};
///
/// #[tokio::main]
/// async fn main() -> Result<(), safe_unzip::Error> {
///     // Simple extraction
///     let report = extract_file("/var/uploads", "archive.zip").await?;
///     
///     // With options
///     let report = AsyncExtractor::new("/var/uploads")?
///         .max_total_bytes(500 * 1024 * 1024)
///         .extract_file("archive.zip")
///         .await?;
///     
///     Ok(())
/// }
/// ```
#[cfg(feature = "async")]
pub mod r#async {
    pub use crate::async_extractor::*;
}

pub use error::Error;
pub use extractor::{ExtractionMode, Extractor, OverwritePolicy, Progress, Report, SymlinkPolicy};
pub use limits::Limits;

// Re-export new types
#[cfg(feature = "sevenz")]
pub use adapter::SevenZAdapter;
#[cfg(feature = "tar")]
pub use adapter::TarAdapter;
pub use adapter::ZipAdapter;
pub use driver::{Driver, ExtractionReport, OverwriteMode, ValidationMode};
pub use entry::{Entry, EntryInfo, EntryKind};
pub use policy::{Policy, PolicyChain, PolicyConfig, SymlinkBehavior};

/// Extract from a reader with default settings.
///
/// This is the "just works" convenience API. It creates the destination directory
/// if it doesn't exist. For more control, use [`Extractor`] directly.
///
/// # Destination Creation
///
/// Unlike [`Extractor::new`], this function creates the destination directory if
/// it doesn't exist. This is convenient but means typos like `/var/uplaods` will
/// silently create a wrong directory. For user-facing code where you want to catch
/// such errors, use [`Extractor::new`] instead.
///
/// # Seekable Reader Required
///
/// The reader must implement [`std::io::Seek`] because zip files store the central
/// directory at the end. For non-seekable streams, buffer into a [`std::io::Cursor`] first.
///
/// # Example
///
/// ```no_run
/// use std::io::Cursor;
/// use safe_unzip::extract;
///
/// let zip_bytes = std::fs::read("archive.zip")?;
/// let report = extract("/var/uploads", Cursor::new(zip_bytes))?;
/// # Ok::<(), safe_unzip::Error>(())
/// ```
pub fn extract<P, R>(destination: P, reader: R) -> Result<Report, Error>
where
    P: AsRef<std::path::Path>,
    R: std::io::Read + std::io::Seek,
{
    Extractor::new_or_create(destination)?.extract(reader)
}

/// Extract from a file path with default settings.
///
/// This is the "just works" convenience API. It creates the destination directory
/// if it doesn't exist. For more control, use [`Extractor`] directly.
///
/// # Destination Creation
///
/// Unlike [`Extractor::new`], this function creates the destination directory if
/// it doesn't exist. This is convenient but means typos like `/var/uplaods` will
/// silently create a wrong directory. For user-facing code where you want to catch
/// such errors, use [`Extractor::new`] instead.
///
/// # Example
///
/// ```no_run
/// use safe_unzip::extract_file;
///
/// let report = extract_file("/var/uploads", "archive.zip")?;
/// println!("Extracted {} files", report.files_extracted);
/// # Ok::<(), safe_unzip::Error>(())
/// ```
pub fn extract_file<P, F>(destination: P, file_path: F) -> Result<Report, Error>
where
    P: AsRef<std::path::Path>,
    F: AsRef<std::path::Path>,
{
    let file = std::fs::File::open(file_path)?;
    let reader = std::io::BufReader::new(file);
    Extractor::new_or_create(destination)?.extract(reader)
}

/// List entries in a ZIP archive without extracting.
///
/// Returns metadata for all entries including name, size, and type.
/// No files are written to disk.
///
/// # Example
///
/// ```no_run
/// use safe_unzip::list_zip_entries;
///
/// let entries = list_zip_entries("archive.zip")?;
/// for entry in entries {
///     println!("{}: {} bytes, {:?}", entry.name, entry.size, entry.kind);
/// }
/// # Ok::<(), safe_unzip::Error>(())
/// ```
pub fn list_zip_entries<P: AsRef<std::path::Path>>(
    path: P,
) -> Result<Vec<entry::EntryInfo>, Error> {
    let mut adapter = ZipAdapter::open(path)?;
    adapter.entries_metadata()
}

/// List entries in a ZIP archive from a reader.
pub fn list_zip<R: std::io::Read + std::io::Seek>(
    reader: R,
) -> Result<Vec<entry::EntryInfo>, Error> {
    let mut adapter = ZipAdapter::new(reader)?;
    adapter.entries_metadata()
}

/// List entries in a TAR archive without extracting.
///
/// Note: TAR is a sequential format, so listing requires reading
/// through the entire archive (but not decompressing file content).
///
/// # Example
///
/// ```no_run
/// use safe_unzip::list_tar_entries;
///
/// let entries = list_tar_entries("archive.tar")?;
/// for entry in entries {
///     println!("{}: {} bytes", entry.name, entry.size);
/// }
/// # Ok::<(), safe_unzip::Error>(())
/// ```
#[cfg(feature = "tar")]
pub fn list_tar_entries<P: AsRef<std::path::Path>>(
    path: P,
) -> Result<Vec<entry::EntryInfo>, Error> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    list_tar(reader)
}

/// List entries in a gzip-compressed TAR archive.
#[cfg(feature = "tar")]
pub fn list_tar_gz_entries<P: AsRef<std::path::Path>>(
    path: P,
) -> Result<Vec<entry::EntryInfo>, Error> {
    let file = std::fs::File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let decoder = flate2::read::GzDecoder::new(reader);
    list_tar(decoder)
}

/// List entries in a TAR archive from a reader.
#[cfg(feature = "tar")]
pub fn list_tar<R: std::io::Read>(reader: R) -> Result<Vec<entry::EntryInfo>, Error> {
    let mut entries = Vec::new();
    let mut archive = tar::Archive::new(reader);

    for entry_result in archive.entries()? {
        let entry = entry_result?;
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
            other => {
                return Err(Error::UnsupportedEntryType {
                    entry: name,
                    entry_type: format!("{:?}", other),
                });
            }
        };

        entries.push(entry::EntryInfo {
            name,
            size: header.size()?,
            kind,
            mode: header.mode().ok(),
        });
    }

    Ok(entries)
}
