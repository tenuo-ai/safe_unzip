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
pub use extractor::{EntryInfo, ExtractionMode, Extractor, OverwritePolicy, Report, SymlinkPolicy};
pub use limits::Limits;

// Re-export new types
pub use adapter::{TarAdapter, ZipAdapter};
pub use driver::{Driver, ExtractionReport, OverwriteMode, ValidationMode};
pub use entry::{Entry, EntryKind};
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
