mod error;
mod extractor;
mod limits;

pub use error::Error;
pub use limits::Limits;
pub use extractor::{Extractor, OverwritePolicy, SymlinkPolicy, ExtractionMode, Report, EntryInfo};

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