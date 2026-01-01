//! Async extraction API (requires the `async` feature).
//!
//! This module provides async versions of the extraction functions. Since the underlying
//! `zip` and `tar` crates are synchronous, extraction runs in a blocking thread pool
//! via [`tokio::task::spawn_blocking`].
//!
//! # Example
//!
//! ```no_run
//! use safe_unzip::r#async::{extract_file, AsyncExtractor};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), safe_unzip::Error> {
//!     // Simple extraction
//!     let report = extract_file("/var/uploads", "archive.zip").await?;
//!     
//!     // With options
//!     let report = AsyncExtractor::new("/var/uploads")?
//!         .max_total_bytes(500 * 1024 * 1024)
//!         .max_file_count(1000)
//!         .extract_file("archive.zip")
//!         .await?;
//!     
//!     println!("Extracted {} files", report.files_extracted);
//!     Ok(())
//! }
//! ```
//!
//! # When to Use Async
//!
//! Use async extraction when:
//! - You're in an async runtime (tokio, async-std)
//! - You want to extract multiple archives concurrently
//! - You need to interleave extraction with other async I/O
//!
//! For simple scripts or sync contexts, use the regular [`crate::extract`] functions.

use crate::{
    Driver, Error, ExtractionMode, ExtractionReport, Extractor, Limits, OverwriteMode,
    OverwritePolicy, Report, SymlinkBehavior, SymlinkPolicy, TarAdapter, ValidationMode,
};
use std::path::{Path, PathBuf};
use tokio::task::spawn_blocking;

/// Async extractor with the same security guarantees as [`Extractor`].
///
/// This wraps the synchronous extractor and runs extraction in a blocking thread pool.
/// All configuration options from [`Extractor`] are available.
#[derive(Clone)]
pub struct AsyncExtractor {
    destination: PathBuf,
    limits: Limits,
    overwrite: OverwritePolicy,
    symlinks: SymlinkPolicy,
    mode: ExtractionMode,
    create_destination: bool,
}

impl AsyncExtractor {
    /// Create an async extractor for the given destination directory.
    ///
    /// Returns [`Error::DestinationNotFound`] if the directory doesn't exist.
    /// Use [`Self::new_or_create`] to auto-create the destination.
    pub fn new<P: AsRef<Path>>(destination: P) -> Result<Self, Error> {
        let dest = destination.as_ref();
        if !dest.exists() {
            return Err(Error::DestinationNotFound {
                path: dest.display().to_string(),
            });
        }
        Ok(Self {
            destination: dest.to_path_buf(),
            limits: Limits::default(),
            overwrite: OverwritePolicy::default(),
            symlinks: SymlinkPolicy::default(),
            mode: ExtractionMode::default(),
            create_destination: false,
        })
    }

    /// Create an async extractor, creating the destination directory if needed.
    pub fn new_or_create<P: AsRef<Path>>(destination: P) -> Result<Self, Error> {
        let dest = destination.as_ref();
        if !dest.exists() {
            std::fs::create_dir_all(dest)?;
        }
        Ok(Self {
            destination: dest.to_path_buf(),
            limits: Limits::default(),
            overwrite: OverwritePolicy::default(),
            symlinks: SymlinkPolicy::default(),
            mode: ExtractionMode::default(),
            create_destination: true,
        })
    }

    /// Set resource limits.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Set maximum total bytes to extract.
    pub fn max_total_bytes(mut self, bytes: u64) -> Self {
        self.limits.max_total_bytes = bytes;
        self
    }

    /// Set maximum number of files to extract.
    pub fn max_file_count(mut self, count: usize) -> Self {
        self.limits.max_file_count = count;
        self
    }

    /// Set maximum size for a single file.
    pub fn max_single_file(mut self, bytes: u64) -> Self {
        self.limits.max_single_file = bytes;
        self
    }

    /// Set maximum directory depth.
    pub fn max_path_depth(mut self, depth: usize) -> Self {
        self.limits.max_path_depth = depth;
        self
    }

    /// Set overwrite policy.
    pub fn overwrite(mut self, policy: OverwritePolicy) -> Self {
        self.overwrite = policy;
        self
    }

    /// Set symlink policy.
    pub fn symlinks(mut self, policy: SymlinkPolicy) -> Self {
        self.symlinks = policy;
        self
    }

    /// Set extraction mode.
    pub fn mode(mut self, mode: ExtractionMode) -> Self {
        self.mode = mode;
        self
    }

    /// Extract a ZIP file asynchronously.
    ///
    /// The actual extraction runs in a blocking thread pool.
    pub async fn extract_file<P: AsRef<Path>>(&self, path: P) -> Result<Report, Error> {
        let extractor = self.build_sync_extractor()?;
        let path = path.as_ref().to_path_buf();

        spawn_blocking(move || extractor.extract_file(path))
            .await
            .map_err(|e| Error::Io(std::io::Error::other(e)))?
    }

    /// Extract a ZIP from bytes asynchronously.
    pub async fn extract_bytes(&self, data: Vec<u8>) -> Result<Report, Error> {
        let extractor = self.build_sync_extractor()?;

        spawn_blocking(move || {
            let cursor = std::io::Cursor::new(data);
            extractor.extract(cursor)
        })
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e)))?
    }

    /// Extract a TAR file asynchronously.
    pub async fn extract_tar_file<P: AsRef<Path>>(&self, path: P) -> Result<Report, Error> {
        let driver = self.build_driver()?;
        let path = path.as_ref().to_path_buf();

        let report = spawn_blocking(move || driver.extract_tar_file(path))
            .await
            .map_err(|e| Error::Io(std::io::Error::other(e)))??;
        Ok(extraction_report_to_report(report))
    }

    /// Extract a gzip-compressed TAR file asynchronously.
    pub async fn extract_tar_gz_file<P: AsRef<Path>>(&self, path: P) -> Result<Report, Error> {
        let driver = self.build_driver()?;
        let path = path.as_ref().to_path_buf();

        let report = spawn_blocking(move || driver.extract_tar_gz_file(path))
            .await
            .map_err(|e| Error::Io(std::io::Error::other(e)))??;
        Ok(extraction_report_to_report(report))
    }

    /// Extract a TAR from bytes asynchronously.
    pub async fn extract_tar_bytes(&self, data: Vec<u8>) -> Result<Report, Error> {
        let driver = self.build_driver()?;

        let report = spawn_blocking(move || {
            let cursor = std::io::Cursor::new(data);
            let adapter = TarAdapter::new(cursor);
            driver.extract_tar(adapter)
        })
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e)))??;
        Ok(extraction_report_to_report(report))
    }

    /// Extract a gzip-compressed TAR from bytes asynchronously.
    pub async fn extract_tar_gz_bytes(&self, data: Vec<u8>) -> Result<Report, Error> {
        let driver = self.build_driver()?;

        let report = spawn_blocking(move || {
            let cursor = std::io::Cursor::new(data);
            let decoder = flate2::read::GzDecoder::new(cursor);
            let adapter = TarAdapter::new(decoder);
            driver.extract_tar(adapter)
        })
        .await
        .map_err(|e| Error::Io(std::io::Error::other(e)))??;
        Ok(extraction_report_to_report(report))
    }

    fn build_sync_extractor(&self) -> Result<Extractor, Error> {
        let extractor = if self.create_destination {
            Extractor::new_or_create(&self.destination)?
        } else {
            Extractor::new(&self.destination)?
        };

        Ok(extractor
            .limits(self.limits)
            .overwrite(self.overwrite)
            .symlinks(self.symlinks)
            .mode(self.mode))
    }

    fn build_driver(&self) -> Result<Driver, Error> {
        let driver = if self.create_destination {
            Driver::new_or_create(&self.destination)?
        } else {
            Driver::new(&self.destination)?
        };

        Ok(driver
            .limits(self.limits)
            .overwrite(convert_overwrite_policy(self.overwrite))
            .symlinks(convert_symlink_policy(self.symlinks))
            .validation(convert_extraction_mode(self.mode)))
    }
}

// Helper to convert between report types
fn extraction_report_to_report(report: ExtractionReport) -> Report {
    Report {
        files_extracted: report.files_extracted,
        dirs_created: report.dirs_created,
        bytes_written: report.bytes_written,
        entries_skipped: report.entries_skipped,
    }
}

// Helper to convert policy types
fn convert_overwrite_policy(policy: OverwritePolicy) -> OverwriteMode {
    match policy {
        OverwritePolicy::Error => OverwriteMode::Error,
        OverwritePolicy::Skip => OverwriteMode::Skip,
        OverwritePolicy::Overwrite => OverwriteMode::Overwrite,
    }
}

fn convert_symlink_policy(policy: SymlinkPolicy) -> SymlinkBehavior {
    match policy {
        SymlinkPolicy::Skip => SymlinkBehavior::Skip,
        SymlinkPolicy::Error => SymlinkBehavior::Error,
    }
}

fn convert_extraction_mode(mode: ExtractionMode) -> ValidationMode {
    match mode {
        ExtractionMode::Streaming => ValidationMode::Streaming,
        ExtractionMode::ValidateFirst => ValidationMode::ValidateFirst,
    }
}

// ============================================================================
// Convenience functions
// ============================================================================

/// Extract a ZIP file asynchronously with default settings.
///
/// Creates the destination directory if it doesn't exist.
///
/// # Example
///
/// ```no_run
/// use safe_unzip::r#async::extract_file;
///
/// #[tokio::main]
/// async fn main() -> Result<(), safe_unzip::Error> {
///     let report = extract_file("/var/uploads", "archive.zip").await?;
///     println!("Extracted {} files", report.files_extracted);
///     Ok(())
/// }
/// ```
pub async fn extract_file<D, F>(destination: D, file_path: F) -> Result<Report, Error>
where
    D: AsRef<Path>,
    F: AsRef<Path>,
{
    AsyncExtractor::new_or_create(destination)?
        .extract_file(file_path)
        .await
}

/// Extract a ZIP from bytes asynchronously with default settings.
///
/// Creates the destination directory if it doesn't exist.
pub async fn extract_bytes<D>(destination: D, data: Vec<u8>) -> Result<Report, Error>
where
    D: AsRef<Path>,
{
    AsyncExtractor::new_or_create(destination)?
        .extract_bytes(data)
        .await
}

/// Extract a TAR file asynchronously with default settings.
///
/// Creates the destination directory if it doesn't exist.
///
/// # Example
///
/// ```no_run
/// use safe_unzip::r#async::extract_tar_file;
///
/// #[tokio::main]
/// async fn main() -> Result<(), safe_unzip::Error> {
///     let report = extract_tar_file("/var/uploads", "archive.tar").await?;
///     println!("Extracted {} files", report.files_extracted);
///     Ok(())
/// }
/// ```
pub async fn extract_tar_file<D, F>(destination: D, file_path: F) -> Result<Report, Error>
where
    D: AsRef<Path>,
    F: AsRef<Path>,
{
    AsyncExtractor::new_or_create(destination)?
        .extract_tar_file(file_path)
        .await
}

/// Extract a gzip-compressed TAR file asynchronously with default settings.
///
/// Creates the destination directory if it doesn't exist.
///
/// # Example
///
/// ```no_run
/// use safe_unzip::r#async::extract_tar_gz_file;
///
/// #[tokio::main]
/// async fn main() -> Result<(), safe_unzip::Error> {
///     let report = extract_tar_gz_file("/var/uploads", "archive.tar.gz").await?;
///     println!("Extracted {} files", report.files_extracted);
///     Ok(())
/// }
/// ```
pub async fn extract_tar_gz_file<D, F>(destination: D, file_path: F) -> Result<Report, Error>
where
    D: AsRef<Path>,
    F: AsRef<Path>,
{
    AsyncExtractor::new_or_create(destination)?
        .extract_tar_gz_file(file_path)
        .await
}

/// Extract a TAR from bytes asynchronously with default settings.
///
/// Creates the destination directory if it doesn't exist.
pub async fn extract_tar_bytes<D>(destination: D, data: Vec<u8>) -> Result<Report, Error>
where
    D: AsRef<Path>,
{
    AsyncExtractor::new_or_create(destination)?
        .extract_tar_bytes(data)
        .await
}

/// Extract a gzip-compressed TAR from bytes asynchronously with default settings.
///
/// Creates the destination directory if it doesn't exist.
pub async fn extract_tar_gz_bytes<D>(destination: D, data: Vec<u8>) -> Result<Report, Error>
where
    D: AsRef<Path>,
{
    AsyncExtractor::new_or_create(destination)?
        .extract_tar_gz_bytes(data)
        .await
}
