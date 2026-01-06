use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::prelude::*;
use std::path::PathBuf;

// ============================================================================
// Error Types
// ============================================================================

pyo3::create_exception!(safe_unzip, SafeUnzipError, pyo3::exceptions::PyException);
pyo3::create_exception!(safe_unzip, PathEscapeError, SafeUnzipError);
pyo3::create_exception!(safe_unzip, SymlinkNotAllowedError, SafeUnzipError);
pyo3::create_exception!(safe_unzip, QuotaError, SafeUnzipError);
pyo3::create_exception!(safe_unzip, AlreadyExistsError, SafeUnzipError);
pyo3::create_exception!(safe_unzip, EncryptedArchiveError, SafeUnzipError);
pyo3::create_exception!(safe_unzip, UnsupportedEntryTypeError, SafeUnzipError);

fn to_py_err(err: safe_unzip::Error) -> PyErr {
    match err {
        safe_unzip::Error::PathEscape { entry, detail } => {
            PathEscapeError::new_err(format!("path '{}' escapes destination: {}", entry, detail))
        }
        safe_unzip::Error::SymlinkNotAllowed { entry, target } => {
            if target.is_empty() {
                SymlinkNotAllowedError::new_err(format!(
                    "archive contains symlink '{}' (symlinks not allowed)",
                    entry
                ))
            } else {
                SymlinkNotAllowedError::new_err(format!(
                    "archive contains symlink '{}' -> '{}' (symlinks not allowed)",
                    entry, target
                ))
            }
        }
        safe_unzip::Error::TotalSizeExceeded { limit, would_be } => QuotaError::new_err(format!(
            "extraction would write {} bytes, exceeding the {} byte limit",
            would_be, limit
        )),
        safe_unzip::Error::FileCountExceeded { limit, attempted } => QuotaError::new_err(format!(
            "archive contains {} files, exceeding the {} file limit",
            attempted, limit
        )),
        safe_unzip::Error::FileTooLarge { entry, limit, size } => QuotaError::new_err(format!(
            "file '{}' is {} bytes (limit: {} bytes)",
            entry, size, limit
        )),
        safe_unzip::Error::SizeMismatch {
            entry,
            declared,
            actual,
        } => QuotaError::new_err(format!(
            "file '{}' decompressed to {} bytes but declared {} bytes (possible zip bomb)",
            entry, actual, declared
        )),
        safe_unzip::Error::PathTooDeep {
            entry,
            depth,
            limit,
        } => QuotaError::new_err(format!(
            "path '{}' has {} directory levels (limit: {})",
            entry, depth, limit
        )),
        safe_unzip::Error::AlreadyExists { entry } => {
            AlreadyExistsError::new_err(format!("file '{}' already exists", entry))
        }
        safe_unzip::Error::InvalidFilename { entry, reason } => {
            PathEscapeError::new_err(format!("invalid filename '{}': {}", entry, reason))
        }
        safe_unzip::Error::EncryptedEntry { entry } => EncryptedArchiveError::new_err(format!(
            "entry '{}' is encrypted (encrypted archives not supported)",
            entry
        )),
        safe_unzip::Error::UnsupportedEntryType { entry, entry_type } => {
            UnsupportedEntryTypeError::new_err(format!(
                "entry '{}' has unsupported type '{}' (device files, fifos not allowed)",
                entry, entry_type
            ))
        }
        safe_unzip::Error::DestinationNotFound { path } => {
            PyIOError::new_err(format!("destination directory '{}' does not exist", path))
        }
        safe_unzip::Error::Zip(e) => PyValueError::new_err(format!("zip format error: {}", e)),
        safe_unzip::Error::Io(e) => PyIOError::new_err(format!("I/O error: {}", e)),
        safe_unzip::Error::Jail(e) => {
            PathEscapeError::new_err(format!("path validation error: {}", e))
        }
        // Catch-all for future error variants (Error is #[non_exhaustive])
        _ => SafeUnzipError::new_err(format!("{}", err)),
    }
}

// ============================================================================
// Report
// ============================================================================

#[pyclass(name = "Report")]
#[derive(Clone)]
struct PyReport {
    #[pyo3(get)]
    files_extracted: usize,
    #[pyo3(get)]
    dirs_created: usize,
    #[pyo3(get)]
    bytes_written: u64,
    #[pyo3(get)]
    entries_skipped: usize,
}

#[pymethods]
impl PyReport {
    fn __repr__(&self) -> String {
        format!(
            "Report(files_extracted={}, dirs_created={}, bytes_written={}, entries_skipped={})",
            self.files_extracted, self.dirs_created, self.bytes_written, self.entries_skipped
        )
    }
}

impl From<safe_unzip::Report> for PyReport {
    fn from(r: safe_unzip::Report) -> Self {
        PyReport {
            files_extracted: r.files_extracted,
            dirs_created: r.dirs_created,
            bytes_written: r.bytes_written,
            entries_skipped: r.entries_skipped,
        }
    }
}

impl From<safe_unzip::ExtractionReport> for PyReport {
    fn from(r: safe_unzip::ExtractionReport) -> Self {
        PyReport {
            files_extracted: r.files_extracted,
            dirs_created: r.dirs_created,
            bytes_written: r.bytes_written,
            entries_skipped: r.entries_skipped,
        }
    }
}

// ============================================================================
// EntryInfo (for listing)
// ============================================================================

#[pyclass(name = "EntryInfo")]
#[derive(Clone)]
struct PyEntryInfo {
    #[pyo3(get)]
    name: String,
    #[pyo3(get)]
    size: u64,
    #[pyo3(get)]
    kind: String,
    #[pyo3(get)]
    is_file: bool,
    #[pyo3(get)]
    is_dir: bool,
    #[pyo3(get)]
    is_symlink: bool,
    #[pyo3(get)]
    symlink_target: Option<String>,
}

#[pymethods]
impl PyEntryInfo {
    fn __repr__(&self) -> String {
        format!(
            "EntryInfo(name='{}', size={}, kind='{}')",
            self.name, self.size, self.kind
        )
    }
}

impl From<safe_unzip::EntryInfo> for PyEntryInfo {
    fn from(e: safe_unzip::EntryInfo) -> Self {
        let (kind_str, is_file, is_dir, is_symlink, symlink_target) = match &e.kind {
            safe_unzip::EntryKind::File => ("file".to_string(), true, false, false, None),
            safe_unzip::EntryKind::Directory => ("directory".to_string(), false, true, false, None),
            safe_unzip::EntryKind::Symlink { target } => (
                "symlink".to_string(),
                false,
                false,
                true,
                Some(target.clone()),
            ),
        };
        PyEntryInfo {
            name: e.name,
            size: e.size,
            kind: kind_str,
            is_file,
            is_dir,
            is_symlink,
            symlink_target,
        }
    }
}

// ============================================================================
// Extractor
// ============================================================================

#[pyclass(name = "Extractor")]
struct PyExtractor {
    destination: PathBuf,
    max_total_bytes: u64,
    max_file_count: usize,
    max_single_file: u64,
    max_path_depth: usize,
    overwrite: String,
    symlinks: String,
    mode: String,
    // Filter options
    only_names: Option<Vec<String>>,
    include_patterns: Option<Vec<String>>,
    exclude_patterns: Option<Vec<String>>,
    // Progress callback
    progress_callback: Option<PyObject>,
}

#[pymethods]
impl PyExtractor {
    #[new]
    fn new(destination: PathBuf) -> Self {
        let defaults = safe_unzip::Limits::default();
        PyExtractor {
            destination,
            max_total_bytes: defaults.max_total_bytes,
            max_file_count: defaults.max_file_count,
            max_single_file: defaults.max_single_file,
            max_path_depth: defaults.max_path_depth,
            overwrite: "error".to_string(),
            symlinks: "skip".to_string(),
            mode: "streaming".to_string(),
            only_names: None,
            include_patterns: None,
            exclude_patterns: None,
            progress_callback: None,
        }
    }

    /// Set maximum total bytes to extract.
    fn max_total_mb(mut slf: PyRefMut<'_, Self>, mb: u64) -> PyRefMut<'_, Self> {
        slf.max_total_bytes = mb * 1024 * 1024;
        slf
    }

    /// Set maximum number of files to extract.
    fn max_files(mut slf: PyRefMut<'_, Self>, count: usize) -> PyRefMut<'_, Self> {
        slf.max_file_count = count;
        slf
    }

    /// Set maximum size of a single file.
    fn max_single_file_mb(mut slf: PyRefMut<'_, Self>, mb: u64) -> PyRefMut<'_, Self> {
        slf.max_single_file = mb * 1024 * 1024;
        slf
    }

    /// Set maximum directory depth.
    fn max_depth(mut slf: PyRefMut<'_, Self>, depth: usize) -> PyRefMut<'_, Self> {
        slf.max_path_depth = depth;
        slf
    }

    /// Set overwrite policy: "error", "skip", or "overwrite".
    fn overwrite(mut slf: PyRefMut<'_, Self>, policy: String) -> PyResult<PyRefMut<'_, Self>> {
        match policy.as_str() {
            "error" | "skip" | "overwrite" => {
                slf.overwrite = policy;
                Ok(slf)
            }
            _ => Err(PyValueError::new_err(
                "overwrite must be 'error', 'skip', or 'overwrite'",
            )),
        }
    }

    /// Set symlink policy: "skip" or "error".
    fn symlinks(mut slf: PyRefMut<'_, Self>, policy: String) -> PyResult<PyRefMut<'_, Self>> {
        match policy.as_str() {
            "skip" | "error" => {
                slf.symlinks = policy;
                Ok(slf)
            }
            _ => Err(PyValueError::new_err("symlinks must be 'skip' or 'error'")),
        }
    }

    /// Set extraction mode: "streaming" or "validate_first".
    fn mode(mut slf: PyRefMut<'_, Self>, mode: String) -> PyResult<PyRefMut<'_, Self>> {
        match mode.as_str() {
            "streaming" | "validate_first" => {
                slf.mode = mode;
                Ok(slf)
            }
            _ => Err(PyValueError::new_err(
                "mode must be 'streaming' or 'validate_first'",
            )),
        }
    }

    /// Extract only specific files by exact name.
    ///
    /// Names are matched exactly (case-sensitive).
    ///
    /// Example:
    ///     extractor.only(["README.md", "LICENSE"]).extract_file("archive.zip")
    fn only(mut slf: PyRefMut<'_, Self>, names: Vec<String>) -> PyRefMut<'_, Self> {
        slf.only_names = Some(names);
        slf
    }

    /// Include only files matching glob patterns.
    ///
    /// Patterns: `*` matches except `/`, `**` matches including `/`, `?` matches one char.
    ///
    /// Example:
    ///     extractor.include_glob(["**/*.py"]).extract_file("archive.zip")
    fn include_glob(mut slf: PyRefMut<'_, Self>, patterns: Vec<String>) -> PyRefMut<'_, Self> {
        slf.include_patterns = Some(patterns);
        slf
    }

    /// Exclude files matching glob patterns.
    ///
    /// Example:
    ///     extractor.exclude_glob(["**/__pycache__/**"]).extract_file("archive.zip")
    fn exclude_glob(mut slf: PyRefMut<'_, Self>, patterns: Vec<String>) -> PyRefMut<'_, Self> {
        slf.exclude_patterns = Some(patterns);
        slf
    }

    /// Set a progress callback.
    ///
    /// The callback is called before processing each entry with a dict containing:
    /// - entry_name: str
    /// - entry_size: int
    /// - entry_index: int
    /// - total_entries: int
    /// - bytes_written: int
    /// - files_extracted: int
    ///
    /// Example:
    ///     def on_progress(p):
    ///         print(f"[{p['entry_index']+1}/{p['total_entries']}] {p['entry_name']}")
    ///     
    ///     extractor.on_progress(on_progress).extract_file("archive.zip")
    fn on_progress(mut slf: PyRefMut<'_, Self>, callback: PyObject) -> PyRefMut<'_, Self> {
        slf.progress_callback = Some(callback);
        slf
    }

    /// Extract from a file path.
    fn extract_file(&self, path: PathBuf) -> PyResult<PyReport> {
        let extractor = self.build_extractor()?;
        let report = extractor.extract_file(path).map_err(to_py_err)?;
        Ok(report.into())
    }

    /// Extract from bytes.
    fn extract_bytes(&self, data: &[u8]) -> PyResult<PyReport> {
        let extractor = self.build_extractor()?;
        let cursor = std::io::Cursor::new(data.to_vec());
        let report = extractor.extract(cursor).map_err(to_py_err)?;
        Ok(report.into())
    }

    /// Extract a TAR file.
    fn extract_tar_file(&self, path: PathBuf) -> PyResult<PyReport> {
        let driver = self.build_driver()?;
        let report = driver.extract_tar_file(path).map_err(to_py_err)?;
        Ok(report.into())
    }

    /// Extract a gzip-compressed TAR file (.tar.gz, .tgz).
    fn extract_tar_gz_file(&self, path: PathBuf) -> PyResult<PyReport> {
        let driver = self.build_driver()?;
        let report = driver.extract_tar_gz_file(path).map_err(to_py_err)?;
        Ok(report.into())
    }

    /// Extract TAR from bytes.
    fn extract_tar_bytes(&self, data: &[u8]) -> PyResult<PyReport> {
        let driver = self.build_driver()?;
        let cursor = std::io::Cursor::new(data.to_vec());
        let adapter = safe_unzip::TarAdapter::new(cursor);
        let report = driver.extract_tar(adapter).map_err(to_py_err)?;
        Ok(report.into())
    }

    /// Extract gzip-compressed TAR from bytes.
    fn extract_tar_gz_bytes(&self, data: &[u8]) -> PyResult<PyReport> {
        use flate2::read::GzDecoder;
        let driver = self.build_driver()?;
        let cursor = std::io::Cursor::new(data.to_vec());
        let decoder = GzDecoder::new(cursor);
        let adapter = safe_unzip::TarAdapter::new(decoder);
        let report = driver.extract_tar(adapter).map_err(to_py_err)?;
        Ok(report.into())
    }

    /// Extract a 7z file.
    fn extract_7z_file(&self, path: PathBuf) -> PyResult<PyReport> {
        let driver = self.build_driver()?;
        let report = driver.extract_7z_file(path).map_err(to_py_err)?;
        Ok(report.into())
    }

    /// Extract 7z from bytes.
    fn extract_7z_bytes(&self, data: &[u8]) -> PyResult<PyReport> {
        let driver = self.build_driver()?;
        let report = driver.extract_7z_bytes(data).map_err(to_py_err)?;
        Ok(report.into())
    }
}

impl PyExtractor {
    fn build_extractor(&self) -> PyResult<safe_unzip::Extractor> {
        let mut extractor = safe_unzip::Extractor::new(&self.destination).map_err(to_py_err)?;

        extractor = extractor.limits(safe_unzip::Limits {
            max_total_bytes: self.max_total_bytes,
            max_file_count: self.max_file_count,
            max_single_file: self.max_single_file,
            max_path_depth: self.max_path_depth,
        });

        extractor = match self.overwrite.as_str() {
            "skip" => extractor.overwrite(safe_unzip::OverwritePolicy::Skip),
            "overwrite" => extractor.overwrite(safe_unzip::OverwritePolicy::Overwrite),
            _ => extractor.overwrite(safe_unzip::OverwritePolicy::Error),
        };

        extractor = match self.symlinks.as_str() {
            "error" => extractor.symlinks(safe_unzip::SymlinkPolicy::Error),
            _ => extractor.symlinks(safe_unzip::SymlinkPolicy::Skip),
        };

        extractor = match self.mode.as_str() {
            "validate_first" => extractor.mode(safe_unzip::ExtractionMode::ValidateFirst),
            _ => extractor.mode(safe_unzip::ExtractionMode::Streaming),
        };

        // Apply filters
        if let Some(ref names) = self.only_names {
            extractor = extractor.only(names);
        }
        if let Some(ref patterns) = self.include_patterns {
            extractor = extractor.include_glob(patterns);
        }
        if let Some(ref patterns) = self.exclude_patterns {
            extractor = extractor.exclude_glob(patterns);
        }

        // Apply progress callback
        if let Some(ref callback) = self.progress_callback {
            // Clone with GIL to get a 'static PyObject
            let callback: PyObject = Python::with_gil(|py| callback.clone_ref(py));
            extractor = extractor.on_progress(move |progress| {
                Python::with_gil(|py| {
                    let dict = pyo3::types::PyDict::new(py);
                    let _ = dict.set_item("entry_name", &progress.entry_name);
                    let _ = dict.set_item("entry_size", progress.entry_size);
                    let _ = dict.set_item("entry_index", progress.entry_index);
                    let _ = dict.set_item("total_entries", progress.total_entries);
                    let _ = dict.set_item("bytes_written", progress.bytes_written);
                    let _ = dict.set_item("files_extracted", progress.files_extracted);
                    let _ = callback.call1(py, (dict,));
                });
            });
        }

        Ok(extractor)
    }

    fn build_driver(&self) -> PyResult<safe_unzip::Driver> {
        let mut driver = safe_unzip::Driver::new(&self.destination).map_err(to_py_err)?;

        driver = driver.limits(safe_unzip::Limits {
            max_total_bytes: self.max_total_bytes,
            max_file_count: self.max_file_count,
            max_single_file: self.max_single_file,
            max_path_depth: self.max_path_depth,
        });

        driver = match self.overwrite.as_str() {
            "skip" => driver.overwrite(safe_unzip::OverwriteMode::Skip),
            "overwrite" => driver.overwrite(safe_unzip::OverwriteMode::Overwrite),
            _ => driver.overwrite(safe_unzip::OverwriteMode::Error),
        };

        driver = match self.symlinks.as_str() {
            "error" => driver.symlinks(safe_unzip::SymlinkBehavior::Error),
            _ => driver.symlinks(safe_unzip::SymlinkBehavior::Skip),
        };

        driver = match self.mode.as_str() {
            "validate_first" => driver.validation(safe_unzip::ValidationMode::ValidateFirst),
            _ => driver.validation(safe_unzip::ValidationMode::Streaming),
        };

        // Apply filters
        if let Some(ref names) = self.only_names {
            driver = driver.only(names);
        }
        if let Some(ref patterns) = self.include_patterns {
            driver = driver.include_glob(patterns);
        }
        if let Some(ref patterns) = self.exclude_patterns {
            driver = driver.exclude_glob(patterns);
        }

        Ok(driver)
    }
}

// ============================================================================
// Convenience Functions
// ============================================================================

/// Extract a zip file with default settings.
#[pyfunction]
fn extract_file(destination: PathBuf, path: PathBuf) -> PyResult<PyReport> {
    let report = safe_unzip::extract_file(&destination, &path).map_err(to_py_err)?;
    Ok(report.into())
}

/// Extract from bytes with default settings.
#[pyfunction]
fn extract_bytes(destination: PathBuf, data: &[u8]) -> PyResult<PyReport> {
    let cursor = std::io::Cursor::new(data.to_vec());
    let extractor = safe_unzip::Extractor::new(&destination).map_err(to_py_err)?;
    let report = extractor.extract(cursor).map_err(to_py_err)?;
    Ok(report.into())
}

/// Extract a TAR file with default settings.
#[pyfunction]
fn extract_tar_file(destination: PathBuf, path: PathBuf) -> PyResult<PyReport> {
    let driver = safe_unzip::Driver::new_or_create(&destination).map_err(to_py_err)?;
    let report = driver.extract_tar_file(path).map_err(to_py_err)?;
    Ok(report.into())
}

/// Extract a gzip-compressed TAR file (.tar.gz, .tgz) with default settings.
#[pyfunction]
fn extract_tar_gz_file(destination: PathBuf, path: PathBuf) -> PyResult<PyReport> {
    let driver = safe_unzip::Driver::new_or_create(&destination).map_err(to_py_err)?;
    let report = driver.extract_tar_gz_file(path).map_err(to_py_err)?;
    Ok(report.into())
}

/// Extract TAR from bytes with default settings.
#[pyfunction]
fn extract_tar_bytes(destination: PathBuf, data: &[u8]) -> PyResult<PyReport> {
    let driver = safe_unzip::Driver::new_or_create(&destination).map_err(to_py_err)?;
    let cursor = std::io::Cursor::new(data.to_vec());
    let adapter = safe_unzip::TarAdapter::new(cursor);
    let report = driver.extract_tar(adapter).map_err(to_py_err)?;
    Ok(report.into())
}

/// Extract a 7z file with default settings.
#[pyfunction]
fn extract_7z_file(destination: PathBuf, path: PathBuf) -> PyResult<PyReport> {
    let driver = safe_unzip::Driver::new_or_create(&destination).map_err(to_py_err)?;
    let report = driver.extract_7z_file(path).map_err(to_py_err)?;
    Ok(report.into())
}

/// Extract 7z from bytes with default settings.
#[pyfunction]
fn extract_7z_bytes(destination: PathBuf, data: &[u8]) -> PyResult<PyReport> {
    let driver = safe_unzip::Driver::new_or_create(&destination).map_err(to_py_err)?;
    let report = driver.extract_7z_bytes(data).map_err(to_py_err)?;
    Ok(report.into())
}

// ============================================================================
// Listing Functions
// ============================================================================

/// List entries in a ZIP file without extracting.
#[pyfunction]
fn list_zip_entries(path: PathBuf) -> PyResult<Vec<PyEntryInfo>> {
    let entries = safe_unzip::list_zip_entries(&path).map_err(to_py_err)?;
    Ok(entries.into_iter().map(PyEntryInfo::from).collect())
}

/// List entries in a ZIP from bytes without extracting.
#[pyfunction]
fn list_zip_bytes(data: &[u8]) -> PyResult<Vec<PyEntryInfo>> {
    let cursor = std::io::Cursor::new(data.to_vec());
    let entries = safe_unzip::list_zip(cursor).map_err(to_py_err)?;
    Ok(entries.into_iter().map(PyEntryInfo::from).collect())
}

/// List entries in a TAR file without extracting.
#[pyfunction]
fn list_tar_entries(path: PathBuf) -> PyResult<Vec<PyEntryInfo>> {
    let entries = safe_unzip::list_tar_entries(&path).map_err(to_py_err)?;
    Ok(entries.into_iter().map(PyEntryInfo::from).collect())
}

/// List entries in a gzip-compressed TAR file without extracting.
#[pyfunction]
fn list_tar_gz_entries(path: PathBuf) -> PyResult<Vec<PyEntryInfo>> {
    let entries = safe_unzip::list_tar_gz_entries(&path).map_err(to_py_err)?;
    Ok(entries.into_iter().map(PyEntryInfo::from).collect())
}

/// List entries in a TAR from bytes without extracting.
#[pyfunction]
fn list_tar_bytes(data: &[u8]) -> PyResult<Vec<PyEntryInfo>> {
    let cursor = std::io::Cursor::new(data.to_vec());
    let entries = safe_unzip::list_tar(cursor).map_err(to_py_err)?;
    Ok(entries.into_iter().map(PyEntryInfo::from).collect())
}

// ============================================================================
// Verification Report
// ============================================================================

/// Report returned by verify functions.
#[pyclass(name = "VerifyReport")]
#[derive(Clone)]
struct PyVerifyReport {
    #[pyo3(get)]
    entries_verified: usize,
    #[pyo3(get)]
    bytes_verified: u64,
}

impl From<safe_unzip::VerifyReport> for PyVerifyReport {
    fn from(r: safe_unzip::VerifyReport) -> Self {
        Self {
            entries_verified: r.entries_verified,
            bytes_verified: r.bytes_verified,
        }
    }
}

#[pymethods]
impl PyVerifyReport {
    fn __repr__(&self) -> String {
        format!(
            "VerifyReport(entries_verified={}, bytes_verified={})",
            self.entries_verified, self.bytes_verified
        )
    }
}

// ============================================================================
// Verification Functions
// ============================================================================

/// Verify archive integrity by checking CRC32 for all entries.
///
/// Reads and decompresses all file entries without writing to disk.
/// Returns a VerifyReport on success, raises an exception on CRC failure.
#[pyfunction]
fn verify_file(path: PathBuf) -> PyResult<PyVerifyReport> {
    let report = safe_unzip::verify_file(&path).map_err(to_py_err)?;
    Ok(PyVerifyReport::from(report))
}

/// Verify archive integrity from bytes.
#[pyfunction]
fn verify_bytes(data: &[u8]) -> PyResult<PyVerifyReport> {
    let report = safe_unzip::verify_bytes(data).map_err(to_py_err)?;
    Ok(PyVerifyReport::from(report))
}

// ============================================================================
// Module
// ============================================================================

#[pymodule]
fn _safe_unzip(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Classes
    m.add_class::<PyExtractor>()?;
    m.add_class::<PyReport>()?;
    m.add_class::<PyVerifyReport>()?;
    m.add_class::<PyEntryInfo>()?;

    // Functions - ZIP extraction
    m.add_function(wrap_pyfunction!(extract_file, m)?)?;
    m.add_function(wrap_pyfunction!(extract_bytes, m)?)?;

    // Functions - TAR extraction
    m.add_function(wrap_pyfunction!(extract_tar_file, m)?)?;
    m.add_function(wrap_pyfunction!(extract_tar_gz_file, m)?)?;
    m.add_function(wrap_pyfunction!(extract_tar_bytes, m)?)?;

    // Functions - 7z extraction
    m.add_function(wrap_pyfunction!(extract_7z_file, m)?)?;
    m.add_function(wrap_pyfunction!(extract_7z_bytes, m)?)?;

    // Functions - Listing (no extraction)
    m.add_function(wrap_pyfunction!(list_zip_entries, m)?)?;
    m.add_function(wrap_pyfunction!(list_zip_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(list_tar_entries, m)?)?;
    m.add_function(wrap_pyfunction!(list_tar_gz_entries, m)?)?;
    m.add_function(wrap_pyfunction!(list_tar_bytes, m)?)?;

    // Functions - Verification (no extraction)
    m.add_function(wrap_pyfunction!(verify_file, m)?)?;
    m.add_function(wrap_pyfunction!(verify_bytes, m)?)?;

    // Exceptions
    m.add("SafeUnzipError", py.get_type::<SafeUnzipError>())?;
    m.add("PathEscapeError", py.get_type::<PathEscapeError>())?;
    m.add(
        "SymlinkNotAllowedError",
        py.get_type::<SymlinkNotAllowedError>(),
    )?;
    m.add("QuotaError", py.get_type::<QuotaError>())?;
    m.add("AlreadyExistsError", py.get_type::<AlreadyExistsError>())?;
    m.add(
        "EncryptedArchiveError",
        py.get_type::<EncryptedArchiveError>(),
    )?;
    m.add(
        "UnsupportedEntryTypeError",
        py.get_type::<UnsupportedEntryTypeError>(),
    )?;

    Ok(())
}
