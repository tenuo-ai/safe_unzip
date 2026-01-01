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

        Ok(extractor)
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

// ============================================================================
// Module
// ============================================================================

#[pymodule]
fn _safe_unzip(py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    // Classes
    m.add_class::<PyExtractor>()?;
    m.add_class::<PyReport>()?;

    // Functions
    m.add_function(wrap_pyfunction!(extract_file, m)?)?;
    m.add_function(wrap_pyfunction!(extract_bytes, m)?)?;

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
