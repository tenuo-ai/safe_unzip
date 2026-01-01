use std::fmt;

/// Errors that can occur during archive extraction.
///
/// This enum is marked `#[non_exhaustive]` to allow adding new variants
/// in minor versions without breaking existing code. Always include a
/// catch-all `_ =>` arm when matching.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Path escapes destination directory (Zip Slip).
    PathEscape { entry: String, detail: String },

    /// Archive contains symlink and policy is Error.
    SymlinkNotAllowed { entry: String, target: String },

    /// Exceeded maximum total bytes.
    TotalSizeExceeded { limit: u64, would_be: u64 },

    /// Exceeded maximum file count.
    FileCountExceeded { limit: usize, attempted: usize },

    /// Single file exceeds size limit.
    FileTooLarge {
        entry: String,
        limit: u64,
        size: u64,
    },

    /// Actual decompressed size exceeds declared size (potential zip bomb).
    SizeMismatch {
        entry: String,
        declared: u64,
        actual: u64,
    },

    /// Path exceeds depth limit.
    PathTooDeep {
        entry: String,
        depth: usize,
        limit: usize,
    },

    /// File already exists and policy is Error.
    AlreadyExists { entry: String },

    /// Destination directory does not exist or is invalid.
    DestinationNotFound { path: String },

    /// Filename contains invalid characters or reserved names.
    InvalidFilename { entry: String, reason: String },

    /// Archive entry is encrypted (not supported).
    EncryptedEntry { entry: String },

    /// Archive contains unsupported entry type (device file, fifo, etc.).
    UnsupportedEntryType { entry: String, entry_type: String },

    /// Zip format error.
    Zip(zip::result::ZipError),

    /// IO error (includes TAR format errors since tar crate uses io::Error).
    Io(std::io::Error),

    /// Path jail error.
    Jail(path_jail::JailError),
}

/// Format bytes in human-readable form (e.g., "1.5 GB").
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} bytes", bytes)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PathEscape { entry, detail } => {
                write!(f, "path '{}' escapes destination: {}", entry, detail)
            }
            Self::SymlinkNotAllowed { entry, target } => {
                if target.is_empty() {
                    write!(
                        f,
                        "archive contains symlink '{}' (symlinks not allowed)",
                        entry
                    )
                } else {
                    write!(
                        f,
                        "archive contains symlink '{}' -> '{}' (symlinks not allowed)",
                        entry, target
                    )
                }
            }
            Self::TotalSizeExceeded { limit, would_be } => {
                write!(
                    f,
                    "extraction would write {}, exceeding the {} limit",
                    format_bytes(*would_be),
                    format_bytes(*limit)
                )
            }
            Self::FileCountExceeded { limit, attempted } => {
                write!(
                    f,
                    "extraction stopped at entry {}: would exceed {} file limit",
                    attempted, limit
                )
            }
            Self::FileTooLarge { entry, limit, size } => {
                write!(
                    f,
                    "file '{}' is {} (limit: {})",
                    entry,
                    format_bytes(*size),
                    format_bytes(*limit)
                )
            }
            Self::SizeMismatch {
                entry,
                declared,
                actual,
            } => {
                write!(
                    f,
                    "file '{}' decompressed to {} but declared {} (possible zip bomb)",
                    entry,
                    format_bytes(*actual),
                    format_bytes(*declared)
                )
            }
            Self::PathTooDeep {
                entry,
                depth,
                limit,
            } => {
                write!(
                    f,
                    "path '{}' has {} directory levels (limit: {})",
                    entry, depth, limit
                )
            }
            Self::AlreadyExists { entry } => {
                write!(f, "file '{}' already exists", entry)
            }
            Self::DestinationNotFound { path } => {
                write!(f, "destination directory '{}' does not exist", path)
            }
            Self::InvalidFilename { entry, reason } => {
                write!(f, "invalid filename '{}': {}", entry, reason)
            }
            Self::EncryptedEntry { entry } => {
                write!(
                    f,
                    "entry '{}' is encrypted (encrypted archives not supported)",
                    entry
                )
            }
            Self::UnsupportedEntryType { entry, entry_type } => {
                write!(
                    f,
                    "entry '{}' has unsupported type '{}' (device files, fifos, etc. are not allowed)",
                    entry, entry_type
                )
            }
            Self::Zip(e) => write!(f, "zip format error: {}", e),
            Self::Io(e) => write!(f, "I/O error: {}", e),
            Self::Jail(e) => write!(f, "path validation error: {}", e),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Zip(e) => Some(e),
            Self::Io(e) => Some(e),
            Self::Jail(e) => Some(e),
            _ => None,
        }
    }
}

// Automatic conversions for ease of use
impl From<zip::result::ZipError> for Error {
    fn from(e: zip::result::ZipError) -> Self {
        Self::Zip(e)
    }
}
impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<path_jail::JailError> for Error {
    fn from(e: path_jail::JailError) -> Self {
        Self::Jail(e)
    }
}
