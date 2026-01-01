# safe_unzip Specification (v0.1.2+)

Archive extraction that won't ruin your day.

> **Note:** This spec reflects v0.1.2 with Python TAR bindings added post-release.

## 1. Overview

`safe_unzip` is a secure archive extraction library that prevents:

- **Zip Slip**: Path traversal via `../../` in entry names
- **Zip Bombs**: Archives that expand to exhaust disk/memory
- **Symlink Attacks**: Symlinks pointing outside extraction directory

Built on `path_jail` for path validation.

## 2. Threat Model

| Threat | Attack Vector | Defense |
|--------|---------------|---------|
| Zip Slip | Entry named `../../etc/cron.d/pwned` | `path_jail` validates every path |
| Zip Bomb (size) | 42KB expands to 4PB | `max_total_bytes` limit |
| Zip Bomb (count) | 1 million empty files | `max_file_count` limit |
| Zip Bomb (ratio) | Single file with extreme compression | `max_single_file` limit |
| Zip Bomb (lying) | Declared 1KB, decompresses to 1GB | `LimitReader` enforces during read |
| Symlink Escape | Symlink to `/etc/passwd` | Skip or error on symlinks |
| Symlink Overwrite | Create symlink, then overwrite its target | Remove symlinks before overwrite |
| Path Depth | `a/b/c/d/.../` to 10000 levels | `max_path_depth` limit |
| Invalid Filename | Control chars, `CON`, `NUL`, backslashes | Filename sanitization |
| Overwrite | Replace existing sensitive file | `OverwritePolicy::Error` default |
| Setuid Escalation | Archive creates setuid binaries | Permission bits stripped |
| Device Files (TAR) | TAR contains block/char devices, FIFOs | `UnsupportedEntryType` error |
| TOCTOU Race | Check-then-create race condition | Atomic `create_new(true)` |

## 3. Scope

### v0.1.2 (This Spec)

- **ZIP format** — Full support
- **TAR format** — Plain `.tar` and gzip-compressed `.tar.gz`
- Synchronous API
- File and directory extraction
- Configurable limits
- Filter callback
- New adapter/policy/driver architecture for extensibility

### v0.2 (Planned)

- ~~Async API~~ ✅ Added in post-0.1.2 (via `async` feature)
- Atomic extraction (temp dir, move on success)
- Progress callback
- More compression formats (bzip2, xz)

### Non-Goals

- Creating archives (extraction only)
- Encrypted archives (use `zip` crate directly for decryption first)
- Self-extracting archives

## 4. Dependencies

```toml
[dependencies]
path_jail = "0.2"
zip = "2.1"
tar = "0.4"
flate2 = "1"  # For .tar.gz support
tokio = { version = "1", features = ["rt", "fs", "sync"], optional = true }

[features]
default = []
async = ["tokio"]
```

## 5. Rust API

### 5.1 Core Types

```rust
use std::io::{Read, Seek};
use std::path::Path;

/// Zip extractor with security constraints.
pub struct Extractor {
    jail: path_jail::Jail,
    limits: Limits,
    overwrite: OverwritePolicy,
    symlinks: SymlinkPolicy,
    mode: ExtractionMode,
    filter: Option<Box<dyn Fn(&EntryInfo) -> bool + Send + Sync>>,
}

/// Resource limits to prevent denial of service.
pub struct Limits {
    /// Maximum total bytes to extract. Default: 1 GB.
    pub max_total_bytes: u64,
    
    /// Maximum number of files to extract. Default: 10,000.
    pub max_file_count: usize,
    
    /// Maximum size of a single file. Default: 100 MB.
    pub max_single_file: u64,
    
    /// Maximum directory depth. Default: 50.
    pub max_path_depth: usize,
}

/// What to do when a file already exists.
#[derive(Debug, Clone, Copy, Default)]
pub enum OverwritePolicy {
    /// Fail extraction if file exists.
    #[default]
    Error,
    
    /// Skip files that already exist.
    Skip,
    
    /// Overwrite existing files.
    Overwrite,
}

/// What to do with symlinks in the archive.
#[derive(Debug, Clone, Copy, Default)]
pub enum SymlinkPolicy {
    /// Ignore symlinks silently.
    #[default]
    Skip,
    
    /// Fail extraction if archive contains symlinks.
    Error,
}

/// Extraction strategy.
///
/// # Tradeoffs
///
/// | Mode | Speed | On Failure | Use When |
/// |------|-------|------------|----------|
/// | `Streaming` | Fast (1 pass) | Partial files remain | Speed matters; you'll clean up on error |
/// | `ValidateFirst` | Slower (2 passes) | No files if validation fails | Can't tolerate partial state |
///
/// **Neither mode is truly atomic.** If extraction fails mid-write (e.g., disk full),
/// partial files remain regardless of mode. `ValidateFirst` only prevents writes when
/// *validation* fails (bad paths, limits exceeded), not when I/O fails during extraction.
#[derive(Debug, Clone, Copy, Default)]
pub enum ExtractionMode {
    /// Extract entries as they are read. Fast but leaves partial state on failure.
    /// 
    /// Tradeoff: If extraction fails on entry N, entries 1..N-1 remain on disk.
    #[default]
    Streaming,
    
    /// Validate all entries first, then extract. Slower but no partial state on validation failure.
    /// 
    /// Tradeoff: 2x slower (iterates archive twice). Still not atomic for I/O failures.
    /// Note: Filter callbacks are NOT applied during validation—limits are checked against ALL entries.
    ValidateFirst,
}

/// Information about an archive entry (for filtering).
pub struct EntryInfo<'a> {
    /// Entry name as stored in archive.
    pub name: &'a str,
    
    /// Uncompressed size in bytes.
    pub size: u64,
    
    /// Compressed size in bytes.
    pub compressed_size: u64,
    
    /// True if entry is a directory.
    pub is_dir: bool,
    
    /// True if entry is a symlink.
    pub is_symlink: bool,
}

/// Extraction report.
#[derive(Debug, Clone)]
pub struct Report {
    /// Number of files successfully extracted.
    pub files_extracted: usize,
    
    /// Number of directories created.
    pub dirs_created: usize,
    
    /// Total bytes written.
    pub bytes_written: u64,
    
    /// Number of entries skipped (symlinks, filtered, existing).
    pub entries_skipped: usize,
}
```

### 5.2 Builder API

```rust
impl Extractor {
    /// Create extractor for the given destination directory.
    /// Returns Error::DestinationNotFound if directory doesn't exist.
    /// 
    /// Security: Requiring the destination to exist catches typos like
    /// `/var/uplaods` that would otherwise silently create a wrong directory.
    pub fn new<P: AsRef<Path>>(destination: P) -> Result<Self, Error>;
    
    /// Create extractor, creating the destination directory if it doesn't exist.
    /// 
    /// Convenience method for "just works" behavior. Be careful with user-provided
    /// paths—typos will silently create wrong directories.
    pub fn new_or_create<P: AsRef<Path>>(destination: P) -> Result<Self, Error>;
    
    /// Set resource limits.
    pub fn limits(self, limits: Limits) -> Self;
    
    /// Set overwrite policy.
    pub fn overwrite(self, policy: OverwritePolicy) -> Self;
    
    /// Set symlink policy.
    pub fn symlinks(self, policy: SymlinkPolicy) -> Self;
    
    /// Set extraction mode.
    pub fn mode(self, mode: ExtractionMode) -> Self;
    
    /// Set filter function. Return `true` to extract, `false` to skip.
    pub fn filter<F>(self, f: F) -> Self
    where
        F: Fn(&EntryInfo) -> bool + Send + Sync + 'static;
    
    /// Extract from a reader.
    pub fn extract<R: Read + Seek>(self, reader: R) -> Result<Report, Error>;
    
    /// Extract from a file path.
    pub fn extract_file<P: AsRef<Path>>(self, path: P) -> Result<Report, Error>;
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_total_bytes: 1024 * 1024 * 1024,  // 1 GB
            max_file_count: 10_000,
            max_single_file: 100 * 1024 * 1024,   // 100 MB
            max_path_depth: 50,
        }
    }
}
```

### 5.3 Convenience Functions

These are the "just works" API. They create the destination directory if it doesn't exist.

```rust
/// Extract from a reader with default settings.
/// Creates destination directory if it doesn't exist.
pub fn extract<P, R>(destination: P, reader: R) -> Result<Report, Error>
where
    P: AsRef<Path>,
    R: Read + Seek,
{
    Extractor::new_or_create(destination)?.extract(reader)
}

/// Extract from a file path with default settings.
/// Creates destination directory if it doesn't exist.
pub fn extract_file<D, F>(destination: D, file: F) -> Result<Report, Error>
where
    D: AsRef<Path>,
    F: AsRef<Path>,
{
    Extractor::new_or_create(destination)?.extract_file(file)
}
```

**Note:** The convenience functions use `new_or_create`, while the `Extractor` builder uses
`new` (which requires the destination to exist). This is intentional:
- Convenience API: "just works" for quick scripts
- Builder API: explicit control for production code where typos should fail

### 5.4 New Architecture (v0.1.2)

The v0.2 architecture separates concerns for multi-format support:

```rust
// Adapters normalize archive formats
pub struct ZipAdapter<R: Read + Seek> { ... }
pub struct TarAdapter<R: Read> { ... }

// Generic entry representation
pub struct EntryInfo {
    pub name: String,
    pub size: u64,
    pub kind: EntryKind,
    pub mode: Option<u32>,
}

pub enum EntryKind {
    File,
    Directory,
    Symlink { target: String },
}

// Driver orchestrates extraction
pub struct Driver {
    destination: PathBuf,
    limits: Limits,
    overwrite: OverwriteMode,
    symlinks: SymlinkBehavior,
    validation: ValidationMode,
    filter: Option<Box<dyn Fn(&EntryInfo) -> bool + Send + Sync>>,
}

impl Driver {
    pub fn new<P: AsRef<Path>>(destination: P) -> Result<Self, Error>;
    pub fn new_or_create<P: AsRef<Path>>(destination: P) -> Result<Self, Error>;
    
    // Builder methods
    pub fn limits(self, limits: Limits) -> Self;
    pub fn overwrite(self, mode: OverwriteMode) -> Self;
    pub fn symlinks(self, behavior: SymlinkBehavior) -> Self;
    pub fn validation(self, mode: ValidationMode) -> Self;
    pub fn filter<F>(self, f: F) -> Self;
    
    // Extraction methods
    pub fn extract_zip<R: Read + Seek>(&self, adapter: ZipAdapter<R>) -> Result<ExtractionReport, Error>;
    pub fn extract_tar<R: Read>(&self, adapter: TarAdapter<R>) -> Result<ExtractionReport, Error>;
    pub fn extract_zip_file<P: AsRef<Path>>(&self, path: P) -> Result<ExtractionReport, Error>;
    pub fn extract_tar_file<P: AsRef<Path>>(&self, path: P) -> Result<ExtractionReport, Error>;
    pub fn extract_tar_gz_file<P: AsRef<Path>>(&self, path: P) -> Result<ExtractionReport, Error>;
}
```

The legacy `Extractor` API remains for backward compatibility (ZIP-only).

### 5.5 Async API (Feature: `async`)

The `async` feature provides tokio-based async extraction:

```rust
use safe_unzip::r#async::{extract_file, AsyncExtractor};

// Simple async extraction
let report = extract_file("/var/uploads", "archive.zip").await?;

// With options
let report = AsyncExtractor::new("/var/uploads")?
    .max_total_bytes(500 * 1024 * 1024)
    .max_file_count(1000)
    .extract_file("archive.zip")
    .await?;

// TAR extraction
let report = AsyncExtractor::new("/var/uploads")?
    .extract_tar_file("archive.tar")
    .await?;
```

The async API uses `spawn_blocking` internally since the `zip` and `tar` crates are synchronous.

Available functions:
- `extract_file`, `extract_bytes` — ZIP
- `extract_tar_file`, `extract_tar_gz_file`, `extract_tar_bytes`, `extract_tar_gz_bytes` — TAR
- `AsyncExtractor` — Builder API with all the same options as `Extractor`

### 5.6 Error Type

```rust
/// Errors that can occur during archive extraction.
/// 
/// This enum is marked `#[non_exhaustive]` to allow adding new variants
/// without breaking existing code. Always include a `_ =>` catch-all.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Path escapes destination directory.
    PathEscape {
        entry: String,
        detail: String,
    },
    
    /// Archive contains symlink and policy is Error.
    SymlinkNotAllowed {
        entry: String,
        target: String,  // Symlink target path
    },
    
    /// Exceeded maximum total bytes.
    TotalSizeExceeded {
        limit: u64,
        would_be: u64,
    },
    
    /// Exceeded maximum file count.
    FileCountExceeded {
        limit: usize,
        attempted: usize,
    },
    
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
    AlreadyExists {
        entry: String,  // Consistent naming
    },
    
    /// Filename contains invalid characters or reserved names.
    InvalidFilename {
        entry: String,
        reason: String,
    },
    
    /// Archive entry is encrypted (not supported).
    EncryptedEntry {
        entry: String,
    },
    
    /// Archive contains unsupported entry type (device file, fifo, etc.).
    UnsupportedEntryType {
        entry: String,
        entry_type: String,
    },
    
    /// Destination directory does not exist.
    DestinationNotFound {
        path: String,
    },
    
    /// Zip format error.
    Zip(zip::result::ZipError),
    
    /// IO error (includes TAR format errors).
    Io(std::io::Error),
    
    /// Path jail error.
    Jail(path_jail::JailError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PathEscape { entry, detail } => {
                write!(f, "path '{}' escapes destination: {}", entry, detail)
            }
            Self::SymlinkNotAllowed { entry, target } => {
                if target.is_empty() {
                    write!(f, "archive contains symlink '{}' (symlinks not allowed)", entry)
                } else {
                    write!(f, "archive contains symlink '{}' -> '{}' (symlinks not allowed)", entry, target)
                }
            }
            Self::TotalSizeExceeded { limit, would_be } => {
                write!(f, "extraction would write {} bytes, exceeding {} limit", would_be, limit)
            }
            Self::FileCountExceeded { limit, attempted } => {
                write!(f, "extraction stopped at entry {}: would exceed {} file limit", attempted, limit)
            }
            Self::FileTooLarge { entry, limit, size } => {
                write!(f, "file '{}' is {} bytes (limit: {})", entry, size, limit)
            }
            Self::SizeMismatch { entry, declared, actual } => {
                write!(f, "file '{}' decompressed to {} bytes but declared {} (possible zip bomb)", 
                    entry, actual, declared)
            }
            Self::PathTooDeep { entry, depth, limit } => {
                write!(f, "path '{}' has {} directory levels (limit: {})", entry, depth, limit)
            }
            Self::AlreadyExists { entry } => {
                write!(f, "file '{}' already exists", entry)
            }
            Self::InvalidFilename { entry, reason } => {
                write!(f, "invalid filename '{}': {}", entry, reason)
            }
            Self::EncryptedEntry { entry } => {
                write!(f, "entry '{}' is encrypted (not supported)", entry)
            }
            Self::DestinationNotFound { path } => {
                write!(f, "destination directory '{}' does not exist", path)
            }
            Self::UnsupportedEntryType { entry, entry_type } => {
                write!(f, "entry '{}' has unsupported type '{}' (device files, fifos not allowed)", 
                    entry, entry_type)
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
```

## 6. Implementation Notes

### 6.1 Two-Pass Extraction (ValidateFirst Mode)

When `ExtractionMode::ValidateFirst` is set:

1. **Pass 1 (Validation):** Iterate all entries using `by_index_raw()` (no decompression). Check paths, limits, policies. Accumulate totals.
2. **Pass 2 (Extraction):** Only runs if validation passed. Extract files normally.

Key: `by_index_raw()` reads metadata without decompressing, making validation fast.

### 6.2 Extraction Order

The extraction loop processes each entry in this order:

1. **Path validation** (path_jail) — catches traversal before any other checks
2. **Symlink policy** — skip or error on symlinks
3. **Filter callback** — user-defined skip logic
4. **Limits** (depth, size, count) — resource constraints
5. **Overwrite policy** — handle existing files
6. **Extract** — write file, apply permissions

This ordering ensures security checks run first and cannot be bypassed.

### 6.3 Filter Semantics

The filter callback is **advisory, not a security boundary**:

- Filter runs after path validation (traversal attempts still error)
- Filter runs before limit checks
- Limits are checked on entries that pass the filter

This means:
- A malicious entry with `../../etc/passwd` will error even if your filter would reject it
- An oversized file will error even if your filter would skip it

This ordering ensures security checks cannot be bypassed by filter logic.

### 6.4 Symlink Counting

When `SymlinkPolicy::Skip` is active:

- Symlinks count toward `entries_skipped`
- Symlinks do NOT count toward `files_extracted` or `file_count` limit
- Symlinks ARE validated for path traversal before skipping

This ensures traversal attempts via symlinks still error, even when skipping.

### 6.5 Streaming Limitation

The `zip` crate requires `Read + Seek` because zip files have a central directory at the end. True streaming extraction from stdin is not possible with the standard zip format.

**What works:**
- `std::fs::File`
- `std::io::Cursor<Vec<u8>>`
- `std::io::Cursor<&[u8]>`
- Flask `FileStorage` (seekable)
- Django `UploadedFile` (seekable)

**What does NOT work:**
- `request.stream` (not seekable)
- Piped stdin
- HTTP response bodies (without buffering)

For non-seekable streams, buffer to `Cursor` first:

```rust
let mut buf = Vec::new();
stream.read_to_end(&mut buf)?;
let cursor = std::io::Cursor::new(buf);
extract(dest, cursor)?;
```

Document this limitation. Users needing true streaming should use tar.gz (planned for v0.2).

### 6.6 Partial Extraction on Failure

**Streaming mode:** If extraction fails mid-way, already-extracted files remain on disk. This matches the behavior of standard tools like `unzip`.

**ValidateFirst mode:** Validation failures happen before any files are written. Extraction failures (e.g., disk full) can still leave partial state.

For fully atomic extraction (all-or-nothing), planned for v0.2:
1. Extract to temp directory
2. Move to destination on success
3. Clean up temp on failure

### 6.7 Permissions

**Unix:** Permissions from the archive are applied with dangerous bits stripped:

```rust
let safe_mode = mode & 0o0777;  // Remove setuid, setgid, sticky
```

This prevents archives from creating setuid executables.

**Windows:** Archive permissions are ignored. Windows does not use Unix-style permission bits.

### 6.8 Strict Size Enforcement (LimitReader)

Malicious zips can lie about declared size. A `LimitReader` wrapper enforces limits during actual read, returning EOF after `max_single_file` bytes regardless of header claims.

### 6.9 Secure Overwrite

Symlink attack: archive creates `/uploads/log -> /etc/passwd`, second extraction overwrites through symlink.

Defense: Use `symlink_metadata()` to detect symlinks, remove them before writing (don't follow).

### 6.10 Filename Sanitization

Reject filenames with:
- Empty names or just `/`
- Control characters (< 0x20 or 0x7F)
- Backslashes (Windows path confusion)
- Path > 1024 bytes or component > 255 bytes
- Windows reserved names: `CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`

### 6.11 Atomic File Creation (TOCTOU Mitigation)

For `OverwriteMode::Error` and `OverwriteMode::Skip`, use `O_CREAT | O_EXCL` (atomic):

```rust
fs::OpenOptions::new()
    .write(true)
    .create_new(true)  // Fails atomically if file exists
    .open(&path)
```

This eliminates the race condition between checking if a file exists and creating it.

For `OverwriteMode::Overwrite`, symlinks are removed before writing to prevent symlink-following attacks.

### 6.12 Encrypted Archive Handling

Encrypted entries are rejected with `Error::EncryptedEntry`. This is intentional:
- Password handling adds complexity and attack surface
- Users should decrypt with the `zip` crate first, then extract with `safe_unzip`

## 7. Python API

### 7.1 Module Structure

```
python/
  safe_unzip/
    __init__.py
    __init__.pyi
    py.typed
```

### 7.2 API

```python
from safe_unzip import (
    # ZIP functions
    extract_file, extract_bytes,
    # TAR functions
    extract_tar_file, extract_tar_gz_file, extract_tar_bytes,
    # Builder
    Extractor,
)

# Simple ZIP extraction
report = extract_file("/var/uploads", "archive.zip")
report = extract_bytes("/var/uploads", zip_data)

# Simple TAR extraction
report = extract_tar_file("/var/uploads", "archive.tar")
report = extract_tar_gz_file("/var/uploads", "archive.tar.gz")
report = extract_tar_bytes("/var/uploads", tar_data)

# With options (works for both ZIP and TAR)
extractor = (
    Extractor("/var/uploads")
    .max_total_mb(500)
    .max_files(1000)
    .max_single_file_mb(50)
    .max_depth(20)
    .overwrite("skip")          # "error" | "skip" | "overwrite"
    .symlinks("error")          # "skip" | "error"
    .mode("validate_first")     # "streaming" | "validate_first"
)

# ZIP via Extractor
report = extractor.extract_file("archive.zip")
report = extractor.extract_bytes(zip_data)

# TAR via Extractor
report = extractor.extract_tar_file("archive.tar")
report = extractor.extract_tar_gz_file("archive.tar.gz")
report = extractor.extract_tar_bytes(tar_data)
report = extractor.extract_tar_gz_bytes(tar_gz_data)

# Report
print(report.files_extracted)
print(report.dirs_created)
print(report.bytes_written)
print(report.entries_skipped)
```

### 7.3 Input Requirements

The source must be seekable. This works:

- `open("file.zip", "rb")`
- `io.BytesIO(data)`
- Flask `FileStorage`
- Django `UploadedFile`
- Django `InMemoryUploadedFile`

This does NOT work:

- `request.stream` (not seekable)
- Raw `wsgi.input`
- HTTP response bodies without buffering

For non-seekable streams, buffer first:

```python
import io
from safe_unzip import extract

# Buffer to BytesIO
data = request.stream.read()
extract("/var/uploads", io.BytesIO(data))
```

### 7.4 Error Handling

```python
from safe_unzip import extract_file, PathEscapeError, QuotaError

try:
    report = extract_file("/var/uploads", "untrusted.zip")
except PathEscapeError as e:
    print(f"Blocked traversal: {e.entry}")
except QuotaError as e:
    print(f"Resource limit exceeded: {e}")
except OSError as e:
    print(f"IO error: {e}")
```

Exception hierarchy:

```
Exception
  SafeUnzipError (base)
    PathEscapeError           # Traversal, invalid filename
    SymlinkNotAllowedError    # Symlink with policy=error
    QuotaError                # All limit violations (size, count, depth)
    AlreadyExistsError        # File exists with policy=error
    EncryptedArchiveError     # Encrypted ZIP entries
    UnsupportedEntryTypeError # Device files, FIFOs in TAR
  OSError (for IO errors)
```

## 8. Project Structure

### 8.1 Flattened Layout

This is a small crate with one binding. We use a flat structure:

```
safe_unzip/
├── Cargo.toml                    # Workspace root + core library
├── src/
│   ├── lib.rs                    # Public API
│   ├── extractor.rs              # Legacy ZIP-only API
│   ├── driver.rs                 # New generic extraction driver
│   ├── limits.rs                 # Resource limits
│   ├── error.rs                  # Error types
│   ├── entry.rs                  # Generic entry types
│   ├── policy.rs                 # Security policies
│   └── adapter/
│       ├── mod.rs
│       ├── zip_adapter.rs        # ZIP format adapter
│       └── tar_adapter.rs        # TAR format adapter
├── python/                       # Python bindings
│   ├── Cargo.toml
│   ├── pyproject.toml
│   ├── src/
│   │   └── lib.rs                # PyO3 bindings
│   └── python/
│       └── safe_unzip/
│           ├── __init__.py
│           ├── __init__.pyi      # Type stubs
│           └── py.typed          # PEP 561 marker
├── fuzz/                         # Fuzzing targets
│   ├── Cargo.toml
│   └── fuzz_targets/
│       ├── fuzz_extract.rs
│       └── fuzz_zip_adapter.rs
├── tests/
│   ├── security_test.rs          # ZIP security tests
│   ├── driver_test.rs            # Driver API tests
│   └── tar_test.rs               # TAR tests
├── README.md
├── LICENSE-MIT
└── LICENSE-APACHE
```

### 8.2 Key Configuration

- **Root `Cargo.toml`**: Workspace with `members = [".", "python"]`
- **Dependencies**: `path_jail = "0.2"`, `zip = "2.1"`, `tar = "0.4"`, `flate2 = "1"`
- **Python bindings**: PyO3 0.24, maturin build system
- **Package name**: `safe-unzip` on PyPI, `safe_unzip` on crates.io
- **Fuzzing**: cargo-fuzz with libfuzzer

## 9. Test Strategy

### 9.1 Test Fixtures

Create malicious zip files for testing:

```
tests/fixtures/
├── normal.zip              # Valid archive
├── traversal.zip           # Contains ../../etc/passwd
├── symlink_escape.zip      # Symlink to /etc
├── bomb_size.zip           # Expands to > limit
├── bomb_count.zip          # 100,000 empty files
├── deep_path.zip           # a/b/c/d/.../file (100 levels)
├── existing_file.zip       # File that will conflict
└── setuid.zip              # Contains setuid executable
```

### 9.2 Required Test Coverage

**Rust tests must verify (ZIP):**
- Path traversal blocked (`PathEscape` error)
- Symlink escape blocked (skip or `SymlinkNotAllowed`)
- Size limits enforced (`TotalSizeExceeded`, `FileTooLarge`)
- File count limits enforced (`FileCountExceeded`)
- Path depth limits enforced (`PathTooDeep`)
- Overwrite policies work (Error, Skip, Overwrite)
- Filter callback works
- ValidateFirst prevents partial state
- Setuid bits stripped (Unix only)
- Size mismatch detected (`SizeMismatch`)
- Encrypted entries rejected (`EncryptedEntry`)
- Atomic file creation (TOCTOU)

**Rust tests must verify (TAR):**
- Basic extraction (.tar)
- Gzip extraction (.tar.gz)
- Path traversal blocked
- Absolute paths blocked/sanitized
- Symlink policies (skip, error)
- Hard links treated as symlinks
- Device files rejected (block, char, fifo)
- Setuid/setgid bits stripped
- Size/count/depth limits enforced
- ValidateFirst mode
- Filter callback works

**Python tests must verify:**
- Same security guarantees as Rust (ZIP and TAR)
- Exception hierarchy works (`PathEscapeError`, `QuotaError`, `EncryptedArchiveError`, `UnsupportedEntryTypeError`)
- Builder API works with string policies
- TAR extraction methods work
