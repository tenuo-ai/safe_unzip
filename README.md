# safe_unzip

Zip extraction that won't ruin your day.

## The Problem

Zip files can contain malicious paths that escape the extraction directory:

```python
# Python 3.12, tested January 2025 — STILL VULNERABLE
import zipfile
zipfile.ZipFile("evil.zip").extractall("/var/uploads")
# Extracts ../../etc/cron.d/pwned → /etc/cron.d/pwned 💀
```

This is [Zip Slip](https://snyk.io/research/zip-slip-vulnerability), and it **still affects Python in 2025**.

### "But didn't Python fix this?"

Sort of. Python added warnings and `ZipInfo.filename` sanitization in 2014. In Python 3.12+, there's a `filter` parameter:

```python
# The "safe" way — but who knows this exists?
zipfile.ZipFile("evil.zip").extractall("/var/uploads", filter="data")
```

The problem: **the safe option is opt-in**. The default is still vulnerable. Most developers don't read the docs carefully enough to discover `filter="data"`.

`safe_unzip` makes security the default, not an afterthought.

## The Solution

```rust
use safe_unzip::extract_file;

extract_file("/var/uploads", "evil.zip")?;
// Err(PathEscape { entry: "../../etc/cron.d/pwned", ... })
```

```python
# Python bindings — same safety
from safe_unzip import extract_file

extract_file("/var/uploads", "evil.zip")
# Raises: PathEscapeError
```

**Security is the default.** No special flags, no opt-in safety. Every path is validated. Malicious archives are rejected, not extracted.

## Features

- **Zip Slip Protection** — Path traversal attacks blocked via [path_jail](https://crates.io/crates/path_jail)
- **Zip Bomb Protection** — Configurable limits on size, file count, and path depth
- **Strict Size Enforcement** — Catches files that decompress larger than declared
- **Filename Sanitization** — Blocks control characters and Windows reserved names
- **Symlink Handling** — Skip or reject symlinks (no symlink-based escapes)
- **Secure Overwrite** — Removes symlinks before overwriting to prevent symlink attacks
- **Overwrite Policies** — Error, skip, or overwrite existing files
- **Filter Callback** — Extract only the files you want
- **Two-Pass Mode** — Validate everything before writing anything
- **Permission Stripping** — Removes setuid/setgid bits on Unix

## Installation

```toml
[dependencies]
safe_unzip = "0.1"
```

## Quick Start

```rust
use safe_unzip::extract_file;

// Extract with safe defaults
let report = extract_file("/var/uploads", "archive.zip")?;
println!("Extracted {} files ({} bytes)", 
    report.files_extracted, 
    report.bytes_written
);
```

## Usage Examples

### Basic Extraction

```rust
use safe_unzip::Extractor;

let report = Extractor::new("/var/uploads")?
    .extract_file("archive.zip")?;
```

### Create Destination if Missing

```rust
use safe_unzip::Extractor;

// Extractor::new() errors if destination doesn't exist (catches typos)
// Extractor::new_or_create() creates it automatically
let report = Extractor::new_or_create("/var/uploads/new_folder")?
    .extract_file("archive.zip")?;

// The convenience functions (extract_file, extract) also create automatically
use safe_unzip::extract_file;
extract_file("/var/uploads/new_folder", "archive.zip")?;
```

### Custom Limits (Prevent Zip Bombs)

```rust
use safe_unzip::{Extractor, Limits};

let report = Extractor::new("/var/uploads")?
    .limits(Limits {
        max_total_bytes: 500 * 1024 * 1024,  // 500 MB total
        max_file_count: 1_000,                // Max 1000 files
        max_single_file: 50 * 1024 * 1024,   // 50 MB per file
        max_path_depth: 10,                   // No deeper than 10 levels
    })
    .extract_file("archive.zip")?;
```

### Filter by Extension

```rust
use safe_unzip::Extractor;

// Only extract images
let report = Extractor::new("/var/uploads")?
    .filter(|entry| {
        entry.name.ends_with(".png") || 
        entry.name.ends_with(".jpg") ||
        entry.name.ends_with(".gif")
    })
    .extract_file("archive.zip")?;

println!("Extracted {} images, skipped {} other files",
    report.files_extracted,
    report.entries_skipped
);
```

### Overwrite Policies

```rust
use safe_unzip::{Extractor, OverwritePolicy};

// Skip files that already exist
let report = Extractor::new("/var/uploads")?
    .overwrite(OverwritePolicy::Skip)
    .extract_file("archive.zip")?;

// Or overwrite them
let report = Extractor::new("/var/uploads")?
    .overwrite(OverwritePolicy::Overwrite)
    .extract_file("archive.zip")?;

// Default: Error if file exists
let report = Extractor::new("/var/uploads")?
    .overwrite(OverwritePolicy::Error)  // This is the default
    .extract_file("archive.zip")?;
```

### Symlink Policies

```rust
use safe_unzip::{Extractor, SymlinkPolicy};

// Default: silently skip symlinks
let report = Extractor::new("/var/uploads")?
    .symlinks(SymlinkPolicy::Skip)
    .extract_file("archive.zip")?;

// Or reject archives containing symlinks
let report = Extractor::new("/var/uploads")?
    .symlinks(SymlinkPolicy::Error)
    .extract_file("archive.zip")?;
```

### Extraction Modes

| Mode | Speed | On Failure | Use When |
|------|-------|------------|----------|
| `Streaming` (default) | Fast (1 pass) | Partial files remain | Speed matters; you'll clean up on error |
| `ValidateFirst` | Slower (2 passes) | No files if validation fails | Can't tolerate partial state |

**⚠️ Neither mode is truly atomic.** If extraction fails mid-write (e.g., disk full), partial files remain regardless of mode. `ValidateFirst` only prevents writes when *validation* fails (bad paths, limits exceeded), not when I/O fails during extraction.

```rust
use safe_unzip::{Extractor, ExtractionMode};

// Two-pass extraction:
// 1. Validate ALL entries (no disk writes)
// 2. Extract (only if validation passed)
let report = Extractor::new("/var/uploads")?
    .mode(ExtractionMode::ValidateFirst)
    .extract_file("untrusted.zip")?;
```

Use `ValidateFirst` when you can't tolerate partial state from malicious archives. Use `Streaming` (default) when speed matters and you can clean up on error.

### Extracting from Memory

```rust
use safe_unzip::Extractor;
use std::io::Cursor;

let zip_bytes: Vec<u8> = download_zip_somehow();
let cursor = Cursor::new(zip_bytes);

let report = Extractor::new("/var/uploads")?
    .extract(cursor)?;
```

## Security Model

| Threat | Attack Vector | Defense |
|--------|---------------|---------|
| **Zip Slip** | Entry named `../../etc/cron.d/pwned` | `path_jail` validates every path |
| **Zip Bomb (size)** | 42KB → 4PB expansion | `max_total_bytes` limit + streaming enforcement |
| **Zip Bomb (count)** | 1 million empty files | `max_file_count` limit |
| **Zip Bomb (lying)** | Declared 1KB, decompresses to 1GB | Strict size reader detects mismatch |
| **Symlink Escape** | Symlink to `/etc/passwd` | Skip or reject symlinks |
| **Symlink Overwrite** | Create symlink, then overwrite target | Symlinks removed before overwrite |
| **Path Depth** | `a/b/c/.../1000levels` | `max_path_depth` limit |
| **Invalid Filename** | Control chars, `CON`, `NUL` | Filename sanitization |
| **Overwrite** | Replace sensitive files | `OverwritePolicy::Error` default |
| **Setuid** | Create setuid executables | Permission bits stripped |

## Default Limits

| Limit | Default | Description |
|-------|---------|-------------|
| `max_total_bytes` | 1 GB | Total uncompressed size |
| `max_file_count` | 10,000 | Number of files |
| `max_single_file` | 100 MB | Largest single file |
| `max_path_depth` | 50 | Directory nesting depth |

## Error Handling

```rust
use safe_unzip::{extract_file, Error};

match extract_file("/var/uploads", "archive.zip") {
    Ok(report) => {
        println!("Success: {} files", report.files_extracted);
    }
    Err(Error::PathEscape { entry, detail }) => {
        eprintln!("Blocked path traversal in '{}': {}", entry, detail);
    }
    Err(Error::TotalSizeExceeded { limit, would_be }) => {
        eprintln!("Archive too large: {} bytes (limit: {})", would_be, limit);
    }
    Err(Error::FileTooLarge { entry, size, limit }) => {
        eprintln!("File '{}' too large: {} bytes (limit: {})", entry, size, limit);
    }
    Err(Error::FileCountExceeded { limit }) => {
        eprintln!("Too many files (limit: {})", limit);
    }
    Err(Error::AlreadyExists { path }) => {
        eprintln!("File already exists: {}", path);
    }
    Err(Error::InvalidFilename { entry }) => {
        eprintln!("Invalid filename: {}", entry);
    }
    Err(e) => {
        eprintln!("Extraction failed: {}", e);
    }
}
```

## Limitations

### Format Limitations

- **Zip format only** — Tar/gzip support planned for v0.2
- **Requires seekable input** — No stdin streaming (zip format requires reading the central directory at the end of the file)
- **No password-protected zips** — Use the `zip` crate directly for encrypted archives

### Extraction Behavior

- **Partial state in Streaming mode** — If extraction fails mid-way, already-extracted files remain on disk. Use `ExtractionMode::ValidateFirst` to validate before writing.
- **Filters not applied during validation** — In `ValidateFirst` mode, limits are checked against ALL entries. Filtered entries still count toward limits. This is conservative: validation may reject archives that would succeed with filtering.

### Security Scope

These threats are **not fully addressed** (by design or complexity):

| Limitation | Reason |
|------------|--------|
| **Case-insensitive collisions** | On Windows/macOS, `File.txt` and `file.txt` map to the same file. We don't track extracted names to detect this. |
| **Unicode normalization** | `café` (NFC) vs `café` (NFD) appear identical but are different bytes. Full normalization requires ICU. |
| **TOCTOU race conditions** | Between path validation and file creation, a symlink could theoretically be created. Mitigated by secure overwrite, but not fully atomic. |
| **Sparse file attacks** | Not applicable to zip format. |
| **Hard links** | Zip format doesn't support hard links. |
| **Device files** | Zip format doesn't support special device files. |

### Filename Restrictions

These filenames are **rejected** for security:

- Control characters (including null bytes)
- Backslashes (`\`) — prevents Windows path separator confusion
- Paths longer than 1024 bytes
- Path components longer than 255 bytes
- Windows reserved names: `CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`

## License

MIT OR Apache-2.0

