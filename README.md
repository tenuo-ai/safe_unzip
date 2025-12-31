# safe_unzip

Zip extraction that won't ruin your day.

## The Problem

Zip files can contain malicious paths that escape the extraction directory:

```python
# Python's zipfile is vulnerable to Zip Slip
import zipfile
zipfile.ZipFile("evil.zip").extractall("/var/uploads")
# Extracts ../../etc/cron.d/pwned → /etc/cron.d/pwned 💀
```

This is [CVE-2018-1000001](https://snyk.io/research/zip-slip-vulnerability) (Zip Slip), and it affects many languages and libraries.

## The Solution

```rust
use safe_unzip::extract_file;

extract_file("/var/uploads", "evil.zip")?;
// Err(PathEscape { entry: "../../etc/cron.d/pwned", ... })
```

`safe_unzip` validates every path before extraction. Malicious archives are rejected, not extracted.

## Features

- **Zip Slip Protection** — Path traversal attacks blocked via [path_jail](https://crates.io/crates/path_jail)
- **Zip Bomb Protection** — Configurable limits on size, file count, and path depth
- **Symlink Handling** — Skip or reject symlinks (no symlink-based escapes)
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

### Validate Before Extracting

Use `ValidateFirst` mode to catch all errors **before** writing any files:

```rust
use safe_unzip::{Extractor, ExtractionMode};

// Two-pass extraction:
// 1. Validate ALL entries (no disk writes)
// 2. Extract (only if validation passed)
let report = Extractor::new("/var/uploads")?
    .mode(ExtractionMode::ValidateFirst)
    .extract_file("untrusted.zip")?;
```

This prevents partial extraction state when an archive contains a mix of valid and malicious entries.

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
| **Zip Bomb (size)** | 42KB → 4PB expansion | `max_total_bytes` limit |
| **Zip Bomb (count)** | 1 million empty files | `max_file_count` limit |
| **Zip Bomb (ratio)** | Extreme compression ratio | `max_single_file` limit |
| **Symlink Escape** | Symlink to `/etc/passwd` | Skip or reject symlinks |
| **Path Depth** | `a/b/c/.../1000levels` | `max_path_depth` limit |
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
    Err(e) => {
        eprintln!("Extraction failed: {}", e);
    }
}
```

## Limitations

- **Zip format only** — Tar/gzip support planned for v0.2
- **Requires seekable input** — No stdin streaming (zip format limitation)
- **Partial state possible** — Use `ExtractionMode::ValidateFirst` to prevent

## License

MIT OR Apache-2.0

