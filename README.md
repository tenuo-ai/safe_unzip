# safe_unzip

Secure archive extraction. Supports **ZIP** (core), **TAR**, and **7z** (optional features).

## The Problem

Zip files can contain malicious paths that escape the extraction directory:

```python
import zipfile
zipfile.ZipFile("evil.zip").extractall("/var/uploads")
# Extracts ../../etc/cron.d/pwned → /etc/cron.d/pwned 💀
```

This is [Zip Slip](https://snyk.io/research/zip-slip-vulnerability), and Python's default behavior is still vulnerable.

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

## Why Not Just Use `zip` / `tar` / `zipfile`?

Because **archive extraction is a security boundary**, and most libraries treat it as a convenience function.

| Library | Default Behavior | Safe Option |
|---------|------------------|-------------|
| Python `zipfile` | Vulnerable | `filter="data"` (opt-in, obscure) |
| Python `tarfile` | Vulnerable | `filter="data"` (opt-in, Python 3.12+) |
| Rust `zip` | Vulnerable | Manual path validation |
| Rust `tar` | Vulnerable | Manual path validation |
| `safe_unzip` | **Safe by default** | N/A — always safe |

If you're extracting untrusted archives, you need a library designed for that threat model.

## Who Should Use This

- **Backend services** handling user-uploaded zip files
- **CI/CD systems** unpacking third-party artifacts  
- **SaaS platforms** with file import features
- **Forensics / malware analysis** pipelines
- **Anything running as a privileged user**

If your zip files only come from trusted sources you control, the standard `zip` crate is fine. If users can upload archives, use `safe_unzip`.

## Features

- **Multi-Format Support** — ZIP (core), TAR, and 7z (feature flags)
- **Partial Extraction** — Extract specific files with `only()` or glob patterns
- **Progress Callbacks** — Monitor extraction progress (Rust API)
- **Async API** — Optional tokio-based async extraction (feature flag)
- **Zip Slip Protection** — Path traversal attacks blocked via [path_jail](https://crates.io/crates/path_jail)
- **Zip Bomb Protection** — Configurable limits on size, file count, and path depth
- **Strict Size Enforcement** — Catches files that decompress larger than declared
- **Filename Sanitization** — Blocks control characters and Windows reserved names
- **Symlink Handling** — Skip or reject symlinks (no symlink-based escapes)
- **Secure Overwrite** — Removes symlinks before overwriting to prevent symlink attacks
- **Atomic File Creation** — TOCTOU-safe file creation using `O_EXCL`
- **Overwrite Policies** — Error, skip, or overwrite existing files
- **Filter Callback** — Extract only the files you want
- **Two-Pass Mode** — Validate everything before writing anything
- **Permission Stripping** — Removes setuid/setgid bits on Unix

## Installation

**Rust:**
```toml
[dependencies]
safe_unzip = "0.1"
```

**Python:**
```bash
pip install safe-unzip
```

### Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `tar` | ❌ | TAR/TAR.GZ extraction |
| `async` | ❌ | Tokio-based async API |
| `sevenz` | ❌ | 7z extraction (heavier deps) |

```toml
# ZIP only (smallest, ~30 deps)
safe_unzip = "0.1"

# With TAR support (~40 deps)
safe_unzip = { version = "0.1", features = ["tar"] }

# With async API
safe_unzip = { version = "0.1", features = ["async"] }

# Kitchen sink (~85 deps)
safe_unzip = { version = "0.1", features = ["tar", "async", "sevenz"] }
```

> **Note:** Python bindings always include TAR support.

### Python Bindings

The Python bindings are **thin wrappers** over the Rust implementation via PyO3. This means:

- ✅ **Identical security guarantees** — same code path, same validation
- ✅ **Identical limits** — same defaults (1GB total, 10K files, 100MB per file)
- ✅ **Identical semantics** — same error conditions, same behavior
- ✅ **No re-implementation** — Python calls Rust directly, no logic duplication

Security reviewers: the Python API is a direct binding, not a port.

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

### Partial Extraction (New in v0.1.5)

Extract specific files by name or glob pattern:

```rust
use safe_unzip::Extractor;

// Extract only specific files
let report = Extractor::new("/var/uploads")?
    .only(&["README.md", "LICENSE"])
    .extract_file("archive.zip")?;

// Include by glob pattern
let report = Extractor::new("/var/uploads")?
    .include_glob(&["**/*.py", "**/*.rs"])
    .extract_file("archive.zip")?;

// Exclude by glob pattern
let report = Extractor::new("/var/uploads")?
    .exclude_glob(&["**/__pycache__/**", "**/*.pyc"])
    .extract_file("archive.zip")?;
```

**Python:**
```python
from safe_unzip import Extractor

# Extract only specific files
report = Extractor("/var/uploads").only(["README.md", "LICENSE"]).extract_file("archive.zip")

# Include by pattern
report = Extractor("/var/uploads").include_glob(["**/*.py"]).extract_file("archive.zip")

# Exclude by pattern  
report = Extractor("/var/uploads").exclude_glob(["**/__pycache__/**"]).extract_file("archive.zip")
```

### Progress Callbacks

Monitor extraction progress:

```rust
use safe_unzip::Extractor;

let report = Extractor::new("/var/uploads")?
    .on_progress(|p| {
        println!("[{}/{}] {} ({} bytes)",
            p.entry_index + 1,
            p.total_entries,
            p.entry_name,
            p.entry_size
        );
    })
    .extract_file("archive.zip")?;
```

**Python:**
```python
from safe_unzip import Extractor

def show_progress(p):
    print(f"[{p['entry_index']+1}/{p['total_entries']}] {p['entry_name']}")

Extractor("/var/uploads").on_progress(show_progress).extract_file("archive.zip")

# Or with tqdm for a progress bar
from tqdm import tqdm
entries = list_zip_entries("archive.zip")
pbar = tqdm(total=len(entries))
def update_bar(p):
    pbar.update(1)
    pbar.set_description(p['entry_name'])
Extractor("/var/uploads").on_progress(update_bar).extract_file("archive.zip")
pbar.close()
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

### TAR Extraction (New in v0.1.2)

```rust
use safe_unzip::{Driver, TarAdapter};

// Extract a .tar file
let report = Driver::new("/var/uploads")?
    .extract_tar_file("archive.tar")?;

// Extract a .tar.gz file
let report = Driver::new("/var/uploads")?
    .extract_tar_gz_file("archive.tar.gz")?;

// With options
let report = Driver::new("/var/uploads")?
    .filter(|entry| entry.name.ends_with(".txt"))
    .validation(safe_unzip::ValidationMode::ValidateFirst)
    .extract_tar_file("archive.tar")?;
```

The new `Driver` API provides a unified interface for all archive formats with the same security guarantees.

### 7z Extraction (Requires `sevenz` Feature)

Enable the `sevenz` feature:

```toml
[dependencies]
safe_unzip = { version = "0.1", features = ["sevenz"] }
```

```rust
use safe_unzip::{Driver, SevenZAdapter};

// Extract a .7z file
let report = Driver::new("/var/uploads")?
    .extract_7z_file("archive.7z")?;

// Or from bytes
let report = Driver::new("/var/uploads")?
    .extract_7z_bytes(&seven_z_bytes)?;
```

**Note:** 7z archives are fully decompressed into memory before extraction, so large archives may use significant RAM.

**Python:**
```python
from safe_unzip import extract_7z_file, Extractor

# Simple extraction
report = extract_7z_file("/var/uploads", "archive.7z")

# With options
report = Extractor("/var/uploads").extract_7z_file("archive.7z")
```

### Async Extraction (New)

Enable the `async` feature for tokio-based async extraction:

```toml
[dependencies]
safe_unzip = { version = "0.1", features = ["async"] }
```

```rust
use safe_unzip::r#async::{extract_file, extract_tar_file, AsyncExtractor};

#[tokio::main]
async fn main() -> Result<(), safe_unzip::Error> {
    // Simple async extraction
    let report = extract_file("/var/uploads", "archive.zip").await?;
    
    // TAR extraction
    let report = extract_tar_file("/var/uploads", "archive.tar").await?;
    
    // With options
    let report = AsyncExtractor::new("/var/uploads")?
        .max_total_bytes(500 * 1024 * 1024)
        .max_file_count(1000)
        .extract_file("archive.zip")
        .await?;
    
    Ok(())
}
```

Concurrent extraction of multiple archives:

```rust
use safe_unzip::r#async::{extract_file, extract_tar_bytes};

let (zip_result, tar_result) = tokio::join!(
    extract_file("/uploads/a", "first.zip"),
    extract_tar_bytes("/uploads/b", tar_data),
);
```

The async API uses `spawn_blocking` internally, so extraction runs in a thread pool without blocking the async runtime.

### Python Async API

Python async support uses `asyncio.to_thread()` to run extraction in a thread pool:

```python
import asyncio
from safe_unzip import async_extract_file, AsyncExtractor

async def main():
    # Simple async extraction
    report = await async_extract_file("/var/uploads", "archive.zip")
    
    # TAR extraction
    from safe_unzip import async_extract_tar_file
    report = await async_extract_tar_file("/var/uploads", "archive.tar")
    
    # With options
    report = await (
        AsyncExtractor("/var/uploads")
        .max_total_mb(500)
        .max_files(1000)
        .extract_file("archive.zip")
    )

asyncio.run(main())
```

Concurrent extraction:

```python
async def extract_all(archives):
    tasks = [
        async_extract_file(f"/uploads/{i}", path)
        for i, path in enumerate(archives)
    ]
    return await asyncio.gather(*tasks)
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
| **Encrypted Archives** | Password handling complexity | Rejected (see [Encrypted Archives](#encrypted-archives)) |

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
    Err(Error::InvalidFilename { entry, .. }) => {
        eprintln!("Invalid filename: {}", entry);
    }
    Err(Error::EncryptedEntry { entry }) => {
        eprintln!("Encrypted entry not supported: {}", entry);
    }
    Err(e) => {
        eprintln!("Extraction failed: {}", e);
    }
}
```

## Limitations

### Format Limitations

- **ZIP, TAR, 7z only** — RAR not supported
- **Requires seekable input for ZIP** — ZIP format requires reading the central directory at the end
- **TAR is sequential** — TAR files are read in order; `ValidateFirst` mode caches entries in memory
- **No encrypted archives** — See below

### Encrypted Archives

`safe_unzip` does not support password-protected zip files. Encrypted entries are rejected with `Error::EncryptedEntry`.

If you need to extract encrypted archives:
1. Decrypt first using the `zip` crate directly
2. Then extract with `safe_unzip`

This is intentional—encryption handling is outside our security scope. Password management, key derivation, and cryptographic validation are complex domains that deserve dedicated tooling.

### Extraction Behavior

- **Partial state in Streaming mode** — If extraction fails mid-way, already-extracted files remain on disk. Use `ExtractionMode::ValidateFirst` to validate before writing.
- **Filters not applied during validation** — In `ValidateFirst` mode, limits are checked against ALL entries. Filtered entries still count toward limits. This is conservative: validation may reject archives that would succeed with filtering.

### Security Scope

These threats are **not fully addressed** (by design or complexity):

| Limitation | Reason |
|------------|--------|
| **Case-insensitive collisions** | On Windows/macOS, `File.txt` and `file.txt` map to the same file. We don't track extracted names to detect this. |
| **Unicode normalization** | `café` (NFC) vs `café` (NFD) appear identical but are different bytes. Full normalization requires ICU. |
| **Concurrent extraction** | If multiple threads/processes extract to the same destination, race conditions can occur. Use file locking or separate destinations. |
| **Sparse file attacks** | Not applicable to zip format. |
| **Hard links** | Zip format doesn't support hard links. |
| **Device files** | Zip format doesn't support special device files. |

### TOCTOU Mitigations

For `OverwriteMode::Error` and `OverwriteMode::Skip`, we use **atomic file creation** (`O_CREAT | O_EXCL`) instead of check-then-create. This eliminates race conditions between checking if a file exists and creating it.

For `OverwriteMode::Overwrite`, symlinks are removed before writing to prevent symlink-following attacks, but there's a brief window between removal and creation.

### Filename Restrictions

These filenames are **rejected** for security:

- Control characters (including null bytes)
- Backslashes (`\`) — prevents Windows path separator confusion
- Paths longer than 1024 bytes
- Path components longer than 255 bytes
- Windows reserved names: `CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`

## Development

### Fuzzing

We use [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) with two targets:

```bash
# Install cargo-fuzz (requires nightly)
cargo install cargo-fuzz

# Run the main extraction fuzzer
cargo +nightly fuzz run fuzz_extract

# Run the adapter fuzzer (tests parsing layer)
cargo +nightly fuzz run fuzz_zip_adapter
```

Fuzzing targets are in `fuzz/fuzz_targets/`. Run fuzzing before releases to catch parsing edge cases.

## License

MIT OR Apache-2.0

