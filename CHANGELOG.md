# Changelog

All notable changes to this project will be documented in this file.

## [0.1.5] - 2026-01-03

### Added

- **Partial Extraction**: Extract specific files by name or pattern
  - `only(&["file1", "file2"])` — extract specific files by exact name
  - `include_glob(&["**/*.py"])` — include files matching glob patterns
  - `exclude_glob(&["**/__pycache__/**"])` — exclude files matching patterns
  - Available on `Extractor`, `Driver`, and `AsyncExtractor`
  - Full Python bindings support

- **Progress Callbacks**: Monitor extraction progress
  - `on_progress(callback)` with entry name, size, index, totals
  - Rust: `Progress` struct, Python: dict with same fields
  - Full Python bindings support (callbacks run in thread pool)

- **7z Support** (feature-gated): Read-only 7z extraction
  - `Driver::extract_7z_file()`, `extract_7z_bytes()`
  - `SevenZAdapter` for low-level access
  - Enable with `features = ["sevenz"]`
  - Python bindings included when sevenz feature enabled

- **Optional TAR Support**: TAR/FLATE2 are now optional dependencies via `tar` feature flag
  - Default: ZIP only (~30 deps)
  - With `tar` feature: ~40 deps
  - Python bindings always enable `tar` for full feature parity

### Changed

- `tar` and `flate2` dependencies are now optional (gated behind `tar` feature)
- `default = []` — only ZIP included by default (breaking if you used TAR without feature flag)
- Python bindings explicitly enable `tar` and `sevenz` features

## [0.1.4] - 2026-01-02

### Added

- **Archive Listing**: List entries without extracting
  - Rust: `list_zip_entries()`, `list_tar_entries()`, `list_tar_gz_entries()`
  - Python: `list_zip_entries()`, `list_zip_bytes()`, `list_tar_entries()`, etc.
  - Async: `async_list_zip_bytes()`, `async_list_tar_bytes()`, etc.
  - New `EntryInfo` class with `name`, `size`, `kind`, `is_file`, `is_dir`, `is_symlink`
- **Context Manager**: Pythonic resource handling
  - `with Extractor(...) as e:` for sync extraction
  - `async with AsyncExtractor(...) as e:` for async extraction
- 8 new Python tests for listing and context managers (58 total)

## [0.1.3] - 2026-01-01

### Added

- **Async API**: Optional tokio-based async extraction via `async` feature
  - `safe_unzip::r#async::{extract_file, extract_bytes, AsyncExtractor}`
  - `extract_tar_file`, `extract_tar_gz_file`, `extract_tar_bytes`, `extract_tar_gz_bytes`
  - 15 async tests covering ZIP, TAR, and concurrent extraction
- **Comprehensive Test Coverage**: ~140 tests total
  - 25 policy unit tests (PathPolicy, SizePolicy, CountPolicy, etc.)
  - Edge case tests (empty archives, directory-only, zero limits)
  - Encrypted ZIP detection test
- **Fuzzing Validated**: 2.2 million iterations with zero crashes
- CI now tests with `--features async`

### Changed

- **Minimal ZIP Dependencies**: Use only deflate + time features
  - Removes xz2, zstd, bzip2 transitive dependencies
  - Lighter binary, faster builds

### Python Bindings

- **Python Async API**: Pure Python async wrappers using `asyncio.to_thread()`
  - `async_extract_file`, `async_extract_bytes`, `async_extract_tar_file`, etc.
  - `AsyncExtractor` class with builder pattern
  - 8 async tests for Python bindings

## [0.1.2] - 2025-12-31

### Added

- **TAR Support**: Extract `.tar` and `.tar.gz` archives with the same security guarantees
  - `Driver::extract_tar()`, `extract_tar_file()`, `extract_tar_gz_file()`
  - `TarAdapter` for the new architecture
- **New Architecture**: Modular design with Adapters, Policies, and Driver
  - `Driver` - generic extraction engine
  - `ZipAdapter`, `TarAdapter` - format-specific handlers
  - `Policy` trait with `PathPolicy`, `SizePolicy`, `CountPolicy`, `DepthPolicy`, `SymlinkPolicy`
  - `PolicyChain` for composing multiple policies
- **Encryption Detection**: Error on encrypted ZIP entries with clear message
- **Atomic File Creation**: Uses `create_new(true)` for `OverwriteMode::Error/Skip` to prevent TOCTOU races
- **Device File Rejection**: TAR entries with block devices, char devices, or FIFOs now error with `UnsupportedEntryType`
- **Fuzzing Setup**: `cargo-fuzz` with `fuzz_extract` and `fuzz_zip_adapter` targets
- **12 New TAR Security Tests**: Block/char devices, FIFOs, absolute paths, symlinks, setuid stripping, limits

### Changed

- **Improved Error Messages**:
  - `SymlinkNotAllowed` now shows target path (e.g., `'link' -> '/etc/passwd'`)
  - `FileCountExceeded` clarifies stopping point
  - `AlreadyExists` uses `entry` field for consistency
- **`#[non_exhaustive]` on `Error` enum**: Future error variants won't break exhaustive matches

### Python Bindings

- Added `UnsupportedEntryTypeError` exception
- Updated error messages to match Rust improvements

## [0.1.1] - 2025-12-31

### Changed

- Upgraded `path_jail` dependency from 0.1 to 0.2
- Added ARM64 CI builds (Linux arm64, Windows arm64)

### Fixed

- Fixed PyPI sdist build (README handling)

## [0.1.0] - 2025-12-31

### Initial Release 🎉

**safe_unzip** is a secure zip extraction library that prevents common archive-based attacks.

### Features

- **Zip Slip Prevention**: Blocks path traversal attacks (`../../etc/passwd`)
- **Zip Bomb Protection**: Limits on total size, file count, single file size, and path depth
- **Symlink Safety**: Configurable policies (skip or error)
- **Secure Overwrite**: Removes symlinks before overwriting to prevent TOCTOU attacks
- **Filename Sanitization**: Rejects control characters, backslashes, Windows reserved names
- **Strict Size Enforcement**: Catches zip bombs that lie about declared size
- **Two Extraction Modes**: 
  - `Streaming` (default): Fast, may leave partial state on error
  - `ValidateFirst`: Two-pass, atomic (all-or-nothing)

### Python Bindings

Full Python bindings with identical security guarantees:

```python
from safe_unzip import Extractor

Extractor("/path/to/dest").extract_file("archive.zip")
```

### Platforms

- Linux (x86_64)
- macOS (arm64, x86_64)
- Windows (x86_64)

### Links

- [crates.io](https://crates.io/crates/safe_unzip)
- [PyPI](https://pypi.org/project/safe-unzip/)
- [Documentation](https://github.com/tenuo-ai/safe_unzip)

