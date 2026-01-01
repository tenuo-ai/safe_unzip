# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

### Added

- **Async API**: Optional tokio-based async extraction via `async` feature
  - `safe_unzip::r#async::{extract_file, extract_bytes, AsyncExtractor}`
  - `extract_tar_file`, `extract_tar_gz_file`, `extract_tar_bytes`, `extract_tar_gz_bytes`
  - 15 async tests covering ZIP, TAR, and concurrent extraction
- CI now tests with `--features async`

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

