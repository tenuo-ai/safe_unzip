"""Type stubs for safe_unzip."""

from os import PathLike
from pathlib import Path
from typing import Union, Literal, Coroutine, List, Optional, Callable

_PathType = Union[str, PathLike[str], Path]
_OverwritePolicy = Literal["error", "skip", "overwrite"]
_SymlinkPolicy = Literal["skip", "error"]
_ExtractionMode = Literal["streaming", "validate_first"]
_EntryKind = Literal["file", "directory", "symlink"]


class EntryInfo:
    """Metadata for an archive entry."""
    @property
    def name(self) -> str:
        """The path/name of the entry within the archive."""
        ...
    @property
    def size(self) -> int:
        """The uncompressed size in bytes."""
        ...
    @property
    def kind(self) -> _EntryKind:
        """The type of entry: 'file', 'directory', or 'symlink'."""
        ...
    @property
    def is_file(self) -> bool:
        """True if this is a regular file."""
        ...
    @property
    def is_dir(self) -> bool:
        """True if this is a directory."""
        ...
    @property
    def is_symlink(self) -> bool:
        """True if this is a symbolic link."""
        ...
    @property
    def symlink_target(self) -> Optional[str]:
        """The target path if this is a symlink, None otherwise."""
        ...


class Report:
    """Extraction report."""
    @property
    def files_extracted(self) -> int:
        """Number of files successfully extracted."""
        ...
    @property
    def dirs_created(self) -> int:
        """Number of directories created."""
        ...
    @property
    def bytes_written(self) -> int:
        """Total bytes written."""
        ...
    @property
    def entries_skipped(self) -> int:
        """Number of entries skipped (symlinks, filtered, existing)."""
        ...


class VerifyReport:
    """Verification report."""
    @property
    def entries_verified(self) -> int:
        """Number of file entries that passed CRC verification."""
        ...
    @property
    def bytes_verified(self) -> int:
        """Total bytes read and verified."""
        ...


class Extractor:
    """Archive extractor with security constraints. Supports ZIP and TAR.
    
    Can be used as a context manager:
        with Extractor("/var/uploads") as e:
            e.extract_file("archive.zip")
    """
    
    def __init__(self, destination: _PathType) -> None:
        """Create extractor for the given destination directory."""
        ...
    
    def __enter__(self) -> "Extractor":
        """Enter the context manager."""
        ...
    
    def __exit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[object],
    ) -> bool:
        """Exit the context manager."""
        ...
    
    def max_total_mb(self, mb: int) -> "Extractor":
        """Set maximum total bytes to extract (in megabytes)."""
        ...
    
    def max_files(self, count: int) -> "Extractor":
        """Set maximum number of files to extract."""
        ...
    
    def max_single_file_mb(self, mb: int) -> "Extractor":
        """Set maximum size of a single file (in megabytes)."""
        ...
    
    def max_depth(self, depth: int) -> "Extractor":
        """Set maximum directory depth."""
        ...
    
    def overwrite(self, policy: _OverwritePolicy) -> "Extractor":
        """Set overwrite policy: 'error', 'skip', or 'overwrite'."""
        ...
    
    def symlinks(self, policy: _SymlinkPolicy) -> "Extractor":
        """Set symlink policy: 'skip' or 'error'."""
        ...
    
    def mode(self, mode: _ExtractionMode) -> "Extractor":
        """Set extraction mode: 'streaming' or 'validate_first'."""
        ...
    
    def only(self, names: list[str]) -> "Extractor":
        """Extract only specific files by exact name (case-sensitive)."""
        ...
    
    def include_glob(self, patterns: list[str]) -> "Extractor":
        """Include only files matching glob patterns."""
        ...
    
    def exclude_glob(self, patterns: list[str]) -> "Extractor":
        """Exclude files matching glob patterns."""
        ...
    
    def on_progress(self, callback: Callable[[dict], None]) -> "Extractor":
        """Set a progress callback called for each entry."""
        ...
    
    # ZIP extraction
    def extract_file(self, path: _PathType) -> Report:
        """Extract a ZIP file."""
        ...
    
    def extract_bytes(self, data: bytes) -> Report:
        """Extract ZIP from bytes."""
        ...
    
    # TAR extraction
    def extract_tar_file(self, path: _PathType) -> Report:
        """Extract a TAR file."""
        ...
    
    def extract_tar_gz_file(self, path: _PathType) -> Report:
        """Extract a gzip-compressed TAR file (.tar.gz, .tgz)."""
        ...
    
    def extract_tar_bytes(self, data: bytes) -> Report:
        """Extract TAR from bytes."""
        ...
    
    def extract_tar_gz_bytes(self, data: bytes) -> Report:
        """Extract gzip-compressed TAR from bytes."""
        ...


class AsyncExtractor:
    """Async archive extractor with security constraints. Supports ZIP and TAR.
    
    Can be used as an async context manager:
        async with AsyncExtractor("/var/uploads") as e:
            await e.extract_file("archive.zip")
    """
    
    def __init__(self, destination: _PathType) -> None:
        """Create async extractor for the given destination directory."""
        ...
    
    async def __aenter__(self) -> "AsyncExtractor":
        """Enter the async context manager."""
        ...
    
    async def __aexit__(
        self,
        exc_type: Optional[type],
        exc_val: Optional[BaseException],
        exc_tb: Optional[object],
    ) -> bool:
        """Exit the async context manager."""
        ...
    
    def max_total_mb(self, mb: int) -> "AsyncExtractor":
        """Set maximum total bytes to extract (in megabytes)."""
        ...
    
    def max_files(self, count: int) -> "AsyncExtractor":
        """Set maximum number of files to extract."""
        ...
    
    def max_single_file_mb(self, mb: int) -> "AsyncExtractor":
        """Set maximum size of a single file (in megabytes)."""
        ...
    
    def max_depth(self, depth: int) -> "AsyncExtractor":
        """Set maximum directory depth."""
        ...
    
    def overwrite(self, policy: _OverwritePolicy) -> "AsyncExtractor":
        """Set overwrite policy: 'error', 'skip', or 'overwrite'."""
        ...
    
    def symlinks(self, policy: _SymlinkPolicy) -> "AsyncExtractor":
        """Set symlink policy: 'skip' or 'error'."""
        ...
    
    def mode(self, mode: _ExtractionMode) -> "AsyncExtractor":
        """Set extraction mode: 'streaming' or 'validate_first'."""
        ...
    
    def only(self, names: list[str]) -> "AsyncExtractor":
        """Extract only specific files by exact name (case-sensitive)."""
        ...
    
    def include_glob(self, patterns: list[str]) -> "AsyncExtractor":
        """Include only files matching glob patterns."""
        ...
    
    def exclude_glob(self, patterns: list[str]) -> "AsyncExtractor":
        """Exclude files matching glob patterns."""
        ...
    
    def on_progress(self, callback: Callable[[dict], None]) -> "AsyncExtractor":
        """Set a progress callback called for each entry."""
        ...
    
    # ZIP extraction (async)
    async def extract_file(self, path: _PathType) -> Report:
        """Extract a ZIP file asynchronously."""
        ...
    
    async def extract_bytes(self, data: bytes) -> Report:
        """Extract ZIP from bytes asynchronously."""
        ...
    
    # TAR extraction (async)
    async def extract_tar_file(self, path: _PathType) -> Report:
        """Extract a TAR file asynchronously."""
        ...
    
    async def extract_tar_gz_file(self, path: _PathType) -> Report:
        """Extract a gzip-compressed TAR file (.tar.gz, .tgz) asynchronously."""
        ...
    
    async def extract_tar_bytes(self, data: bytes) -> Report:
        """Extract TAR from bytes asynchronously."""
        ...
    
    async def extract_tar_gz_bytes(self, data: bytes) -> Report:
        """Extract gzip-compressed TAR from bytes asynchronously."""
        ...


# ============================================================================
# Sync Convenience Functions
# ============================================================================

# ZIP
def extract_file(destination: _PathType, path: _PathType) -> Report:
    """Extract a ZIP file with default settings."""
    ...

def extract_bytes(destination: _PathType, data: bytes) -> Report:
    """Extract ZIP from bytes with default settings."""
    ...

# TAR
def extract_tar_file(destination: _PathType, path: _PathType) -> Report:
    """Extract a TAR file with default settings."""
    ...

def extract_tar_gz_file(destination: _PathType, path: _PathType) -> Report:
    """Extract a gzip-compressed TAR file (.tar.gz, .tgz) with default settings."""
    ...

def extract_tar_bytes(destination: _PathType, data: bytes) -> Report:
    """Extract TAR from bytes with default settings."""
    ...


# ============================================================================
# Async Convenience Functions
# ============================================================================

# ZIP
async def async_extract_file(destination: _PathType, path: _PathType) -> Report:
    """Extract a ZIP file asynchronously with default settings."""
    ...

async def async_extract_bytes(destination: _PathType, data: bytes) -> Report:
    """Extract ZIP from bytes asynchronously with default settings."""
    ...

# TAR
async def async_extract_tar_file(destination: _PathType, path: _PathType) -> Report:
    """Extract a TAR file asynchronously with default settings."""
    ...

async def async_extract_tar_gz_file(destination: _PathType, path: _PathType) -> Report:
    """Extract a gzip-compressed TAR file asynchronously with default settings."""
    ...

async def async_extract_tar_bytes(destination: _PathType, data: bytes) -> Report:
    """Extract TAR from bytes asynchronously with default settings."""
    ...


# ============================================================================
# Sync Listing Functions
# ============================================================================

# ZIP
def list_zip_entries(path: _PathType) -> List[EntryInfo]:
    """List entries in a ZIP file without extracting."""
    ...

def list_zip_bytes(data: bytes) -> List[EntryInfo]:
    """List entries in ZIP bytes without extracting."""
    ...

# TAR
def list_tar_entries(path: _PathType) -> List[EntryInfo]:
    """List entries in a TAR file without extracting."""
    ...

def list_tar_gz_entries(path: _PathType) -> List[EntryInfo]:
    """List entries in a gzip-compressed TAR file without extracting."""
    ...

def list_tar_bytes(data: bytes) -> List[EntryInfo]:
    """List entries in TAR bytes without extracting."""
    ...


# ============================================================================
# Sync Verification Functions
# ============================================================================

def verify_file(path: _PathType) -> VerifyReport:
    """Verify archive integrity by checking CRC32 for all entries.
    
    Reads and decompresses all file entries without writing to disk.
    Returns VerifyReport on success, raises exception on CRC failure.
    """
    ...


def verify_bytes(data: bytes) -> VerifyReport:
    """Verify archive integrity from bytes."""
    ...


# ============================================================================
# Async Listing Functions
# ============================================================================

async def async_list_zip_entries(path: _PathType) -> List[EntryInfo]:
    """List entries in a ZIP file asynchronously without extracting."""
    ...

async def async_list_zip_bytes(data: bytes) -> List[EntryInfo]:
    """List entries in ZIP bytes asynchronously without extracting."""
    ...

async def async_list_tar_entries(path: _PathType) -> List[EntryInfo]:
    """List entries in a TAR file asynchronously without extracting."""
    ...

async def async_list_tar_gz_entries(path: _PathType) -> List[EntryInfo]:
    """List entries in a gzip-compressed TAR file asynchronously."""
    ...

async def async_list_tar_bytes(data: bytes) -> List[EntryInfo]:
    """List entries in TAR bytes asynchronously without extracting."""
    ...


# ============================================================================
# Async Verification Functions
# ============================================================================

async def async_verify_file(path: _PathType) -> VerifyReport:
    """Verify archive integrity asynchronously without extracting.
    
    Reads and decompresses all file entries to check CRC32.
    Returns VerifyReport on success, raises exception on CRC failure.
    """
    ...


async def async_verify_bytes(data: bytes) -> VerifyReport:
    """Verify archive integrity from bytes asynchronously."""
    ...


class SafeUnzipError(Exception):
    """Base exception for safe_unzip errors."""
    ...

class PathEscapeError(SafeUnzipError):
    """Path escapes destination directory (Zip Slip attack) or contains invalid characters."""
    ...

class SymlinkNotAllowedError(SafeUnzipError):
    """Archive contains symlink and policy is 'error'."""
    ...

class QuotaError(SafeUnzipError):
    """Resource limit exceeded (size, count, depth)."""
    ...

class AlreadyExistsError(SafeUnzipError):
    """File already exists and policy is 'error'."""
    ...

class EncryptedArchiveError(SafeUnzipError):
    """Archive contains encrypted entries (not supported)."""
    ...

class UnsupportedEntryTypeError(SafeUnzipError):
    """Archive contains unsupported entry type (device file, fifo, etc.)."""
    ...

