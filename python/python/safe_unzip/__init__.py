"""
safe_unzip - Secure archive extraction that prevents Zip Slip and Zip Bombs.

Example usage:
    from safe_unzip import extract_file, extract_tar_file
    
    # ZIP extraction
    report = extract_file("/var/uploads", "archive.zip")
    print(f"Extracted {report.files_extracted} files")
    
    # TAR extraction
    report = extract_tar_file("/var/uploads", "archive.tar")
    report = extract_tar_gz_file("/var/uploads", "archive.tar.gz")

With options:
    from safe_unzip import Extractor
    
    report = (
        Extractor("/var/uploads")
        .max_total_mb(500)
        .max_files(1000)
        .mode("validate_first")
        .extract_file("archive.zip")  # or .extract_tar_file("archive.tar")
    )

Async usage:
    from safe_unzip import async_extract_file, AsyncExtractor
    
    # Convenience function
    report = await async_extract_file("/var/uploads", "archive.zip")
    
    # With options
    report = await (
        AsyncExtractor("/var/uploads")
        .max_total_mb(500)
        .extract_file("archive.zip")
    )
"""

import asyncio
from os import PathLike
from pathlib import Path
from typing import Union, Literal, Optional, Callable

from safe_unzip._safe_unzip import (
    # Classes
    Extractor as _RustExtractor,
    Report,
    VerifyReport,
    EntryInfo,
    # Functions - ZIP extraction
    extract_file,
    extract_bytes,
    # Functions - TAR extraction
    extract_tar_file,
    extract_tar_gz_file,
    extract_tar_bytes,
    # Functions - Listing (no extraction)
    list_zip_entries,
    list_zip_bytes,
    list_tar_entries,
    list_tar_gz_entries,
    list_tar_bytes,
    # Functions - Verification (no extraction)
    verify_file,
    verify_bytes,
    # Exceptions
    SafeUnzipError,
    PathEscapeError,
    SymlinkNotAllowedError,
    QuotaError,
    AlreadyExistsError,
    EncryptedArchiveError,
    UnsupportedEntryTypeError,
)

_PathType = Union[str, PathLike, Path]
_OverwritePolicy = Literal["error", "skip", "overwrite"]
_SymlinkPolicy = Literal["skip", "error"]
_ExtractionMode = Literal["streaming", "validate_first"]


# ============================================================================
# Extractor with context manager support
# ============================================================================

class Extractor:
    """Archive extractor with security constraints. Supports ZIP and TAR.
    
    Can be used as a context manager:
        with Extractor("/var/uploads") as e:
            e.extract_file("archive.zip")
    
    Or with builder pattern:
        report = (
            Extractor("/var/uploads")
            .max_total_mb(500)
            .max_files(1000)
            .extract_file("archive.zip")
        )
    """
    
    def __init__(self, destination: _PathType) -> None:
        """Create extractor for the given destination directory."""
        self._inner = _RustExtractor(destination)
    
    def __enter__(self) -> "Extractor":
        """Enter the context manager."""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Exit the context manager."""
        return False
    
    # Builder methods
    def max_total_mb(self, mb: int) -> "Extractor":
        """Set maximum total bytes to extract (in megabytes)."""
        self._inner.max_total_mb(mb)
        return self
    
    def max_files(self, count: int) -> "Extractor":
        """Set maximum number of files to extract."""
        self._inner.max_files(count)
        return self
    
    def max_single_file_mb(self, mb: int) -> "Extractor":
        """Set maximum size of a single file (in megabytes)."""
        self._inner.max_single_file_mb(mb)
        return self
    
    def max_depth(self, depth: int) -> "Extractor":
        """Set maximum directory depth."""
        self._inner.max_depth(depth)
        return self
    
    def overwrite(self, policy: _OverwritePolicy) -> "Extractor":
        """Set overwrite policy: 'error', 'skip', or 'overwrite'."""
        self._inner.overwrite(policy)
        return self
    
    def symlinks(self, policy: _SymlinkPolicy) -> "Extractor":
        """Set symlink policy: 'skip' or 'error'."""
        self._inner.symlinks(policy)
        return self
    
    def mode(self, mode: _ExtractionMode) -> "Extractor":
        """Set extraction mode: 'streaming' or 'validate_first'."""
        self._inner.mode(mode)
        return self
    
    # Filter methods
    def only(self, names: list[str]) -> "Extractor":
        """Extract only specific files by exact name (case-sensitive).
        
        Example:
            extractor.only(["README.md", "LICENSE"]).extract_file("archive.zip")
        """
        self._inner.only(names)
        return self
    
    def include_glob(self, patterns: list[str]) -> "Extractor":
        """Include only files matching glob patterns.
        
        Patterns: `*` matches except `/`, `**` matches including `/`, `?` matches one char.
        
        Example:
            extractor.include_glob(["**/*.py"]).extract_file("archive.zip")
        """
        self._inner.include_glob(patterns)
        return self
    
    def exclude_glob(self, patterns: list[str]) -> "Extractor":
        """Exclude files matching glob patterns.
        
        Example:
            extractor.exclude_glob(["**/__pycache__/**"]).extract_file("archive.zip")
        """
        self._inner.exclude_glob(patterns)
        return self
    
    def on_progress(self, callback) -> "Extractor":
        """Set a progress callback.
        
        The callback is called before processing each entry with a dict:
        - entry_name: str
        - entry_size: int  
        - entry_index: int
        - total_entries: int
        - bytes_written: int
        - files_extracted: int
        
        Example:
            def show_progress(p):
                print(f"[{p['entry_index']+1}/{p['total_entries']}] {p['entry_name']}")
            
            extractor.on_progress(show_progress).extract_file("archive.zip")
        """
        self._inner.on_progress(callback)
        return self
    
    # ZIP extraction
    def extract_file(self, path: _PathType) -> Report:
        """Extract a ZIP file."""
        return self._inner.extract_file(path)
    
    def extract_bytes(self, data: bytes) -> Report:
        """Extract ZIP from bytes."""
        return self._inner.extract_bytes(data)
    
    # TAR extraction
    def extract_tar_file(self, path: _PathType) -> Report:
        """Extract a TAR file."""
        return self._inner.extract_tar_file(path)
    
    def extract_tar_gz_file(self, path: _PathType) -> Report:
        """Extract a gzip-compressed TAR file (.tar.gz, .tgz)."""
        return self._inner.extract_tar_gz_file(path)
    
    def extract_tar_bytes(self, data: bytes) -> Report:
        """Extract TAR from bytes."""
        return self._inner.extract_tar_bytes(data)
    
    def extract_tar_gz_bytes(self, data: bytes) -> Report:
        """Extract gzip-compressed TAR from bytes."""
        return self._inner.extract_tar_gz_bytes(data)


# ============================================================================
# Async Convenience Functions
# ============================================================================

async def async_extract_file(destination: _PathType, path: _PathType) -> Report:
    """Extract a ZIP file asynchronously with default settings."""
    return await asyncio.to_thread(extract_file, destination, path)


async def async_extract_bytes(destination: _PathType, data: bytes) -> Report:
    """Extract ZIP from bytes asynchronously with default settings."""
    return await asyncio.to_thread(extract_bytes, destination, data)


async def async_extract_tar_file(destination: _PathType, path: _PathType) -> Report:
    """Extract a TAR file asynchronously with default settings."""
    return await asyncio.to_thread(extract_tar_file, destination, path)


async def async_extract_tar_gz_file(destination: _PathType, path: _PathType) -> Report:
    """Extract a gzip-compressed TAR file asynchronously with default settings."""
    return await asyncio.to_thread(extract_tar_gz_file, destination, path)


async def async_extract_tar_bytes(destination: _PathType, data: bytes) -> Report:
    """Extract TAR from bytes asynchronously with default settings."""
    return await asyncio.to_thread(extract_tar_bytes, destination, data)


# ============================================================================
# Async Listing Functions
# ============================================================================

async def async_list_zip_entries(path: _PathType) -> list:
    """List entries in a ZIP file asynchronously without extracting."""
    return await asyncio.to_thread(list_zip_entries, path)


async def async_list_zip_bytes(data: bytes) -> list:
    """List entries in ZIP bytes asynchronously without extracting."""
    return await asyncio.to_thread(list_zip_bytes, data)


async def async_list_tar_entries(path: _PathType) -> list:
    """List entries in a TAR file asynchronously without extracting."""
    return await asyncio.to_thread(list_tar_entries, path)


async def async_list_tar_gz_entries(path: _PathType) -> list:
    """List entries in a gzip-compressed TAR file asynchronously."""
    return await asyncio.to_thread(list_tar_gz_entries, path)


async def async_list_tar_bytes(data: bytes) -> list:
    """List entries in TAR bytes asynchronously without extracting."""
    return await asyncio.to_thread(list_tar_bytes, data)


# ============================================================================
# Async Verification Functions
# ============================================================================

async def async_verify_file(path: _PathType) -> "VerifyReport":
    """Verify archive integrity asynchronously without extracting.
    
    Reads and decompresses all file entries to check CRC32.
    Returns VerifyReport on success, raises exception on CRC failure.
    """
    return await asyncio.to_thread(verify_file, path)


async def async_verify_bytes(data: bytes) -> "VerifyReport":
    """Verify archive integrity from bytes asynchronously."""
    return await asyncio.to_thread(verify_bytes, data)


# ============================================================================
# AsyncExtractor - Async wrapper for Extractor
# ============================================================================

class AsyncExtractor:
    """Async archive extractor with security constraints. Supports ZIP and TAR.
    
    Example:
        report = await (
            AsyncExtractor("/var/uploads")
            .max_total_mb(500)
            .max_files(1000)
            .extract_file("archive.zip")
        )
    
    Or as an async context manager:
        async with AsyncExtractor("/var/uploads") as e:
            await e.extract_file("archive.zip")
    """
    
    def __init__(self, destination: _PathType) -> None:
        """Create async extractor for the given destination directory."""
        self._extractor = _RustExtractor(destination)
    
    async def __aenter__(self) -> "AsyncExtractor":
        """Enter the async context manager."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb) -> bool:
        """Exit the async context manager."""
        return False
    
    def max_total_mb(self, mb: int) -> "AsyncExtractor":
        """Set maximum total bytes to extract (in megabytes)."""
        self._extractor.max_total_mb(mb)
        return self
    
    def max_files(self, count: int) -> "AsyncExtractor":
        """Set maximum number of files to extract."""
        self._extractor.max_files(count)
        return self
    
    def max_single_file_mb(self, mb: int) -> "AsyncExtractor":
        """Set maximum size of a single file (in megabytes)."""
        self._extractor.max_single_file_mb(mb)
        return self
    
    def max_depth(self, depth: int) -> "AsyncExtractor":
        """Set maximum directory depth."""
        self._extractor.max_depth(depth)
        return self
    
    def overwrite(self, policy: _OverwritePolicy) -> "AsyncExtractor":
        """Set overwrite policy: 'error', 'skip', or 'overwrite'."""
        self._extractor.overwrite(policy)
        return self
    
    def symlinks(self, policy: _SymlinkPolicy) -> "AsyncExtractor":
        """Set symlink policy: 'skip' or 'error'."""
        self._extractor.symlinks(policy)
        return self
    
    def mode(self, mode: _ExtractionMode) -> "AsyncExtractor":
        """Set extraction mode: 'streaming' or 'validate_first'."""
        self._extractor.mode(mode)
        return self
    
    # Filter methods
    def only(self, names: list[str]) -> "AsyncExtractor":
        """Extract only specific files by exact name (case-sensitive)."""
        self._extractor.only(names)
        return self
    
    def include_glob(self, patterns: list[str]) -> "AsyncExtractor":
        """Include only files matching glob patterns."""
        self._extractor.include_glob(patterns)
        return self
    
    def exclude_glob(self, patterns: list[str]) -> "AsyncExtractor":
        """Exclude files matching glob patterns."""
        self._extractor.exclude_glob(patterns)
        return self
    
    def on_progress(self, callback) -> "AsyncExtractor":
        """Set a progress callback.
        
        The callback is called before processing each entry with a dict.
        Note: The callback runs in a thread pool, so it should be thread-safe.
        """
        self._extractor.on_progress(callback)
        return self
    
    # ZIP extraction
    async def extract_file(self, path: _PathType) -> Report:
        """Extract a ZIP file asynchronously."""
        return await asyncio.to_thread(self._extractor.extract_file, path)
    
    async def extract_bytes(self, data: bytes) -> Report:
        """Extract ZIP from bytes asynchronously."""
        return await asyncio.to_thread(self._extractor.extract_bytes, data)
    
    # TAR extraction
    async def extract_tar_file(self, path: _PathType) -> Report:
        """Extract a TAR file asynchronously."""
        return await asyncio.to_thread(self._extractor.extract_tar_file, path)
    
    async def extract_tar_gz_file(self, path: _PathType) -> Report:
        """Extract a gzip-compressed TAR file (.tar.gz, .tgz) asynchronously."""
        return await asyncio.to_thread(self._extractor.extract_tar_gz_file, path)
    
    async def extract_tar_bytes(self, data: bytes) -> Report:
        """Extract TAR from bytes asynchronously."""
        return await asyncio.to_thread(self._extractor.extract_tar_bytes, data)
    
    async def extract_tar_gz_bytes(self, data: bytes) -> Report:
        """Extract gzip-compressed TAR from bytes asynchronously."""
        return await asyncio.to_thread(self._extractor.extract_tar_gz_bytes, data)


__all__ = [
    # Classes
    "Extractor",
    "AsyncExtractor",
    "Report",
    "VerifyReport",
    "EntryInfo",
    # Sync Functions - ZIP extraction
    "extract_file",
    "extract_bytes",
    # Sync Functions - TAR extraction
    "extract_tar_file",
    "extract_tar_gz_file",
    "extract_tar_bytes",
    # Sync Functions - Listing (no extraction)
    "list_zip_entries",
    "list_zip_bytes",
    "list_tar_entries",
    "list_tar_gz_entries",
    "list_tar_bytes",
    # Sync Functions - Verification (no extraction)
    "verify_file",
    "verify_bytes",
    # Async Functions - ZIP
    "async_extract_file",
    "async_extract_bytes",
    # Async Functions - TAR
    "async_extract_tar_file",
    "async_extract_tar_gz_file",
    "async_extract_tar_bytes",
    # Async Functions - Listing
    "async_list_zip_entries",
    "async_list_tar_entries",
    # Async Functions - Verification
    "async_verify_file",
    "async_verify_bytes",
    # Exceptions
    "SafeUnzipError",
    "PathEscapeError",
    "SymlinkNotAllowedError",
    "QuotaError",
    "AlreadyExistsError",
    "EncryptedArchiveError",
    "UnsupportedEntryTypeError",
]

__version__ = "0.1.4"

