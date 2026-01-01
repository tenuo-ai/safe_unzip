"""Type stubs for safe_unzip."""

from os import PathLike
from pathlib import Path
from typing import Union, Literal

_PathType = Union[str, PathLike[str], Path]
_OverwritePolicy = Literal["error", "skip", "overwrite"]
_SymlinkPolicy = Literal["skip", "error"]
_ExtractionMode = Literal["streaming", "validate_first"]

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

class Extractor:
    """Zip extractor with security constraints."""
    
    def __init__(self, destination: _PathType) -> None:
        """Create extractor for the given destination directory."""
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
    
    def extract_file(self, path: _PathType) -> Report:
        """Extract from a file path."""
        ...
    
    def extract_bytes(self, data: bytes) -> Report:
        """Extract from bytes."""
        ...

def extract_file(destination: _PathType, path: _PathType) -> Report:
    """Extract a zip file with default settings."""
    ...

def extract_bytes(destination: _PathType, data: bytes) -> Report:
    """Extract from bytes with default settings."""
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

