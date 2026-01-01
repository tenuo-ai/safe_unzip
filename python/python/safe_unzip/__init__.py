"""
safe_unzip - Secure zip extraction that prevents Zip Slip and Zip Bombs.

Example usage:
    from safe_unzip import extract_file
    
    report = extract_file("/var/uploads", "archive.zip")
    print(f"Extracted {report.files_extracted} files")

With options:
    from safe_unzip import Extractor
    
    report = (
        Extractor("/var/uploads")
        .max_total_mb(500)
        .max_files(1000)
        .mode("validate_first")
        .extract_file("archive.zip")
    )
"""

from safe_unzip._safe_unzip import (
    # Classes
    Extractor,
    Report,
    # Functions
    extract_file,
    extract_bytes,
    # Exceptions
    SafeUnzipError,
    PathEscapeError,
    SymlinkNotAllowedError,
    QuotaError,
    AlreadyExistsError,
    EncryptedArchiveError,
    UnsupportedEntryTypeError,
)

__all__ = [
    # Classes
    "Extractor",
    "Report",
    # Functions
    "extract_file",
    "extract_bytes",
    # Exceptions
    "SafeUnzipError",
    "PathEscapeError",
    "SymlinkNotAllowedError",
    "QuotaError",
    "AlreadyExistsError",
    "EncryptedArchiveError",
    "UnsupportedEntryTypeError",
]

__version__ = "0.1.0"

