"""Tests for safe_unzip Python bindings.

These tests verify that the Python bindings have identical security
guarantees to the Rust implementation.
"""

import io
import gzip
import os
import tarfile
import zipfile
from pathlib import Path

import pytest

from safe_unzip import (
    Extractor,
    extract_file,
    extract_bytes,
    extract_tar_file,
    extract_tar_gz_file,
    extract_tar_bytes,
    PathEscapeError,
    QuotaError,
    AlreadyExistsError,
    UnsupportedEntryTypeError,
)


# ============================================================================
# Helper Functions
# ============================================================================

def create_simple_zip(filename: str, content: bytes) -> bytes:
    """Create a zip file with a single entry."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zf:
        zf.writestr(filename, content)
    return buffer.getvalue()


def create_multi_file_zip(files: dict[str, bytes]) -> bytes:
    """Create a zip file with multiple entries."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buffer.getvalue()


# ============================================================================
# Basic Functionality Tests
# ============================================================================

def test_extract_simple_zip(tmp_path):
    """Test basic extraction works."""
    zip_data = create_simple_zip("hello.txt", b"Hello, World!")
    
    report = Extractor(tmp_path).extract_bytes(zip_data)
    
    assert report.files_extracted == 1
    assert report.bytes_written == 13
    assert (tmp_path / "hello.txt").read_text() == "Hello, World!"


def test_extract_multiple_files(tmp_path):
    """Test extracting multiple files."""
    zip_data = create_multi_file_zip({
        "a.txt": b"aaa",
        "b.txt": b"bbb",
        "subdir/c.txt": b"ccc",
    })
    
    report = Extractor(tmp_path).extract_bytes(zip_data)
    
    assert report.files_extracted == 3
    # Note: dirs_created only counts explicit directory entries, not implicit parent creation
    assert (tmp_path / "a.txt").exists()
    assert (tmp_path / "subdir" / "c.txt").exists()


def test_extract_to_subdirectory(tmp_path):
    """Test extracting to a subdirectory."""
    new_dest = tmp_path / "new_folder"
    new_dest.mkdir()  # Extractor requires existing directory
    zip_data = create_simple_zip("file.txt", b"data")
    
    report = Extractor(new_dest).extract_bytes(zip_data)
    
    assert (new_dest / "file.txt").exists()
    assert report.files_extracted == 1


# ============================================================================
# Security Tests: Path Traversal (Zip Slip)
# ============================================================================

def test_blocks_path_traversal(tmp_path):
    """Test that path traversal attacks are blocked."""
    # Create malicious zip with traversal path
    zip_data = create_simple_zip("../../etc/passwd", b"evil")
    
    with pytest.raises(PathEscapeError):
        Extractor(tmp_path).extract_bytes(zip_data)
    
    # Ensure nothing was written outside
    assert not (tmp_path.parent.parent / "etc" / "passwd").exists()


def test_blocks_absolute_path(tmp_path):
    """Test that absolute paths are blocked or contained."""
    zip_data = create_simple_zip("/tmp/evil.txt", b"evil")
    
    # Should either raise PathEscapeError or safely contain it
    try:
        Extractor(tmp_path).extract_bytes(zip_data)
        # If it succeeded, verify it didn't write to actual /tmp
        assert not Path("/tmp/evil.txt").exists()
    except PathEscapeError:
        pass  # Expected behavior


@pytest.mark.skipif(os.name == 'nt', reason="Windows normalizes backslashes before Rust sees them")
def test_blocks_backslash_traversal(tmp_path):
    """Test that backslash paths are rejected."""
    zip_data = create_simple_zip("folder\\file.txt", b"data")
    
    with pytest.raises(PathEscapeError):
        Extractor(tmp_path).extract_bytes(zip_data)


@pytest.mark.skipif(os.name != 'nt', reason="Windows-only test")
def test_blocks_windows_drive_path(tmp_path):
    """Test that Windows drive paths are blocked."""
    zip_data = create_simple_zip("C:\\Windows\\evil.txt", b"evil")
    
    # Should either raise PathEscapeError or safely contain it
    try:
        Extractor(tmp_path).extract_bytes(zip_data)
        # If succeeded, ensure it didn't write to actual C:\Windows
        assert not Path("C:\\Windows\\evil.txt").exists()
    except PathEscapeError:
        pass  # Expected behavior


# ============================================================================
# Security Tests: Zip Bombs
# ============================================================================

def test_enforces_total_size_limit(tmp_path):
    """Test that total size limit is enforced."""
    # Create zip with content larger than limit
    zip_data = create_simple_zip("big.txt", b"x" * 1000)
    
    with pytest.raises(QuotaError):
        Extractor(tmp_path).max_total_mb(0).extract_bytes(zip_data)  # 0 MB limit


def test_enforces_file_count_limit(tmp_path):
    """Test that file count limit is enforced."""
    zip_data = create_multi_file_zip({
        "a.txt": b"a",
        "b.txt": b"b",
        "c.txt": b"c",
        "d.txt": b"d",
        "e.txt": b"e",
    })
    
    with pytest.raises(QuotaError):
        Extractor(tmp_path).max_files(3).extract_bytes(zip_data)


def test_enforces_single_file_limit(tmp_path):
    """Test that single file size limit is enforced."""
    zip_data = create_simple_zip("big.txt", b"x" * 10000)
    
    with pytest.raises(QuotaError):
        # 1 byte limit per file
        Extractor(tmp_path).max_single_file_mb(0).extract_bytes(zip_data)


def test_enforces_path_depth_limit(tmp_path):
    """Test that path depth limit is enforced."""
    deep_path = "/".join(["d"] * 100) + "/file.txt"
    zip_data = create_simple_zip(deep_path, b"deep")
    
    with pytest.raises(QuotaError):
        Extractor(tmp_path).max_depth(10).extract_bytes(zip_data)


# ============================================================================
# Security Tests: Overwrite Policies
# ============================================================================

def test_overwrite_policy_error(tmp_path):
    """Test that overwrite policy 'error' raises on existing files."""
    (tmp_path / "existing.txt").write_text("original")
    zip_data = create_simple_zip("existing.txt", b"new")
    
    with pytest.raises(AlreadyExistsError):
        Extractor(tmp_path).overwrite("error").extract_bytes(zip_data)
    
    # Original should be unchanged
    assert (tmp_path / "existing.txt").read_text() == "original"


def test_overwrite_policy_skip(tmp_path):
    """Test that overwrite policy 'skip' preserves existing files."""
    (tmp_path / "existing.txt").write_text("original")
    zip_data = create_simple_zip("existing.txt", b"new")
    
    report = Extractor(tmp_path).overwrite("skip").extract_bytes(zip_data)
    
    assert report.entries_skipped == 1
    assert (tmp_path / "existing.txt").read_text() == "original"


def test_overwrite_policy_overwrite(tmp_path):
    """Test that overwrite policy 'overwrite' replaces existing files."""
    (tmp_path / "existing.txt").write_text("original")
    zip_data = create_simple_zip("existing.txt", b"new")
    
    report = Extractor(tmp_path).overwrite("overwrite").extract_bytes(zip_data)
    
    assert report.files_extracted == 1
    assert (tmp_path / "existing.txt").read_bytes() == b"new"


# ============================================================================
# Security Tests: Symlinks (Unix only)
# ============================================================================

@pytest.mark.skipif(os.name != 'posix', reason="Unix-only test")
def test_symlink_overwrite_protection(tmp_path):
    """Test that symlinks are removed before overwriting, not followed."""
    # Create target and symlink
    target = tmp_path / "target.txt"
    target.write_text("sensitive")
    link = tmp_path / "link"
    link.symlink_to(target)
    
    # Create zip that writes to "link"
    zip_data = create_simple_zip("link", b"overwritten")
    
    # Extract with overwrite
    Extractor(tmp_path).overwrite("overwrite").extract_bytes(zip_data)
    
    # Link should now be a regular file
    assert not link.is_symlink()
    assert link.read_bytes() == b"overwritten"
    
    # Target should be unchanged (symlink was removed, not followed)
    assert target.read_text() == "sensitive"


# ============================================================================
# Extraction Mode Tests
# ============================================================================

def test_validate_first_prevents_partial_extraction(tmp_path):
    """Test that validate_first mode doesn't write if validation fails."""
    # Create zip with valid file first, then traversal attempt
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zf:
        zf.writestr("good.txt", b"good")
        zf.writestr("../../evil.txt", b"evil")
    zip_data = buffer.getvalue()
    
    with pytest.raises(PathEscapeError):
        Extractor(tmp_path).mode("validate_first").extract_bytes(zip_data)
    
    # Nothing should be extracted (not even good.txt)
    assert not (tmp_path / "good.txt").exists()


def test_streaming_may_leave_partial_state(tmp_path):
    """Test that streaming mode may leave partial files on failure."""
    # Create zip with valid file first, then traversal attempt
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as zf:
        zf.writestr("good.txt", b"good")
        zf.writestr("../../evil.txt", b"evil")
    zip_data = buffer.getvalue()
    
    with pytest.raises(PathEscapeError):
        Extractor(tmp_path).mode("streaming").extract_bytes(zip_data)
    
    # In streaming mode, good.txt MAY have been extracted before failure
    # (This is expected behavior, not a bug)


# ============================================================================
# Invalid Filename Tests
# ============================================================================

# Note: Some invalid filename tests are skipped because Python's zipfile module
# either can't create such files or handles them differently than raw zip bytes.
# These cases are fully tested in the Rust test suite.

@pytest.mark.skip(reason="Python's zipfile truncates at null byte, can't test from Python")
def test_rejects_null_byte_in_filename(tmp_path):
    """Test that null bytes in filenames are rejected."""
    zip_data = create_simple_zip("file.txt\x00.exe", b"data")
    
    with pytest.raises(PathEscapeError):
        Extractor(tmp_path).extract_bytes(zip_data)


@pytest.mark.skip(reason="Python's zipfile crashes on empty filename, can't create test fixture")
def test_rejects_empty_filename(tmp_path):
    """Test that empty filenames are rejected."""
    zip_data = create_simple_zip("", b"data")
    
    with pytest.raises(PathEscapeError):
        Extractor(tmp_path).extract_bytes(zip_data)


# ============================================================================
# TAR Extraction Tests
# ============================================================================

def create_simple_tar(filename: str, content: bytes) -> bytes:
    """Create a tar file with a single entry."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as tf:
        info = tarfile.TarInfo(name=filename)
        info.size = len(content)
        tf.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def create_multi_file_tar(files: dict[str, bytes]) -> bytes:
    """Create a tar file with multiple entries."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode='w') as tf:
        for name, content in files.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return buffer.getvalue()


def create_tar_gz(tar_data: bytes) -> bytes:
    """Compress tar data with gzip."""
    buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=buffer, mode='wb') as gz:
        gz.write(tar_data)
    return buffer.getvalue()


def test_tar_extract_simple(tmp_path):
    """Test basic TAR extraction."""
    tar_data = create_simple_tar("hello.txt", b"Hello, TAR!")
    
    report = Extractor(tmp_path).extract_tar_bytes(tar_data)
    
    assert report.files_extracted == 1
    assert report.bytes_written == 11
    assert (tmp_path / "hello.txt").read_text() == "Hello, TAR!"


def test_tar_extract_multiple_files(tmp_path):
    """Test extracting multiple files from TAR."""
    tar_data = create_multi_file_tar({
        "a.txt": b"aaa",
        "b.txt": b"bbb",
        "subdir/c.txt": b"ccc",
    })
    
    report = Extractor(tmp_path).extract_tar_bytes(tar_data)
    
    assert report.files_extracted == 3
    assert (tmp_path / "a.txt").exists()
    assert (tmp_path / "subdir" / "c.txt").exists()


def test_tar_gz_extraction(tmp_path):
    """Test .tar.gz extraction."""
    tar_data = create_simple_tar("compressed.txt", b"I was compressed!")
    gz_data = create_tar_gz(tar_data)
    
    report = Extractor(tmp_path).extract_tar_gz_bytes(gz_data)
    
    assert report.files_extracted == 1
    assert (tmp_path / "compressed.txt").read_text() == "I was compressed!"


def test_tar_convenience_function(tmp_path):
    """Test extract_tar_bytes convenience function."""
    tar_data = create_simple_tar("test.txt", b"test content")
    
    report = extract_tar_bytes(tmp_path, tar_data)
    
    assert report.files_extracted == 1
    assert (tmp_path / "test.txt").exists()


def test_tar_blocks_path_traversal(tmp_path):
    """Test that TAR path traversal is blocked."""
    # Note: Python's tarfile sanitizes paths, but we test anyway
    tar_data = create_simple_tar("../evil.txt", b"evil")
    
    # Should either raise or safely contain
    try:
        Extractor(tmp_path).extract_tar_bytes(tar_data)
        # If it succeeded, ensure nothing was written outside
        assert not (tmp_path.parent / "evil.txt").exists()
    except PathEscapeError:
        pass  # Expected


def test_tar_enforces_size_limit(tmp_path):
    """Test that TAR respects size limits."""
    tar_data = create_simple_tar("big.txt", b"x" * 1000)
    
    with pytest.raises(QuotaError):
        Extractor(tmp_path).max_total_mb(0).extract_tar_bytes(tar_data)


def test_tar_enforces_file_count_limit(tmp_path):
    """Test that TAR respects file count limits."""
    tar_data = create_multi_file_tar({
        "a.txt": b"a",
        "b.txt": b"b",
        "c.txt": b"c",
        "d.txt": b"d",
        "e.txt": b"e",
    })
    
    with pytest.raises(QuotaError):
        Extractor(tmp_path).max_files(3).extract_tar_bytes(tar_data)


def test_tar_enforces_depth_limit(tmp_path):
    """Test that TAR respects depth limits."""
    deep_path = "/".join(["d"] * 100) + "/file.txt"
    tar_data = create_simple_tar(deep_path, b"deep")
    
    with pytest.raises(QuotaError):
        Extractor(tmp_path).max_depth(10).extract_tar_bytes(tar_data)


def test_tar_overwrite_policy_error(tmp_path):
    """Test that TAR respects overwrite policy 'error'."""
    (tmp_path / "existing.txt").write_text("original")
    tar_data = create_simple_tar("existing.txt", b"new")
    
    with pytest.raises(AlreadyExistsError):
        Extractor(tmp_path).overwrite("error").extract_tar_bytes(tar_data)
    
    assert (tmp_path / "existing.txt").read_text() == "original"


def test_tar_overwrite_policy_skip(tmp_path):
    """Test that TAR respects overwrite policy 'skip'."""
    (tmp_path / "existing.txt").write_text("original")
    tar_data = create_simple_tar("existing.txt", b"new")
    
    report = Extractor(tmp_path).overwrite("skip").extract_tar_bytes(tar_data)
    
    assert report.entries_skipped == 1
    assert (tmp_path / "existing.txt").read_text() == "original"


def test_tar_validate_first_mode(tmp_path):
    """Test that TAR validate_first mode works."""
    # Create tar with valid file then oversized file
    tar_data = create_multi_file_tar({
        "good.txt": b"good",
        "big.txt": b"x" * 10000,
    })
    
    with pytest.raises(QuotaError):
        (Extractor(tmp_path)
         .max_single_file_mb(0)
         .mode("validate_first")
         .extract_tar_bytes(tar_data))
    
    # Nothing should be extracted in validate_first mode
    assert not (tmp_path / "good.txt").exists()


# ============================================================================
# Edge Case Tests
# ============================================================================

def test_empty_zip_archive(tmp_path):
    """Test that empty ZIP archives are handled correctly."""
    import zipfile
    
    # Create empty zip
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        pass  # No files added
    
    report = Extractor(tmp_path).extract_bytes(buf.getvalue())
    assert report.files_extracted == 0
    assert report.bytes_written == 0


def test_directory_only_zip(tmp_path):
    """Test ZIP with only directory entries."""
    import zipfile
    
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        # Add directory entries (trailing slash)
        zf.writestr("dir1/", "")
        zf.writestr("dir1/subdir/", "")
        zf.writestr("dir2/", "")
    
    report = Extractor(tmp_path).extract_bytes(buf.getvalue())
    assert report.files_extracted == 0  # No files, only dirs
    assert (tmp_path / "dir1").is_dir()
    assert (tmp_path / "dir1" / "subdir").is_dir()
    assert (tmp_path / "dir2").is_dir()


def test_empty_tar_archive(tmp_path):
    """Test that empty TAR archives are handled correctly."""
    # Create empty tar
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w') as tar:
        pass  # No files added
    
    report = Extractor(tmp_path).extract_tar_bytes(buf.getvalue())
    assert report.files_extracted == 0
    assert report.bytes_written == 0


def test_zero_size_limit(tmp_path):
    """Test that zero size limit rejects all files."""
    zip_data = create_simple_zip("tiny.txt", b"x")
    
    with pytest.raises(QuotaError):
        (Extractor(tmp_path)
         .max_total_mb(0)
         .extract_bytes(zip_data))


def test_zero_file_count_limit(tmp_path):
    """Test that zero file count limit rejects all files."""
    zip_data = create_simple_zip("tiny.txt", b"x")
    
    with pytest.raises(QuotaError):
        (Extractor(tmp_path)
         .max_files(0)
         .extract_bytes(zip_data))


def test_zero_single_file_limit(tmp_path):
    """Test that zero single file limit rejects all files."""
    zip_data = create_simple_zip("tiny.txt", b"x")
    
    with pytest.raises(QuotaError):
        (Extractor(tmp_path)
         .max_single_file_mb(0)
         .extract_bytes(zip_data))


def test_very_deep_nesting_tar(tmp_path):
    """Test TAR with many levels of nesting."""
    # Create deeply nested path
    deep_path = "/".join(["d"] * 30) + "/file.txt"
    tar_data = create_simple_tar(deep_path, b"deep")
    
    # Default depth limit is 50, so 30 should pass
    report = Extractor(tmp_path).extract_tar_bytes(tar_data)
    assert report.files_extracted == 1
    
    # With strict limit, should fail
    with pytest.raises(QuotaError):
        (Extractor(tmp_path)
         .max_depth(10)
         .extract_tar_bytes(tar_data))

