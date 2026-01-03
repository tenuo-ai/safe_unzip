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
    AsyncExtractor,
    EntryInfo,
    extract_file,
    extract_bytes,
    extract_tar_file,
    extract_tar_gz_file,
    extract_tar_bytes,
    list_zip_entries,
    list_zip_bytes,
    list_tar_entries,
    list_tar_bytes,
    async_list_zip_bytes,
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


# ============================================================================
# Async Tests
# ============================================================================

@pytest.mark.asyncio
async def test_async_extract_bytes(tmp_path):
    """Test async extraction from bytes."""
    from safe_unzip import async_extract_bytes
    
    zip_data = create_simple_zip("hello.txt", b"Hello, World!")
    
    report = await async_extract_bytes(tmp_path, zip_data)
    
    assert report.files_extracted == 1
    assert (tmp_path / "hello.txt").read_bytes() == b"Hello, World!"


@pytest.mark.asyncio
async def test_async_extractor_basic(tmp_path):
    """Test AsyncExtractor with builder pattern."""
    from safe_unzip import AsyncExtractor
    
    zip_data = create_simple_zip("test.txt", b"test content")
    
    report = await (
        AsyncExtractor(tmp_path)
        .max_total_mb(100)
        .max_files(10)
        .extract_bytes(zip_data)
    )
    
    assert report.files_extracted == 1
    assert (tmp_path / "test.txt").read_bytes() == b"test content"


@pytest.mark.asyncio
async def test_async_extract_tar_bytes(tmp_path):
    """Test async TAR extraction."""
    from safe_unzip import async_extract_tar_bytes
    
    tar_data = create_simple_tar("file.txt", b"tar content")
    
    report = await async_extract_tar_bytes(tmp_path, tar_data)
    
    assert report.files_extracted == 1
    assert (tmp_path / "file.txt").read_bytes() == b"tar content"


@pytest.mark.asyncio
async def test_async_extractor_tar(tmp_path):
    """Test AsyncExtractor with TAR files."""
    from safe_unzip import AsyncExtractor
    
    tar_data = create_simple_tar("async.txt", b"async tar")
    
    report = await (
        AsyncExtractor(tmp_path)
        .max_files(5)
        .extract_tar_bytes(tar_data)
    )
    
    assert report.files_extracted == 1


@pytest.mark.asyncio
async def test_async_extract_tar_gz_bytes(tmp_path):
    """Test async .tar.gz extraction."""
    from safe_unzip import async_extract_tar_bytes
    
    # Create a .tar.gz
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w") as tf:
        data = b"gzipped tar content"
        info = tarfile.TarInfo(name="gz_file.txt")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))
    tar_data = tar_buffer.getvalue()
    
    gz_buffer = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buffer, mode="wb") as gz:
        gz.write(tar_data)
    gz_data = gz_buffer.getvalue()
    
    from safe_unzip import AsyncExtractor
    report = await AsyncExtractor(tmp_path).extract_tar_gz_bytes(gz_data)
    
    assert report.files_extracted == 1
    assert (tmp_path / "gz_file.txt").read_bytes() == b"gzipped tar content"


@pytest.mark.asyncio
async def test_async_concurrent_extractions(tmp_path):
    """Test multiple async extractions running concurrently."""
    import asyncio
    from safe_unzip import async_extract_bytes
    
    # Create several zip files
    zips = [
        create_simple_zip(f"file{i}.txt", f"content {i}".encode())
        for i in range(5)
    ]
    
    # Create separate directories for each
    dirs = [tmp_path / f"dir{i}" for i in range(5)]
    for d in dirs:
        d.mkdir()
    
    # Extract all concurrently
    reports = await asyncio.gather(*[
        async_extract_bytes(dirs[i], zips[i])
        for i in range(5)
    ])
    
    # Verify all succeeded
    assert all(r.files_extracted == 1 for r in reports)
    for i in range(5):
        assert (dirs[i] / f"file{i}.txt").read_bytes() == f"content {i}".encode()


@pytest.mark.asyncio
async def test_async_path_escape_rejected(tmp_path):
    """Test that path traversal is rejected in async mode."""
    from safe_unzip import async_extract_bytes
    
    zip_data = create_simple_zip("../escape.txt", b"malicious")
    
    with pytest.raises(PathEscapeError):
        await async_extract_bytes(tmp_path, zip_data)


@pytest.mark.asyncio
async def test_async_quota_enforced(tmp_path):
    """Test that quotas are enforced in async mode."""
    from safe_unzip import AsyncExtractor
    
    # 100 KB file
    large_data = b"x" * (100 * 1024)
    zip_data = create_simple_zip("large.txt", large_data)
    
    with pytest.raises(QuotaError):
        await (
            AsyncExtractor(tmp_path)
            .max_total_mb(0)  # 0 MB limit
            .extract_bytes(zip_data)
        )


# ============================================================================
# Listing Tests
# ============================================================================

def test_list_zip_bytes():
    """Test listing ZIP entries without extracting."""
    zip_data = create_multi_file_zip({
        "a.txt": b"hello",
        "dir/b.txt": b"world",
    })
    
    entries = list_zip_bytes(zip_data)
    
    assert len(entries) == 2
    assert entries[0].name == "a.txt"
    assert entries[0].size == 5
    assert entries[0].kind == "file"
    assert entries[0].is_file
    assert not entries[0].is_dir
    assert not entries[0].is_symlink


def test_list_tar_bytes():
    """Test listing TAR entries without extracting."""
    tar_data = create_multi_file_tar({
        "x.txt": b"xxx",
        "y.txt": b"yyyy",
    })
    
    entries = list_tar_bytes(tar_data)
    
    assert len(entries) == 2
    names = [e.name for e in entries]
    assert "x.txt" in names
    assert "y.txt" in names


def test_list_with_directory():
    """Test listing shows directories."""
    # Create TAR with explicit directory entry
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as tf:
        # Add directory
        dir_info = tarfile.TarInfo(name="mydir/")
        dir_info.type = tarfile.DIRTYPE
        tf.addfile(dir_info)
        # Add file in directory
        data = b"content"
        file_info = tarfile.TarInfo(name="mydir/file.txt")
        file_info.size = len(data)
        tf.addfile(file_info, io.BytesIO(data))
    tar_data = buffer.getvalue()
    
    entries = list_tar_bytes(tar_data)
    
    # Should have directory and file
    kinds = [e.kind for e in entries]
    assert "directory" in kinds
    assert "file" in kinds


@pytest.mark.asyncio
async def test_async_list_zip_bytes():
    """Test async listing of ZIP entries."""
    zip_data = create_simple_zip("test.txt", b"async listing test")
    
    entries = await async_list_zip_bytes(zip_data)
    
    assert len(entries) == 1
    assert entries[0].name == "test.txt"


# ============================================================================
# Context Manager Tests
# ============================================================================

def test_sync_context_manager(tmp_path):
    """Test Extractor as sync context manager."""
    zip_data = create_simple_zip("ctx.txt", b"context manager test")
    
    with Extractor(tmp_path) as ext:
        report = ext.extract_bytes(zip_data)
    
    assert report.files_extracted == 1
    assert (tmp_path / "ctx.txt").exists()


def test_sync_context_manager_with_options(tmp_path):
    """Test context manager with builder pattern."""
    zip_data = create_simple_zip("opts.txt", b"options test")
    
    with Extractor(tmp_path) as ext:
        ext.max_total_mb(100)
        ext.max_files(50)
        report = ext.extract_bytes(zip_data)
    
    assert report.files_extracted == 1


@pytest.mark.asyncio
async def test_async_context_manager(tmp_path):
    """Test AsyncExtractor as async context manager."""
    zip_data = create_simple_zip("async_ctx.txt", b"async context manager")
    
    async with AsyncExtractor(tmp_path) as ext:
        report = await ext.extract_bytes(zip_data)
    
    assert report.files_extracted == 1
    assert (tmp_path / "async_ctx.txt").exists()


def test_context_manager_exception_propagates(tmp_path):
    """Test that exceptions within context manager propagate correctly."""
    class CustomError(Exception):
        pass
    
    with pytest.raises(CustomError):
        with Extractor(tmp_path) as ext:
            raise CustomError("test error")


# ============================================================================
# Filtering Tests
# ============================================================================

def test_only_filter(tmp_path):
    """Test extracting only specific files by name."""
    zip_data = create_multi_file_zip({
        "readme.txt": b"readme",
        "license.txt": b"license",
        "code.py": b"code",
    })
    
    report = (
        Extractor(tmp_path)
        .only(["readme.txt", "license.txt"])
        .extract_bytes(zip_data)
    )
    
    assert report.files_extracted == 2
    assert report.entries_skipped == 1
    assert (tmp_path / "readme.txt").exists()
    assert (tmp_path / "license.txt").exists()
    assert not (tmp_path / "code.py").exists()


def test_include_glob_filter(tmp_path):
    """Test include_glob pattern matching."""
    zip_data = create_multi_file_zip({
        "src/main.py": b"main",
        "src/utils.py": b"utils",
        "tests/test_main.py": b"test",
        "readme.md": b"readme",
    })
    
    report = (
        Extractor(tmp_path)
        .include_glob(["**/*.py"])
        .extract_bytes(zip_data)
    )
    
    assert report.files_extracted == 3
    assert report.entries_skipped == 1
    assert (tmp_path / "src/main.py").exists()
    assert (tmp_path / "tests/test_main.py").exists()
    assert not (tmp_path / "readme.md").exists()


def test_exclude_glob_filter(tmp_path):
    """Test exclude_glob pattern matching."""
    zip_data = create_multi_file_zip({
        "src/main.py": b"main",
        "src/__pycache__/main.pyc": b"cache",
        "tests/test_main.py": b"test",
    })
    
    report = (
        Extractor(tmp_path)
        .exclude_glob(["**/__pycache__/**"])
        .extract_bytes(zip_data)
    )
    
    assert report.files_extracted == 2
    assert report.entries_skipped == 1
    assert (tmp_path / "src/main.py").exists()
    assert not (tmp_path / "src/__pycache__/main.pyc").exists()


def test_only_filter_on_tar(tmp_path):
    """Test only filter on TAR archives."""
    tar_data = create_multi_file_tar({
        "a.txt": b"aaa",
        "b.txt": b"bbb",
        "c.txt": b"ccc",
    })
    
    report = (
        Extractor(tmp_path)
        .only(["a.txt", "c.txt"])
        .extract_tar_bytes(tar_data)
    )
    
    assert report.files_extracted == 2
    assert (tmp_path / "a.txt").exists()
    assert not (tmp_path / "b.txt").exists()
    assert (tmp_path / "c.txt").exists()


@pytest.mark.asyncio
async def test_async_filter(tmp_path):
    """Test filtering with async extractor."""
    zip_data = create_multi_file_zip({
        "keep.txt": b"keep",
        "skip.txt": b"skip",
    })
    
    report = await (
        AsyncExtractor(tmp_path)
        .only(["keep.txt"])
        .extract_bytes(zip_data)
    )
    
    assert report.files_extracted == 1
    assert (tmp_path / "keep.txt").exists()
    assert not (tmp_path / "skip.txt").exists()

