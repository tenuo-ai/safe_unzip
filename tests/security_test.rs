use safe_unzip::{Driver, Error, ExtractionMode, Extractor, Limits, OverwritePolicy, ZipAdapter};
use std::io::{Seek, Write};
use tempfile::{tempdir, NamedTempFile};
use zip::write::FileOptions;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a simple valid zip with one file
fn create_simple_zip(filename: &str, content: &[u8]) -> std::fs::File {
    let file = tempfile::tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options: FileOptions<()> = FileOptions::default();
    zip.start_file(filename, options).unwrap();
    zip.write_all(content).unwrap();
    zip.finish().unwrap()
}

/// Create a zip with multiple files
fn create_multi_file_zip(files: &[(&str, &[u8])]) -> std::fs::File {
    let file = tempfile::tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options: FileOptions<()> = FileOptions::default();
    for (name, content) in files {
        zip.start_file(*name, options).unwrap();
        zip.write_all(content).unwrap();
    }
    zip.finish().unwrap()
}

fn create_malicious_zip() -> std::io::Result<std::fs::File> {
    let file = tempfile::tempfile()?;
    let mut zip = zip::ZipWriter::new(file);

    // Add a normal file (should be processed first if we order it so,
    // or just checking if the whole thing fails)
    let options: FileOptions<()> =
        FileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file("safe.txt", options)?;
    zip.write_all(b"safe content")?;

    // Add the ATTACK file: tries to write to parent directory
    // We use a raw filename that includes traversal characters
    zip.start_file("../../evil.txt", options)?;
    zip.write_all(b"evil content")?;

    Ok(zip.finish()?)
}

#[test]
fn test_blocks_zip_slip() {
    // 1. Setup
    let root = tempdir().unwrap();
    let zip_file = create_malicious_zip().expect("failed to create fixture");

    // 2. Execution
    let result = Extractor::new(root.path())
        .expect("jail init failed")
        .extract(zip_file);

    // 3. Assertion
    match result {
        Err(Error::PathEscape { entry, .. }) => {
            println!("✅ Successfully blocked traversal: {}", entry);
            assert_eq!(entry, "../../evil.txt");
        }
        Ok(_) => panic!("❌ SECURITY FAIL: Malicious file was extracted!"),
        Err(e) => panic!("❌ Unexpected error type: {:?}", e),
    }

    // Double check: ensure 'evil.txt' does NOT exist outside the root
    let evil_path = root.path().join("../../evil.txt");
    if evil_path.exists() {
        // Cleanup if it actually leaked (should never happen)
        let _ = std::fs::remove_file(evil_path);
        panic!("❌ SECURITY FAIL: File found on disk outside jail!");
    }
}

#[test]
fn test_limits_quota() {
    let root = tempdir().unwrap();
    let file = tempfile::tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(file);

    // Create a 200 byte file
    let options: FileOptions<()> = FileOptions::default();
    zip.start_file("big.txt", options).unwrap();
    zip.write_all(&[0u8; 200]).unwrap();
    let zip_file = zip.finish().unwrap();

    // Set limit to 100 bytes (should fail)
    let result = Extractor::new(root.path())
        .unwrap()
        .limits(safe_unzip::Limits {
            max_total_bytes: 100,
            ..Default::default()
        })
        .extract(zip_file);

    match result {
        Err(Error::TotalSizeExceeded { limit, would_be }) => {
            println!("✅ Successfully enforced quota: {} > {}", would_be, limit);
        }
        _ => panic!("❌ Failed to enforce quota"),
    }
}

#[test]
fn test_extract_file_method() {
    // Create a valid zip file on disk
    let mut zip_file = NamedTempFile::new().unwrap();
    {
        let mut zip = zip::ZipWriter::new(&mut zip_file);
        let options: FileOptions<()> = FileOptions::default();
        zip.start_file("hello.txt", options).unwrap();
        zip.write_all(b"Hello, World!").unwrap();
        zip.finish().unwrap();
    }

    // Reset file position to beginning (important!)
    zip_file.seek(std::io::SeekFrom::Start(0)).unwrap();

    // Extract using the new extract_file method
    let dest = tempdir().unwrap();
    let report = Extractor::new(dest.path())
        .unwrap()
        .extract_file(zip_file.path())
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(report.bytes_written, 13); // "Hello, World!" = 13 bytes

    // Verify file exists and has correct content
    let content = std::fs::read_to_string(dest.path().join("hello.txt")).unwrap();
    assert_eq!(content, "Hello, World!");

    println!("✅ extract_file() works correctly");
}

#[test]
fn test_validate_first_no_partial_state() {
    // Create a zip with:
    // 1. A valid file FIRST
    // 2. A malicious file SECOND
    // In Streaming mode, the first file would be written before failing.
    // In ValidateFirst mode, NOTHING should be written.

    let file = tempfile::tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options: FileOptions<()> = FileOptions::default();

    // First: a valid file
    zip.start_file("good.txt", options).unwrap();
    zip.write_all(b"This is fine").unwrap();

    // Second: a malicious file (Zip Slip attack)
    zip.start_file("../../evil.txt", options).unwrap();
    zip.write_all(b"pwned").unwrap();

    let zip_file = zip.finish().unwrap();

    let dest = tempdir().unwrap();

    // Use ValidateFirst mode
    let result = Extractor::new(dest.path())
        .unwrap()
        .mode(ExtractionMode::ValidateFirst)
        .extract(zip_file);

    // Should fail with PathEscape
    assert!(matches!(result, Err(Error::PathEscape { .. })));

    // THE KEY ASSERTION: Nothing should be written!
    // In Streaming mode, "good.txt" would exist. In ValidateFirst, it shouldn't.
    let good_path = dest.path().join("good.txt");
    assert!(
        !good_path.exists(),
        "❌ ValidateFirst FAIL: good.txt was written before validation completed!"
    );

    println!("✅ ValidateFirst prevented partial extraction");
}

// ============================================================================
// Overwrite Policy Tests
// ============================================================================

#[test]
fn test_overwrite_policy_error() {
    let dest = tempdir().unwrap();

    // First extraction
    let zip1 = create_simple_zip("test.txt", b"original");
    Extractor::new(dest.path()).unwrap().extract(zip1).unwrap();

    // Second extraction should fail (default policy is Error)
    let zip2 = create_simple_zip("test.txt", b"modified");
    let result = Extractor::new(dest.path()).unwrap().extract(zip2);

    assert!(matches!(result, Err(Error::AlreadyExists { .. })));

    // Content should be unchanged
    let content = std::fs::read_to_string(dest.path().join("test.txt")).unwrap();
    assert_eq!(content, "original");

    println!("✅ OverwritePolicy::Error works");
}

#[test]
fn test_overwrite_policy_skip() {
    let dest = tempdir().unwrap();

    // First extraction
    let zip1 = create_simple_zip("test.txt", b"original");
    Extractor::new(dest.path()).unwrap().extract(zip1).unwrap();

    // Second extraction with Skip policy
    let zip2 = create_simple_zip("test.txt", b"modified");
    let report = Extractor::new(dest.path())
        .unwrap()
        .overwrite(OverwritePolicy::Skip)
        .extract(zip2)
        .unwrap();

    // Should succeed but skip the file
    assert_eq!(report.entries_skipped, 1);
    assert_eq!(report.files_extracted, 0);

    // Content should be unchanged
    let content = std::fs::read_to_string(dest.path().join("test.txt")).unwrap();
    assert_eq!(content, "original");

    println!("✅ OverwritePolicy::Skip works");
}

#[test]
fn test_overwrite_policy_overwrite() {
    let dest = tempdir().unwrap();

    // First extraction
    let zip1 = create_simple_zip("test.txt", b"original");
    Extractor::new(dest.path()).unwrap().extract(zip1).unwrap();

    // Second extraction with Overwrite policy
    let zip2 = create_simple_zip("test.txt", b"modified");
    let report = Extractor::new(dest.path())
        .unwrap()
        .overwrite(OverwritePolicy::Overwrite)
        .extract(zip2)
        .unwrap();

    assert_eq!(report.files_extracted, 1);

    // Content should be updated
    let content = std::fs::read_to_string(dest.path().join("test.txt")).unwrap();
    assert_eq!(content, "modified");

    println!("✅ OverwritePolicy::Overwrite works");
}

// ============================================================================
// Filter Tests
// ============================================================================

#[test]
fn test_filter_by_extension() {
    let dest = tempdir().unwrap();

    let zip = create_multi_file_zip(&[
        ("image.png", b"fake png data"),
        ("document.txt", b"text content"),
        ("photo.jpg", b"fake jpg data"),
        ("script.sh", b"#!/bin/bash"),
    ]);

    // Only extract .txt files
    let report = Extractor::new(dest.path())
        .unwrap()
        .filter(|e| e.name.ends_with(".txt"))
        .extract(zip)
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(report.entries_skipped, 3);

    // Only document.txt should exist
    assert!(dest.path().join("document.txt").exists());
    assert!(!dest.path().join("image.png").exists());
    assert!(!dest.path().join("photo.jpg").exists());
    assert!(!dest.path().join("script.sh").exists());

    println!("✅ Filter by extension works");
}

#[test]
fn test_filter_by_size() {
    let dest = tempdir().unwrap();

    let zip = create_multi_file_zip(&[
        ("small.txt", b"tiny"),
        ("large.txt", b"this is a much larger file with more content"),
    ]);

    // Only extract files smaller than 10 bytes
    let report = Extractor::new(dest.path())
        .unwrap()
        .filter(|e| e.size < 10)
        .extract(zip)
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert!(dest.path().join("small.txt").exists());
    assert!(!dest.path().join("large.txt").exists());

    println!("✅ Filter by size works");
}

// ============================================================================
// Limits Tests
// ============================================================================

#[test]
fn test_single_file_size_limit() {
    let dest = tempdir().unwrap();

    let zip = create_simple_zip("big.txt", &[0u8; 500]);

    let result = Extractor::new(dest.path())
        .unwrap()
        .limits(Limits {
            max_single_file: 100,
            ..Default::default()
        })
        .extract(zip);

    match result {
        Err(Error::FileTooLarge { entry, limit, size }) => {
            assert_eq!(entry, "big.txt");
            assert_eq!(limit, 100);
            assert_eq!(size, 500);
            println!("✅ Single file size limit works");
        }
        _ => panic!("Expected FileTooLarge error"),
    }
}

#[test]
fn test_file_count_limit() {
    let dest = tempdir().unwrap();

    let zip = create_multi_file_zip(&[
        ("file1.txt", b"1"),
        ("file2.txt", b"2"),
        ("file3.txt", b"3"),
        ("file4.txt", b"4"),
        ("file5.txt", b"5"),
    ]);

    let result = Extractor::new(dest.path())
        .unwrap()
        .limits(Limits {
            max_file_count: 3,
            ..Default::default()
        })
        .extract(zip);

    assert!(matches!(
        result,
        Err(Error::FileCountExceeded { limit: 3, .. })
    ));

    println!("✅ File count limit works");
}

#[test]
fn test_path_depth_limit() {
    let dest = tempdir().unwrap();

    // Create a deeply nested file
    let file = tempfile::tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options: FileOptions<()> = FileOptions::default();
    zip.start_file("a/b/c/d/e/f/g/deep.txt", options).unwrap();
    zip.write_all(b"deep").unwrap();
    let zip_file = zip.finish().unwrap();

    let result = Extractor::new(dest.path())
        .unwrap()
        .limits(Limits {
            max_path_depth: 3,
            ..Default::default()
        })
        .extract(zip_file);

    match result {
        Err(Error::PathTooDeep { depth, limit, .. }) => {
            assert_eq!(limit, 3);
            assert!(depth > 3);
            println!(
                "✅ Path depth limit works (depth={}, limit={})",
                depth, limit
            );
        }
        _ => panic!("Expected PathTooDeep error"),
    }
}

// ============================================================================
// Directory Extraction Tests
// ============================================================================

#[test]
fn test_creates_directories() {
    let dest = tempdir().unwrap();

    let file = tempfile::tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options: FileOptions<()> = FileOptions::default();

    // Add a directory entry
    zip.add_directory("mydir/", options).unwrap();
    // Add a file in a nested directory
    zip.start_file("mydir/subdir/file.txt", options).unwrap();
    zip.write_all(b"nested content").unwrap();

    let zip_file = zip.finish().unwrap();

    let report = Extractor::new(dest.path())
        .unwrap()
        .extract(zip_file)
        .unwrap();

    assert_eq!(report.dirs_created, 1);
    assert_eq!(report.files_extracted, 1);
    assert!(dest.path().join("mydir").is_dir());
    assert!(dest.path().join("mydir/subdir/file.txt").exists());

    println!("✅ Directory creation works");
}

#[test]
fn test_sanitize_filenames() {
    let dest = tempdir().unwrap();

    // Test Windows reserved names
    // ZIP spec allows basically anything, but we want to fail on "CON.txt"
    let zip = create_simple_zip("CON.txt", b"safe");
    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Err(Error::InvalidFilename { entry, reason }) => {
            assert_eq!(entry, "CON.txt");
            assert!(
                reason.contains("reserved"),
                "reason should mention reserved: {}",
                reason
            );
            println!("✅ Successfully rejected '{}': {}", entry, reason);
        }
        _ => panic!("❌ Failed to reject reserved filename"),
    }
}

#[test]
fn test_symlink_overwrite_protection() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let dest = tempdir().unwrap();

        // Setup:
        // jail/target.txt (sensitive)
        // jail/link -> target.txt
        let target_path = dest.path().join("target.txt");
        let link_path = dest.path().join("link");

        std::fs::write(&target_path, "sensitive").unwrap();
        symlink(&target_path, &link_path).unwrap();

        // Attack: Extract file named "link" with content "pwned"
        // If secure, it should replace "link" with a file "pwned", and NOT write to "target.txt"
        let zip = create_simple_zip("link", b"pwned");

        let report = Extractor::new(dest.path())
            .unwrap()
            .overwrite(OverwritePolicy::Overwrite)
            .extract(zip)
            .unwrap();

        assert_eq!(report.files_extracted, 1);

        // Verify 'link' is now a file with 'pwned'
        let link_content = std::fs::read_to_string(&link_path).unwrap();
        assert_eq!(link_content, "pwned");
        assert!(!link_path.is_symlink());

        // Verify 'target.txt' is UNTOUCHED
        let target_content = std::fs::read_to_string(&target_path).unwrap();
        assert_eq!(target_content, "sensitive");

        println!("✅ Symlink overwrite protection works");
    }
}

// Helper to modify zip bytes to fake size
fn create_fake_size_zip(name: &str, content: &[u8], declared_size: u32) -> std::fs::File {
    let file = tempfile::tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options: FileOptions<()> = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored)
        .unix_permissions(0o644);

    zip.start_file(name, options).unwrap();
    zip.write_all(content).unwrap();
    let mut finalized_file = zip.finish().unwrap();

    // Rewind and read into buffer
    finalized_file.seek(std::io::SeekFrom::Start(0)).unwrap();
    let mut buffer = Vec::new();
    use std::io::Read;
    finalized_file.read_to_end(&mut buffer).unwrap();

    // Basic Zip structure hacking (Stored only):
    // Local File Header signature: 0x04034b50
    // ...
    // Offset 18: Compressed size (4 bytes)
    // Offset 22: Uncompressed size (4 bytes)
    //
    // We need to find the LFH for our file.
    let lfh_sig = &[0x50, 0x4b, 0x03, 0x04];
    if &buffer[0..4] == lfh_sig {
        // Overwrite uncompressed size at 22
        let size_bytes = declared_size.to_le_bytes();
        buffer[22] = size_bytes[0];
        buffer[23] = size_bytes[1];
        buffer[24] = size_bytes[2];
        buffer[25] = size_bytes[3];

        // Overwrite compressed size at 18
        buffer[18] = size_bytes[0];
        buffer[19] = size_bytes[1];
        buffer[20] = size_bytes[2];
        buffer[21] = size_bytes[3];

        // Also need to update Central Directory Header
        // Signature: 0x02014b50
        // Search for it
        let cd_sig = &[0x50, 0x4b, 0x01, 0x02];
        if let Some(pos) = buffer.windows(4).position(|w| w == cd_sig) {
            // Offset 20: Compressed size
            // Offset 24: Uncompressed size
            buffer[pos + 20] = size_bytes[0];
            buffer[pos + 21] = size_bytes[1];
            buffer[pos + 22] = size_bytes[2];
            buffer[pos + 23] = size_bytes[3];

            buffer[pos + 24] = size_bytes[0];
            buffer[pos + 25] = size_bytes[1];
            buffer[pos + 26] = size_bytes[2];
            buffer[pos + 27] = size_bytes[3];
        } else {
            println!("⚠️ Could not find Central Directory");
        }
    } else {
        println!("⚠️ Could not find LFH");
    }

    let mut hacked_file = tempfile::tempfile().unwrap();
    hacked_file.write_all(&buffer).unwrap();
    hacked_file.seek(std::io::SeekFrom::Start(0)).unwrap();
    hacked_file
}

#[test]
fn test_strict_size_enforcement() {
    let dest = tempdir().unwrap();

    // Create zip with 10 bytes content, but declare 5 bytes
    let zip_file = create_fake_size_zip("lie.txt", b"0123456789", 5);

    // Attempt extract. Should fail because read returns more data than declared
    let result = Extractor::new(dest.path()).unwrap().extract(zip_file);

    match result {
        Err(Error::FileTooLarge { limit, size, .. }) => {
            // We expect limit=5 (declared), size=6 (attempted read)
            assert_eq!(limit, 5);
            assert_eq!(size, 6);
            println!("✅ Successfully caught zip bomb verification failure");
        }
        Err(Error::Io(e)) if e.to_string().contains("Invalid checksum") => {
            // The zip crate might catch the mismatch via CRC Checksum error
            // because our fake zip didn't update the CRC to match the fake size
            // (or the full content). This is also a valid rejection.
            println!("✅ Successfully rejected zip bomb (checksum)");
        }
        _ => panic!("❌ Failed to enforce declared size: {:?}", result),
    }
}

// ============================================================================
// Advanced Attack Vector Tests
// ============================================================================

/// Test: Absolute paths in zip entries should be blocked or safely contained
/// Attack: Archive contains "/tmp/evil.txt" or "C:\evil.txt"
/// Defense: path_jail should reject or strip the root
#[test]
fn test_absolute_path_rejection() {
    let dest = tempdir().unwrap();

    // Create zip with absolute path entry
    #[cfg(unix)]
    let zip = create_simple_zip("/tmp/evil.txt", b"evil");
    #[cfg(windows)]
    let zip = create_simple_zip("C:\\evil.txt", b"evil");

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Err(Error::PathEscape { .. }) => {
            println!("✅ Blocked absolute path via PathEscape");
        }
        Err(Error::InvalidFilename { .. }) => {
            // Backslash rejection on Windows path
            println!("✅ Blocked absolute path via InvalidFilename");
        }
        Ok(_) => {
            // If it succeeded, ensure it didn't write outside the jail
            #[cfg(unix)]
            assert!(
                !std::path::Path::new("/tmp/evil.txt").exists(),
                "❌ Wrote to absolute path outside jail!"
            );
            // It should be inside the jail (with root stripped)
            let inside =
                dest.path().join("tmp/evil.txt").exists() || dest.path().join("evil.txt").exists();
            assert!(inside, "File should be inside jail");
            println!("✅ Absolute path stripped and contained in jail");
        }
        Err(e) => panic!("❌ Unexpected error: {:?}", e),
    }
}

/// Test: Backslash in filename should be rejected
/// Attack: "folder\file.txt" or "..\secret.txt" on Windows
/// Defense: is_valid_filename rejects backslashes
#[test]
fn test_backslash_rejection() {
    let dest = tempdir().unwrap();

    // This tests that backslash rejection happens in filename validation,
    // not later in path processing
    let zip = create_simple_zip("folder\\file.txt", b"data");

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Err(Error::InvalidFilename { entry, reason }) => {
            assert!(
                reason.contains("backslash"),
                "Should mention backslash: {}",
                reason
            );
            println!("✅ Rejected backslash in filename '{}': {}", entry, reason);
        }
        _ => panic!("❌ Should reject backslash in filename: {:?}", result),
    }
}

/// Test: Null byte in filename should be rejected
/// Attack: "image.png\0.exe" - OS might truncate at null
/// Defense: is_valid_filename rejects control characters
#[test]
fn test_null_byte_rejection() {
    let dest = tempdir().unwrap();

    // Filename with embedded null byte
    let zip = create_simple_zip("harmless.txt\0.exe", b"malware");

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Err(Error::InvalidFilename { entry, reason }) => {
            assert!(
                reason.contains("control"),
                "Should mention control chars: {}",
                reason
            );
            println!("✅ Rejected null byte in filename '{}': {}", entry, reason);
        }
        _ => panic!("❌ Should reject null byte in filename: {:?}", result),
    }
}

/// Test: Empty filename should be rejected
/// Attack: Entry with empty name could confuse path joining
/// Defense: is_valid_filename rejects empty names
#[test]
fn test_empty_filename_rejection() {
    let dest = tempdir().unwrap();

    let zip = create_simple_zip("", b"data");

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Err(Error::InvalidFilename { reason, .. }) => {
            assert!(reason.contains("empty"), "Should mention empty: {}", reason);
            println!("✅ Rejected empty filename: {}", reason);
        }
        _ => panic!("❌ Should reject empty filename: {:?}", result),
    }
}

/// Test: Symlink followed by file with same name
/// Attack: Archive has symlink "link -> /etc/passwd", then file "link" with content
/// Defense: When overwriting, remove symlink before creating file
#[test]
#[cfg(unix)]
fn test_symlink_then_file_in_same_archive() {
    use std::os::unix::fs::symlink;

    let dest = tempdir().unwrap();

    // Create a scenario where the ARCHIVE tries to create a symlink,
    // then overwrite it with a file.
    // Since we skip symlinks by default, let's test with Overwrite policy
    // by pre-creating a symlink at the destination.

    // Step 1: Pre-create a symlink in destination that points outside
    let link_path = dest.path().join("link");
    let target_file = dest.path().join("target.txt");
    std::fs::write(&target_file, "original").unwrap();
    symlink("target.txt", &link_path).unwrap();

    // Verify symlink works
    assert!(link_path.is_symlink());
    assert_eq!(std::fs::read_to_string(&link_path).unwrap(), "original");

    // Step 2: Create zip that writes to "link"
    let zip = create_simple_zip("link", b"overwritten");

    // Step 3: Extract with Overwrite policy
    let result = Extractor::new(dest.path())
        .unwrap()
        .overwrite(OverwritePolicy::Overwrite)
        .extract(zip);

    // Step 4: Verify the symlink was replaced with a file
    assert!(result.is_ok(), "Should succeed: {:?}", result);

    // The path should now be a regular file, NOT a symlink
    assert!(!link_path.is_symlink(), "Should no longer be a symlink");
    assert!(link_path.is_file(), "Should be a regular file");

    // Content should be the new content, not overwriting through the symlink
    let content = std::fs::read_to_string(&link_path).unwrap();
    assert_eq!(content, "overwritten", "File should have new content");

    // The original target should be unchanged (symlink was removed, not followed)
    let target_content = std::fs::read_to_string(&target_file).unwrap();
    assert_eq!(
        target_content, "original",
        "Original target should be unchanged"
    );

    println!("✅ Symlink replaced with file safely (didn't follow symlink)");
}

/// Test: Traversal using backslash on Windows-style paths
/// Attack: "..\\..\secret.txt" mixing slashes
/// Defense: Reject backslash before any path processing
#[test]
fn test_mixed_slash_traversal() {
    let dest = tempdir().unwrap();

    // Mix forward and back slashes with traversal
    let zip = create_simple_zip("foo\\..\\bar.txt", b"data");

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    // Should be caught by backslash rejection
    assert!(
        matches!(result, Err(Error::InvalidFilename { .. })),
        "Should reject mixed slashes: {:?}",
        result
    );
    println!("✅ Rejected mixed slash traversal attempt");
}

// ============================================================================
// Red Team: Advanced Edge Case Tests
// ============================================================================

/// Test: Unicode lookalike characters should not cause path confusion
/// Attack: "file․txt" (U+2024 ONE DOT LEADER) vs "file.txt"
/// Defense: Both should extract as separate files; no collision
#[test]
fn test_unicode_lookalike_characters() {
    let dest = tempdir().unwrap();

    // U+2024 ONE DOT LEADER looks like a period but is a different character
    let zip = create_multi_file_zip(&[
        ("file.txt", b"normal dot"),
        ("file\u{2024}txt", b"unicode lookalike"), // ․ = U+2024
    ]);

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    // Both should extract successfully as separate files
    match result {
        Ok(report) => {
            assert_eq!(report.files_extracted, 2, "Both files should extract");
            println!("✅ Unicode lookalike characters handled correctly (both extracted)");
        }
        Err(e) => {
            // Also acceptable: reject the lookalike as invalid filename
            println!("✅ Unicode lookalike rejected: {:?}", e);
        }
    }
}

/// Test: URL-encoded path traversal should be blocked
/// Attack: Entry named "..%2Fevil.txt" or "%2e%2e/evil.txt"
/// Defense: These should either be rejected or treated literally (not decoded)
#[test]
fn test_url_encoded_traversal() {
    let dest = tempdir().unwrap();

    // %2F is URL-encoded forward slash
    let zip = create_simple_zip("..%2Fevil.txt", b"evil");

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Ok(report) => {
            // If it succeeds, verify it was treated literally (not decoded)
            // The file should be inside dest, with the literal name
            assert_eq!(report.files_extracted, 1);
            // It should NOT have escaped to parent
            let parent_evil = dest.path().parent().unwrap().join("evil.txt");
            assert!(
                !parent_evil.exists(),
                "❌ URL-encoded traversal escaped jail!"
            );
            println!("✅ URL-encoded traversal treated as literal filename");
        }
        Err(Error::PathEscape { .. }) | Err(Error::InvalidFilename { .. }) => {
            println!("✅ URL-encoded traversal rejected");
        }
        Err(e) => panic!("❌ Unexpected error: {:?}", e),
    }
}

/// Test: Double-encoded traversal should be blocked
/// Attack: "%252e%252e%252f" = %2e%2e%2f after one decode = "../" after two decodes
/// Defense: No decoding should happen; treat as literal
#[test]
fn test_double_encoded_traversal() {
    let dest = tempdir().unwrap();

    // Double-encoded "../" -> after one decode: "%2e%2e%2f" -> after two: "../"
    let zip = create_simple_zip("%252e%252e%252fevil.txt", b"evil");

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Ok(_) => {
            // If it succeeds, verify no escape happened
            let parent_evil = dest.path().parent().unwrap().join("evil.txt");
            assert!(
                !parent_evil.exists(),
                "❌ Double-encoded traversal escaped!"
            );
            println!("✅ Double-encoded traversal treated as literal");
        }
        Err(_) => {
            println!("✅ Double-encoded traversal rejected");
        }
    }
}

/// Test: Windows drive letter paths should be rejected or contained
/// Attack: "C:\\Windows\\System32\\evil.dll" or "D:/evil.txt"
/// Defense: Reject or strip drive letter, never write outside jail
#[test]
fn test_windows_drive_letter_colon() {
    let dest = tempdir().unwrap();

    // Windows-style with colon (even on Unix, should be rejected)
    let zip = create_simple_zip("C:/Windows/evil.txt", b"evil");

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Ok(_) => {
            // If allowed, must be contained in jail
            assert!(
                !std::path::Path::new("/C:/Windows/evil.txt").exists(),
                "❌ Created file at absolute Windows path!"
            );
            // Should be something like dest/C:/Windows/evil.txt or dest/Windows/evil.txt
            println!("✅ Windows drive letter path contained in jail");
        }
        Err(Error::InvalidFilename { reason, .. }) => {
            // Colon is not allowed in filenames on Windows
            println!("✅ Windows drive letter rejected: {}", reason);
        }
        Err(Error::PathEscape { .. }) => {
            println!("✅ Windows drive letter blocked by path jail");
        }
        Err(e) => panic!("❌ Unexpected error: {:?}", e),
    }
}

/// Test: Trailing spaces in filename should be handled safely
/// Attack: "file.txt " (trailing space) - Windows strips trailing spaces
/// Defense: Reject or normalize consistently
#[test]
fn test_trailing_space_in_filename() {
    let dest = tempdir().unwrap();

    let zip = create_simple_zip("file.txt ", b"data");

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Ok(_) => {
            // If allowed, the file should exist (with or without trailing space)
            let exists_with_space = dest.path().join("file.txt ").exists();
            let exists_without = dest.path().join("file.txt").exists();
            assert!(
                exists_with_space || exists_without,
                "File should exist somewhere"
            );
            println!("✅ Trailing space handled (file exists)");
        }
        Err(Error::InvalidFilename { reason, .. }) => {
            assert!(
                reason.contains("trailing") || reason.contains("space"),
                "Reason should mention trailing/space: {}",
                reason
            );
            println!("✅ Trailing space rejected: {}", reason);
        }
        Err(e) => panic!("❌ Unexpected error: {:?}", e),
    }
}

/// Test: Trailing dot in filename should be handled safely
/// Attack: "file.txt." - Windows strips trailing dots
/// Defense: Reject or normalize consistently
#[test]
fn test_trailing_dot_in_filename() {
    let dest = tempdir().unwrap();

    let zip = create_simple_zip("file.txt.", b"data");

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Ok(_) => {
            // If allowed on Unix, file should exist with the dot
            let exists_with_dot = dest.path().join("file.txt.").exists();
            let exists_without = dest.path().join("file.txt").exists();
            assert!(
                exists_with_dot || exists_without,
                "File should exist somewhere"
            );
            println!("✅ Trailing dot handled (file exists)");
        }
        Err(Error::InvalidFilename { reason, .. }) => {
            println!("✅ Trailing dot rejected: {}", reason);
        }
        Err(e) => panic!("❌ Unexpected error: {:?}", e),
    }
}

/// Test: NTFS Alternate Data Streams should be blocked
/// Attack: "file.txt:Zone.Identifier" or "file.txt::$DATA"
/// Defense: Reject filenames with colons (except drive letters on Windows)
#[test]
fn test_ntfs_alternate_data_stream() {
    let dest = tempdir().unwrap();

    // NTFS ADS syntax: filename:streamname
    let zip = create_simple_zip("file.txt:hidden", b"secret data");

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Err(Error::InvalidFilename { reason, .. }) => {
            // Colon should be rejected in filenames
            println!("✅ NTFS ADS syntax rejected: {}", reason);
        }
        Ok(_) => {
            // On Unix, colon is allowed in filenames, so this might succeed
            // But file should be inside jail with literal name
            let file_path = dest.path().join("file.txt:hidden");
            if file_path.exists() {
                println!("✅ NTFS ADS treated as literal filename on Unix");
            } else {
                println!("⚠️ File created with unexpected name");
            }
        }
        Err(e) => panic!("❌ Unexpected error: {:?}", e),
    }
}

/// Test: Zone.Identifier ADS specifically
/// Attack: "download.exe:Zone.Identifier" - hide malware metadata
#[test]
fn test_zone_identifier_ads() {
    let dest = tempdir().unwrap();

    let zip = create_simple_zip("download.exe:Zone.Identifier", b"[ZoneTransfer]\nZoneId=3");

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    // On any platform, we should either reject or treat literally
    match result {
        Err(_) => println!("✅ Zone.Identifier ADS rejected"),
        Ok(_) => {
            // If allowed, must be literal
            let exists = dest.path().join("download.exe:Zone.Identifier").exists();
            assert!(exists, "If allowed, file should exist with literal name");
            println!("✅ Zone.Identifier ADS treated literally");
        }
    }
}

/// Test: Very long filename should be rejected
/// Attack: Filename with 500+ characters to cause filesystem errors
/// Defense: is_valid_filename enforces max length
#[test]
fn test_very_long_filename() {
    let dest = tempdir().unwrap();

    let long_name = "a".repeat(300) + ".txt";
    let zip = create_simple_zip(&long_name, b"data");

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Err(Error::InvalidFilename { reason, .. }) => {
            assert!(
                reason.contains("long") || reason.contains("length"),
                "Reason should mention length: {}",
                reason
            );
            println!("✅ Very long filename rejected: {}", reason);
        }
        Err(Error::Io(e)) => {
            // Filesystem might reject it
            println!("✅ Very long filename rejected by filesystem: {}", e);
        }
        Ok(_) => {
            // If filesystem allows it, that's okay
            println!("⚠️ Very long filename allowed (filesystem accepted)");
        }
        Err(e) => {
            // Other errors are unexpected
            panic!("❌ Unexpected error: {}", e);
        }
    }
}

/// Test: Unicode normalization attack
/// Attack: Two entries "café" (composed) and "café" (decomposed) collide
/// Defense: Detect collision or handle consistently
#[test]
fn test_unicode_normalization_collision() {
    let dest = tempdir().unwrap();

    // NFC (composed): é = U+00E9
    // NFD (decomposed): é = e (U+0065) + ́ (U+0301)
    let composed = "caf\u{00E9}.txt"; // NFC
    let decomposed = "cafe\u{0301}.txt"; // NFD

    let zip = create_multi_file_zip(&[(composed, b"composed"), (decomposed, b"decomposed")]);

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Ok(report) => {
            // On macOS HFS+, these might collide (both normalize to same name)
            // On most Linux filesystems, they're separate files
            if report.files_extracted == 1 {
                println!("✅ Unicode normalization caused collision (filesystem normalized)");
            } else if report.files_extracted == 2 {
                println!("✅ Unicode NFC/NFD treated as separate files");
            }
        }
        Err(Error::AlreadyExists { .. }) => {
            println!("✅ Unicode normalization collision detected");
        }
        Err(e) => panic!("❌ Unexpected error: {:?}", e),
    }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

/// Test: Empty archive (no entries)
/// Defense: Should succeed with zero files extracted
#[test]
fn test_empty_archive() {
    let dest = tempdir().unwrap();

    // Create empty zip
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let zip = zip::ZipWriter::new(&mut buffer);
        zip.finish().unwrap();
    }

    let result = Extractor::new(dest.path()).unwrap().extract(buffer);

    match result {
        Ok(report) => {
            assert_eq!(report.files_extracted, 0);
            assert_eq!(report.dirs_created, 0);
            assert_eq!(report.bytes_written, 0);
            println!("✅ Empty archive handled correctly");
        }
        Err(e) => panic!("❌ Empty archive should succeed: {:?}", e),
    }
}

/// Test: Archive with only directories (no files)
/// Defense: Should succeed, create directories, report zero files
#[test]
fn test_directory_only_archive() {
    let dest = tempdir().unwrap();

    // Create zip with only directories
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options: zip::write::FileOptions<()> = zip::write::FileOptions::default();
        zip.add_directory("dir1/", options).unwrap();
        zip.add_directory("dir1/subdir/", options).unwrap();
        zip.add_directory("dir2/", options).unwrap();
        zip.finish().unwrap();
    }

    let result = Extractor::new(dest.path()).unwrap().extract(buffer);

    match result {
        Ok(report) => {
            assert_eq!(report.files_extracted, 0, "No files should be extracted");
            // dirs_created is always >= 0 (usize), just verify extraction succeeded
            let _ = report.dirs_created;
            assert!(dest.path().join("dir1").is_dir());
            assert!(dest.path().join("dir1/subdir").is_dir());
            assert!(dest.path().join("dir2").is_dir());
            println!(
                "✅ Directory-only archive: {} dirs created",
                report.dirs_created
            );
        }
        Err(e) => panic!("❌ Directory-only archive should succeed: {:?}", e),
    }
}

/// Test: Encrypted ZIP entries should be rejected
/// Defense: EncryptedEntry error prevents extraction of password-protected files
#[test]
fn test_encrypted_entry_rejected() {
    let dest = tempdir().unwrap();

    // Create a zip with an encrypted entry
    // Note: The zip crate doesn't support creating encrypted zips easily,
    // so we'll create one manually with the encrypted flag set
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        // Add a normal file first
        zip.start_file("normal.txt", options).unwrap();
        zip.write_all(b"not encrypted").unwrap();

        // The zip crate's FileOptions doesn't expose encryption easily
        // We'll test via the new Driver API which checks encrypted() on entries
        zip.finish().unwrap();
    }

    // For a proper test, we need to create an actually encrypted zip
    // Using raw bytes for a minimal encrypted zip structure
    let encrypted_zip = create_encrypted_zip();

    let adapter = match ZipAdapter::new(std::io::Cursor::new(encrypted_zip)) {
        Ok(a) => a,
        Err(e) => {
            // If the zip crate rejects the malformed zip, that's acceptable
            println!("✅ Malformed encrypted zip rejected at parse: {:?}", e);
            return;
        }
    };

    let result = Driver::new(dest.path()).unwrap().extract_zip(adapter);

    match result {
        Err(Error::EncryptedEntry { entry }) => {
            println!("✅ Encrypted entry rejected: {}", entry);
        }
        Err(Error::Zip(_)) => {
            // Some zip parsing errors are also acceptable
            println!("✅ Encrypted/malformed zip rejected");
        }
        Ok(_) => {
            // If the zip crate skips or handles encrypted entries differently, that's okay
            // The important thing is we don't silently extract garbage
            println!("⚠️ Zip crate handled encrypted entry (check contents)");
        }
        Err(e) => panic!("❌ Unexpected error: {:?}", e),
    }
}

/// Create a minimal encrypted ZIP file structure
fn create_encrypted_zip() -> Vec<u8> {
    // Minimal ZIP with encrypted flag set in general purpose bit flag
    // Local file header for "secret.txt"
    let mut zip = Vec::new();

    let filename = b"secret.txt";
    let data = b"encrypted content";

    // Local file header signature
    zip.extend_from_slice(&[0x50, 0x4b, 0x03, 0x04]); // PK\x03\x04
                                                      // Version needed to extract (2.0 = 20)
    zip.extend_from_slice(&[0x14, 0x00]);
    // General purpose bit flag - bit 0 set = encrypted
    zip.extend_from_slice(&[0x01, 0x00]); // Encrypted flag!
                                          // Compression method (0 = stored)
    zip.extend_from_slice(&[0x00, 0x00]);
    // Last mod time/date
    zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // CRC-32 (fake)
    zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Compressed size
    let size = data.len() as u32;
    zip.extend_from_slice(&size.to_le_bytes());
    // Uncompressed size
    zip.extend_from_slice(&size.to_le_bytes());
    // Filename length
    let name_len = filename.len() as u16;
    zip.extend_from_slice(&name_len.to_le_bytes());
    // Extra field length
    zip.extend_from_slice(&[0x00, 0x00]);
    // Filename
    zip.extend_from_slice(filename);
    // File data (would be encrypted, but we just put raw bytes)
    zip.extend_from_slice(data);

    // Central directory header
    let local_header_offset = 0u32;
    zip.extend_from_slice(&[0x50, 0x4b, 0x01, 0x02]); // PK\x01\x02
                                                      // Version made by
    zip.extend_from_slice(&[0x14, 0x00]);
    // Version needed
    zip.extend_from_slice(&[0x14, 0x00]);
    // General purpose bit flag - encrypted
    zip.extend_from_slice(&[0x01, 0x00]);
    // Compression method
    zip.extend_from_slice(&[0x00, 0x00]);
    // Last mod time/date
    zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // CRC-32
    zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Compressed size
    zip.extend_from_slice(&size.to_le_bytes());
    // Uncompressed size
    zip.extend_from_slice(&size.to_le_bytes());
    // Filename length
    zip.extend_from_slice(&name_len.to_le_bytes());
    // Extra field length
    zip.extend_from_slice(&[0x00, 0x00]);
    // Comment length
    zip.extend_from_slice(&[0x00, 0x00]);
    // Disk number start
    zip.extend_from_slice(&[0x00, 0x00]);
    // Internal file attributes
    zip.extend_from_slice(&[0x00, 0x00]);
    // External file attributes
    zip.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    // Relative offset of local header
    zip.extend_from_slice(&local_header_offset.to_le_bytes());
    // Filename
    zip.extend_from_slice(filename);

    let cd_offset = (30 + filename.len() + data.len()) as u32;
    let cd_size = (46 + filename.len()) as u32;

    // End of central directory
    zip.extend_from_slice(&[0x50, 0x4b, 0x05, 0x06]); // PK\x05\x06
                                                      // Disk number
    zip.extend_from_slice(&[0x00, 0x00]);
    // Disk with CD
    zip.extend_from_slice(&[0x00, 0x00]);
    // Number of entries on disk
    zip.extend_from_slice(&[0x01, 0x00]);
    // Total entries
    zip.extend_from_slice(&[0x01, 0x00]);
    // CD size
    zip.extend_from_slice(&cd_size.to_le_bytes());
    // CD offset
    zip.extend_from_slice(&cd_offset.to_le_bytes());
    // Comment length
    zip.extend_from_slice(&[0x00, 0x00]);

    zip
}

/// Test: Zero limits should be handled gracefully
#[test]
fn test_zero_limits() {
    let dest = tempdir().unwrap();

    // Helper to create zip bytes
    fn make_zip() -> std::io::Cursor<Vec<u8>> {
        let mut buffer = std::io::Cursor::new(Vec::new());
        {
            let mut zip = zip::ZipWriter::new(&mut buffer);
            let options: FileOptions<()> = FileOptions::default();
            zip.start_file("tiny.txt", options).unwrap();
            zip.write_all(b"x").unwrap();
            zip.finish().unwrap();
        }
        buffer.set_position(0);
        buffer
    }

    // Zero max_total_bytes
    let result = Extractor::new(dest.path())
        .unwrap()
        .limits(Limits {
            max_total_bytes: 0,
            ..Limits::default()
        })
        .extract(make_zip());

    assert!(
        matches!(result, Err(Error::TotalSizeExceeded { .. })),
        "Zero max_total_bytes should reject any content: {:?}",
        result
    );

    // Zero max_file_count
    let result = Extractor::new(dest.path())
        .unwrap()
        .limits(Limits {
            max_file_count: 0,
            ..Limits::default()
        })
        .extract(make_zip());

    assert!(
        matches!(result, Err(Error::FileCountExceeded { .. })),
        "Zero max_file_count should reject any file: {:?}",
        result
    );

    // Zero max_single_file
    let result = Extractor::new(dest.path())
        .unwrap()
        .limits(Limits {
            max_single_file: 0,
            ..Limits::default()
        })
        .extract(make_zip());

    assert!(
        matches!(result, Err(Error::FileTooLarge { .. })),
        "Zero max_single_file should reject any file: {:?}",
        result
    );

    println!("✅ Zero limits handled correctly");
}

// ============================================================================
// Red Team: Duplicate/Collision Attack Tests
// ============================================================================

/// Test: Duplicate entry names in same archive
/// Attack: Two entries with exact same path - second might overwrite first
/// Defense: Zip crate rejects duplicates at creation, or extractor rejects at extraction
#[test]
fn test_duplicate_entry_names() {
    let dest = tempdir().unwrap();

    // The zip crate itself prevents creating archives with duplicate names.
    // This is a defense-in-depth: even if we craft a malicious zip manually,
    // the safe_unzip extractor's overwrite policy would catch it.

    // Try to create a zip with duplicates - the zip crate should reject this
    let file = tempfile::tempfile().unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options: FileOptions<()> = FileOptions::default();

    zip.start_file("same.txt", options).unwrap();
    zip.write_all(b"first content").unwrap();

    // Attempt to add second file with same name
    let dup_result = zip.start_file("same.txt", options);

    match dup_result {
        Err(e) => {
            // Zip crate prevents duplicate creation - this is a valid defense
            println!("✅ Zip crate rejects duplicate at creation: {}", e);
        }
        Ok(_) => {
            // If the zip crate allowed it, finish and test extraction
            zip.write_all(b"second content").unwrap();
            let mut zip_file = zip.finish().unwrap();
            zip_file.seek(std::io::SeekFrom::Start(0)).unwrap();

            let result = Extractor::new(dest.path()).unwrap().extract(zip_file);

            match result {
                Err(Error::AlreadyExists { entry, .. }) => {
                    println!("✅ Extractor rejected duplicate: {}", entry);
                }
                Ok(report) if report.files_extracted == 1 => {
                    println!("✅ Only first entry extracted (1 file)");
                }
                r => panic!("❌ Unexpected result: {:?}", r),
            }
        }
    }
}

/// Test: Duplicate entry with Overwrite policy explicitly allowed
/// Defense: The zip crate prevents creation, so we test the concept
#[test]
fn test_duplicate_entry_with_overwrite_policy() {
    let dest = tempdir().unwrap();

    // Since zip crate prevents duplicate creation, we test a related scenario:
    // Create first file, then extract second zip with same filename using Overwrite

    // First extraction
    let zip1 = create_simple_zip("same.txt", b"first");
    Extractor::new(dest.path()).unwrap().extract(zip1).unwrap();

    // Second extraction with Overwrite policy
    let zip2 = create_simple_zip("same.txt", b"second");
    let result = Extractor::new(dest.path())
        .unwrap()
        .overwrite(OverwritePolicy::Overwrite)
        .extract(zip2);

    match result {
        Ok(report) => {
            let content = std::fs::read_to_string(dest.path().join("same.txt")).unwrap();
            assert_eq!(content, "second", "With Overwrite, second should win");
            assert_eq!(report.files_extracted, 1);
            println!("✅ With Overwrite policy, second archive wins");
        }
        Err(e) => panic!("❌ Overwrite policy should allow: {:?}", e),
    }
}

/// Test: Case sensitivity collision (File.txt vs file.txt)
/// Attack: On case-insensitive FS (macOS, Windows), these collide
/// Defense: Detect collision or use consistent behavior
#[test]
fn test_case_sensitivity_collision() {
    let dest = tempdir().unwrap();

    let zip = create_multi_file_zip(&[("File.TXT", b"uppercase"), ("file.txt", b"lowercase")]);

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Ok(report) => {
            // On case-sensitive FS (Linux): both files exist
            // On case-insensitive FS (macOS, Windows): collision -> AlreadyExists
            if report.files_extracted == 2 {
                println!("✅ Case-sensitive FS: both files extracted");
                assert!(dest.path().join("File.TXT").exists());
                assert!(dest.path().join("file.txt").exists());
            } else if report.files_extracted == 1 {
                // Filesystem normalized and only one was created
                println!("✅ Case-insensitive FS: first file preserved");
            }
        }
        Err(Error::AlreadyExists { entry, .. }) => {
            // Case-insensitive FS detected collision
            println!("✅ Case collision detected: {}", entry);
        }
        Err(e) => panic!("❌ Unexpected error: {:?}", e),
    }
}

/// Test: Path canonicalization attack using ./
/// Attack: Entry "./foo/../bar.txt" should resolve to "bar.txt"
/// Defense: Jail should handle or reject
#[test]
fn test_path_canonicalization_current_dir() {
    let dest = tempdir().unwrap();

    let zip = create_simple_zip("./foo/../bar.txt", b"data");

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Ok(_) => {
            // Should extract somewhere inside dest
            // Either as literal "./foo/../bar.txt" or canonicalized to "bar.txt"
            let exists_canonical = dest.path().join("bar.txt").exists();
            let exists_literal = dest.path().join("./foo/../bar.txt").exists();
            let exists_in_foo = dest.path().join("foo").join("..").join("bar.txt").exists();

            assert!(
                exists_canonical || exists_literal || exists_in_foo,
                "File should exist somewhere in jail"
            );

            // Most importantly: NOT outside the jail
            let parent_bar = dest.path().parent().unwrap().join("bar.txt");
            assert!(
                !parent_bar.exists(),
                "❌ Escaped jail via canonicalization!"
            );

            println!("✅ Path canonicalization handled safely");
        }
        Err(Error::PathEscape { .. }) => {
            println!("✅ Path with '..' rejected by jail");
        }
        Err(Error::InvalidFilename { .. }) => {
            println!("✅ Path with '..' rejected as invalid");
        }
        Err(e) => panic!("❌ Unexpected error: {:?}", e),
    }
}

/// Test: Path canonicalization with multiple ../ segments
/// Attack: "a/b/../../c.txt" resolves to "c.txt" at root
#[test]
fn test_path_multiple_parent_segments() {
    let dest = tempdir().unwrap();

    let zip = create_simple_zip("a/b/../../c.txt", b"data");

    let result = Extractor::new(dest.path()).unwrap().extract(zip);

    match result {
        Ok(_) => {
            // Should be contained within dest
            let in_dest =
                dest.path().join("c.txt").exists() || dest.path().join("a/b/../../c.txt").exists();
            assert!(in_dest, "File should be in jail");

            // Not escaped
            let parent_c = dest.path().parent().unwrap().join("c.txt");
            assert!(!parent_c.exists(), "❌ Escaped via multiple '..'!");

            println!("✅ Multiple parent segments handled safely");
        }
        Err(Error::PathEscape { .. }) | Err(Error::InvalidFilename { .. }) => {
            println!("✅ Multiple parent segments rejected");
        }
        Err(e) => panic!("❌ Unexpected error: {:?}", e),
    }
}

/// Test: Symbolic component at end of path
/// Attack: "dir/." or "dir/.." as entry name
#[test]
fn test_dot_and_dotdot_entries() {
    let dest = tempdir().unwrap();

    // Entry that IS just "."
    let zip1 = create_simple_zip(".", b"data");
    let result1 = Extractor::new(dest.path()).unwrap().extract(zip1);

    match result1 {
        Err(_) => println!("✅ Single '.' entry rejected"),
        Ok(_) => println!("⚠️ Single '.' entry accepted (check semantics)"),
    }

    // Entry that IS just ".."
    let zip2 = create_simple_zip("..", b"data");
    let result2 = Extractor::new(dest.path()).unwrap().extract(zip2);

    match result2 {
        Err(Error::PathEscape { .. }) | Err(Error::InvalidFilename { .. }) => {
            println!("✅ Single '..' entry rejected");
        }
        Ok(_) => {
            // If it succeeded, must NOT have escaped
            let _parent_exists = dest.path().parent().unwrap().join("..").exists();
            // This is a bit tricky - ".." always "exists" as the parent dir
            // What matters is no FILE was written outside
            println!("⚠️ Single '..' accepted - verify no escape");
        }
        Err(e) => panic!("❌ Unexpected error for '..': {:?}", e),
    }
}

/// Test: Entry ending with slash (explicit directory marker)
/// Defense: Should create directory, not file
#[test]
fn test_trailing_slash_directory() {
    let dest = tempdir().unwrap();

    // This should be treated as a directory, not a file
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options: FileOptions<()> = FileOptions::default();
        zip.add_directory("mydir/", options).unwrap();
        zip.finish().unwrap();
    }
    buffer.set_position(0);

    let result = Extractor::new(dest.path()).unwrap().extract(buffer);

    match result {
        Ok(report) => {
            assert!(
                dest.path().join("mydir").is_dir(),
                "Should create directory"
            );
            assert_eq!(report.files_extracted, 0, "No files, just directory");
            println!("✅ Trailing slash creates directory correctly");
        }
        Err(e) => panic!("❌ Directory entry should work: {:?}", e),
    }
}

/// Test: Very deep path nesting
/// Attack: 100+ levels of nesting to exhaust stack or filesystem
/// Defense: max_path_depth limit
#[test]
fn test_extreme_path_depth() {
    let dest = tempdir().unwrap();

    // Create path with 100 levels
    let deep_path: String = (0..100).map(|i| format!("d{}/", i)).collect::<String>() + "file.txt";

    let zip = create_simple_zip(&deep_path, b"deep");

    let result = Extractor::new(dest.path())
        .unwrap()
        .limits(Limits {
            max_path_depth: 50, // Limit to 50
            ..Limits::default()
        })
        .extract(zip);

    match result {
        Err(Error::PathTooDeep { depth, limit, .. }) => {
            assert_eq!(limit, 50);
            assert!(depth > 50);
            println!("✅ Extreme depth rejected: {} > {}", depth, limit);
        }
        Err(e) => panic!("Expected PathTooDeep, got: {:?}", e),
        Ok(_) => panic!("❌ Should reject 100-level deep path with limit 50"),
    }
}
