use safe_unzip::{Extractor, Error, ExtractionMode, OverwritePolicy, Limits};
use std::io::{Write, Seek};
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
        zip.start_file(*name, options.clone()).unwrap();
        zip.write_all(content).unwrap();
    }
    zip.finish().unwrap()
}

fn create_malicious_zip() -> std::io::Result<std::fs::File> {
    let file = tempfile::tempfile()?;
    let mut zip = zip::ZipWriter::new(file);
    
    // Add a normal file (should be processed first if we order it so, 
    // or just checking if the whole thing fails)
    let options: FileOptions<()> = FileOptions::default()
        .compression_method(zip::CompressionMethod::Stored);
    zip.start_file("safe.txt", options.clone())?;
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
    zip.start_file("good.txt", options.clone()).unwrap();
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
    
    assert!(matches!(result, Err(Error::FileCountExceeded { limit: 3, .. })));
    
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
            println!("✅ Path depth limit works (depth={}, limit={})", depth, limit);
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
    zip.add_directory("mydir/", options.clone()).unwrap();
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
            assert!(reason.contains("reserved"), "reason should mention reserved: {}", reason);
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
    let mut file = tempfile::tempfile().unwrap();
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
    let result = Extractor::new(dest.path())
        .unwrap()
        .extract(zip_file);
        
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
            assert!(!std::path::Path::new("/tmp/evil.txt").exists(), 
                "❌ Wrote to absolute path outside jail!");
            // It should be inside the jail (with root stripped)
            let inside = dest.path().join("tmp/evil.txt").exists() 
                || dest.path().join("evil.txt").exists();
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
            assert!(reason.contains("backslash"), "Should mention backslash: {}", reason);
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
            assert!(reason.contains("control"), "Should mention control chars: {}", reason);
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
    assert_eq!(target_content, "original", "Original target should be unchanged");
    
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
    assert!(matches!(result, Err(Error::InvalidFilename { .. })), 
        "Should reject mixed slashes: {:?}", result);
    println!("✅ Rejected mixed slash traversal attempt");
}