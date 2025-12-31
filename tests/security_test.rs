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
    
    assert!(matches!(result, Err(Error::FileCountExceeded { limit: 3 })));
    
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