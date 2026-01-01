//! Tests for TAR archive extraction.

use safe_unzip::{Driver, Limits, TarAdapter, ValidationMode};
use std::io::Write;
use tempfile::tempdir;

/// Create a simple tar archive with one file.
fn create_simple_tar(name: &str, content: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let mut header = tar::Header::new_gnu();
    header.set_path(name).unwrap();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();

    builder.append(&header, content).unwrap();
    builder.into_inner().unwrap()
}

/// Create a tar archive with multiple files.
fn create_multi_file_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    for (name, content) in files {
        let mut header = tar::Header::new_gnu();
        header.set_path(*name).unwrap();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();

        builder.append(&header, *content).unwrap();
    }

    builder.into_inner().unwrap()
}

/// Create a tar archive with a directory.
fn create_tar_with_dir(dir_name: &str, file_name: &str, content: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    // Add directory
    let mut header = tar::Header::new_gnu();
    header.set_path(dir_name).unwrap();
    header.set_size(0);
    header.set_mode(0o755);
    header.set_entry_type(tar::EntryType::Directory);
    header.set_cksum();
    builder.append(&header, &[][..]).unwrap();

    // Add file in directory
    let full_path = format!("{}/{}", dir_name.trim_end_matches('/'), file_name);
    let mut header = tar::Header::new_gnu();
    header.set_path(&full_path).unwrap();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, content).unwrap();

    builder.into_inner().unwrap()
}

#[test]
fn test_tar_basic_extraction() {
    let dest = tempdir().unwrap();
    let tar_data = create_simple_tar("hello.txt", b"Hello, TAR!");

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let report = Driver::new(dest.path())
        .unwrap()
        .extract_tar(adapter)
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(report.bytes_written, 11);
    assert!(dest.path().join("hello.txt").exists());

    let content = std::fs::read_to_string(dest.path().join("hello.txt")).unwrap();
    assert_eq!(content, "Hello, TAR!");

    println!("✅ TAR basic extraction works");
}

#[test]
fn test_tar_multiple_files() {
    let dest = tempdir().unwrap();
    let tar_data =
        create_multi_file_tar(&[("a.txt", b"aaa"), ("b.txt", b"bbb"), ("c.txt", b"ccc")]);

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let report = Driver::new(dest.path())
        .unwrap()
        .extract_tar(adapter)
        .unwrap();

    assert_eq!(report.files_extracted, 3);
    assert!(dest.path().join("a.txt").exists());
    assert!(dest.path().join("b.txt").exists());
    assert!(dest.path().join("c.txt").exists());

    println!("✅ TAR multiple files extraction works");
}

#[test]
fn test_tar_with_directory() {
    let dest = tempdir().unwrap();
    let tar_data = create_tar_with_dir("subdir/", "file.txt", b"in subdir");

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let report = Driver::new(dest.path())
        .unwrap()
        .extract_tar(adapter)
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(report.dirs_created, 1);
    assert!(dest.path().join("subdir/file.txt").exists());

    println!("✅ TAR with directory works");
}

#[test]
fn test_tar_blocks_path_traversal() {
    let dest = tempdir().unwrap();

    // Create a tar with path traversal attempt using raw bytes
    // The tar crate's set_path() blocks "..", so we manually construct the header
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();

    // Use a safe path first, then modify the raw bytes
    header.set_path("placeholder").unwrap();
    header.set_size(4);
    header.set_mode(0o644);

    // Manually set the path in the header bytes
    let evil_path = b"../../etc/passwd";
    header.as_mut_bytes()[..evil_path.len()].copy_from_slice(evil_path);
    header.as_mut_bytes()[evil_path.len()] = 0; // Null terminate

    header.set_cksum();
    builder.append(&header, &b"evil"[..]).unwrap();
    let tar_data = builder.into_inner().unwrap();

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let result = Driver::new(dest.path()).unwrap().extract_tar(adapter);

    assert!(result.is_err());
    println!("✅ TAR blocks path traversal");
}

#[test]
fn test_tar_validate_first_mode() {
    let dest = tempdir().unwrap();

    // Create tar with valid file then traversal attempt
    let mut builder = tar::Builder::new(Vec::new());

    // Good file
    let mut header = tar::Header::new_gnu();
    header.set_path("good.txt").unwrap();
    header.set_size(12);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &b"This is fine"[..]).unwrap();

    // Bad file (path traversal) - manually set path to bypass tar crate's check
    let mut header = tar::Header::new_gnu();
    header.set_path("placeholder").unwrap();
    header.set_size(5);
    header.set_mode(0o644);

    let evil_path = b"../../evil.txt";
    header.as_mut_bytes()[..evil_path.len()].copy_from_slice(evil_path);
    header.as_mut_bytes()[evil_path.len()] = 0;

    header.set_cksum();
    builder.append(&header, &b"pwned"[..]).unwrap();

    let tar_data = builder.into_inner().unwrap();

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let result = Driver::new(dest.path())
        .unwrap()
        .validation(ValidationMode::ValidateFirst)
        .extract_tar(adapter);

    // Should fail
    assert!(result.is_err());

    // Nothing should be written in ValidateFirst mode
    assert!(
        !dest.path().join("good.txt").exists(),
        "ValidateFirst should not write good.txt before failing"
    );

    println!("✅ TAR ValidateFirst mode works");
}

#[test]
fn test_tar_filter() {
    let dest = tempdir().unwrap();
    let tar_data = create_multi_file_tar(&[
        ("image.png", b"png data"),
        ("document.txt", b"text data"),
        ("photo.jpg", b"jpg data"),
    ]);

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let report = Driver::new(dest.path())
        .unwrap()
        .filter(|info| info.name.ends_with(".txt"))
        .extract_tar(adapter)
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert!(dest.path().join("document.txt").exists());
    assert!(!dest.path().join("image.png").exists());
    assert!(!dest.path().join("photo.jpg").exists());

    println!("✅ TAR filter works");
}

#[test]
fn test_tar_gz_extraction() {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let dest = tempdir().unwrap();

    // Create tar data
    let tar_data = create_simple_tar("compressed.txt", b"I was compressed!");

    // Compress with gzip
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_data).unwrap();
    let gz_data = encoder.finish().unwrap();

    // Extract using GzDecoder
    use flate2::read::GzDecoder;
    let decoder = GzDecoder::new(std::io::Cursor::new(gz_data));
    let adapter = TarAdapter::new(decoder);

    let report = Driver::new(dest.path())
        .unwrap()
        .extract_tar(adapter)
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert!(dest.path().join("compressed.txt").exists());

    let content = std::fs::read_to_string(dest.path().join("compressed.txt")).unwrap();
    assert_eq!(content, "I was compressed!");

    println!("✅ TAR.GZ extraction works");
}

// ===========================================================================
// Security Tests for TAR-specific threats
// ===========================================================================

#[test]
fn test_tar_rejects_block_device() {
    let dest = tempdir().unwrap();

    // Create tar with block device entry
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("dev/sda").unwrap();
    header.set_size(0);
    header.set_mode(0o660);
    header.set_entry_type(tar::EntryType::Block);
    header.set_device_major(8).unwrap();
    header.set_device_minor(0).unwrap();
    header.set_cksum();

    builder.append(&header, &[][..]).unwrap();
    let tar_data = builder.into_inner().unwrap();

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let result = Driver::new(dest.path()).unwrap().extract_tar(adapter);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, safe_unzip::Error::UnsupportedEntryType { .. }),
        "Expected UnsupportedEntryType, got {:?}",
        err
    );

    println!("✅ TAR rejects block device");
}

#[test]
fn test_tar_rejects_char_device() {
    let dest = tempdir().unwrap();

    // Create tar with character device entry (like /dev/null)
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("dev/null").unwrap();
    header.set_size(0);
    header.set_mode(0o666);
    header.set_entry_type(tar::EntryType::Char);
    header.set_device_major(1).unwrap();
    header.set_device_minor(3).unwrap();
    header.set_cksum();

    builder.append(&header, &[][..]).unwrap();
    let tar_data = builder.into_inner().unwrap();

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let result = Driver::new(dest.path()).unwrap().extract_tar(adapter);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, safe_unzip::Error::UnsupportedEntryType { .. }),
        "Expected UnsupportedEntryType, got {:?}",
        err
    );

    println!("✅ TAR rejects character device");
}

#[test]
fn test_tar_rejects_fifo() {
    let dest = tempdir().unwrap();

    // Create tar with FIFO (named pipe) entry
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("my_pipe").unwrap();
    header.set_size(0);
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::Fifo);
    header.set_cksum();

    builder.append(&header, &[][..]).unwrap();
    let tar_data = builder.into_inner().unwrap();

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let result = Driver::new(dest.path()).unwrap().extract_tar(adapter);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, safe_unzip::Error::UnsupportedEntryType { .. }),
        "Expected UnsupportedEntryType, got {:?}",
        err
    );

    println!("✅ TAR rejects FIFO");
}

#[test]
fn test_tar_blocks_absolute_path() {
    let dest = tempdir().unwrap();

    // Create tar with absolute path by manually setting header bytes
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("placeholder").unwrap();
    header.set_size(4);
    header.set_mode(0o644);

    // Inject absolute path
    let evil_path = b"/etc/passwd";
    header.as_mut_bytes()[..evil_path.len()].copy_from_slice(evil_path);
    header.as_mut_bytes()[evil_path.len()] = 0;
    header.set_cksum();

    builder.append(&header, &b"pwnd"[..]).unwrap();
    let tar_data = builder.into_inner().unwrap();

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let result = Driver::new(dest.path()).unwrap().extract_tar(adapter);

    // Should either fail or strip the leading slash (safe behavior)
    match result {
        Err(safe_unzip::Error::PathEscape { .. }) => {
            println!("✅ TAR blocks absolute path (rejected)");
        }
        Ok(_) => {
            // If it succeeded, verify it was extracted safely inside the jail
            assert!(
                !std::path::Path::new("/etc/passwd").exists()
                    || std::fs::read_to_string("/etc/passwd")
                        .map(|s| s != "pwnd")
                        .unwrap_or(true),
                "Should not have written to /etc/passwd"
            );
            // Should be inside the jail with leading slash stripped
            assert!(
                dest.path().join("etc/passwd").exists() || dest.path().join("passwd").exists(),
                "Should be extracted inside jail"
            );
            println!("✅ TAR blocks absolute path (sanitized)");
        }
        Err(e) => panic!("Unexpected error: {:?}", e),
    }
}

#[test]
fn test_tar_symlink_skip_policy() {
    let dest = tempdir().unwrap();

    // Create tar with symlink
    let mut builder = tar::Builder::new(Vec::new());

    // Regular file
    let mut header = tar::Header::new_gnu();
    header.set_path("regular.txt").unwrap();
    header.set_size(4);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &b"safe"[..]).unwrap();

    // Symlink
    let mut header = tar::Header::new_gnu();
    header.set_path("link").unwrap();
    header.set_size(0);
    header.set_mode(0o777);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_link_name("/etc/passwd").unwrap();
    header.set_cksum();
    builder.append(&header, &[][..]).unwrap();

    let tar_data = builder.into_inner().unwrap();

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let report = Driver::new(dest.path())
        .unwrap()
        .symlinks(safe_unzip::SymlinkBehavior::Skip)
        .extract_tar(adapter)
        .unwrap();

    // Regular file should be extracted, symlink should be skipped
    assert_eq!(report.files_extracted, 1);
    assert_eq!(report.entries_skipped, 1);
    assert!(dest.path().join("regular.txt").exists());
    assert!(!dest.path().join("link").exists());

    println!("✅ TAR symlink skip policy works");
}

#[test]
fn test_tar_symlink_error_policy() {
    let dest = tempdir().unwrap();

    // Create tar with symlink
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("evil_link").unwrap();
    header.set_size(0);
    header.set_mode(0o777);
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_link_name("/etc/shadow").unwrap();
    header.set_cksum();
    builder.append(&header, &[][..]).unwrap();

    let tar_data = builder.into_inner().unwrap();

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let result = Driver::new(dest.path())
        .unwrap()
        .symlinks(safe_unzip::SymlinkBehavior::Error)
        .extract_tar(adapter);

    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        safe_unzip::Error::SymlinkNotAllowed { .. }
    ));

    println!("✅ TAR symlink error policy works");
}

#[test]
#[cfg(unix)]
fn test_tar_strips_setuid_setgid() {
    let dest = tempdir().unwrap();

    // Create tar with setuid/setgid file
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("suid_binary").unwrap();
    header.set_size(4);
    // 0o4755 = setuid + rwxr-xr-x
    // 0o2755 = setgid + rwxr-xr-x
    // 0o6755 = both setuid and setgid
    header.set_mode(0o6755);
    header.set_cksum();

    builder.append(&header, &b"exec"[..]).unwrap();
    let tar_data = builder.into_inner().unwrap();

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let report = Driver::new(dest.path())
        .unwrap()
        .extract_tar(adapter)
        .unwrap();

    assert_eq!(report.files_extracted, 1);

    // Verify permissions were stripped to 0o755 or lower (no setuid/setgid)
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(dest.path().join("suid_binary")).unwrap();
    let mode = metadata.permissions().mode();

    // Check that setuid (0o4000) and setgid (0o2000) bits are NOT set
    assert!(
        mode & 0o6000 == 0,
        "setuid/setgid bits should be stripped, got mode {:o}",
        mode
    );

    println!("✅ TAR strips setuid/setgid bits");
}

#[test]
fn test_tar_size_limit_enforcement() {
    let dest = tempdir().unwrap();

    // Create tar with file larger than limit
    let large_content = vec![b'X'; 1024 * 1024]; // 1 MB
    let tar_data = create_simple_tar("large.bin", &large_content);

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let result = Driver::new(dest.path())
        .unwrap()
        .limits(Limits {
            max_total_bytes: 512 * 1024, // 512 KB limit
            ..Default::default()
        })
        .extract_tar(adapter);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, safe_unzip::Error::TotalSizeExceeded { .. }),
        "Expected TotalSizeExceeded, got {:?}",
        err
    );

    println!("✅ TAR size limit enforcement works");
}

#[test]
fn test_tar_single_file_size_limit() {
    let dest = tempdir().unwrap();

    // Create tar with file exceeding single file limit
    let large_content = vec![b'Y'; 100 * 1024]; // 100 KB
    let tar_data = create_simple_tar("big.bin", &large_content);

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let result = Driver::new(dest.path())
        .unwrap()
        .limits(Limits {
            max_single_file: 50 * 1024, // 50 KB limit
            ..Default::default()
        })
        .extract_tar(adapter);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, safe_unzip::Error::FileTooLarge { .. }),
        "Expected FileTooLarge, got {:?}",
        err
    );

    println!("✅ TAR single file size limit works");
}

#[test]
fn test_tar_file_count_limit() {
    let dest = tempdir().unwrap();

    // Create tar with many files
    let files: Vec<(&str, &[u8])> = vec![
        ("a.txt", b"a"),
        ("b.txt", b"b"),
        ("c.txt", b"c"),
        ("d.txt", b"d"),
        ("e.txt", b"e"),
    ];
    let tar_data = create_multi_file_tar(&files);

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let result = Driver::new(dest.path())
        .unwrap()
        .limits(Limits {
            max_file_count: 3, // Only allow 3 files
            ..Default::default()
        })
        .extract_tar(adapter);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, safe_unzip::Error::FileCountExceeded { .. }),
        "Expected FileCountExceeded, got {:?}",
        err
    );

    println!("✅ TAR file count limit works");
}

#[test]
fn test_tar_depth_limit() {
    let dest = tempdir().unwrap();

    // Create tar with deeply nested file
    let mut builder = tar::Builder::new(Vec::new());
    let deep_path = "a/b/c/d/e/f/g/h/i/j/deep.txt";

    let mut header = tar::Header::new_gnu();
    header.set_path(deep_path).unwrap();
    header.set_size(4);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &b"deep"[..]).unwrap();

    let tar_data = builder.into_inner().unwrap();

    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let result = Driver::new(dest.path())
        .unwrap()
        .limits(Limits {
            max_path_depth: 3, // Only allow 3 levels
            ..Default::default()
        })
        .extract_tar(adapter);

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, safe_unzip::Error::PathTooDeep { .. }),
        "Expected PathTooDeep, got {:?}",
        err
    );

    println!("✅ TAR depth limit works");
}

#[test]
fn test_tar_hard_link_treated_as_symlink() {
    let dest = tempdir().unwrap();

    // Create tar with hard link (tar::EntryType::Link)
    let mut builder = tar::Builder::new(Vec::new());

    // First add a regular file
    let mut header = tar::Header::new_gnu();
    header.set_path("original.txt").unwrap();
    header.set_size(5);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, &b"hello"[..]).unwrap();

    // Then add a hard link to it (inside the tar)
    let mut header = tar::Header::new_gnu();
    header.set_path("hardlink.txt").unwrap();
    header.set_size(0);
    header.set_mode(0o644);
    header.set_entry_type(tar::EntryType::Link);
    header.set_link_name("original.txt").unwrap();
    header.set_cksum();
    builder.append(&header, &[][..]).unwrap();

    let tar_data = builder.into_inner().unwrap();

    // With skip policy, hard link should be skipped
    let adapter = TarAdapter::new(std::io::Cursor::new(tar_data));
    let report = Driver::new(dest.path())
        .unwrap()
        .symlinks(safe_unzip::SymlinkBehavior::Skip)
        .extract_tar(adapter)
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(report.entries_skipped, 1);
    assert!(dest.path().join("original.txt").exists());
    assert!(!dest.path().join("hardlink.txt").exists());

    println!("✅ TAR hard link handled as symlink");
}
