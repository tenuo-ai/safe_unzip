//! Async API tests (requires `async` feature)
#![cfg(feature = "async")]

use safe_unzip::r#async::{
    extract_bytes, extract_file, extract_tar_bytes, extract_tar_file, extract_tar_gz_file,
    AsyncExtractor,
};
use safe_unzip::{Error, ExtractionMode, OverwritePolicy};
use std::io::Write;
use tempfile::tempdir;

// ============================================================================
// Helper functions
// ============================================================================

fn create_simple_zip(filename: &str, content: &[u8]) -> Vec<u8> {
    let mut buffer = std::io::Cursor::new(Vec::new());
    {
        let mut zip = zip::ZipWriter::new(&mut buffer);
        let options: zip::write::FileOptions<()> =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file(filename, options).unwrap();
        zip.write_all(content).unwrap();
        zip.finish().unwrap();
    }
    buffer.into_inner()
}

fn create_simple_tar(filename: &str, content: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path(filename).unwrap();
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append(&header, content).unwrap();
    builder.into_inner().unwrap()
}

fn create_tar_gz(filename: &str, content: &[u8]) -> Vec<u8> {
    use flate2::write::GzEncoder;
    use flate2::Compression;

    let tar_data = create_simple_tar(filename, content);
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_data).unwrap();
    encoder.finish().unwrap()
}

// ============================================================================
// ZIP Tests
// ============================================================================

#[tokio::test]
async fn test_async_extract_bytes() {
    let dest = tempdir().unwrap();
    let zip_data = create_simple_zip("test.txt", b"hello async");

    let report = extract_bytes(dest.path(), zip_data).await.unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(report.bytes_written, 11);
    assert!(dest.path().join("test.txt").exists());
    assert_eq!(
        std::fs::read_to_string(dest.path().join("test.txt")).unwrap(),
        "hello async"
    );
}

#[tokio::test]
async fn test_async_extract_file() {
    let dest = tempdir().unwrap();
    let src = tempdir().unwrap();
    let zip_path = src.path().join("test.zip");

    let zip_data = create_simple_zip("file.txt", b"from file");
    std::fs::write(&zip_path, zip_data).unwrap();

    let report = extract_file(dest.path(), &zip_path).await.unwrap();

    assert_eq!(report.files_extracted, 1);
    assert!(dest.path().join("file.txt").exists());
}

#[tokio::test]
async fn test_async_extractor_builder() {
    let dest = tempdir().unwrap();
    let zip_data = create_simple_zip("data.bin", b"binary data");

    let report = AsyncExtractor::new(dest.path())
        .unwrap()
        .max_total_bytes(1024 * 1024)
        .max_file_count(100)
        .extract_bytes(zip_data)
        .await
        .unwrap();

    assert_eq!(report.files_extracted, 1);
}

#[tokio::test]
async fn test_async_destination_not_found() {
    let result = AsyncExtractor::new("/nonexistent/path");
    assert!(matches!(result, Err(Error::DestinationNotFound { .. })));
}

#[tokio::test]
async fn test_async_new_or_create() {
    let dest = tempdir().unwrap();
    let new_path = dest.path().join("new_dir");

    let extractor = AsyncExtractor::new_or_create(&new_path).unwrap();
    let zip_data = create_simple_zip("test.txt", b"hello");
    let report = extractor.extract_bytes(zip_data).await.unwrap();

    assert!(new_path.exists());
    assert_eq!(report.files_extracted, 1);
}

#[tokio::test]
async fn test_async_overwrite_error() {
    let dest = tempdir().unwrap();
    std::fs::write(dest.path().join("existing.txt"), "old content").unwrap();

    let zip_data = create_simple_zip("existing.txt", b"new content");

    let result = AsyncExtractor::new(dest.path())
        .unwrap()
        .overwrite(OverwritePolicy::Error)
        .extract_bytes(zip_data)
        .await;

    assert!(matches!(result, Err(Error::AlreadyExists { .. })));
}

#[tokio::test]
async fn test_async_overwrite_skip() {
    let dest = tempdir().unwrap();
    std::fs::write(dest.path().join("existing.txt"), "old content").unwrap();

    let zip_data = create_simple_zip("existing.txt", b"new content");

    let report = AsyncExtractor::new(dest.path())
        .unwrap()
        .overwrite(OverwritePolicy::Skip)
        .extract_bytes(zip_data)
        .await
        .unwrap();

    assert_eq!(report.files_extracted, 0);
    assert_eq!(report.entries_skipped, 1);
    // Original content preserved
    assert_eq!(
        std::fs::read_to_string(dest.path().join("existing.txt")).unwrap(),
        "old content"
    );
}

#[tokio::test]
async fn test_async_validate_first() {
    let dest = tempdir().unwrap();
    let zip_data = create_simple_zip("valid.txt", b"content");

    let report = AsyncExtractor::new(dest.path())
        .unwrap()
        .mode(ExtractionMode::ValidateFirst)
        .extract_bytes(zip_data)
        .await
        .unwrap();

    assert_eq!(report.files_extracted, 1);
}

#[tokio::test]
async fn test_async_path_traversal_blocked() {
    let dest = tempdir().unwrap();
    let zip_data = create_simple_zip("../escape.txt", b"malicious");

    let result = extract_bytes(dest.path(), zip_data).await;

    assert!(matches!(result, Err(Error::PathEscape { .. })));
}

#[tokio::test]
async fn test_async_size_limit() {
    let dest = tempdir().unwrap();
    let large_content = vec![b'x'; 1000];
    let zip_data = create_simple_zip("large.txt", &large_content);

    let result = AsyncExtractor::new(dest.path())
        .unwrap()
        .max_single_file(100) // Only allow 100 bytes
        .extract_bytes(zip_data)
        .await;

    assert!(matches!(result, Err(Error::FileTooLarge { .. })));
}

// ============================================================================
// TAR Tests
// ============================================================================

#[tokio::test]
async fn test_async_extract_tar_bytes() {
    let dest = tempdir().unwrap();
    let tar_data = create_simple_tar("hello.txt", b"hello tar async");

    let report = extract_tar_bytes(dest.path(), tar_data).await.unwrap();

    assert_eq!(report.files_extracted, 1);
    assert!(dest.path().join("hello.txt").exists());
    assert_eq!(
        std::fs::read_to_string(dest.path().join("hello.txt")).unwrap(),
        "hello tar async"
    );
}

#[tokio::test]
async fn test_async_extract_tar_file() {
    let dest = tempdir().unwrap();
    let src = tempdir().unwrap();
    let tar_path = src.path().join("test.tar");

    let tar_data = create_simple_tar("file.txt", b"from tar file");
    std::fs::write(&tar_path, tar_data).unwrap();

    let report = extract_tar_file(dest.path(), &tar_path).await.unwrap();

    assert_eq!(report.files_extracted, 1);
    assert!(dest.path().join("file.txt").exists());
}

#[tokio::test]
async fn test_async_extract_tar_gz_file() {
    let dest = tempdir().unwrap();
    let src = tempdir().unwrap();
    let tar_gz_path = src.path().join("test.tar.gz");

    let tar_gz_data = create_tar_gz("compressed.txt", b"gzipped content");
    std::fs::write(&tar_gz_path, tar_gz_data).unwrap();

    let report = extract_tar_gz_file(dest.path(), &tar_gz_path)
        .await
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert!(dest.path().join("compressed.txt").exists());
}

#[tokio::test]
async fn test_async_tar_with_builder() {
    let dest = tempdir().unwrap();
    let tar_data = create_simple_tar("data.bin", b"binary data");

    let report = AsyncExtractor::new(dest.path())
        .unwrap()
        .max_file_count(10)
        .extract_tar_bytes(tar_data)
        .await
        .unwrap();

    assert_eq!(report.files_extracted, 1);
}

// ============================================================================
// Concurrent extraction tests
// ============================================================================

#[tokio::test]
async fn test_async_concurrent_extractions() {
    let dest1 = tempdir().unwrap();
    let dest2 = tempdir().unwrap();
    let dest3 = tempdir().unwrap();

    let zip1 = create_simple_zip("file1.txt", b"content1");
    let zip2 = create_simple_zip("file2.txt", b"content2");
    let tar3 = create_simple_tar("file3.txt", b"content3");

    // Run extractions concurrently
    let (r1, r2, r3) = tokio::join!(
        extract_bytes(dest1.path(), zip1),
        extract_bytes(dest2.path(), zip2),
        extract_tar_bytes(dest3.path(), tar3),
    );

    assert!(r1.is_ok());
    assert!(r2.is_ok());
    assert!(r3.is_ok());

    assert!(dest1.path().join("file1.txt").exists());
    assert!(dest2.path().join("file2.txt").exists());
    assert!(dest3.path().join("file3.txt").exists());
}
