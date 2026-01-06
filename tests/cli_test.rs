//! CLI integration tests
//!
//! These tests verify the CLI works correctly end-to-end.

#![cfg(feature = "cli")]

use std::fs;
use std::io::Write;
use std::process::Command;

fn cli_binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_safe_unzip"))
}

fn create_test_zip(dir: &std::path::Path) -> std::path::PathBuf {
    let zip_path = dir.join("test.zip");
    let file = fs::File::create(&zip_path).unwrap();
    let mut zip = zip::ZipWriter::new(file);
    let options: zip::write::FileOptions<()> = zip::write::FileOptions::default();

    zip.start_file("hello.txt", options).unwrap();
    zip.write_all(b"Hello, World!").unwrap();

    zip.start_file("subdir/nested.txt", options).unwrap();
    zip.write_all(b"Nested content").unwrap();

    zip.finish().unwrap();
    zip_path
}

#[test]
fn test_cli_help() {
    let output = cli_binary().arg("--help").output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Secure archive extraction"));
    assert!(stdout.contains("--list"));
    assert!(stdout.contains("--verify"));
    assert!(stdout.contains("--max-size"));
}

#[test]
fn test_cli_version() {
    let output = cli_binary().arg("--version").output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("safe_unzip"));
}

#[test]
fn test_cli_list() {
    let temp = tempfile::tempdir().unwrap();
    let zip_path = create_test_zip(temp.path());

    let output = cli_binary().arg(&zip_path).arg("--list").output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello.txt"));
    assert!(stdout.contains("subdir/nested.txt"));
    assert!(stdout.contains("2 entries"));
}

#[test]
fn test_cli_verify() {
    let temp = tempfile::tempdir().unwrap();
    let zip_path = create_test_zip(temp.path());

    let output = cli_binary()
        .arg(&zip_path)
        .arg("--verify")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Verified"));
    assert!(stdout.contains("2 entries"));
}

#[test]
fn test_cli_extract() {
    let temp = tempfile::tempdir().unwrap();
    let zip_path = create_test_zip(temp.path());
    let dest = temp.path().join("output");
    fs::create_dir(&dest).unwrap();

    let output = cli_binary()
        .arg(&zip_path)
        .arg("-d")
        .arg(&dest)
        .output()
        .unwrap();

    assert!(output.status.success());

    // Verify files were extracted
    assert!(dest.join("hello.txt").exists());
    assert!(dest.join("subdir/nested.txt").exists());

    let content = fs::read_to_string(dest.join("hello.txt")).unwrap();
    assert_eq!(content, "Hello, World!");
}

#[test]
fn test_cli_extract_verbose() {
    let temp = tempfile::tempdir().unwrap();
    let zip_path = create_test_zip(temp.path());
    let dest = temp.path().join("output");
    fs::create_dir(&dest).unwrap();

    let output = cli_binary()
        .arg(&zip_path)
        .arg("-d")
        .arg(&dest)
        .arg("-v")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("hello.txt"));
    assert!(stdout.contains("nested.txt"));
}

#[test]
fn test_cli_extract_quiet() {
    let temp = tempfile::tempdir().unwrap();
    let zip_path = create_test_zip(temp.path());
    let dest = temp.path().join("output");
    fs::create_dir(&dest).unwrap();

    let output = cli_binary()
        .arg(&zip_path)
        .arg("-d")
        .arg(&dest)
        .arg("-q")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.is_empty() || stdout.trim().is_empty());
}

#[test]
fn test_cli_max_size_limit() {
    let temp = tempfile::tempdir().unwrap();
    let zip_path = create_test_zip(temp.path());
    let dest = temp.path().join("output");
    fs::create_dir(&dest).unwrap();

    // Set a very small limit that will be exceeded
    let output = cli_binary()
        .arg(&zip_path)
        .arg("-d")
        .arg(&dest)
        .arg("--max-size")
        .arg("1") // 1 byte limit
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("too large") || stderr.contains("limit"));
}

#[test]
fn test_cli_max_files_limit() {
    let temp = tempfile::tempdir().unwrap();
    let zip_path = create_test_zip(temp.path());
    let dest = temp.path().join("output");
    fs::create_dir(&dest).unwrap();

    // Set a limit of 1 file (archive has 2)
    let output = cli_binary()
        .arg(&zip_path)
        .arg("-d")
        .arg(&dest)
        .arg("--max-files")
        .arg("1")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("files") || stderr.contains("limit"));
}

#[test]
fn test_cli_include_filter() {
    let temp = tempfile::tempdir().unwrap();
    let zip_path = create_test_zip(temp.path());
    let dest = temp.path().join("output");
    fs::create_dir(&dest).unwrap();

    let output = cli_binary()
        .arg(&zip_path)
        .arg("-d")
        .arg(&dest)
        .arg("--include")
        .arg("**/*.txt")
        .output()
        .unwrap();

    assert!(output.status.success());
    // Both files should be extracted (both are .txt)
    assert!(dest.join("hello.txt").exists());
}

#[test]
fn test_cli_only_filter() {
    let temp = tempfile::tempdir().unwrap();
    let zip_path = create_test_zip(temp.path());
    let dest = temp.path().join("output");
    fs::create_dir(&dest).unwrap();

    let output = cli_binary()
        .arg(&zip_path)
        .arg("-d")
        .arg(&dest)
        .arg("--only")
        .arg("hello.txt")
        .output()
        .unwrap();

    assert!(output.status.success());
    assert!(dest.join("hello.txt").exists());
    // nested.txt should NOT be extracted
    assert!(!dest.join("subdir/nested.txt").exists());
}

#[test]
fn test_cli_overwrite_error() {
    let temp = tempfile::tempdir().unwrap();
    let zip_path = create_test_zip(temp.path());
    let dest = temp.path().join("output");
    fs::create_dir(&dest).unwrap();

    // Create existing file
    fs::write(dest.join("hello.txt"), "existing").unwrap();

    let output = cli_binary()
        .arg(&zip_path)
        .arg("-d")
        .arg(&dest)
        .arg("--overwrite")
        .arg("error")
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("exists"));
}

#[test]
fn test_cli_overwrite_skip() {
    let temp = tempfile::tempdir().unwrap();
    let zip_path = create_test_zip(temp.path());
    let dest = temp.path().join("output");
    fs::create_dir(&dest).unwrap();

    // Create existing file
    fs::write(dest.join("hello.txt"), "existing").unwrap();

    let output = cli_binary()
        .arg(&zip_path)
        .arg("-d")
        .arg(&dest)
        .arg("--overwrite")
        .arg("skip")
        .output()
        .unwrap();

    assert!(output.status.success());
    // Original content should be preserved
    let content = fs::read_to_string(dest.join("hello.txt")).unwrap();
    assert_eq!(content, "existing");
}

#[test]
fn test_cli_missing_archive() {
    let output = cli_binary()
        .arg("/nonexistent/archive.zip")
        .arg("--list")
        .output()
        .unwrap();

    assert!(!output.status.success());
}

#[test]
fn test_cli_size_parsing() {
    let temp = tempfile::tempdir().unwrap();
    let zip_path = create_test_zip(temp.path());
    let dest = temp.path().join("output");
    fs::create_dir(&dest).unwrap();

    // Test various size formats
    for size in &["100M", "100MB", "1G", "1GB", "1024K", "1024KB"] {
        let output = cli_binary()
            .arg(&zip_path)
            .arg("-d")
            .arg(&dest)
            .arg("--max-size")
            .arg(size)
            .arg("--overwrite")
            .arg("overwrite")
            .output()
            .unwrap();

        assert!(output.status.success(), "Failed for size: {}", size);
    }
}
