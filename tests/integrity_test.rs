//! Integrity tests: corrupt entries must never leave files on disk.
//!
//! Regression tests for https://github.com/tenuo-ai/safe_unzip/issues/3

use safe_unzip::{Driver, Error, ExtractionMode, Extractor, Limits, ValidationMode, ZipAdapter};
use std::io::{Cursor, Write};
use tempfile::tempdir;
use zip::write::FileOptions;
use zip::CompressionMethod;

/// Build a zip, then corrupt the stored CRC32 of `corrupt` (local header and
/// central directory) so the data no longer matches its checksum.
fn zip_with_bad_crc(files: &[(&str, &[u8])], corrupt: &str, method: CompressionMethod) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options: FileOptions<()> = FileOptions::default().compression_method(method);
    for (name, content) in files {
        zip.start_file(*name, options).unwrap();
        zip.write_all(content).unwrap();
    }
    let mut bytes = zip.finish().unwrap().into_inner();

    let content = files.iter().find(|(n, _)| *n == corrupt).unwrap().1;
    let crc = crc32(content).to_le_bytes();
    let bad = (crc32(content) ^ 0xdead_beef).to_le_bytes();
    let mut replaced = 0;
    for i in 0..bytes.len() - 4 {
        if bytes[i..i + 4] == crc {
            bytes[i..i + 4].copy_from_slice(&bad);
            replaced += 1;
        }
    }
    assert_eq!(
        replaced, 2,
        "expected CRC in local header and central directory"
    );
    bytes
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn payload() -> Vec<u8> {
    (0..64 * 1024u32).map(|i| (i % 251) as u8).collect()
}

const METHODS: [CompressionMethod; 2] = [CompressionMethod::Stored, CompressionMethod::Deflated];

#[test]
fn extractor_streaming_removes_corrupt_file() {
    let data = payload();
    for method in METHODS {
        let zip = zip_with_bad_crc(&[("bad.bin", &data)], "bad.bin", method);
        let dest = tempdir().unwrap();

        let result = Extractor::new(dest.path())
            .unwrap()
            .extract(Cursor::new(zip));

        assert!(
            matches!(result, Err(Error::ChecksumMismatch { ref entry }) if entry == "bad.bin"),
            "{method:?}: {result:?}"
        );
        assert!(
            !dest.path().join("bad.bin").exists(),
            "{method:?}: corrupt file left on disk"
        );
    }
}

#[test]
fn extractor_validate_first_writes_nothing_on_bad_crc() {
    let data = payload();
    for method in METHODS {
        let zip = zip_with_bad_crc(
            &[("good.txt", b"fine"), ("bad.bin", &data)],
            "bad.bin",
            method,
        );
        let dest = tempdir().unwrap();

        let result = Extractor::new(dest.path())
            .unwrap()
            .mode(ExtractionMode::ValidateFirst)
            .extract(Cursor::new(zip));

        assert!(
            matches!(result, Err(Error::ChecksumMismatch { ref entry }) if entry == "bad.bin"),
            "{method:?}: {result:?}"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dest.path()).unwrap().collect();
        assert!(leftovers.is_empty(), "{method:?}: wrote {leftovers:?}");
    }
}

#[test]
fn driver_streaming_removes_corrupt_file() {
    let data = payload();
    for method in METHODS {
        let zip = zip_with_bad_crc(&[("bad.bin", &data)], "bad.bin", method);
        let dest = tempdir().unwrap();

        let adapter = ZipAdapter::new(Cursor::new(zip)).unwrap();
        let result = Driver::new(dest.path()).unwrap().extract_zip(adapter);

        assert!(
            matches!(result, Err(Error::ChecksumMismatch { ref entry }) if entry == "bad.bin"),
            "{method:?}: {result:?}"
        );
        assert!(
            !dest.path().join("bad.bin").exists(),
            "{method:?}: corrupt file left on disk"
        );
    }
}

#[test]
fn driver_streaming_checks_crc_when_entry_fills_limit() {
    // Entry size == max_single_file: the copy loop stops at the limit, so the
    // CRC check (which fires on EOF) must still be forced.
    let data = payload();
    let zip = zip_with_bad_crc(&[("bad.bin", &data)], "bad.bin", CompressionMethod::Stored);
    let dest = tempdir().unwrap();

    let adapter = ZipAdapter::new(Cursor::new(zip)).unwrap();
    let result = Driver::new(dest.path())
        .unwrap()
        .limits(Limits {
            max_single_file: data.len() as u64,
            ..Default::default()
        })
        .extract_zip(adapter);

    assert!(
        matches!(result, Err(Error::ChecksumMismatch { .. })),
        "{result:?}"
    );
    assert!(!dest.path().join("bad.bin").exists());
}

#[test]
fn driver_validate_first_writes_nothing_on_bad_crc() {
    let data = payload();
    for method in METHODS {
        let zip = zip_with_bad_crc(
            &[("good.txt", b"fine"), ("bad.bin", &data)],
            "bad.bin",
            method,
        );
        let dest = tempdir().unwrap();

        let adapter = ZipAdapter::new(Cursor::new(zip)).unwrap();
        let result = Driver::new(dest.path())
            .unwrap()
            .validation(ValidationMode::ValidateFirst)
            .extract_zip(adapter);

        assert!(
            matches!(result, Err(Error::ChecksumMismatch { ref entry }) if entry == "bad.bin"),
            "{method:?}: {result:?}"
        );
        let leftovers: Vec<_> = std::fs::read_dir(dest.path()).unwrap().collect();
        assert!(leftovers.is_empty(), "{method:?}: wrote {leftovers:?}");
    }
}

#[test]
fn intact_archives_still_extract() {
    let data = payload();
    for method in METHODS {
        let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options: FileOptions<()> = FileOptions::default().compression_method(method);
        zip.start_file("ok.bin", options).unwrap();
        zip.write_all(&data).unwrap();
        let bytes = zip.finish().unwrap().into_inner();

        for validate_first in [false, true] {
            let dest = tempdir().unwrap();
            let mode = if validate_first {
                ExtractionMode::ValidateFirst
            } else {
                ExtractionMode::Streaming
            };
            Extractor::new(dest.path())
                .unwrap()
                .mode(mode)
                .extract(Cursor::new(bytes.clone()))
                .unwrap();
            assert_eq!(std::fs::read(dest.path().join("ok.bin")).unwrap(), data);

            let dest = tempdir().unwrap();
            let validation = if validate_first {
                ValidationMode::ValidateFirst
            } else {
                ValidationMode::Streaming
            };
            Driver::new(dest.path())
                .unwrap()
                .validation(validation)
                .limits(Limits {
                    max_single_file: data.len() as u64,
                    ..Default::default()
                })
                .extract_zip(ZipAdapter::new(Cursor::new(bytes.clone())).unwrap())
                .unwrap();
            assert_eq!(std::fs::read(dest.path().join("ok.bin")).unwrap(), data);
        }
    }
}

#[test]
fn verify_reports_checksum_mismatch() {
    let data = payload();
    let zip = zip_with_bad_crc(
        &[("bad.bin", &data)],
        "bad.bin",
        CompressionMethod::Deflated,
    );

    let result = safe_unzip::verify_bytes(&zip);

    assert!(
        matches!(result, Err(Error::ChecksumMismatch { ref entry }) if entry == "bad.bin"),
        "{result:?}"
    );
}
