//! Tests for 7z extraction (sevenz-rust2 backend).
//!
//! Fixtures in tests/fixtures/7z were generated with sevenz-rust2's encoder:
//! - basic.7z      a.txt ("alpha"), dir/, dir/b.txt ("beta")
//! - traversal.7z  ../escape.txt
//! - bomb.7z       zeros.bin: 64 MiB of zeros, ~10 KB compressed
//! - solid.7z      one solid block: skip.bin (1 MiB zeros), then keep.txt ("keep")
//! - bad_crc.7z    data.bin stored uncompressed, one data byte flipped
#![cfg(feature = "sevenz")]

use safe_unzip::{Driver, Error, Limits, SevenZAdapter, ValidationMode};
use std::path::PathBuf;
use tempfile::tempdir;

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/7z")
        .join(name)
}

fn bytes(name: &str) -> Vec<u8> {
    std::fs::read(fixture(name)).unwrap()
}

fn is_empty(dir: &std::path::Path) -> bool {
    std::fs::read_dir(dir).unwrap().next().is_none()
}

#[test]
fn extracts_7z_from_bytes() {
    let dest = tempdir().unwrap();

    let report = Driver::new(dest.path())
        .unwrap()
        .extract_7z_bytes(&bytes("basic.7z"))
        .unwrap();

    assert_eq!(report.files_extracted, 2);
    assert_eq!(std::fs::read(dest.path().join("a.txt")).unwrap(), b"alpha");
    assert_eq!(
        std::fs::read(dest.path().join("dir/b.txt")).unwrap(),
        b"beta"
    );
}

#[test]
fn extracts_7z_from_file() {
    let dest = tempdir().unwrap();

    let adapter = SevenZAdapter::open(fixture("basic.7z")).unwrap();
    assert_eq!(adapter.len(), 3);
    Driver::new(dest.path())
        .unwrap()
        .validation(ValidationMode::ValidateFirst)
        .extract_7z(adapter)
        .unwrap();

    assert_eq!(std::fs::read(dest.path().join("a.txt")).unwrap(), b"alpha");
}

#[test]
fn reads_7z_metadata_without_decompressing() {
    let adapter = SevenZAdapter::from_bytes(&bytes("bomb.7z")).unwrap();
    let entries = adapter.entries_metadata();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].size, 64 << 20);
}

#[test]
fn blocks_7z_path_traversal() {
    let dest = tempdir().unwrap();

    let result = Driver::new(dest.path())
        .unwrap()
        .extract_7z_bytes(&bytes("traversal.7z"));

    assert!(
        matches!(result, Err(Error::PathEscape { .. })),
        "{result:?}"
    );
    assert!(!dest.path().parent().unwrap().join("escape.txt").exists());
}

#[test]
fn rejects_7z_bomb_before_decompressing() {
    let dest = tempdir().unwrap();

    let result = Driver::new(dest.path())
        .unwrap()
        .limits(Limits {
            max_single_file: 1024 * 1024,
            ..Default::default()
        })
        .extract_7z_file(fixture("bomb.7z"));

    assert!(
        matches!(result, Err(Error::FileTooLarge { .. })),
        "{result:?}"
    );
    assert!(is_empty(dest.path()));
}

#[test]
fn rejects_7z_bomb_over_total_limit() {
    let dest = tempdir().unwrap();

    let result = Driver::new(dest.path())
        .unwrap()
        .limits(Limits {
            max_total_bytes: 1024 * 1024,
            ..Default::default()
        })
        .extract_7z_file(fixture("bomb.7z"));

    assert!(
        matches!(result, Err(Error::TotalSizeExceeded { .. })),
        "{result:?}"
    );
    assert!(is_empty(dest.path()));
}

#[test]
fn skips_entries_in_solid_block() {
    // keep.txt sits after skip.bin in the same compressed stream; skipping
    // skip.bin must still leave the stream positioned at keep.txt.
    let dest = tempdir().unwrap();

    let report = Driver::new(dest.path())
        .unwrap()
        .only(&["keep.txt"])
        .extract_7z_file(fixture("solid.7z"))
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(
        std::fs::read(dest.path().join("keep.txt")).unwrap(),
        b"keep"
    );
    assert!(!dest.path().join("skip.bin").exists());
}

#[test]
fn rejects_7z_checksum_mismatch() {
    for validation in [ValidationMode::Streaming, ValidationMode::ValidateFirst] {
        let dest = tempdir().unwrap();

        let result = Driver::new(dest.path())
            .unwrap()
            .validation(validation)
            .extract_7z_file(fixture("bad_crc.7z"));

        assert!(
            matches!(result, Err(Error::ChecksumMismatch { ref entry }) if entry == "data.bin"),
            "{validation:?}: {result:?}"
        );
        assert!(is_empty(dest.path()), "{validation:?}: file left on disk");
    }
}

#[test]
fn rejects_7z_needing_too_much_decoder_memory() {
    let dest = tempdir().unwrap();
    // basic.7z uses a multi-KiB LZMA2 dictionary; a 1 KiB cap must refuse it
    // before any decompression.
    let adapter = SevenZAdapter::open(fixture("basic.7z"))
        .unwrap()
        .max_decoder_memory(1024);

    let result = Driver::new(dest.path()).unwrap().extract_7z(adapter);

    assert!(
        matches!(
            result,
            Err(Error::DecoderMemoryExceeded { limit: 1024, .. })
        ),
        "{result:?}"
    );
    assert!(is_empty(dest.path()));
}

#[test]
fn callback_false_stops_iteration_across_blocks() {
    let mut adapter = SevenZAdapter::open(fixture("basic.7z")).unwrap();
    let mut seen = 0;

    adapter
        .for_each(|_, _| {
            seen += 1;
            Ok(false)
        })
        .unwrap();

    assert_eq!(seen, 1);
}
