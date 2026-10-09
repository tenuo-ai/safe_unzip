//! Junk-paths mode (`unzip -j`): files land at the destination root.
//!
//! https://github.com/tenuo-ai/safe_unzip/issues/4

use safe_unzip::{
    Driver, Error, ExtractionMode, Extractor, Limits, OverwriteMode, OverwritePolicy,
    ValidationMode, ZipAdapter,
};
use std::io::{Cursor, Write};
use std::path::Path;
use tempfile::tempdir;
use zip::write::FileOptions;

/// Build a zip. Names ending in '/' become directory entries.
fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options: FileOptions<()> = FileOptions::default();
    for (name, content) in entries {
        if name.ends_with('/') {
            zip.add_directory(*name, options).unwrap();
        } else {
            zip.start_file(*name, options).unwrap();
            zip.write_all(content).unwrap();
        }
    }
    zip.finish().unwrap().into_inner()
}

/// Sorted names directly under `dir`.
fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn read(dir: &Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap()
}

fn nested_zip() -> Vec<u8> {
    make_zip(&[
        ("docs/", b""),
        ("docs/guide/", b""),
        ("docs/guide/intro.md", b"intro"),
        ("src/main.rs", b"fn main() {}"),
        ("README", b"readme"),
    ])
}

fn colliding_zip() -> Vec<u8> {
    make_zip(&[("a/x.txt", b"first"), ("b/x.txt", b"second")])
}

// ============================================================================
// Extractor
// ============================================================================

#[test]
fn extractor_flattens_without_creating_dirs() {
    let dest = tempdir().unwrap();

    let report = Extractor::new(dest.path())
        .unwrap()
        .junk_paths(true)
        .extract(Cursor::new(nested_zip()))
        .unwrap();

    assert_eq!(listing(dest.path()), ["README", "intro.md", "main.rs"]);
    assert_eq!(read(dest.path(), "intro.md"), b"intro");
    assert_eq!(report.files_extracted, 3);
    assert_eq!(report.dirs_created, 0);
}

#[test]
fn extractor_off_by_default() {
    let dest = tempdir().unwrap();

    Extractor::new(dest.path())
        .unwrap()
        .extract(Cursor::new(nested_zip()))
        .unwrap();

    assert_eq!(listing(dest.path()), ["README", "docs", "src"]);
}

#[test]
fn extractor_collision_names_both_entries() {
    let dest = tempdir().unwrap();

    let result = Extractor::new(dest.path())
        .unwrap()
        .junk_paths(true)
        .extract(Cursor::new(colliding_zip()));

    match result {
        Err(Error::PathCollision {
            entry,
            previous,
            path,
        }) => {
            assert_eq!(entry, "b/x.txt");
            assert_eq!(previous, "a/x.txt");
            assert_eq!(path, "x.txt");
        }
        other => panic!("expected PathCollision, got {other:?}"),
    }
}

#[test]
fn extractor_validate_first_collision_writes_nothing() {
    let dest = tempdir().unwrap();

    let result = Extractor::new(dest.path())
        .unwrap()
        .junk_paths(true)
        .mode(ExtractionMode::ValidateFirst)
        .extract(Cursor::new(colliding_zip()));

    assert!(
        matches!(result, Err(Error::PathCollision { .. })),
        "{result:?}"
    );
    assert!(listing(dest.path()).is_empty());
}

#[test]
fn extractor_skip_keeps_first_overwrite_keeps_last() {
    let dest = tempdir().unwrap();
    let report = Extractor::new(dest.path())
        .unwrap()
        .junk_paths(true)
        .overwrite(OverwritePolicy::Skip)
        .extract(Cursor::new(colliding_zip()))
        .unwrap();
    assert_eq!(read(dest.path(), "x.txt"), b"first");
    assert_eq!(report.entries_skipped, 1);

    let dest = tempdir().unwrap();
    Extractor::new(dest.path())
        .unwrap()
        .junk_paths(true)
        .overwrite(OverwritePolicy::Overwrite)
        .extract(Cursor::new(colliding_zip()))
        .unwrap();
    assert_eq!(read(dest.path(), "x.txt"), b"second");
}

#[test]
fn extractor_still_rejects_traversal() {
    // The base name "evil.txt" is harmless; the full path is not.
    let zip = make_zip(&[("../evil.txt", b"evil")]);
    let dest = tempdir().unwrap();

    let result = Extractor::new(dest.path())
        .unwrap()
        .junk_paths(true)
        .extract(Cursor::new(zip));

    assert!(
        matches!(result, Err(Error::PathEscape { .. })),
        "{result:?}"
    );
    assert!(listing(dest.path()).is_empty());
}

#[test]
fn extractor_filter_sees_full_path() {
    // b/x.txt is filtered out, so it can't collide with a/x.txt.
    for mode in [ExtractionMode::Streaming, ExtractionMode::ValidateFirst] {
        let dest = tempdir().unwrap();

        Extractor::new(dest.path())
            .unwrap()
            .junk_paths(true)
            .mode(mode)
            .include_glob(&["a/**"])
            .extract(Cursor::new(colliding_zip()))
            .unwrap();

        assert_eq!(listing(dest.path()), ["x.txt"], "{mode:?}");
        assert_eq!(read(dest.path(), "x.txt"), b"first");
    }
}

#[test]
fn extractor_depth_limit_uses_full_path() {
    let zip = make_zip(&[("a/b/c/d.txt", b"deep")]);
    let dest = tempdir().unwrap();

    let result = Extractor::new(dest.path())
        .unwrap()
        .junk_paths(true)
        .limits(Limits {
            max_path_depth: 2,
            ..Default::default()
        })
        .extract(Cursor::new(zip));

    assert!(
        matches!(result, Err(Error::PathTooDeep { .. })),
        "{result:?}"
    );
}

// ============================================================================
// Driver
// ============================================================================

#[test]
fn driver_zip_flattens() {
    let dest = tempdir().unwrap();

    let report = Driver::new(dest.path())
        .unwrap()
        .junk_paths(true)
        .extract_zip(ZipAdapter::new(Cursor::new(nested_zip())).unwrap())
        .unwrap();

    assert_eq!(listing(dest.path()), ["README", "intro.md", "main.rs"]);
    assert_eq!(report.dirs_created, 0);
}

#[test]
fn driver_zip_collisions() {
    for validation in [ValidationMode::Streaming, ValidationMode::ValidateFirst] {
        let dest = tempdir().unwrap();

        let result = Driver::new(dest.path())
            .unwrap()
            .junk_paths(true)
            .validation(validation)
            .extract_zip(ZipAdapter::new(Cursor::new(colliding_zip())).unwrap());

        assert!(
            matches!(result, Err(Error::PathCollision { .. })),
            "{validation:?}: {result:?}"
        );
        if validation == ValidationMode::ValidateFirst {
            assert!(listing(dest.path()).is_empty());
        }
    }

    let dest = tempdir().unwrap();
    Driver::new(dest.path())
        .unwrap()
        .junk_paths(true)
        .overwrite(OverwriteMode::Overwrite)
        .extract_zip(ZipAdapter::new(Cursor::new(colliding_zip())).unwrap())
        .unwrap();
    assert_eq!(read(dest.path(), "x.txt"), b"second");
}

#[cfg(feature = "tar")]
#[test]
fn driver_tar_flattens() {
    let mut builder = tar::Builder::new(Vec::new());
    for (name, content) in [("pkg/lib/a.txt", &b"a"[..]), ("pkg/b.txt", &b"b"[..])] {
        let mut header = tar::Header::new_gnu();
        header.set_path(name).unwrap();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append(&header, content).unwrap();
    }
    let tar = builder.into_inner().unwrap();

    for validation in [ValidationMode::Streaming, ValidationMode::ValidateFirst] {
        let dest = tempdir().unwrap();
        Driver::new(dest.path())
            .unwrap()
            .junk_paths(true)
            .validation(validation)
            .extract_tar(safe_unzip::TarAdapter::new(Cursor::new(tar.clone())))
            .unwrap();
        assert_eq!(listing(dest.path()), ["a.txt", "b.txt"], "{validation:?}");
    }
}

#[cfg(feature = "sevenz")]
#[test]
fn driver_7z_flattens() {
    // basic.7z: a.txt, dir/, dir/b.txt
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/7z/basic.7z");

    for validation in [ValidationMode::Streaming, ValidationMode::ValidateFirst] {
        let dest = tempdir().unwrap();
        Driver::new(dest.path())
            .unwrap()
            .junk_paths(true)
            .validation(validation)
            .extract_7z_file(&fixture)
            .unwrap();
        assert_eq!(listing(dest.path()), ["a.txt", "b.txt"], "{validation:?}");
    }
}

#[cfg(feature = "async")]
#[tokio::test]
async fn async_extractor_flattens() {
    let dest = tempdir().unwrap();

    safe_unzip::r#async::AsyncExtractor::new(dest.path())
        .unwrap()
        .junk_paths(true)
        .extract_bytes(nested_zip())
        .await
        .unwrap();

    assert_eq!(listing(dest.path()), ["README", "intro.md", "main.rs"]);
}
