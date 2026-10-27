//! Names that refer to the same file on case-insensitive, normalizing or
//! Windows filesystems are treated consistently.

use safe_unzip::{Driver, Error, Extractor, ZipAdapter};
use std::io::{Cursor, Write};
use std::path::Path;
use tempfile::tempdir;
use zip::write::FileOptions;

fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options: FileOptions<()> = FileOptions::default();
    for (name, content) in entries {
        zip.start_file(*name, options).unwrap();
        zip.write_all(content).unwrap();
    }
    zip.finish().unwrap().into_inner()
}

fn files_under(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for entry in walk(dir) {
        out.push(
            entry
                .strip_prefix(dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/"),
        );
    }
    out.sort();
    out
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files.extend(walk(&path));
        } else {
            files.push(path);
        }
    }
    files
}

fn variant_zip() -> Vec<u8> {
    make_zip(&[
        ("src/main.rs", b"fn main() {}"),
        (".git/config", b"a"),
        (".GIT/hooks/post-checkout", b"b"),
        ("Build/Tool.EXE", b"c"),
        ("cafe\u{301}/notes.txt", b"d"),
        ("caf\u{e9}.TXT", b"e"),
        ("_.TXT", b"f"),
        ("q.DAT", b"g"),
    ])
}

const EXCLUDES: [&str; 6] = [
    "**/.git/**",
    "**/*.exe",
    "caf\u{e9}/**",
    "cafe*.txt",
    "[A-z].txt",
    "[A-Z].dat",
];

#[test]
fn extractor_exclude_matches_equivalent_names() {
    let dest = tempdir().unwrap();

    Extractor::new(dest.path())
        .unwrap()
        .exclude_glob(&EXCLUDES)
        .extract(Cursor::new(variant_zip()))
        .unwrap();

    assert_eq!(files_under(dest.path()), ["src/main.rs"]);
}

#[test]
fn driver_exclude_matches_equivalent_names() {
    let dest = tempdir().unwrap();

    Driver::new(dest.path())
        .unwrap()
        .exclude_glob(&EXCLUDES)
        .extract_zip(ZipAdapter::new(Cursor::new(variant_zip())).unwrap())
        .unwrap();

    assert_eq!(files_under(dest.path()), ["src/main.rs"]);
}

#[test]
fn expanded_case_fold_scalars_are_excluded_by_both_apis() {
    for (pattern, name) in [
        ("?.txt", "\u{df}.TXT"),
        ("[\u{df}].txt", "\u{df}.TXT"),
        ("?.txt", "I\u{307}.TXT"),
        ("[\u{130}].txt", "I\u{307}.TXT"),
        ("?.txt", "\u{fb03}.TXT"),
        ("[\u{fb03}].txt", "\u{fb03}.TXT"),
        ("?.txt", "\u{fb04}.TXT"),
        ("[\u{fb04}].txt", "\u{fb04}.TXT"),
    ] {
        let zip = make_zip(&[(name, b"x")]);

        let dest = tempdir().unwrap();
        Extractor::new(dest.path())
            .unwrap()
            .exclude_glob(&[pattern])
            .extract(Cursor::new(zip.clone()))
            .unwrap();
        assert!(
            files_under(dest.path()).is_empty(),
            "Extractor: {pattern} against {name}"
        );

        let dest = tempdir().unwrap();
        Driver::new(dest.path())
            .unwrap()
            .exclude_glob(&[pattern])
            .extract_zip(ZipAdapter::new(Cursor::new(zip)).unwrap())
            .unwrap();
        assert!(
            files_under(dest.path()).is_empty(),
            "Driver: {pattern} against {name}"
        );
    }
}

#[test]
fn large_brace_nonmatch_does_not_exclude_unrelated_files() {
    let pattern = format!("{}.txt", "{a,b}".repeat(13));
    let zip = make_zip(&[("unrelated.rs", b"x")]);

    let dest = tempdir().unwrap();
    Extractor::new(dest.path())
        .unwrap()
        .exclude_glob(&[&pattern])
        .extract(Cursor::new(zip.clone()))
        .unwrap();
    assert_eq!(files_under(dest.path()), ["unrelated.rs"]);

    let dest = tempdir().unwrap();
    Driver::new(dest.path())
        .unwrap()
        .exclude_glob(&[&pattern])
        .extract_zip(ZipAdapter::new(Cursor::new(zip)).unwrap())
        .unwrap();
    assert_eq!(files_under(dest.path()), ["unrelated.rs"]);
}

#[test]
fn normalization_across_braces_is_excluded_by_both_apis() {
    let pattern = "\u{3b1}{\u{345},x}\u{301}.txt";
    let zip = make_zip(&[("\u{3b1}\u{345}\u{301}.TXT", b"x")]);

    let dest = tempdir().unwrap();
    Extractor::new(dest.path())
        .unwrap()
        .exclude_glob(&[pattern])
        .extract(Cursor::new(zip.clone()))
        .unwrap();
    assert!(files_under(dest.path()).is_empty());

    let dest = tempdir().unwrap();
    Driver::new(dest.path())
        .unwrap()
        .exclude_glob(&[pattern])
        .extract_zip(ZipAdapter::new(Cursor::new(zip)).unwrap())
        .unwrap();
    assert!(files_under(dest.path()).is_empty());
}

#[test]
fn many_independent_name_variants_do_not_exclude_a_nonmatch() {
    let name = format!("{}.txt", "\u{1ead}".repeat(9));
    let zip = make_zip(&[(&name, b"x")]);

    let dest = tempdir().unwrap();
    Extractor::new(dest.path())
        .unwrap()
        .exclude_glob(&["*.exe"])
        .extract(Cursor::new(zip.clone()))
        .unwrap();
    assert_eq!(files_under(dest.path()), std::slice::from_ref(&name));

    let dest = tempdir().unwrap();
    Driver::new(dest.path())
        .unwrap()
        .exclude_glob(&["*.exe"])
        .extract_zip(ZipAdapter::new(Cursor::new(zip)).unwrap())
        .unwrap();
    assert_eq!(files_under(dest.path()), [name]);
}

#[test]
fn normalization_before_a_wildcard_is_excluded_by_both_apis() {
    let pattern = "\u{3b1}\u{345}*.txt";
    let zip = make_zip(&[("\u{3b1}\u{345}\u{301}.TXT", b"x")]);

    let dest = tempdir().unwrap();
    Extractor::new(dest.path())
        .unwrap()
        .exclude_glob(&[pattern])
        .extract(Cursor::new(zip.clone()))
        .unwrap();
    assert!(files_under(dest.path()).is_empty());

    let dest = tempdir().unwrap();
    Driver::new(dest.path())
        .unwrap()
        .exclude_glob(&[pattern])
        .extract_zip(ZipAdapter::new(Cursor::new(zip)).unwrap())
        .unwrap();
    assert!(files_under(dest.path()).is_empty());
}

#[test]
fn combining_mark_braces_do_not_exclude_a_nonmatch() {
    let pattern = format!("a{}.txt", "{\u{301},\u{300}}".repeat(20));
    let zip = make_zip(&[("unrelated.rs", b"x")]);

    let dest = tempdir().unwrap();
    Extractor::new(dest.path())
        .unwrap()
        .exclude_glob(&[&pattern])
        .extract(Cursor::new(zip.clone()))
        .unwrap();
    assert_eq!(files_under(dest.path()), ["unrelated.rs"]);

    let dest = tempdir().unwrap();
    Driver::new(dest.path())
        .unwrap()
        .exclude_glob(&[&pattern])
        .extract_zip(ZipAdapter::new(Cursor::new(zip)).unwrap())
        .unwrap();
    assert_eq!(files_under(dest.path()), ["unrelated.rs"]);
}

#[test]
fn interleaved_prefold_composition_is_excluded_by_both_apis() {
    let pattern = "[\u{130}]*.txt";
    let zip = make_zip(&[("I\u{327}\u{307}.TXT", b"x")]);

    let dest = tempdir().unwrap();
    Extractor::new(dest.path())
        .unwrap()
        .exclude_glob(&[pattern])
        .extract(Cursor::new(zip.clone()))
        .unwrap();
    assert!(files_under(dest.path()).is_empty());

    let dest = tempdir().unwrap();
    Driver::new(dest.path())
        .unwrap()
        .exclude_glob(&[pattern])
        .extract_zip(ZipAdapter::new(Cursor::new(zip)).unwrap())
        .unwrap();
    assert!(files_under(dest.path()).is_empty());
}

#[test]
fn duplicate_braces_do_not_exclude_a_nonmatch() {
    let pattern = format!("{{{}}}.txt", vec!["a"; 1_025].join(","));
    let zip = make_zip(&[("another.rs", b"x")]);

    let dest = tempdir().unwrap();
    Extractor::new(dest.path())
        .unwrap()
        .exclude_glob(&[&pattern])
        .extract(Cursor::new(zip.clone()))
        .unwrap();
    assert_eq!(files_under(dest.path()), ["another.rs"]);

    let dest = tempdir().unwrap();
    Driver::new(dest.path())
        .unwrap()
        .exclude_glob(&[&pattern])
        .extract_zip(ZipAdapter::new(Cursor::new(zip)).unwrap())
        .unwrap();
    assert_eq!(files_under(dest.path()), ["another.rs"]);
}

#[test]
fn include_and_only_stay_exact() {
    let zip = make_zip(&[("README.md", b"a"), ("readme.md", b"b")]);
    let dest = tempdir().unwrap();

    Extractor::new(dest.path())
        .unwrap()
        .only(&["README.md"])
        .extract(Cursor::new(zip))
        .unwrap();

    assert_eq!(std::fs::read(dest.path().join("README.md")).unwrap(), b"a");
}

#[test]
fn rejects_trailing_dot_and_space_components() {
    for name in [
        "notes.txt.",
        "notes.txt ",
        "dir./a.txt",
        "dir /a.txt",
        "CON /a.txt",
    ] {
        let zip = make_zip(&[(name, b"x")]);

        let dest = tempdir().unwrap();
        let result = Extractor::new(dest.path())
            .unwrap()
            .extract(Cursor::new(zip.clone()));
        assert!(
            matches!(result, Err(Error::InvalidFilename { .. })),
            "Extractor {name:?}: {result:?}"
        );

        let dest = tempdir().unwrap();
        let result = Driver::new(dest.path())
            .unwrap()
            .extract_zip(ZipAdapter::new(Cursor::new(zip)).unwrap());
        assert!(
            matches!(result, Err(Error::InvalidFilename { .. })),
            "Driver {name:?}: {result:?}"
        );
        assert!(std::fs::read_dir(dest.path()).unwrap().next().is_none());
    }
}

#[test]
fn ordinary_dotted_names_still_extract() {
    let zip = make_zip(&[(".hidden", b"a"), ("a.b.c.txt", b"b"), ("v1.2/notes", b"c")]);
    let dest = tempdir().unwrap();

    Extractor::new(dest.path())
        .unwrap()
        .extract(Cursor::new(zip))
        .unwrap();

    assert_eq!(
        files_under(dest.path()),
        [".hidden", "a.b.c.txt", "v1.2/notes"]
    );
}
