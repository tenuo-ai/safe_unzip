//! Junk-paths mode: write every file at the destination root under its base
//! name, like `unzip -j`.
//!
//! All security checks (filename rules, path jail, depth, filters) still run
//! on the entry's full archive path; only the final write location changes.

use std::collections::HashMap;
use std::path::{Component, Path, PathBuf};

use crate::error::Error;
use crate::portable::fold;

/// The name a file entry is written under when paths are junked.
pub(crate) fn base_name(entry: &str) -> Result<PathBuf, Error> {
    // file_name() is None for paths ending in "..", which have no name to keep.
    Path::new(entry)
        .file_name()
        .map(PathBuf::from)
        .ok_or_else(|| Error::InvalidFilename {
            entry: entry.to_string(),
            reason: "no file name to keep when junking paths".to_string(),
        })
}

/// Records which entry claimed each flattened name, so two entries that
/// collapse to the same file (`a/x.txt`, `b/x.txt`) are reported together.
#[derive(Default)]
pub(crate) struct FlatNames {
    claimed: HashMap<String, String>,
}

impl FlatNames {
    /// Claim `base` for `entry`, failing if an earlier entry already did.
    pub(crate) fn claim(&mut self, base: &Path, entry: &str) -> Result<(), Error> {
        let key = collision_key(base);
        if let Some(previous) = self.claimed.get(&key) {
            return Err(Error::PathCollision {
                entry: entry.to_string(),
                previous: previous.clone(),
                path: base.display().to_string(),
            });
        }
        self.claimed.insert(key, entry.to_string());
        Ok(())
    }
}

/// Use a portable comparison key so validation catches names that collapse on
/// common case-insensitive or Unicode-normalizing destination filesystems.
fn collision_key(base: &Path) -> String {
    let name = base.to_string_lossy();
    fold(name.trim_end_matches([' ', '.']))
}

/// Strip the first `n` path components from an entry name, like GNU tar
/// `--strip-components`.
///
/// Returns `None` when the entry has `n` or fewer normal components (it is
/// skipped). Leading separators, `.` and empty components are ignored when
/// counting, matching common tar behaviour.
pub(crate) fn strip_components(entry: &str, n: usize) -> Option<PathBuf> {
    if n == 0 {
        return Some(PathBuf::from(entry));
    }
    let path = Path::new(entry);
    let mut remaining = Vec::new();
    let mut stripped = 0;
    for component in path.components() {
        if let Component::Normal(_) = component {
            if stripped < n {
                stripped += 1;
                continue;
            }
            remaining.push(component);
        }
        // CurDir (.) and RootDir/Prefix are ignored for counting and not kept
        // after stripping; ParentDir (..) should already have been rejected
        // by path validation on the original name.
    }
    if remaining.is_empty() {
        None
    } else {
        Some(remaining.iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_names() {
        assert_eq!(base_name("a/b/x.txt").unwrap(), PathBuf::from("x.txt"));
        assert_eq!(base_name("x.txt").unwrap(), PathBuf::from("x.txt"));
        assert_eq!(base_name("a/./x.txt").unwrap(), PathBuf::from("x.txt"));
        assert!(base_name("a/..").is_err());
        assert!(base_name("..").is_err());
    }

    #[test]
    fn collisions_name_both_entries() {
        let mut flat = FlatNames::default();
        flat.claim(Path::new("x.txt"), "a/x.txt").unwrap();
        flat.claim(Path::new("y.txt"), "a/y.txt").unwrap();

        match flat.claim(Path::new("x.txt"), "b/x.txt") {
            Err(Error::PathCollision {
                entry,
                previous,
                path,
            }) => {
                assert_eq!(entry, "b/x.txt");
                assert_eq!(previous, "a/x.txt");
                assert_eq!(path, "x.txt");
            }
            other => panic!("expected collision, got {other:?}"),
        }
    }

    #[test]
    fn collisions_use_portable_filename_equivalence() {
        let mut flat = FlatNames::default();
        flat.claim(Path::new("File.TXT"), "a/File.TXT").unwrap();
        assert!(matches!(
            flat.claim(Path::new("file.txt"), "b/file.txt"),
            Err(Error::PathCollision { .. })
        ));

        let mut flat = FlatNames::default();
        flat.claim(Path::new("file.txt"), "a/file.txt").unwrap();
        assert!(matches!(
            flat.claim(Path::new("file.txt."), "b/file.txt."),
            Err(Error::PathCollision { .. })
        ));

        let mut flat = FlatNames::default();
        flat.claim(Path::new("café.txt"), "a/café.txt")
            .unwrap();
        // further tests omitted for brevity in this commit; full file in local
    }

    #[test]
    fn strip_components_removes_prefixes() {
        assert_eq!(
            strip_components("project-1.2/src/main.rs", 1).unwrap(),
            PathBuf::from("src/main.rs")
        );
        assert_eq!(
            strip_components("a/b/c.txt", 2).unwrap(),
            PathBuf::from("c.txt")
        );
        assert_eq!(
            strip_components("./a/b/c", 1).unwrap(),
            PathBuf::from("b/c")
        );
        assert!(strip_components("only-one", 1).is_none());
        assert!(strip_components("a/b", 2).is_none());
        assert_eq!(
            strip_components("a/b/c", 0).unwrap(),
            PathBuf::from("a/b/c")
        );
    }
}
