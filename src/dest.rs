//! Filesystem writes beneath the extraction destination.
//!
//! Every directory, file and cleanup operation goes through [`Destination`],
//! with paths relative to the destination root. On Linux 5.6+ (x86_64 and
//! aarch64) the destination directory is opened once and each operation is
//! resolved beneath that handle with `openat2(RESOLVE_BENEATH)`, via
//! `path_jail::guard::FdJail`. Elsewhere (macOS, BSD, Windows, older Linux
//! kernels) operations use ordinary paths under the destination.

use std::fs::{self, File};
use std::io;
use std::path::{Component, Path, PathBuf};

use crate::error::Error;

/// What to do when the file being created already exists.
#[derive(Debug, Clone, Copy)]
pub(crate) enum IfExists {
    /// Fail with [`Error::AlreadyExists`].
    Error,
    /// Leave the existing file and skip the entry.
    Skip,
    /// Remove the existing entry (file or symlink, never followed) and
    /// create a new file in its place.
    Replace,
}

/// The extraction destination.
pub(crate) struct Destination {
    root: PathBuf,
    backend: Backend,
}

enum Backend {
    Plain(path_jail::Jail),
    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    Guarded(path_jail::guard::FdJail),
}

impl Destination {
    /// Open the destination. Uses the handle-relative backend when the
    /// platform and kernel support it, and plain paths otherwise.
    pub(crate) fn new(root: &Path) -> Result<Self, Error> {
        #[cfg(all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        ))]
        match path_jail::guard::FdJail::new(root) {
            Ok(jail) => {
                return Ok(Self {
                    root: root.to_path_buf(),
                    backend: Backend::Guarded(jail),
                });
            }
            Err(path_jail::JailError::UnsupportedKernel { .. }) => {}
            Err(e) => return Err(Error::Jail(e)),
        }

        Ok(Self {
            root: root.to_path_buf(),
            backend: Backend::Plain(path_jail::Jail::new(root)?),
        })
    }

    /// Absolute path of `rel`, for error messages.
    pub(crate) fn display_path(&self, rel: &Path) -> String {
        self.root.join(rel).display().to_string()
    }

    /// Create `rel` and any missing parent directories.
    pub(crate) fn create_dir_all(&self, rel: &Path) -> Result<(), Error> {
        match &self.backend {
            Backend::Plain(jail) => Ok(fs::create_dir_all(jail.join(rel)?)?),
            #[cfg(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            Backend::Guarded(jail) => jail
                .create_dir_all(rel)
                .map_err(|e| self.jail_error(rel, e)),
        }
    }

    /// Create the file `rel` for writing. Its parent must already exist.
    ///
    /// Returns `Ok(None)` when the file exists and `if_exists` is `Skip`.
    pub(crate) fn create_file(
        &self,
        rel: &Path,
        if_exists: IfExists,
    ) -> Result<Option<File>, Error> {
        if matches!(if_exists, IfExists::Replace) {
            match self.remove_file(rel) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(Error::Io(e)),
            }
        }

        match self.create_new(rel) {
            Ok(file) => Ok(Some(file)),
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::AlreadyExists => match if_exists {
                IfExists::Skip => Ok(None),
                IfExists::Error | IfExists::Replace => Err(Error::AlreadyExists {
                    entry: self.display_path(rel),
                }),
            },
            Err(e) => Err(e),
        }
    }

    /// Remove the file or symlink `rel` (never follows a final symlink).
    pub(crate) fn remove_file(&self, rel: &Path) -> io::Result<()> {
        match &self.backend {
            Backend::Plain(jail) => {
                let path = plain_leaf_path(jail, rel)?;
                // Only remove non-directories, like unlink(2).
                match fs::symlink_metadata(&path) {
                    Ok(m) if m.is_dir() => Err(io::Error::new(
                        io::ErrorKind::IsADirectory,
                        format!("'{}' is a directory", path.display()),
                    )),
                    Ok(_) => fs::remove_file(&path),
                    Err(e) => Err(e),
                }
            }
            #[cfg(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            Backend::Guarded(jail) => jail.remove_file(rel).map_err(|e| match e {
                path_jail::JailError::Io(e) => e,
                other => io::Error::other(other.to_string()),
            }),
        }
    }

    /// Exclusively create `rel` (fails if anything exists there, including a
    /// symlink).
    fn create_new(&self, rel: &Path) -> Result<File, Error> {
        match &self.backend {
            Backend::Plain(jail) => Ok(fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(plain_leaf_path(jail, rel)?)?),
            #[cfg(all(
                target_os = "linux",
                any(target_arch = "x86_64", target_arch = "aarch64")
            ))]
            Backend::Guarded(jail) => jail
                .create(rel)
                .map(|f| f.into_file())
                .map_err(|e| self.jail_error(rel, e)),
        }
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    fn jail_error(&self, rel: &Path, e: path_jail::JailError) -> Error {
        match e {
            path_jail::JailError::Io(e) => Error::Io(e),
            path_jail::JailError::Escape { .. } | path_jail::JailError::SymlinkRejected { .. } => {
                Error::PathEscape {
                    entry: rel.display().to_string(),
                    detail: e.to_string(),
                }
            }
            other => Error::Jail(other),
        }
    }
}

/// Resolve a file's parent through the path jail, but keep the final name
/// unresolved so callers can safely replace a symlink rather than its target.
fn plain_leaf_path(jail: &path_jail::Jail, rel: &Path) -> io::Result<PathBuf> {
    let parent = rel.parent().unwrap_or_else(|| Path::new(""));
    let parent = jail.join(parent).map_err(io::Error::other)?;
    let name = rel.file_name().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no final component")
    })?;
    Ok(parent.join(name))
}

/// An archive entry name as a path relative to the destination.
///
/// `.` components are dropped and `..` removes the previous component, so the
/// result has only normal components. Callers have already confirmed with
/// the path jail that the name stays inside the destination.
pub(crate) fn relative(name: &str) -> PathBuf {
    let mut rel = PathBuf::new();
    for component in Path::new(name).components() {
        match component {
            Component::Normal(part) => rel.push(part),
            Component::ParentDir => {
                rel.pop();
            }
            Component::CurDir | Component::RootDir | Component::Prefix(_) => {}
        }
    }
    rel
}

/// Set permission bits on an open file, keeping only rwx for user, group and
/// other (no setuid, setgid or sticky).
#[cfg(unix)]
pub(crate) fn set_mode(file: &File, mode: u32) -> Result<(), Error> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(mode & 0o0777))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_paths() {
        assert_eq!(relative("a/b/c.txt"), PathBuf::from("a/b/c.txt"));
        assert_eq!(relative("./a//b/./c.txt"), PathBuf::from("a/b/c.txt"));
        assert_eq!(relative("a/../b.txt"), PathBuf::from("b.txt"));
        assert_eq!(relative("dir/"), PathBuf::from("dir"));
    }

    #[test]
    fn create_and_replace() {
        let tmp = tempfile::tempdir().unwrap();
        let dest = Destination::new(tmp.path()).unwrap();

        dest.create_dir_all(Path::new("a/b")).unwrap();
        dest.create_dir_all(Path::new("a/b")).unwrap(); // idempotent
        assert!(tmp.path().join("a/b").is_dir());

        let rel = Path::new("a/b/f.txt");
        assert!(dest.create_file(rel, IfExists::Error).unwrap().is_some());
        assert!(matches!(
            dest.create_file(rel, IfExists::Error),
            Err(Error::AlreadyExists { .. })
        ));
        assert!(dest.create_file(rel, IfExists::Skip).unwrap().is_none());
        assert!(dest.create_file(rel, IfExists::Replace).unwrap().is_some());

        dest.remove_file(rel).unwrap();
        assert!(!tmp.path().join(rel).exists());
        assert!(dest.remove_file(Path::new("a")).is_err()); // directory
    }

    #[test]
    fn create_dir_all_rejects_existing_file() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("occupied"), b"not a directory").unwrap();
        let dest = Destination::new(tmp.path()).unwrap();

        assert!(dest.create_dir_all(Path::new("occupied/child")).is_err());
        assert!(!tmp.path().join("occupied/child").exists());
    }

    #[cfg(unix)]
    #[test]
    fn plain_backend_revalidates_normalized_parent() {
        use std::os::unix::fs::symlink;

        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        fs::create_dir_all(tmp.path().join("safe/deeper")).unwrap();
        fs::create_dir_all(tmp.path().join("safe/pivot")).unwrap();
        symlink("safe/deeper", tmp.path().join("a")).unwrap();
        symlink(outside.path(), tmp.path().join("pivot")).unwrap();

        // The original spelling resolves to safe/pivot, but lexical
        // normalization produces pivot, which points outside the jail.
        let jail = path_jail::Jail::new(tmp.path()).unwrap();
        assert!(jail.join("a/../pivot/payload.txt").is_ok());
        let dest = Destination {
            root: tmp.path().to_path_buf(),
            backend: Backend::Plain(jail),
        };
        let rel = relative("a/../pivot/payload.txt");
        assert!(dest.create_file(&rel, IfExists::Error).is_err());
        assert!(!outside.path().join("payload.txt").exists());
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn guarded_existing_directory_check_is_nonblocking_and_nonmutating() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        let jail = match path_jail::guard::FdJail::new(tmp.path()) {
            Ok(jail) => jail,
            Err(path_jail::JailError::UnsupportedKernel { .. }) => return,
            Err(e) => panic!("unexpected FdJail initialization error: {e}"),
        };
        let dest = Destination {
            root: tmp.path().to_path_buf(),
            backend: Backend::Guarded(jail),
        };

        // A FIFO must be rejected without waiting for a writer.
        let fifo = tmp.path().join("fifo");
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap();
        assert!(status.success());
        assert!(dest.create_dir_all(Path::new("fifo/child")).is_err());

        // Checking an existing directory needs search permission only: it must
        // not open the directory for reading or attempt a write probe.
        let read_only = tmp.path().join("read-only");
        fs::create_dir_all(read_only.join("writable")).unwrap();
        fs::set_permissions(&read_only, fs::Permissions::from_mode(0o111)).unwrap();
        let existing_result = dest.create_dir_all(Path::new("read-only"));
        let child_result = dest.create_dir_all(Path::new("read-only/writable/created"));
        fs::set_permissions(&read_only, fs::Permissions::from_mode(0o755)).unwrap();
        existing_result.unwrap();
        child_result.unwrap();
        assert!(read_only.join("writable/created").is_dir());
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn linux_selects_backend_from_runtime_support() {
        let tmp = tempfile::tempdir().unwrap();
        let supported = match path_jail::guard::FdJail::new(tmp.path()) {
            Ok(_) => true,
            Err(path_jail::JailError::UnsupportedKernel { .. }) => false,
            Err(e) => panic!("unexpected FdJail initialization error: {e}"),
        };
        let dest = Destination::new(tmp.path()).unwrap();
        assert_eq!(matches!(dest.backend, Backend::Guarded(_)), supported);
    }

    #[cfg(all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    ))]
    #[test]
    fn linux_writes_stay_beneath_destination() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let dest = Destination::new(tmp.path()).unwrap();
        if matches!(dest.backend, Backend::Plain(_)) {
            return;
        }
        std::os::unix::fs::symlink(outside.path(), tmp.path().join("sub")).unwrap();

        assert!(dest.create_dir_all(Path::new("sub/dir")).is_err());
        assert!(dest
            .create_file(Path::new("sub/f.txt"), IfExists::Error)
            .is_err());
        assert!(std::fs::read_dir(outside.path()).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn replace_removes_symlink_without_following() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("target.txt");
        fs::write(&target, b"keep").unwrap();
        std::os::unix::fs::symlink(&target, tmp.path().join("link")).unwrap();

        let dest = Destination::new(tmp.path()).unwrap();
        dest.create_file(Path::new("link"), IfExists::Replace)
            .unwrap()
            .unwrap();

        assert_eq!(fs::read(&target).unwrap(), b"keep");
        assert!(!tmp.path().join("link").is_symlink());
    }
}
