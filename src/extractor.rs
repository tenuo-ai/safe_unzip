use crate::error::Error;
use crate::limits::Limits;
use path_jail::Jail;
use std::fs;
use std::io::{Read, Seek};
use std::path::{Component, Path};

/// What to do when a file already exists at the extraction path.
///
/// # Security Note
///
/// The default (`Error`) is safest—it prevents accidental overwrites of sensitive files.
/// `Overwrite` includes symlink protection: if the target is a symlink, it's removed
/// before writing to prevent symlink-following attacks.
#[derive(Debug, Clone, Copy, Default)]
pub enum OverwritePolicy {
    /// Fail extraction if file exists. Safest default.
    #[default]
    Error,
    /// Skip files that already exist. Useful for resumable extraction.
    Skip,
    /// Overwrite existing files. Symlinks are removed before overwriting (security).
    Overwrite,
}

/// What to do with symlinks in the archive.
///
/// # Security Note
///
/// Symlinks in untrusted archives are dangerous. A malicious archive could:
/// - Create `uploads/evil -> /etc/passwd` then extract content to `uploads/evil`
/// - Create `..` symlinks to escape the destination directory
///
/// The default (`Skip`) silently ignores symlinks, which is safe but may surprise users.
/// Use `Error` if you want to explicitly reject archives containing symlinks.
#[derive(Debug, Clone, Copy, Default)]
pub enum SymlinkPolicy {
    /// Ignore symlinks silently. Safe default.
    #[default]
    Skip,
    /// Fail extraction if archive contains any symlinks.
    Error,
}

/// Extraction strategy.
///
/// # Tradeoffs
///
/// | Mode | Speed | On Failure | Use When |
/// |------|-------|------------|----------|
/// | `Streaming` | Fast (1 pass) | Partial files remain on disk | Speed matters; you'll clean up on error |
/// | `ValidateFirst` | Slower (2 passes) | No files written if validation fails | Can't tolerate partial state |
///
/// ## Important Limitations
///
/// **Neither mode is truly atomic.** If extraction fails mid-write (e.g., disk full),
/// partial files will remain regardless of mode. `ValidateFirst` only prevents writes
/// when *validation* fails (bad paths, exceeded limits, etc.), not when I/O fails.
///
/// For true atomicity, extract to a temp directory and move on success (planned for v0.2).
#[derive(Debug, Clone, Copy, Default)]
pub enum ExtractionMode {
    /// Extract entries as they are read. Fast but leaves partial state on failure.
    ///
    /// **Tradeoff:** If extraction fails on entry N, entries 1..N-1 remain on disk.
    /// Use this when speed matters and you can clean up on error.
    #[default]
    Streaming,

    /// Validate all entries first (paths, limits, policies), then extract.
    ///
    /// **Tradeoff:** 2x slower (iterates archive twice), but guarantees no files are
    /// written if validation fails. Still not atomic for I/O failures during extraction.
    ///
    /// Note: Filter callbacks are NOT applied during validation. Limits are checked
    /// against all entries, which is conservative—validation may reject archives that
    /// would succeed with filtering.
    ValidateFirst,
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub files_extracted: usize,
    pub dirs_created: usize,
    pub bytes_written: u64,
    pub entries_skipped: usize,
}

/// Report returned by `verify()`.
#[derive(Debug, Clone, Default)]
pub struct VerifyReport {
    /// Number of file entries that passed CRC verification.
    pub entries_verified: usize,
    /// Total bytes read (and CRC-verified).
    pub bytes_verified: u64,
}

pub struct EntryInfo<'a> {
    pub name: &'a str,
    pub size: u64,
    pub compressed_size: u64,
    pub is_dir: bool,
    pub is_symlink: bool,
}

/// Progress information passed to callbacks.
#[derive(Debug, Clone)]
pub struct Progress {
    /// Name of the current entry being processed.
    pub entry_name: String,
    /// Size of the current entry in bytes.
    pub entry_size: u64,
    /// Index of the current entry (0-based).
    pub entry_index: usize,
    /// Total number of entries in the archive.
    pub total_entries: usize,
    /// Bytes written so far (cumulative).
    pub bytes_written: u64,
    /// Files extracted so far.
    pub files_extracted: usize,
}

pub struct Extractor {
    root: std::path::PathBuf,
    jail: Jail,
    limits: Limits,
    overwrite: OverwritePolicy,
    symlinks: SymlinkPolicy,
    mode: ExtractionMode,
    // Using a boxed closure for the filter
    #[allow(clippy::type_complexity)]
    filter: Option<Box<dyn Fn(&EntryInfo) -> bool + Send + Sync>>,
    // Progress callback
    #[allow(clippy::type_complexity)]
    on_progress: Option<Box<dyn Fn(&Progress) + Send + Sync>>,
}

impl Extractor {
    /// Create an extractor for the given destination directory.
    ///
    /// # Errors
    ///
    /// Returns [`Error::DestinationNotFound`] if the destination doesn't exist.
    /// Use [`Self::new_or_create`] if you want to create the directory automatically.
    ///
    /// # Security Note
    ///
    /// Requiring the destination to exist catches typos like `/var/uplaods` that would
    /// otherwise silently create a wrong directory. This is intentional for the explicit API.
    pub fn new<P: AsRef<Path>>(destination: P) -> Result<Self, Error> {
        Self::new_impl(destination.as_ref(), false)
    }

    /// Create an extractor, creating the destination directory if it doesn't exist.
    ///
    /// This is a convenience method for cases where you want "just works" behavior.
    /// The directory is created with default permissions (respecting umask).
    ///
    /// # Security Note
    ///
    /// Be careful with user-provided paths. A typo like `/var/uplaods` will silently
    /// create a new directory instead of failing. Consider using [`Self::new`] and
    /// handling [`Error::DestinationNotFound`] explicitly for user-facing code.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use safe_unzip::Extractor;
    ///
    /// // Creates /tmp/extracted if it doesn't exist
    /// let extractor = Extractor::new_or_create("/tmp/extracted")?;
    /// # Ok::<(), safe_unzip::Error>(())
    /// ```
    pub fn new_or_create<P: AsRef<Path>>(destination: P) -> Result<Self, Error> {
        Self::new_impl(destination.as_ref(), true)
    }

    fn new_impl(destination: &Path, create: bool) -> Result<Self, Error> {
        if !destination.exists() {
            if create {
                fs::create_dir_all(destination)?;
            } else {
                return Err(Error::DestinationNotFound {
                    path: destination.to_string_lossy().to_string(),
                });
            }
        }

        let jail = Jail::new(destination)?;
        Ok(Self {
            root: destination.to_path_buf(),
            jail,
            limits: Limits::default(),
            overwrite: OverwritePolicy::default(),
            symlinks: SymlinkPolicy::default(),
            mode: ExtractionMode::default(),
            filter: None,
            on_progress: None,
        })
    }

    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn overwrite(mut self, policy: OverwritePolicy) -> Self {
        self.overwrite = policy;
        self
    }

    pub fn symlinks(mut self, policy: SymlinkPolicy) -> Self {
        self.symlinks = policy;
        self
    }

    pub fn mode(mut self, mode: ExtractionMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn filter<F>(mut self, f: F) -> Self
    where
        F: Fn(&EntryInfo) -> bool + Send + Sync + 'static,
    {
        self.filter = Some(Box::new(f));
        self
    }

    /// Extract only specific files by exact name.
    ///
    /// This is useful for extracting a known subset of files from an archive.
    /// Names are matched exactly (case-sensitive).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use safe_unzip::Extractor;
    ///
    /// // Extract only README and LICENSE
    /// let report = Extractor::new("/tmp/out")?
    ///     .only(&["README.md", "LICENSE"])
    ///     .extract_file("archive.zip")?;
    /// # Ok::<(), safe_unzip::Error>(())
    /// ```
    pub fn only<S: AsRef<str>>(self, names: &[S]) -> Self {
        let names: Vec<String> = names.iter().map(|s| s.as_ref().to_string()).collect();
        self.filter(move |entry| names.iter().any(|n| n == entry.name))
    }

    /// Include only files matching a glob pattern.
    ///
    /// Patterns use standard glob syntax: `*` matches any characters except `/`,
    /// `**` matches any characters including `/`, `?` matches a single character.
    ///
    /// Multiple patterns can be specified; a file is included if it matches ANY pattern.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use safe_unzip::Extractor;
    ///
    /// // Extract only Rust source files
    /// let report = Extractor::new("/tmp/out")?
    ///     .include_glob(&["**/*.rs"])
    ///     .extract_file("code.zip")?;
    ///
    /// // Multiple patterns: images or docs
    /// let report = Extractor::new("/tmp/out")?
    ///     .include_glob(&["**/*.jpg", "**/*.png", "docs/**"])
    ///     .extract_file("archive.zip")?;
    /// # Ok::<(), safe_unzip::Error>(())
    /// ```
    pub fn include_glob<S: AsRef<str>>(self, patterns: &[S]) -> Self {
        let patterns: Vec<String> = patterns.iter().map(|s| s.as_ref().to_string()).collect();
        self.filter(move |entry| {
            patterns
                .iter()
                .any(|p| glob_match::glob_match(p, entry.name))
        })
    }

    /// Exclude files matching a glob pattern.
    ///
    /// Patterns use standard glob syntax. A file is extracted only if it does NOT
    /// match ANY of the exclude patterns.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use safe_unzip::Extractor;
    ///
    /// // Extract everything except tests
    /// let report = Extractor::new("/tmp/out")?
    ///     .exclude_glob(&["**/test_*", "**/tests/**"])
    ///     .extract_file("code.zip")?;
    /// # Ok::<(), safe_unzip::Error>(())
    /// ```
    pub fn exclude_glob<S: AsRef<str>>(self, patterns: &[S]) -> Self {
        let patterns: Vec<String> = patterns.iter().map(|s| s.as_ref().to_string()).collect();
        self.filter(move |entry| {
            !patterns
                .iter()
                .any(|p| glob_match::glob_match(p, entry.name))
        })
    }

    /// Set a progress callback.
    ///
    /// The callback is called before processing each entry, allowing you to
    /// display progress bars, log extraction progress, or implement cancellation.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use safe_unzip::Extractor;
    ///
    /// let report = Extractor::new("/tmp/out")?
    ///     .on_progress(|p| {
    ///         println!("[{}/{}] {} ({} bytes)",
    ///             p.entry_index + 1,
    ///             p.total_entries,
    ///             p.entry_name,
    ///             p.entry_size
    ///         );
    ///     })
    ///     .extract_file("archive.zip")?;
    /// # Ok::<(), safe_unzip::Error>(())
    /// ```
    pub fn on_progress<F>(mut self, callback: F) -> Self
    where
        F: Fn(&Progress) + Send + Sync + 'static,
    {
        self.on_progress = Some(Box::new(callback));
        self
    }

    pub fn extract<R: Read + Seek>(&self, reader: R) -> Result<Report, Error> {
        let mut archive = zip::ZipArchive::new(reader)?;

        // If ValidateFirst mode, do a dry run first
        if matches!(self.mode, ExtractionMode::ValidateFirst) {
            self.validate_all(&mut archive)?;
        }

        let mut report = Report::default();
        let mut total_bytes_written: u64 = 0;
        let total_entries = archive.len();

        for i in 0..total_entries {
            let mut entry = archive.by_index(i)?;
            let name = entry.name().to_string();

            // Call progress callback if set
            if let Some(ref callback) = self.on_progress {
                callback(&Progress {
                    entry_name: name.clone(),
                    entry_size: entry.size(),
                    entry_index: i,
                    total_entries,
                    bytes_written: total_bytes_written,
                    files_extracted: report.files_extracted,
                });
            }

            // 0. SECURITY: Filename Sanitization
            if let Err(reason) = self.validate_filename(&name) {
                return Err(Error::InvalidFilename {
                    entry: name,
                    reason: reason.to_string(),
                });
            }

            // 1. SECURITY: Path Validation (Path Jail)
            // We check this FIRST to ensure the path is safe (doesn't escape root).
            // NOTE: We discard the returned path because Jail might resolve symlinks (e.g. on overwrite),
            // which causes us to overwrite the target instead of the symlink.
            // We construct the path manually relative to root, which is safe because Jail verified it.
            let _ = self.jail.join(&name).map_err(|e| Error::PathEscape {
                entry: name.clone(),
                detail: e.to_string(),
            })?;

            // Construct safe_path manually to preserve symlinks in the path
            let safe_path = self.root.join(&name);

            // 2. CHECK: Symlinks
            if entry.is_symlink() {
                match self.symlinks {
                    SymlinkPolicy::Error => {
                        return Err(Error::SymlinkNotAllowed {
                            entry: name,
                            target: String::new(), // ZIP symlink targets require reading content
                        });
                    }
                    SymlinkPolicy::Skip => {
                        report.entries_skipped += 1;
                        continue;
                    }
                }
            }

            // 3. CHECK: Limits (Depth)
            // Count normal components to check depth
            let depth = Path::new(&name)
                .components()
                .filter(|c| matches!(c, Component::Normal(_)))
                .count();
            if depth > self.limits.max_path_depth {
                return Err(Error::PathTooDeep {
                    entry: name,
                    depth,
                    limit: self.limits.max_path_depth,
                });
            }

            // 4. CHECK: Filter (User Logic)
            let info = EntryInfo {
                name: &name,
                size: entry.size(),
                compressed_size: entry.compressed_size(),
                is_dir: entry.is_dir(),
                is_symlink: entry.is_symlink(),
            };

            if let Some(ref filter) = self.filter {
                if !filter(&info) {
                    report.entries_skipped += 1;
                    continue;
                }
            }

            // 5. CHECK: Limits (Count & Lookahead Total)
            // Check file count
            if report.files_extracted >= self.limits.max_file_count {
                return Err(Error::FileCountExceeded {
                    limit: self.limits.max_file_count,
                    attempted: report.files_extracted + 1,
                });
            }

            // Check single file size (declared)
            if !entry.is_dir() && entry.size() > self.limits.max_single_file {
                return Err(Error::FileTooLarge {
                    entry: name,
                    limit: self.limits.max_single_file,
                    size: entry.size(),
                });
            }

            // Check total size (Lookahead declared)
            // Note: We ALSO check this during streaming to prevent zip bombs that lie about size
            if total_bytes_written + entry.size() > self.limits.max_total_bytes {
                return Err(Error::TotalSizeExceeded {
                    limit: self.limits.max_total_bytes,
                    would_be: total_bytes_written + entry.size(),
                });
            }

            // 7. EXECUTION
            if entry.is_dir() {
                fs::create_dir_all(&safe_path)?;
                report.dirs_created += 1;
            } else {
                if let Some(parent) = safe_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                // SECURITY: Atomic file creation based on overwrite policy
                // Using create_new(true) eliminates TOCTOU race conditions
                let outfile = match self.overwrite {
                    OverwritePolicy::Error => {
                        // create_new(true) is atomic: fails if file exists (no TOCTOU)
                        match fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&safe_path)
                        {
                            Ok(f) => f,
                            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                                return Err(Error::AlreadyExists {
                                    entry: safe_path.display().to_string(),
                                });
                            }
                            Err(e) => return Err(Error::Io(e)),
                        }
                    }
                    OverwritePolicy::Skip => {
                        // Try atomic create, skip on exists
                        match fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&safe_path)
                        {
                            Ok(f) => f,
                            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                                report.entries_skipped += 1;
                                continue;
                            }
                            Err(e) => return Err(Error::Io(e)),
                        }
                    }
                    OverwritePolicy::Overwrite => {
                        // SECURITY: Remove any existing symlink first to prevent following
                        if let Ok(m) = fs::symlink_metadata(&safe_path) {
                            if m.file_type().is_symlink() {
                                let _ = fs::remove_file(&safe_path);
                            }
                        }
                        // Now create/truncate
                        fs::File::create(&safe_path)?
                    }
                };

                // SECURITY: LimitReader
                // Enforce:
                // 1. entry.size() (Declared size) - catch bombs that lie
                // 2. limits.max_single_file - catch bombs exceeding limit
                // 3. limits.max_total_bytes - catch global limit violation

                let limit_single = self.limits.max_single_file.min(entry.size());
                let remaining_global = self
                    .limits
                    .max_total_bytes
                    .saturating_sub(total_bytes_written);
                let hard_limit = limit_single.min(remaining_global);

                let mut limiter = LimitReader::new(&mut entry, hard_limit);
                let mut outfile = outfile;

                // We use io::copy, which loops until EOF or error.
                // LimitReader returns EOF at limit.
                // BUT we need to distinguish EOF at limit vs natural EOF.
                // If EOF at limit AND entry has more data -> Error.

                let written = std::io::copy(&mut limiter, &mut outfile)?;

                // Check if we hit the limit strictly
                if limiter.hit_limit {
                    // If we hit the limit, we must check if there was MORE data expected.
                    // If declared size > written, we stopped early -> OK?
                    // No, if we stopped because of max_single_file, it's an error if the file was larger.
                    // If we stopped because of max_total_bytes, it's an error.
                    // If we stopped because of entry.size(), it's fine (just consumed declared).

                    // Actually, if we hit the hard_limit, we should check WHY.
                    if written >= self.limits.max_single_file
                        && entry.size() > self.limits.max_single_file
                    {
                        return Err(Error::FileTooLarge {
                            entry: name,
                            limit: self.limits.max_single_file,
                            size: written + 1, // At least this much
                        });
                    }

                    if remaining_global <= written && written < entry.size() {
                        return Err(Error::TotalSizeExceeded {
                            limit: self.limits.max_total_bytes,
                            would_be: total_bytes_written + written + 1,
                        });
                    }

                    // Specific check: if written == entry.size(), we are good.
                    // If written < entry.size() but we hit limit, it means limit < entry.size().
                    // Which implies one of the above errors triggered.
                }

                // SECURITY: Detect zip bombs that lie about declared size.
                // If we wrote exactly the declared size, check if there's more data.
                // If so, the file is larger than declared (potential zip bomb).
                if written == entry.size() {
                    let mut buf = [0u8; 1];
                    if entry.read(&mut buf)? > 0 {
                        return Err(Error::SizeMismatch {
                            entry: name.clone(),
                            declared: entry.size(),
                            actual: entry.size() + 1, // At least this much more
                        });
                    }
                }

                total_bytes_written += written;
                report.bytes_written += written;
                report.files_extracted += 1;

                // Handle permissions on Unix
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Some(mode) = entry.unix_mode() {
                        // Strip setuid (0o4000), setgid (0o2000), sticky (0o1000) bits
                        // 0o0777 mask keeps only owner/group/other rwx flags
                        let safe_mode = mode & 0o0777;
                        fs::set_permissions(&safe_path, fs::Permissions::from_mode(safe_mode))?;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Validate all entries without extracting (fast dry run).
    ///
    /// Uses `by_index_raw()` to read metadata without decompressing.
    ///
    /// **Note:** Filter callbacks are NOT applied during validation. This means:
    /// - File count/size limits are checked against ALL entries
    /// - Extraction may skip entries the filter rejects
    /// - This is conservative: validation may reject archives that would succeed with filtering
    ///
    /// This is intentional: filters are advisory, not security boundaries.
    fn validate_all<R: Read + Seek>(&self, archive: &mut zip::ZipArchive<R>) -> Result<(), Error> {
        let mut total_size: u64 = 0;
        let mut file_count: usize = 0;

        for i in 0..archive.len() {
            // by_index_raw reads metadata WITHOUT decompressing
            let entry = archive.by_index_raw(i)?;
            let name = entry.name().to_string();

            // 0. Filename sanitization
            if let Err(reason) = self.validate_filename(&name) {
                return Err(Error::InvalidFilename {
                    entry: name,
                    reason: reason.to_string(),
                });
            }

            // 1. Path validation (Zip Slip check)
            self.jail.join(&name).map_err(|e| Error::PathEscape {
                entry: name.clone(),
                detail: e.to_string(),
            })?;

            // 2. Symlink check
            if entry.is_symlink() && matches!(self.symlinks, SymlinkPolicy::Error) {
                return Err(Error::SymlinkNotAllowed {
                    entry: name,
                    target: String::new(), // ZIP symlink targets require reading content
                });
            }

            // 3. Path depth check
            let depth = Path::new(&name)
                .components()
                .filter(|c| matches!(c, Component::Normal(_)))
                .count();
            if depth > self.limits.max_path_depth {
                return Err(Error::PathTooDeep {
                    entry: name,
                    depth,
                    limit: self.limits.max_path_depth,
                });
            }

            // 4. Single file size check
            if !entry.is_dir() && entry.size() > self.limits.max_single_file {
                return Err(Error::FileTooLarge {
                    entry: name,
                    limit: self.limits.max_single_file,
                    size: entry.size(),
                });
            }

            // Accumulate totals (skip symlinks and dirs)
            if !entry.is_dir() && !entry.is_symlink() {
                total_size += entry.size();
                file_count += 1;
            }
        }

        // 5. Check accumulated totals
        if total_size > self.limits.max_total_bytes {
            return Err(Error::TotalSizeExceeded {
                limit: self.limits.max_total_bytes,
                would_be: total_size,
            });
        }

        if file_count > self.limits.max_file_count {
            return Err(Error::FileCountExceeded {
                limit: self.limits.max_file_count,
                attempted: file_count,
            });
        }

        Ok(())
    }

    /// Extract from a file path. Convenience wrapper around `extract()`.
    pub fn extract_file<P: AsRef<Path>>(&self, path: P) -> Result<Report, Error> {
        let file = fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        self.extract(reader)
    }

    /// Verify archive integrity by reading all entries and checking CRC32.
    ///
    /// This method reads and decompresses all file entries (triggering CRC validation)
    /// but does NOT write anything to disk. Use this to verify an archive is intact
    /// before extraction.
    ///
    /// # Returns
    ///
    /// A `VerifyReport` containing the number of entries verified and total bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Any entry fails CRC32 validation
    /// - Any entry is encrypted
    /// - The archive is corrupted
    ///
    /// # Example
    ///
    /// ```no_run
    /// use safe_unzip::Extractor;
    ///
    /// let extractor = Extractor::new("/tmp/safe_dest").unwrap();
    /// let report = extractor.verify_file("archive.zip")?;
    /// println!("Verified {} entries, {} bytes", report.entries_verified, report.bytes_verified);
    /// # Ok::<(), safe_unzip::Error>(())
    /// ```
    pub fn verify<R: Read + Seek>(&self, reader: R) -> Result<VerifyReport, Error> {
        let mut archive = zip::ZipArchive::new(reader)?;
        let mut entries_verified = 0usize;
        let mut bytes_verified = 0u64;

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            let name = entry.name().to_string();

            // Check for encrypted entries
            if entry.encrypted() {
                return Err(Error::EncryptedEntry { entry: name });
            }

            // Skip directories and symlinks
            if entry.is_dir() || entry.is_symlink() {
                continue;
            }

            // Read the entire entry (triggers CRC validation in zip crate)
            let mut buf = [0u8; 8192];
            let mut entry_bytes = 0u64;
            loop {
                match entry.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => entry_bytes += n as u64,
                    Err(e) => {
                        return Err(Error::Io(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!("CRC check failed for '{}': {}", name, e),
                        )));
                    }
                }
            }

            entries_verified += 1;
            bytes_verified += entry_bytes;
        }

        Ok(VerifyReport {
            entries_verified,
            bytes_verified,
        })
    }

    /// Verify archive integrity from a file path.
    pub fn verify_file<P: AsRef<Path>>(&self, path: P) -> Result<VerifyReport, Error> {
        let file = fs::File::open(path)?;
        let reader = std::io::BufReader::new(file);
        self.verify(reader)
    }

    /// Verify archive integrity from bytes.
    pub fn verify_bytes(&self, data: &[u8]) -> Result<VerifyReport, Error> {
        self.verify(std::io::Cursor::new(data))
    }

    /// Validate filename. Returns Ok(()) if valid, Err(reason) if invalid.
    fn validate_filename(&self, name: &str) -> Result<(), &'static str> {
        // Reject empty names
        if name.is_empty() {
            return Err("empty filename");
        }

        // Reject control characters (includes null bytes)
        if name.chars().any(|c| c.is_control()) {
            return Err("contains control characters");
        }

        // Reject backslashes (Windows path separator could bypass Unix checks)
        if name.contains('\\') {
            return Err("contains backslash");
        }

        // Reject extremely long filenames (filesystem limits)
        if name.len() > 1024 {
            return Err("path too long (>1024 bytes)");
        }

        if name.split('/').any(|component| component.len() > 255) {
            return Err("path component too long (>255 bytes)");
        }

        // Check path components for reserved names
        let path = Path::new(name);
        for component in path.components() {
            if let Component::Normal(os_str) = component {
                if let Some(s) = os_str.to_str() {
                    // Windows reserved names
                    let s_upper = s.to_ascii_uppercase();
                    let file_stem = s_upper.split('.').next().unwrap_or(&s_upper);

                    match file_stem {
                        "CON" | "PRN" | "AUX" | "NUL" | "COM1" | "COM2" | "COM3" | "COM4"
                        | "COM5" | "COM6" | "COM7" | "COM8" | "COM9" | "LPT1" | "LPT2" | "LPT3"
                        | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9" => {
                            return Err("Windows reserved name");
                        }
                        _ => {}
                    }
                }
            }
        }
        Ok(())
    }
}

// Helper struct to enforce read limits
struct LimitReader<'a, R> {
    inner: &'a mut R,
    limit: u64,
    bytes_read: u64,
    hit_limit: bool,
}

impl<'a, R: Read> LimitReader<'a, R> {
    fn new(inner: &'a mut R, limit: u64) -> Self {
        Self {
            inner,
            limit,
            bytes_read: 0,
            hit_limit: false,
        }
    }
}

impl<'a, R: Read> Read for LimitReader<'a, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.bytes_read >= self.limit {
            self.hit_limit = true;
            return Ok(0);
        }

        // Cap the read length to the limit
        let remaining = self.limit - self.bytes_read;
        let len = buf.len().min(remaining as usize);

        let n = self.inner.read(&mut buf[0..len])?;
        self.bytes_read += n as u64;

        if self.bytes_read >= self.limit {
            self.hit_limit = true;
        }

        Ok(n)
    }
}
