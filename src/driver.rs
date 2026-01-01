//! Generic extraction driver.
//!
//! The driver orchestrates extraction using adapters (format-specific) and
//! policies (security checks).

use std::fs;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use crate::adapter::{TarAdapter, ZipAdapter};
use crate::entry::{EntryInfo, EntryKind};
use crate::error::Error;
use crate::limits::Limits;
use crate::policy::{
    CountPolicy, DepthPolicy, ExtractionState, PathPolicy, PolicyChain, SizePolicy,
    SymlinkBehavior, SymlinkPolicy,
};

/// What to do when a file already exists at the extraction path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum OverwriteMode {
    /// Fail extraction if file exists. Safest default.
    #[default]
    Error,
    /// Skip files that already exist.
    Skip,
    /// Overwrite existing files. Symlinks are removed before overwriting.
    Overwrite,
}

/// Extraction mode determining validation strategy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ValidationMode {
    /// Extract entries as they are read. Fast but leaves partial state on failure.
    #[default]
    Streaming,
    /// Validate all entries first, then extract. Slower but atomic for validation failures.
    ValidateFirst,
}

/// Extraction report with statistics.
#[derive(Debug, Clone, Default)]
pub struct ExtractionReport {
    /// Number of files successfully extracted.
    pub files_extracted: usize,
    /// Number of directories created.
    pub dirs_created: usize,
    /// Total bytes written.
    pub bytes_written: u64,
    /// Number of entries skipped (symlinks, filtered, existing).
    pub entries_skipped: usize,
}

/// Generic extraction driver that works with any archive format.
///
/// The driver uses:
/// - **Adapters** to normalize archive formats into a common interface
/// - **Policies** to validate entries before extraction
///
/// # Example
///
/// ```ignore
/// use safe_unzip::{Driver, ZipAdapter};
///
/// let adapter = ZipAdapter::open("archive.zip")?;
/// let report = Driver::new("/dest")?.extract_zip(adapter)?;
/// ```
pub struct Driver {
    /// Destination directory.
    destination: PathBuf,
    /// Security limits.
    limits: Limits,
    /// What to do on existing files.
    overwrite: OverwriteMode,
    /// What to do with symlinks.
    symlinks: SymlinkBehavior,
    /// Validation strategy.
    validation: ValidationMode,
    /// Optional entry filter.
    #[allow(clippy::type_complexity)]
    filter: Option<Box<dyn Fn(&EntryInfo) -> bool + Send + Sync>>,
}

impl Driver {
    /// Create a new driver for the given destination.
    ///
    /// Returns an error if the destination doesn't exist.
    pub fn new<P: AsRef<Path>>(destination: P) -> Result<Self, Error> {
        Self::new_impl(destination.as_ref(), false)
    }

    /// Create a new driver, creating the destination if it doesn't exist.
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

        Ok(Self {
            destination: destination.to_path_buf(),
            limits: Limits::default(),
            overwrite: OverwriteMode::default(),
            symlinks: SymlinkBehavior::default(),
            validation: ValidationMode::default(),
            filter: None,
        })
    }

    /// Set extraction limits.
    pub fn limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// Set overwrite mode.
    pub fn overwrite(mut self, mode: OverwriteMode) -> Self {
        self.overwrite = mode;
        self
    }

    /// Set symlink handling.
    pub fn symlinks(mut self, behavior: SymlinkBehavior) -> Self {
        self.symlinks = behavior;
        self
    }

    /// Set validation mode.
    pub fn validation(mut self, mode: ValidationMode) -> Self {
        self.validation = mode;
        self
    }

    /// Set entry filter.
    pub fn filter<F>(mut self, f: F) -> Self
    where
        F: Fn(&EntryInfo) -> bool + Send + Sync + 'static,
    {
        self.filter = Some(Box::new(f));
        self
    }

    /// Build the policy chain from current settings.
    fn build_policies(&self) -> Result<PolicyChain, Error> {
        Ok(PolicyChain::new()
            .with(PathPolicy::new(&self.destination)?)
            .with(SizePolicy::new(
                self.limits.max_single_file,
                self.limits.max_total_bytes,
            ))
            .with(CountPolicy::new(self.limits.max_file_count))
            .with(DepthPolicy::new(self.limits.max_path_depth))
            .with(SymlinkPolicy::new(self.symlinks)))
    }

    /// Extract a ZIP archive.
    pub fn extract_zip<R: Read + Seek>(
        &self,
        mut adapter: ZipAdapter<R>,
    ) -> Result<ExtractionReport, Error> {
        let policies = self.build_policies()?;

        // ValidateFirst mode: check all entries before extracting
        if self.validation == ValidationMode::ValidateFirst {
            self.validate_all_zip(&mut adapter, &policies)?;
        }

        let mut state = ExtractionState::default();

        for i in 0..adapter.len() {
            self.extract_zip_entry(&mut adapter, i, &policies, &mut state)?;
        }

        Ok(ExtractionReport {
            files_extracted: state.files_extracted,
            dirs_created: state.dirs_created,
            bytes_written: state.bytes_written,
            entries_skipped: state.entries_skipped,
        })
    }

    /// Validate all entries without extracting.
    fn validate_all_zip<R: Read + Seek>(
        &self,
        adapter: &mut ZipAdapter<R>,
        policies: &PolicyChain,
    ) -> Result<(), Error> {
        let entries = adapter.entries_metadata()?;
        let mut state = ExtractionState::default();

        for info in entries {
            policies.check_all(&info, &state)?;

            // Update state for cumulative checks
            if matches!(info.kind, EntryKind::File) {
                state.bytes_written += info.size;
                state.files_extracted += 1;
            }
        }

        Ok(())
    }

    /// Extract a single ZIP entry.
    fn extract_zip_entry<R: Read + Seek>(
        &self,
        adapter: &mut ZipAdapter<R>,
        index: usize,
        policies: &PolicyChain,
        state: &mut ExtractionState,
    ) -> Result<(), Error> {
        let info = adapter.entry_info(index)?;

        // Apply filter
        if let Some(ref filter) = self.filter {
            if !filter(&info) {
                state.entries_skipped += 1;
                return Ok(());
            }
        }

        // Check policies
        policies.check_all(&info, state)?;

        // Handle symlinks (skip by default, policy may error)
        if matches!(info.kind, EntryKind::Symlink { .. }) {
            state.entries_skipped += 1;
            return Ok(());
        }

        let safe_path = self.destination.join(&info.name);

        // Extract based on entry type
        match info.kind {
            EntryKind::Directory => {
                // For directories, just create (idempotent)
                fs::create_dir_all(&safe_path)?;
                state.dirs_created += 1;
            }
            EntryKind::File => {
                if let Some(parent) = safe_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                // Atomic file creation based on overwrite mode
                let outfile = match self.overwrite {
                    OverwriteMode::Error => {
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
                            Err(e) => return Err(e.into()),
                        }
                    }
                    OverwriteMode::Skip => {
                        // Try atomic create, skip on exists
                        match fs::OpenOptions::new()
                            .write(true)
                            .create_new(true)
                            .open(&safe_path)
                        {
                            Ok(f) => f,
                            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                                state.entries_skipped += 1;
                                return Ok(());
                            }
                            Err(e) => return Err(e.into()),
                        }
                    }
                    OverwriteMode::Overwrite => {
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

                let mut outfile = outfile;
                let limit = self.limits.max_single_file.min(
                    self.limits
                        .max_total_bytes
                        .saturating_sub(state.bytes_written),
                );

                let (_, written) = adapter.extract_to(index, &mut outfile, limit)?;

                // Set permissions on Unix
                #[cfg(unix)]
                if let Some(mode) = info.mode {
                    use std::os::unix::fs::PermissionsExt;
                    let safe_mode = mode & 0o0777;
                    fs::set_permissions(&safe_path, fs::Permissions::from_mode(safe_mode))?;
                }

                state.bytes_written += written;
                state.files_extracted += 1;
            }
            EntryKind::Symlink { .. } => {
                // Already handled above (skipped or errored by policy)
            }
        }

        Ok(())
    }

    /// Convenience: extract ZIP from a file path.
    pub fn extract_zip_file<P: AsRef<Path>>(&self, path: P) -> Result<ExtractionReport, Error> {
        let adapter = ZipAdapter::open(path)?;
        self.extract_zip(adapter)
    }

    // =========================================================================
    // TAR Extraction
    // =========================================================================

    /// Extract a TAR archive.
    ///
    /// For `.tar.gz` files, use [`Self::extract_tar_gz`] or wrap the reader
    /// in `flate2::read::GzDecoder`.
    pub fn extract_tar<R: Read>(
        &self,
        mut adapter: TarAdapter<R>,
    ) -> Result<ExtractionReport, Error> {
        let policies = self.build_policies()?;

        // ValidateFirst mode: cache all entries, validate, then extract
        if self.validation == ValidationMode::ValidateFirst {
            let entries = adapter.cache_all()?;
            let mut state = ExtractionState::default();

            // Validate all entries
            for info in &entries {
                policies.check_all(info, &state)?;
                if matches!(info.kind, EntryKind::File) {
                    state.bytes_written += info.size;
                    state.files_extracted += 1;
                }
            }

            // Extract from cache
            let mut state = ExtractionState::default();
            adapter.extract_cached(|info, data| {
                self.extract_tar_entry_data(&info, data, &policies, &mut state)?;
                Ok(true)
            })?;

            return Ok(ExtractionReport {
                files_extracted: state.files_extracted,
                dirs_created: state.dirs_created,
                bytes_written: state.bytes_written,
                entries_skipped: state.entries_skipped,
            });
        }

        // Streaming mode: extract as we read
        let mut state = ExtractionState::default();

        adapter.for_each(|info, reader| {
            self.extract_tar_entry(&info, reader, &policies, &mut state)?;
            Ok(true)
        })?;

        Ok(ExtractionReport {
            files_extracted: state.files_extracted,
            dirs_created: state.dirs_created,
            bytes_written: state.bytes_written,
            entries_skipped: state.entries_skipped,
        })
    }

    /// Extract a single TAR entry (streaming mode).
    fn extract_tar_entry(
        &self,
        info: &EntryInfo,
        reader: Option<&mut dyn Read>,
        policies: &PolicyChain,
        state: &mut ExtractionState,
    ) -> Result<(), Error> {
        // Apply filter
        if let Some(ref filter) = self.filter {
            if !filter(info) {
                state.entries_skipped += 1;
                return Ok(());
            }
        }

        // Check policies
        policies.check_all(info, state)?;

        // Handle symlinks
        if matches!(info.kind, EntryKind::Symlink { .. }) {
            state.entries_skipped += 1;
            return Ok(());
        }

        let safe_path = self.destination.join(&info.name);

        match info.kind {
            EntryKind::Directory => {
                fs::create_dir_all(&safe_path)?;
                state.dirs_created += 1;
            }
            EntryKind::File => {
                if let Some(parent) = safe_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                let outfile = self.open_for_write(&safe_path, state)?;
                let Some(mut outfile) = outfile else {
                    return Ok(()); // Skipped
                };

                if let Some(reader) = reader {
                    let limit = self.limits.max_single_file.min(
                        self.limits
                            .max_total_bytes
                            .saturating_sub(state.bytes_written),
                    );
                    let written = crate::adapter::copy_limited(reader, &mut outfile, limit)?;
                    state.bytes_written += written;
                }

                #[cfg(unix)]
                if let Some(mode) = info.mode {
                    use std::os::unix::fs::PermissionsExt;
                    let safe_mode = mode & 0o0777;
                    fs::set_permissions(&safe_path, fs::Permissions::from_mode(safe_mode))?;
                }

                state.files_extracted += 1;
            }
            EntryKind::Symlink { .. } => {
                // Already handled
            }
        }

        Ok(())
    }

    /// Extract a single TAR entry from cached data (ValidateFirst mode).
    fn extract_tar_entry_data(
        &self,
        info: &EntryInfo,
        data: Option<&[u8]>,
        policies: &PolicyChain,
        state: &mut ExtractionState,
    ) -> Result<(), Error> {
        // Apply filter
        if let Some(ref filter) = self.filter {
            if !filter(info) {
                state.entries_skipped += 1;
                return Ok(());
            }
        }

        // Check policies (already validated, but need for state updates)
        policies.check_all(info, state)?;

        // Handle symlinks
        if matches!(info.kind, EntryKind::Symlink { .. }) {
            state.entries_skipped += 1;
            return Ok(());
        }

        let safe_path = self.destination.join(&info.name);

        match info.kind {
            EntryKind::Directory => {
                fs::create_dir_all(&safe_path)?;
                state.dirs_created += 1;
            }
            EntryKind::File => {
                if let Some(parent) = safe_path.parent() {
                    fs::create_dir_all(parent)?;
                }

                let outfile = self.open_for_write(&safe_path, state)?;
                let Some(mut outfile) = outfile else {
                    return Ok(()); // Skipped
                };

                if let Some(data) = data {
                    use std::io::Write;
                    outfile.write_all(data)?;
                    state.bytes_written += data.len() as u64;
                }

                #[cfg(unix)]
                if let Some(mode) = info.mode {
                    use std::os::unix::fs::PermissionsExt;
                    let safe_mode = mode & 0o0777;
                    fs::set_permissions(&safe_path, fs::Permissions::from_mode(safe_mode))?;
                }

                state.files_extracted += 1;
            }
            EntryKind::Symlink { .. } => {
                // Already handled
            }
        }

        Ok(())
    }

    /// Open a file for writing based on overwrite policy.
    /// Returns None if the file should be skipped.
    fn open_for_write(
        &self,
        path: &Path,
        state: &mut ExtractionState,
    ) -> Result<Option<fs::File>, Error> {
        match self.overwrite {
            OverwriteMode::Error => {
                match fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                {
                    Ok(f) => Ok(Some(f)),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        Err(Error::AlreadyExists {
                            entry: path.display().to_string(),
                        })
                    }
                    Err(e) => Err(e.into()),
                }
            }
            OverwriteMode::Skip => {
                match fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(path)
                {
                    Ok(f) => Ok(Some(f)),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                        state.entries_skipped += 1;
                        Ok(None)
                    }
                    Err(e) => Err(e.into()),
                }
            }
            OverwriteMode::Overwrite => {
                if let Ok(m) = fs::symlink_metadata(path) {
                    if m.file_type().is_symlink() {
                        let _ = fs::remove_file(path);
                    }
                }
                Ok(Some(fs::File::create(path)?))
            }
        }
    }

    /// Convenience: extract TAR from a file path.
    pub fn extract_tar_file<P: AsRef<Path>>(&self, path: P) -> Result<ExtractionReport, Error> {
        let adapter = TarAdapter::open(path)?;
        self.extract_tar(adapter)
    }

    /// Convenience: extract gzip-compressed TAR (.tar.gz, .tgz) from a file path.
    pub fn extract_tar_gz_file<P: AsRef<Path>>(&self, path: P) -> Result<ExtractionReport, Error> {
        let adapter = TarAdapter::open_gz(path)?;
        self.extract_tar(adapter)
    }
}
