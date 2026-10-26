//! Generic extraction driver.
//!
//! The driver orchestrates extraction using adapters (format-specific) and
//! policies (security checks).

#[cfg(feature = "sevenz")]
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek};
use std::path::{Path, PathBuf};

use path_jail::Jail;

#[cfg(feature = "tar")]
use crate::adapter::TarAdapter;
use crate::adapter::ZipAdapter;
#[cfg(feature = "sevenz")]
use crate::copy::copy_entry;
#[cfg(unix)]
use crate::dest::set_mode;
use crate::dest::{relative, Destination, IfExists};
use crate::entry::{EntryInfo, EntryKind};
use crate::error::Error;
use crate::flatten::{base_name, FlatNames};
use crate::limits::Limits;
use crate::partial::PartialFile;
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
    ///
    /// For ZIP, validation also decompresses every file to check its CRC32.
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
    /// Writes beneath the destination.
    dest: Destination,
    /// Path jail rooted at the destination.
    jail: Jail,
    /// Security limits.
    limits: Limits,
    /// What to do on existing files.
    overwrite: OverwriteMode,
    /// What to do with symlinks.
    symlinks: SymlinkBehavior,
    /// Validation strategy.
    validation: ValidationMode,
    /// Write files at the destination root under their base names.
    junk_paths: bool,
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

        let jail = Jail::new(destination)?;
        Ok(Self {
            destination: destination.to_path_buf(),
            dest: Destination::new(destination)?,
            jail,
            limits: Limits::default(),
            overwrite: OverwriteMode::default(),
            symlinks: SymlinkBehavior::default(),
            validation: ValidationMode::default(),
            junk_paths: false,
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

    /// Write every file at the destination root under its base name, without
    /// creating directories (like `unzip -j`).
    ///
    /// All checks (path policy, depth, filters) still run on each entry's full
    /// archive path. Directory entries are skipped. When two entries share a
    /// base name, the overwrite mode decides: `Error` (the default) fails with
    /// [`Error::PathCollision`] naming both entries (before anything is written
    /// in `ValidateFirst` mode), `Skip` keeps the first, and `Overwrite` keeps
    /// the last.
    pub fn junk_paths(mut self, junk: bool) -> Self {
        self.junk_paths = junk;
        self
    }

    /// Where an entry is written, relative to the destination. With junk
    /// paths, files go to the destination root under their base name.
    fn output_path(&self, info: &EntryInfo, flat: &mut FlatNames) -> Result<PathBuf, Error> {
        if !self.junk_paths || !matches!(info.kind, EntryKind::File) {
            return Ok(relative(&info.name));
        }
        let base = base_name(&info.name)?;
        self.jail.join(&base).map_err(|e| Error::PathEscape {
            entry: info.name.clone(),
            detail: e.to_string(),
        })?;
        if self.overwrite == OverwriteMode::Error {
            flat.claim(&base, &info.name)?;
        }
        Ok(base)
    }

    /// In junk-paths mode, validate every kept file's flattened name before
    /// writing. With `OverwriteMode::Error`, also reject collisions.
    fn check_flat_names<'a>(
        &self,
        entries: impl IntoIterator<Item = &'a EntryInfo>,
    ) -> Result<Option<Vec<bool>>, Error> {
        if !self.junk_paths {
            return Ok(None);
        }
        let mut flat = FlatNames::default();
        let mut filter_decisions = self.filter.as_ref().map(|_| Vec::new());
        for info in entries {
            let keep = if let Some(ref mut decisions) = filter_decisions {
                let keep = self.filter.as_ref().is_none_or(|filter| filter(info));
                decisions.push(keep);
                keep
            } else {
                true
            };
            if !keep || !matches!(info.kind, EntryKind::File) {
                continue;
            }
            let base = base_name(&info.name)?;
            self.jail.join(&base).map_err(|e| Error::PathEscape {
                entry: info.name.clone(),
                detail: e.to_string(),
            })?;
            if self.overwrite == OverwriteMode::Error {
                flat.claim(&base, &info.name)?;
            }
        }
        Ok(filter_decisions)
    }

    fn keep_entry(&self, info: &EntryInfo, cached: Option<bool>) -> bool {
        cached.unwrap_or_else(|| self.filter.as_ref().is_none_or(|filter| filter(info)))
    }

    /// Set entry filter.
    pub fn filter<F>(mut self, f: F) -> Self
    where
        F: Fn(&EntryInfo) -> bool + Send + Sync + 'static,
    {
        self.filter = Some(Box::new(f));
        self
    }

    /// Extract only specific files by exact name.
    ///
    /// Names are matched exactly (case-sensitive).
    ///
    /// # Example
    ///
    /// ```no_run
    /// use safe_unzip::Driver;
    ///
    /// let report = Driver::new("/tmp/out")?
    ///     .only(&["README.md", "LICENSE"])
    ///     .extract_zip_file("archive.zip")?;
    /// # Ok::<(), safe_unzip::Error>(())
    /// ```
    pub fn only<S: AsRef<str>>(self, names: &[S]) -> Self {
        let names: Vec<String> = names.iter().map(|s| s.as_ref().to_string()).collect();
        self.filter(move |entry| names.iter().any(|n| n == &entry.name))
    }

    /// Include only files matching glob patterns.
    ///
    /// Patterns: `*` matches except `/`, `**` matches including `/`, `?` matches one char.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use safe_unzip::Driver;
    ///
    /// // Extract only Rust source files
    /// let report = Driver::new("/tmp/out")?
    ///     .include_glob(&["**/*.rs"])
    ///     .extract_zip_file("archive.zip")?;
    /// # Ok::<(), safe_unzip::Error>(())
    /// ```
    pub fn include_glob<S: AsRef<str>>(self, patterns: &[S]) -> Self {
        let patterns: Vec<String> = patterns.iter().map(|s| s.as_ref().to_string()).collect();
        self.filter(move |entry| {
            patterns
                .iter()
                .any(|p| glob_match::glob_match(p, &entry.name))
        })
    }

    /// Exclude files matching glob patterns.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use safe_unzip::Driver;
    ///
    /// // Extract everything except tests
    /// let report = Driver::new("/tmp/out")?
    ///     .exclude_glob(&["**/test_*", "**/tests/**"])
    ///     .extract_zip_file("archive.zip")?;
    /// # Ok::<(), safe_unzip::Error>(())
    /// ```
    pub fn exclude_glob<S: AsRef<str>>(self, patterns: &[S]) -> Self {
        let patterns: Vec<String> = patterns.iter().map(|s| s.as_ref().to_string()).collect();
        self.filter(move |entry| {
            !patterns
                .iter()
                .any(|p| glob_match::glob_match(p, &entry.name))
        })
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
        let filter_decisions = if self.validation == ValidationMode::ValidateFirst {
            self.validate_all_zip(&mut adapter, &policies)?
        } else {
            None
        };

        let mut state = ExtractionState::default();
        let mut flat = FlatNames::default();

        for i in 0..adapter.len() {
            self.extract_zip_entry(
                &mut adapter,
                i,
                &policies,
                &mut state,
                &mut flat,
                filter_decisions.as_ref().map(|decisions| decisions[i]),
            )?;
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
    ) -> Result<Option<Vec<bool>>, Error> {
        let entries = adapter.entries_metadata()?;
        let filter_decisions = self.check_flat_names(&entries)?;
        let mut state = ExtractionState::default();

        for info in entries {
            policies.check_all(&info, &state)?;

            // Update state for cumulative checks
            if matches!(info.kind, EntryKind::File) {
                state.bytes_written += info.size;
                state.files_extracted += 1;
            }
        }

        // Metadata passed and the declared sizes fit the limits, so the
        // integrity pass is bounded. Decompress each file to check its CRC32
        // before anything is written.
        for index in 0..adapter.len() {
            adapter.verify_entry(index)?;
        }

        Ok(filter_decisions)
    }

    /// Extract a single ZIP entry.
    fn extract_zip_entry<R: Read + Seek>(
        &self,
        adapter: &mut ZipAdapter<R>,
        index: usize,
        policies: &PolicyChain,
        state: &mut ExtractionState,
        flat: &mut FlatNames,
        filter_decision: Option<bool>,
    ) -> Result<(), Error> {
        let info = adapter.entry_info(index)?;

        // Apply filter
        if !self.keep_entry(&info, filter_decision) {
            state.entries_skipped += 1;
            return Ok(());
        }

        // Check policies
        policies.check_all(&info, state)?;

        // Handle symlinks (skip by default, policy may error)
        if matches!(info.kind, EntryKind::Symlink { .. }) {
            state.entries_skipped += 1;
            return Ok(());
        }

        let rel = self.output_path(&info, flat)?;

        // Extract based on entry type
        match info.kind {
            // Junk paths: no directories are created.
            EntryKind::Directory if self.junk_paths => {}
            EntryKind::Directory => {
                // For directories, just create (idempotent)
                self.dest.create_dir_all(&rel)?;
                state.dirs_created += 1;
            }
            EntryKind::File => {
                if let Some(parent) = rel.parent() {
                    self.dest.create_dir_all(parent)?;
                }

                let Some(outfile) = self.open_for_write(&rel, state)? else {
                    return Ok(()); // Skipped
                };

                let partial = PartialFile::new(&self.dest, &rel);
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
                    set_mode(&outfile, mode)?;
                }
                partial.commit();

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
    // TAR Extraction (requires "tar" feature)
    // =========================================================================

    /// Extract a TAR archive.
    ///
    /// For `.tar.gz` files, use [`Self::extract_tar_gz_file`] or wrap the reader
    /// in `flate2::read::GzDecoder`.
    #[cfg(feature = "tar")]
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

            let filter_decisions = self.check_flat_names(&entries)?;

            // Extract from cache
            let mut state = ExtractionState::default();
            let mut flat = FlatNames::default();
            let mut entry_index = 0;
            adapter.extract_cached(|info, data| {
                let filter_decision = filter_decisions
                    .as_ref()
                    .map(|decisions| decisions[entry_index]);
                entry_index += 1;
                self.extract_tar_entry_data(
                    &info,
                    data,
                    &policies,
                    &mut state,
                    &mut flat,
                    filter_decision,
                )?;
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
        let mut flat = FlatNames::default();

        adapter.for_each(|info, reader| {
            self.extract_tar_entry(&info, reader, &policies, &mut state, &mut flat, None)?;
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
    #[cfg(feature = "tar")]
    fn extract_tar_entry(
        &self,
        info: &EntryInfo,
        reader: Option<&mut dyn Read>,
        policies: &PolicyChain,
        state: &mut ExtractionState,
        flat: &mut FlatNames,
        filter_decision: Option<bool>,
    ) -> Result<(), Error> {
        // Apply filter
        if !self.keep_entry(info, filter_decision) {
            state.entries_skipped += 1;
            return Ok(());
        }

        // Check policies
        policies.check_all(info, state)?;

        // Handle symlinks
        if matches!(info.kind, EntryKind::Symlink { .. }) {
            state.entries_skipped += 1;
            return Ok(());
        }

        let rel = self.output_path(info, flat)?;

        match info.kind {
            // Junk paths: no directories are created.
            EntryKind::Directory if self.junk_paths => {}
            EntryKind::Directory => {
                self.dest.create_dir_all(&rel)?;
                state.dirs_created += 1;
            }
            EntryKind::File => {
                if let Some(parent) = rel.parent() {
                    self.dest.create_dir_all(parent)?;
                }

                let outfile = self.open_for_write(&rel, state)?;
                let Some(mut outfile) = outfile else {
                    return Ok(()); // Skipped
                };
                let partial = PartialFile::new(&self.dest, &rel);

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
                    set_mode(&outfile, mode)?;
                }
                partial.commit();

                state.files_extracted += 1;
            }
            EntryKind::Symlink { .. } => {
                // Already handled
            }
        }

        Ok(())
    }

    /// Extract a single TAR entry from cached data (ValidateFirst mode).
    #[cfg(feature = "tar")]
    fn extract_tar_entry_data(
        &self,
        info: &EntryInfo,
        data: Option<&[u8]>,
        policies: &PolicyChain,
        state: &mut ExtractionState,
        flat: &mut FlatNames,
        filter_decision: Option<bool>,
    ) -> Result<(), Error> {
        // Apply filter
        if !self.keep_entry(info, filter_decision) {
            state.entries_skipped += 1;
            return Ok(());
        }

        // Check policies (already validated, but need for state updates)
        policies.check_all(info, state)?;

        // Handle symlinks
        if matches!(info.kind, EntryKind::Symlink { .. }) {
            state.entries_skipped += 1;
            return Ok(());
        }

        let rel = self.output_path(info, flat)?;

        match info.kind {
            // Junk paths: no directories are created.
            EntryKind::Directory if self.junk_paths => {}
            EntryKind::Directory => {
                self.dest.create_dir_all(&rel)?;
                state.dirs_created += 1;
            }
            EntryKind::File => {
                if let Some(parent) = rel.parent() {
                    self.dest.create_dir_all(parent)?;
                }

                let outfile = self.open_for_write(&rel, state)?;
                let Some(mut outfile) = outfile else {
                    return Ok(()); // Skipped
                };
                let partial = PartialFile::new(&self.dest, &rel);

                if let Some(data) = data {
                    use std::io::Write;
                    outfile.write_all(data)?;
                    state.bytes_written += data.len() as u64;
                }

                #[cfg(unix)]
                if let Some(mode) = info.mode {
                    set_mode(&outfile, mode)?;
                }
                partial.commit();

                state.files_extracted += 1;
            }
            EntryKind::Symlink { .. } => {
                // Already handled
            }
        }

        Ok(())
    }

    /// Create a file for writing based on the overwrite mode.
    /// Returns None if the file should be skipped.
    fn open_for_write(
        &self,
        rel: &Path,
        state: &mut ExtractionState,
    ) -> Result<Option<fs::File>, Error> {
        let if_exists = match self.overwrite {
            OverwriteMode::Error => IfExists::Error,
            OverwriteMode::Skip => IfExists::Skip,
            OverwriteMode::Overwrite => IfExists::Replace,
        };
        let file = self.dest.create_file(rel, if_exists)?;
        if file.is_none() {
            state.entries_skipped += 1;
        }
        Ok(file)
    }

    /// Convenience: extract TAR from a file path.
    #[cfg(feature = "tar")]
    pub fn extract_tar_file<P: AsRef<Path>>(&self, path: P) -> Result<ExtractionReport, Error> {
        let adapter = TarAdapter::open(path)?;
        self.extract_tar(adapter)
    }

    /// Convenience: extract gzip-compressed TAR (.tar.gz, .tgz) from a file path.
    #[cfg(feature = "tar")]
    pub fn extract_tar_gz_file<P: AsRef<Path>>(&self, path: P) -> Result<ExtractionReport, Error> {
        let adapter = TarAdapter::open_gz(path)?;
        self.extract_tar(adapter)
    }

    /// Extract a 7z archive.
    ///
    /// Requires the `sevenz` feature to be enabled.
    ///
    /// Entries are decompressed one at a time and streamed to disk under the
    /// same limits as ZIP. In `ValidateFirst` mode, every entry's metadata is
    /// checked and its CRC32 verified before anything is written.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use safe_unzip::{Driver, SevenZAdapter};
    ///
    /// let adapter = SevenZAdapter::open("archive.7z")?;
    /// let report = Driver::new("/tmp/out")?.extract_7z(adapter)?;
    /// ```
    #[cfg(feature = "sevenz")]
    pub fn extract_7z(
        &self,
        mut adapter: crate::adapter::SevenZAdapter,
    ) -> Result<ExtractionReport, Error> {
        let policies = self.build_policies()?;

        let filter_decisions = if self.validation == ValidationMode::ValidateFirst {
            self.validate_all_7z(&mut adapter, &policies)?
        } else {
            None
        };

        let mut state = ExtractionState::default();
        let mut flat = FlatNames::default();
        adapter.for_each_indexed(|entry_index, info, reader| {
            let filter_decision = filter_decisions
                .as_ref()
                .and_then(|decisions| decisions.get(&entry_index).copied());
            self.extract_7z_entry(
                info,
                reader,
                &policies,
                &mut state,
                &mut flat,
                filter_decision,
            )?;
            Ok(true)
        })?;

        Ok(ExtractionReport {
            files_extracted: state.files_extracted,
            dirs_created: state.dirs_created,
            bytes_written: state.bytes_written,
            entries_skipped: state.entries_skipped,
        })
    }

    /// Validate all 7z entries (metadata, then CRC32) without writing.
    #[cfg(feature = "sevenz")]
    fn validate_all_7z(
        &self,
        adapter: &mut crate::adapter::SevenZAdapter,
        policies: &PolicyChain,
    ) -> Result<Option<HashMap<usize, bool>>, Error> {
        let indexed_entries = adapter.entries_metadata_indexed();
        let entries: Vec<_> = indexed_entries
            .iter()
            .map(|(_, info)| info.clone())
            .collect();
        let filter_decisions = self.check_flat_names(&entries)?;
        let filter_decisions = filter_decisions.map(|decisions| {
            indexed_entries
                .iter()
                .zip(decisions)
                .map(|((index, _), keep)| (*index, keep))
                .collect()
        });
        let mut state = ExtractionState::default();
        for info in entries {
            policies.check_all(&info, &state)?;
            if matches!(info.kind, EntryKind::File) {
                state.bytes_written += info.size;
                state.files_extracted += 1;
            }
        }

        // Declared sizes now fit the limits, and each entry's reader stops at
        // its declared size, so this pass is bounded. The adapter drains
        // every file (checking CRC32) when the callback leaves it unread.
        adapter.for_each(|_, _| Ok(true))?;
        Ok(filter_decisions)
    }

    /// Extract a single 7z entry.
    #[cfg(feature = "sevenz")]
    fn extract_7z_entry(
        &self,
        info: &EntryInfo,
        reader: Option<&mut dyn Read>,
        policies: &PolicyChain,
        state: &mut ExtractionState,
        flat: &mut FlatNames,
        filter_decision: Option<bool>,
    ) -> Result<(), Error> {
        // Apply filter
        if !self.keep_entry(info, filter_decision) {
            state.entries_skipped += 1;
            return Ok(());
        }

        // Validate with policies
        policies.check_all(info, state)?;

        let rel = self.output_path(info, flat)?;

        match info.kind {
            // Junk paths: no directories are created.
            EntryKind::Directory if self.junk_paths => {}
            EntryKind::Directory => {
                self.dest.create_dir_all(&rel)?;
                state.dirs_created += 1;
            }
            EntryKind::File => {
                if let Some(parent) = rel.parent() {
                    self.dest.create_dir_all(parent)?;
                }

                let outfile = self.open_for_write(&rel, state)?;
                let Some(mut outfile) = outfile else {
                    return Ok(()); // Skipped
                };
                let partial = PartialFile::new(&self.dest, &rel);

                if let Some(reader) = reader {
                    let limit = self.limits.max_single_file.min(
                        self.limits
                            .max_total_bytes
                            .saturating_sub(state.bytes_written),
                    );
                    let cap = limit.min(info.size);
                    let copied = copy_entry(reader, &mut outfile, cap, &info.name)?;
                    if copied.overflow {
                        return Err(if cap < info.size {
                            Error::FileTooLarge {
                                entry: info.name.clone(),
                                limit,
                                size: info.size,
                            }
                        } else {
                            Error::SizeMismatch {
                                entry: info.name.clone(),
                                declared: info.size,
                                actual: copied.written + 1,
                            }
                        });
                    }
                    if copied.written != info.size {
                        return Err(Error::SizeMismatch {
                            entry: info.name.clone(),
                            declared: info.size,
                            actual: copied.written,
                        });
                    }
                    state.bytes_written += copied.written;
                }
                partial.commit();

                state.files_extracted += 1;
            }
            EntryKind::Symlink { .. } => {
                // Skip symlinks for 7z (same policy as TAR)
                state.entries_skipped += 1;
            }
        }

        Ok(())
    }

    /// Convenience: extract 7z from a file path.
    #[cfg(feature = "sevenz")]
    pub fn extract_7z_file<P: AsRef<Path>>(&self, path: P) -> Result<ExtractionReport, Error> {
        let adapter = crate::adapter::SevenZAdapter::open(path)?;
        self.extract_7z(adapter)
    }

    /// Convenience: extract 7z from bytes.
    #[cfg(feature = "sevenz")]
    pub fn extract_7z_bytes(&self, data: &[u8]) -> Result<ExtractionReport, Error> {
        let adapter = crate::adapter::SevenZAdapter::from_bytes(data)?;
        self.extract_7z(adapter)
    }
}
