use std::fs;
use std::io::{Read, Seek};
use std::path::{Component, Path};
use path_jail::Jail;
use crate::error::Error;
use crate::limits::Limits;

// Policies
#[derive(Debug, Clone, Copy, Default)]
pub enum OverwritePolicy {
    #[default]
    Error,
    Skip,
    Overwrite,
}

#[derive(Debug, Clone, Copy, Default)]
pub enum SymlinkPolicy {
    #[default]
    Skip,
    Error,
}

/// Extraction strategy.
#[derive(Debug, Clone, Copy, Default)]
pub enum ExtractionMode {
    /// Extract immediately. Partial state on failure.
    #[default]
    Streaming,
    /// Validate all entries first, then extract.
    /// Slower (2x iteration) but no partial state on validation failure.
    ValidateFirst,
}

#[derive(Debug, Clone, Default)]
pub struct Report {
    pub files_extracted: usize,
    pub dirs_created: usize,
    pub bytes_written: u64,
    pub entries_skipped: usize,
}

pub struct EntryInfo<'a> {
    pub name: &'a str,
    pub size: u64,
    pub compressed_size: u64,
    pub is_dir: bool,
    pub is_symlink: bool,
}

pub struct Extractor {
    jail: Jail,
    limits: Limits,
    overwrite: OverwritePolicy,
    symlinks: SymlinkPolicy,
    mode: ExtractionMode,
    // Using a boxed closure for the filter
    filter: Option<Box<dyn Fn(&EntryInfo) -> bool + Send + Sync>>,
}

impl Extractor {
    pub fn new<P: AsRef<Path>>(destination: P) -> Result<Self, Error> {
        // Ensure root exists so Jail can canonicalize it
        if !destination.as_ref().exists() {
            return Err(Error::DestinationNotFound {
                path: destination.as_ref().to_string_lossy().to_string(),
            });
        }

        let jail = Jail::new(destination)?;
        Ok(Self {
            jail,
            limits: Limits::default(),
            overwrite: OverwritePolicy::default(),
            symlinks: SymlinkPolicy::default(),
            mode: ExtractionMode::default(),
            filter: None,
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

    pub fn extract<R: Read + Seek>(&self, reader: R) -> Result<Report, Error> {
        let mut archive = zip::ZipArchive::new(reader)?;
        
        // If ValidateFirst mode, do a dry run first
        if matches!(self.mode, ExtractionMode::ValidateFirst) {
            self.validate_all(&mut archive)?;
        }
        
        let mut report = Report::default();
        let mut total_bytes_written: u64 = 0;

        for i in 0..archive.len() {
            let mut entry = archive.by_index(i)?;
            let name = entry.name().to_string();

            // 1. SECURITY: Path Validation (Path Jail)
            // We check this FIRST. Even if we skip the file later, 
            // we want to know if it was malicious.
            let safe_path = self.jail.join(&name).map_err(|e| Error::PathEscape {
                entry: name.clone(),
                detail: e.to_string(),
            })?;

            // 2. CHECK: Symlinks
            if entry.is_symlink() {
                match self.symlinks {
                    SymlinkPolicy::Error => return Err(Error::SymlinkNotAllowed { entry: name }),
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

            // 5. CHECK: Limits (Size & Count)
            // Check file count
            if report.files_extracted >= self.limits.max_file_count {
                return Err(Error::FileCountExceeded { limit: self.limits.max_file_count });
            }

            // Check single file size
            if !entry.is_dir() && entry.size() > self.limits.max_single_file {
                 return Err(Error::FileTooLarge {
                    entry: name,
                    limit: self.limits.max_single_file,
                    size: entry.size(),
                });
            }

            // Check total size (Lookahead)
            if total_bytes_written + entry.size() > self.limits.max_total_bytes {
                return Err(Error::TotalSizeExceeded {
                    limit: self.limits.max_total_bytes,
                    would_be: total_bytes_written + entry.size(),
                });
            }

            // 6. CHECK: Overwrite Policy
            if safe_path.exists() {
                match self.overwrite {
                    OverwritePolicy::Error => return Err(Error::AlreadyExists { path: safe_path.display().to_string() }),
                    OverwritePolicy::Skip => {
                        report.entries_skipped += 1;
                        continue;
                    },
                    OverwritePolicy::Overwrite => { /* Proceed */ }
                }
            }

            // 7. EXECUTION
            if entry.is_dir() {
                fs::create_dir_all(&safe_path)?;
                report.dirs_created += 1;
            } else {
                if let Some(parent) = safe_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                
                let mut outfile = fs::File::create(&safe_path)?;
                let written = std::io::copy(&mut entry, &mut outfile)?;
                
                total_bytes_written += written;
                report.bytes_written += written;
                report.files_extracted += 1;

                // Handle permissions on Unix
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Some(mode) = entry.unix_mode() {
                        // Strip dangerous bits (setuid, setgid, sticky)
                        // 0o777 mask keeps only rwx flags
                        let safe_mode = mode & 0o777; 
                        fs::set_permissions(&safe_path, fs::Permissions::from_mode(safe_mode))?;
                    }
                }
            }
        }

        Ok(report)
    }

    /// Validate all entries without extracting (fast dry run).
    /// Uses `by_index_raw()` to read metadata without decompressing.
    fn validate_all<R: Read + Seek>(&self, archive: &mut zip::ZipArchive<R>) -> Result<(), Error> {
        let mut total_size: u64 = 0;
        let mut file_count: usize = 0;

        for i in 0..archive.len() {
            // by_index_raw reads metadata WITHOUT decompressing
            let entry = archive.by_index_raw(i)?;
            let name = entry.name().to_string();

            // 1. Path validation (Zip Slip check)
            self.jail.join(&name).map_err(|e| Error::PathEscape {
                entry: name.clone(),
                detail: e.to_string(),
            })?;

            // 2. Symlink check
            if entry.is_symlink() && matches!(self.symlinks, SymlinkPolicy::Error) {
                return Err(Error::SymlinkNotAllowed { entry: name });
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
}