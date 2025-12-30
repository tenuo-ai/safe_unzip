mod error;
mod extractor;
mod limits;

pub use error::Error;
pub use limits::Limits;
pub use extractor::{Extractor, OverwritePolicy, SymlinkPolicy, ExtractionMode, Report, EntryInfo};

/// Convenience function to extract a zip file with default settings.
pub fn extract_file<P: AsRef<std::path::Path>, F: AsRef<std::path::Path>>(
    destination: P, 
    file_path: F
) -> Result<Report, Error> {
    let file = std::fs::File::open(file_path)?;
    let reader = std::io::BufReader::new(file);
    Extractor::new(destination)?.extract(reader)
}