//! 7z archive adapter.
//!
//! Provides read-only extraction of 7z archives with the same security
//! guarantees as ZIP and TAR.

use std::fs::File;
use std::io::{BufReader, Cursor, Read, Seek};
use std::path::Path;

use sevenz_rust2::{ArchiveEntry, ArchiveReader, EncoderMethod, Password};

use crate::entry::{EntryInfo, EntryKind};
use crate::error::Error;

/// Object-safe `Read + Seek`, so the adapter isn't generic over its source.
trait Source: Read + Seek + Send + Sync {}
impl<T: Read + Seek + Send + Sync> Source for T {}

/// Adapter for 7z archives.
///
/// Uses the `sevenz-rust2` crate for decompression. Entry metadata comes from
/// the archive header; content is decompressed one entry at a time and
/// streamed to the callback, so memory use does not grow with archive size.
/// Each entry's reader stops at its header-declared size and verifies its
/// CRC32 at EOF.
///
/// 7z archives are often *solid*: entries share one compressed stream, so
/// reaching an entry means decompressing every entry before it in the same
/// block, including ones the caller skips.
///
/// # Example
///
/// ```ignore
/// use safe_unzip::{Driver, SevenZAdapter};
///
/// let adapter = SevenZAdapter::open("archive.7z")?;
/// let report = Driver::new("/tmp/out")?.extract_7z(adapter)?;
/// ```
pub struct SevenZAdapter {
    reader: ArchiveReader<Box<dyn Source>>,
    max_decoder_memory: u64,
}

impl SevenZAdapter {
    /// Default cap on decoder working memory: 256 MiB.
    ///
    /// 7-Zip's strongest presets use a 64 MiB LZMA2 dictionary and a 192 MiB
    /// PPMd model, so ordinary archives fit. The decoder allocates whatever the
    /// header asks for (up to 4 GiB) before producing any output, so without a
    /// cap a tiny archive could exhaust memory.
    pub const DEFAULT_MAX_DECODER_MEMORY: u64 = 256 * 1024 * 1024;

    /// Create an adapter from any seekable reader.
    pub fn new<R: Read + Seek + Send + Sync + 'static>(reader: R) -> Result<Self, Error> {
        let source: Box<dyn Source> = Box::new(reader);
        let mut reader = ArchiveReader::new(source, Password::empty()).map_err(|e| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("7z open error: {}", e),
            ))
        })?;
        // The multi-threaded LZMA2 decoder works ahead and buffers output,
        // so memory would grow with the archive. Decode on one thread.
        reader.set_thread_count(1);
        Ok(Self {
            reader,
            max_decoder_memory: Self::DEFAULT_MAX_DECODER_MEMORY,
        })
    }

    /// Set the most memory a block's decoder may allocate (dictionary or
    /// model size). Default: [`Self::DEFAULT_MAX_DECODER_MEMORY`].
    pub fn max_decoder_memory(mut self, bytes: u64) -> Self {
        self.max_decoder_memory = bytes;
        self
    }

    /// Reject blocks whose decoder would allocate more than the cap.
    fn check_decoder_memory(&self) -> Result<(), Error> {
        for block in &self.reader.archive().blocks {
            for coder in &block.coders {
                let required = decoder_memory(
                    coder.encoder_method_id(),
                    coder.properties(),
                    block.get_unpack_size(),
                );
                if required > self.max_decoder_memory {
                    return Err(Error::DecoderMemoryExceeded {
                        required,
                        limit: self.max_decoder_memory,
                    });
                }
            }
        }
        Ok(())
    }

    /// Open a 7z file from a path.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, Error> {
        Self::new(BufReader::new(File::open(path.as_ref())?))
    }

    /// Open a 7z file from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<Self, Error> {
        Self::new(Cursor::new(data.to_vec()))
    }

    /// Get all entry metadata (from the header; nothing is decompressed).
    pub fn entries_metadata(&self) -> Vec<EntryInfo> {
        self.reader
            .archive()
            .files
            .iter()
            .filter(|e| !e.is_anti_item)
            .map(entry_info)
            .collect()
    }

    /// Get the number of entries.
    pub fn len(&self) -> usize {
        self.entries_metadata().len()
    }

    /// Check if the archive is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Process each entry with a callback.
    ///
    /// The callback receives the entry's metadata and, for files, a reader over
    /// its decompressed content. Data the callback leaves unread is drained
    /// (and CRC-checked) before the next entry, since entries in a solid block
    /// share one stream.
    ///
    /// Return `Ok(true)` to continue, `Ok(false)` to stop, or `Err` to abort.
    pub fn for_each<F>(&mut self, mut callback: F) -> Result<(), Error>
    where
        F: FnMut(&EntryInfo, Option<&mut dyn Read>) -> Result<bool, Error>,
    {
        self.check_decoder_memory()?;

        // sevenz-rust2's callback must return its own error type, so park ours
        // here and stop iteration.
        let mut failure: Option<Error> = None;
        let mut stopped = false;

        let result = self.reader.for_each_entries(|entry, reader| {
            // ArchiveReader only stops the current block when its callback
            // returns false. Suppress callbacks from subsequent blocks so our
            // documented stop/error semantics still apply to the whole archive.
            if stopped || failure.is_some() {
                return Ok(false);
            }
            if entry.is_anti_item {
                return Ok(true);
            }
            let info = entry_info(entry);
            let is_file = matches!(info.kind, EntryKind::File);

            let outcome = if is_file {
                callback(&info, Some(&mut *reader))
            } else {
                callback(&info, None)
            };

            match outcome {
                Ok(true) => {
                    if is_file {
                        if let Err(e) = std::io::copy(reader, &mut std::io::sink()) {
                            failure = Some(Error::from_entry_read(&info.name, e));
                            return Ok(false);
                        }
                    }
                    Ok(true)
                }
                Ok(false) => {
                    stopped = true;
                    Ok(false)
                }
                Err(e) => {
                    failure = Some(e);
                    Ok(false)
                }
            }
        });

        if let Some(e) = failure {
            return Err(e);
        }
        result.map_err(|e| {
            Error::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("7z read error: {}", e),
            ))
        })
    }
}

/// Memory a coder's decoder allocates up front, from its method ID and
/// header properties.
///
/// Malformed properties count as 0 here; the decoder rejects them itself.
fn decoder_memory(id: &[u8], props: &[u8], unpack_size: u64) -> u64 {
    if id == EncoderMethod::ID_LZMA2 {
        // Dictionary size encoded in 6 bits; 40 means 4 GiB - 1.
        return match props.first().copied().map(u32::from) {
            Some(40) => u64::from(u32::MAX),
            Some(bits) if bits < 40 => u64::from(2 | (bits & 1)) << (bits / 2 + 11),
            _ => 0,
        };
    }
    if id == EncoderMethod::ID_LZMA {
        // LZMA never allocates more dictionary than it will decompress.
        return match props.get(1..5) {
            Some(b) => u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])).min(unpack_size),
            None => 0,
        };
    }
    if id == EncoderMethod::ID_PPMD {
        return match props.get(1..5) {
            Some(b) => u64::from(u32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            None => 0,
        };
    }
    0
}

fn entry_info(entry: &ArchiveEntry) -> EntryInfo {
    EntryInfo {
        name: entry.name().to_string(),
        size: entry.size(),
        kind: if entry.is_directory() {
            EntryKind::Directory
        } else {
            EntryKind::File
        },
        mode: None, // 7z doesn't preserve Unix permissions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lzma2_dictionary_sizes() {
        let lzma2 = |bits: u8| decoder_memory(EncoderMethod::ID_LZMA2, &[bits], 0);
        assert_eq!(lzma2(0), 4 << 10); // 4 KiB
        assert_eq!(lzma2(1), 6 << 10); // 6 KiB
        assert_eq!(lzma2(24), 16 << 20); // 16 MiB
        assert_eq!(lzma2(28), 64 << 20); // 64 MiB (7-Zip -mx9)
        assert_eq!(lzma2(40), u64::from(u32::MAX)); // 4 GiB - 1
        assert_eq!(lzma2(41), 0); // invalid: decoder rejects it
    }

    #[test]
    fn lzma_dictionary_capped_by_unpack_size() {
        let dict = (1u32 << 30).to_le_bytes(); // 1 GiB
        let props = [0x5d, dict[0], dict[1], dict[2], dict[3]];
        let lzma = |unpack| decoder_memory(EncoderMethod::ID_LZMA, &props, unpack);
        assert_eq!(lzma(1000), 1000);
        assert_eq!(lzma(u64::MAX), 1 << 30);
    }

    #[test]
    fn ppmd_model_size() {
        let mem = (192u32 << 20).to_le_bytes();
        let props = [6, mem[0], mem[1], mem[2], mem[3]];
        assert_eq!(decoder_memory(EncoderMethod::ID_PPMD, &props, 0), 192 << 20);
    }

    #[test]
    fn adapter_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SevenZAdapter>();
    }
}
