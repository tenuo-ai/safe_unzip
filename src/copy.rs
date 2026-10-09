//! Bounded copy of a single entry's data.

use std::io::{ErrorKind, Read, Write};

use crate::error::Error;

/// Outcome of [`copy_entry`].
pub(crate) struct Copied {
    /// Bytes written to the destination.
    pub written: u64,
    /// The entry had more data than `cap` allowed.
    pub overflow: bool,
}

/// Copy at most `cap` bytes of entry `name` from `reader` into `writer`.
///
/// When the copy reaches `cap` without seeing EOF, one more byte is read. A
/// byte there means the entry is larger than allowed (`overflow`); EOF is what
/// makes archive readers run their CRC32 check, so the check is never skipped
/// just because an entry exactly fills its limit. Checksum failures come back
/// as [`Error::ChecksumMismatch`].
pub(crate) fn copy_entry<R, W>(
    reader: &mut R,
    writer: &mut W,
    cap: u64,
    name: &str,
) -> Result<Copied, Error>
where
    R: Read + ?Sized,
    W: Write + ?Sized,
{
    let mut buf = [0u8; 8192];
    let mut written = 0u64;

    loop {
        let remaining = cap - written;
        if remaining == 0 {
            let mut probe = [0u8; 1];
            let n = read_entry(reader, &mut probe, name)?;
            return Ok(Copied {
                written,
                overflow: n > 0,
            });
        }

        let want = (buf.len() as u64).min(remaining) as usize;
        let n = read_entry(reader, &mut buf[..want], name)?;
        if n == 0 {
            return Ok(Copied {
                written,
                overflow: false,
            });
        }

        writer.write_all(&buf[..n])?;
        written += n as u64;
    }
}

fn read_entry<R: Read + ?Sized>(
    reader: &mut R,
    buf: &mut [u8],
    name: &str,
) -> Result<usize, Error> {
    loop {
        match reader.read(buf) {
            Ok(n) => return Ok(n),
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(Error::from_entry_read(name, e)),
        }
    }
}
