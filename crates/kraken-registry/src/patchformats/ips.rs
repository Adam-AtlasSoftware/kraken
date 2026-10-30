//! IPS and IPS32.

use super::{Files, FormatError, MAX_RECORD, MAX_RECORDS, Record, WriteRecord, malformed};

const EOF3: u64 = 0x45_4F_46;
/// Most bytes all records of one file may expand to (run-length records are tiny on disk).
const MAX_DECODED: usize = 64 << 20;

pub(super) fn write(
    files: &Files<'_>,
    records: &[WriteRecord],
    wide: bool,
) -> Result<Vec<u8>, FormatError> {
    let mut out = Vec::new();
    out.extend_from_slice(if wide { b"IPS32" } else { b"PATCH" });
    for r in records {
        for (i, chunk) in r.replacement.chunks(MAX_RECORD).enumerate() {
            let mut offset = r.offset + (i * MAX_RECORD) as u64;
            let mut data = chunk.to_vec();
            if wide {
                let o = u32::try_from(offset).map_err(|_| {
                    FormatError::Unrepresentable(format!(
                        "file offset {offset:#x} does not fit IPS32's 4 bytes; use BPS or JSON"
                    ))
                })?;
                out.extend_from_slice(&o.to_be_bytes());
            } else {
                // An offset that spells "EOF" would end the file early; start one byte before.
                if offset == EOF3 {
                    offset -= 1;
                    data.insert(0, files.patched[offset as usize]);
                }
                if offset > 0xFF_FFFF {
                    return Err(FormatError::Unrepresentable(format!(
                        "file offset {offset:#x} is past the 16 MiB IPS can address; use IPS32, \
                         BPS or JSON"
                    )));
                }
                out.extend_from_slice(&(offset as u32).to_be_bytes()[1..]);
            }
            out.extend_from_slice(&(data.len() as u16).to_be_bytes());
            out.extend_from_slice(&data);
        }
    }
    out.extend_from_slice(if wide { b"EEOF" } else { b"EOF" });
    Ok(out)
}

pub(super) fn read(data: &[u8], wide: bool) -> Result<Vec<Record>, FormatError> {
    let magic: &[u8] = if wide { b"IPS32" } else { b"PATCH" };
    let end_mark: &[u8] = if wide { b"EEOF" } else { b"EOF" };
    let off_len = if wide { 4 } else { 3 };
    let mut rest = data
        .strip_prefix(magic)
        .ok_or_else(|| malformed("not an IPS file (no PATCH header)"))?;
    let mut out = Vec::new();
    let mut decoded = 0usize;
    loop {
        if let Some(tail) = rest.strip_prefix(end_mark) {
            // A 3-byte truncation length may follow; this importer never changes the size.
            if !tail.is_empty() && tail.len() != 3 {
                return Err(malformed("bytes follow the end marker of the IPS file"));
            }
            return Ok(out);
        }
        if out.len() >= MAX_RECORDS {
            return Err(FormatError::Limit(format!(
                "more than {MAX_RECORDS} records"
            )));
        }
        let (head, tail) = rest
            .split_at_checked(off_len + 2)
            .ok_or_else(|| malformed("the IPS file ends inside a record header"))?;
        let offset = head[..off_len]
            .iter()
            .fold(0u64, |a, &b| (a << 8) | u64::from(b));
        let size = usize::from(u16::from_be_bytes([head[off_len], head[off_len + 1]]));
        if size == 0 {
            let (rle, tail) = tail
                .split_at_checked(3)
                .ok_or_else(|| malformed("the IPS file ends inside a run-length record"))?;
            let count = usize::from(u16::from_be_bytes([rle[0], rle[1]]));
            if count == 0 {
                return Err(malformed("a run-length record of zero bytes"));
            }
            decoded += count;
            if decoded > MAX_DECODED {
                return Err(FormatError::Limit(format!(
                    "the records expand to more than {MAX_DECODED} bytes"
                )));
            }
            out.push(Record {
                offset,
                bytes: vec![rle[2]; count],
                original: None,
            });
            rest = tail;
        } else {
            let (bytes, tail) = tail
                .split_at_checked(size)
                .ok_or_else(|| malformed("the IPS file ends inside a record's data"))?;
            out.push(Record {
                offset,
                bytes: bytes.to_vec(),
                original: None,
            });
            rest = tail;
        }
    }
}
