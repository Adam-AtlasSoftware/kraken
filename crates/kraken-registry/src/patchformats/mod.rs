//! Patch files other tools read and write: IPS, IPS32, BPS, `.1337`, DIF and JSON.
//!
//! Every format here describes changes as offsets into the original *file*, not addresses, so
//! `patch_export_diff` maps the enabled patches to file offsets with `patchfile` first and
//! `patch_import` maps them back. Writers take the original image and the patched one. Readers
//! parse files from strangers: they never allocate from a length field before checking it
//! against the data that is really there, cap the file, the record count and the size of a
//! record, check every offset against the original file with checked arithmetic, and verify
//! the source CRC of a BPS file against the file it is applied to. A reader returns plain
//! [`Record`]s; [`normalize`] lays them over the original and reports the bytes that really
//! change, so overlapping or no-op records in a foreign file settle to one clean set.

mod bps;
mod crc;
mod ips;
mod json;
mod text;

use std::fmt;

pub use crc::crc32;

/// Largest patch file a reader looks at.
pub const MAX_PATCH_FILE: usize = 16 << 20;
/// Largest single record (the 16-bit length of an IPS record).
pub const MAX_RECORD: usize = 65_535;
/// Most records a reader accepts from one file.
pub const MAX_RECORDS: usize = 100_000;

/// A patch file format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// IPS: 3-byte offsets, files up to 16 MiB.
    Ips,
    /// IPS32: 4-byte offsets.
    Ips32,
    /// BPS: a delta with CRC-32 checks of the source, target and patch.
    Bps,
    /// `.1337`: one `offset:old->new` text line per byte.
    X1337,
    /// DIF: the text format of IDA's difference files.
    Dif,
    /// JSON: offsets, addresses and hex bytes, with the file's size and SHA-256.
    Json,
}

impl Format {
    /// Every format, in the order the GUI lists them.
    pub const ALL: [Format; 6] = [
        Format::Ips,
        Format::Ips32,
        Format::Bps,
        Format::X1337,
        Format::Dif,
        Format::Json,
    ];

    /// The name used in command arguments, and the usual file extension.
    pub fn name(self) -> &'static str {
        match self {
            Format::Ips => "ips",
            Format::Ips32 => "ips32",
            Format::Bps => "bps",
            Format::X1337 => "1337",
            Format::Dif => "dif",
            Format::Json => "json",
        }
    }

    /// Looks a format up by its name (case-insensitive, an optional leading dot).
    pub fn from_name(s: &str) -> Option<Format> {
        let s = s.trim().trim_start_matches('.').to_ascii_lowercase();
        Format::ALL.into_iter().find(|f| f.name() == s)
    }
}

/// Why a patch file could not be written or read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    /// The file is not well formed.
    Malformed(String),
    /// A limit was exceeded (file, record or count size).
    Limit(String),
    /// The file was made for a different original than the one it is applied to.
    WrongSource(String),
    /// The change cannot be written or read in this format.
    Unrepresentable(String),
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FormatError::Malformed(m)
            | FormatError::Limit(m)
            | FormatError::WrongSource(m)
            | FormatError::Unrepresentable(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for FormatError {}

pub(crate) fn malformed(m: impl Into<String>) -> FormatError {
    FormatError::Malformed(m.into())
}

/// Bytes at a file offset, as read from a patch file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// File offset of the first byte.
    pub offset: u64,
    /// The new bytes.
    pub bytes: Vec<u8>,
    /// The bytes the file expects there, when the format carries them.
    pub original: Option<Vec<u8>>,
}

/// One patch being written: where it sits in the file and what it replaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteRecord {
    /// The patch's virtual address.
    pub address: u64,
    /// File offset of the first byte.
    pub offset: u64,
    /// The bytes in the original file.
    pub original: Vec<u8>,
    /// The new bytes.
    pub replacement: Vec<u8>,
    /// The patch's note.
    pub note: String,
}

/// What a writer needs about the file.
#[derive(Debug, Clone, Copy)]
pub struct Files<'a> {
    /// The original file.
    pub original: &'a [u8],
    /// The file with the patches applied.
    pub patched: &'a [u8],
    /// The original's file name, for formats that name it.
    pub name: &'a str,
}

/// Writes `records` (sorted by offset, not overlapping, none empty) as `format`.
pub fn write(
    format: Format,
    files: &Files<'_>,
    records: &[WriteRecord],
) -> Result<Vec<u8>, FormatError> {
    match format {
        Format::Ips => ips::write(files, records, false),
        Format::Ips32 => ips::write(files, records, true),
        Format::Bps => bps::write(files, records),
        Format::X1337 => Ok(text::write_1337(files, records)),
        Format::Dif => Ok(text::write_dif(files, records)),
        Format::Json => json::write(files, records),
    }
}

/// The format a patch file is, by its magic.
pub fn detect(data: &[u8]) -> Option<Format> {
    if data.starts_with(b"PATCH") {
        Some(Format::Ips)
    } else if data.starts_with(b"IPS32") {
        Some(Format::Ips32)
    } else if data.starts_with(b"BPS1") {
        Some(Format::Bps)
    } else if data.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{') {
        Some(Format::Json)
    } else {
        None
    }
}

/// Reads the records of a patch file made for `source`.
pub fn read(format: Format, data: &[u8], source: &[u8]) -> Result<Vec<Record>, FormatError> {
    if data.len() > MAX_PATCH_FILE {
        return Err(FormatError::Limit(format!(
            "the patch file is {} bytes; at most {MAX_PATCH_FILE} are read",
            data.len()
        )));
    }
    match format {
        Format::Ips => ips::read(data, false),
        Format::Ips32 => ips::read(data, true),
        Format::Bps => bps::read(data, source),
        Format::Json => json::read(data, source),
        Format::X1337 | Format::Dif => Err(FormatError::Unrepresentable(format!(
            "{} files can be written but not imported",
            format.name()
        ))),
    }
}

/// Lays `records` over `source` and returns the runs of bytes that really change, ordered and
/// not overlapping (a later record wins where two overlap). A record outside the file is an
/// error, as is a recorded original that is not what the file holds.
pub fn normalize(source: &[u8], records: &[Record]) -> Result<Vec<Record>, FormatError> {
    let mut target = source.to_vec();
    for r in records {
        let len = r.bytes.len();
        let end = r
            .offset
            .checked_add(len as u64)
            .filter(|e| *e <= source.len() as u64)
            .ok_or_else(|| {
                FormatError::Malformed(format!(
                    "a record of {len} byte{} at file offset {:#x} lies outside the {}-byte file; \
                     patches that grow the file are not imported",
                    if len == 1 { "" } else { "s" },
                    r.offset,
                    source.len()
                ))
            })? as usize;
        let start = r.offset as usize;
        if let Some(o) = &r.original
            && o.as_slice() != &source[start..end]
        {
            return Err(FormatError::WrongSource(format!(
                "the bytes at file offset {:#x} are not what the patch file recorded; it was \
                 made for a different file",
                r.offset
            )));
        }
        target[start..end].copy_from_slice(&r.bytes);
    }
    Ok(diff_runs(source, &target))
}

/// The runs where `a` and `b` (the same length) differ.
pub fn diff_runs(a: &[u8], b: &[u8]) -> Vec<Record> {
    let n = a.len().min(b.len());
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        if a[i] == b[i] {
            i += 1;
            continue;
        }
        let start = i;
        while i < n && a[i] != b[i] {
            i += 1;
        }
        out.push(Record {
            offset: start as u64,
            bytes: b[start..i].to_vec(),
            original: Some(a[start..i].to_vec()),
        });
    }
    out
}

pub(crate) fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}

#[cfg(test)]
fn bps_put_varint_for_tests(out: &mut Vec<u8>, v: u64) {
    bps::put_varint(out, v);
}

#[cfg(test)]
mod tests;
