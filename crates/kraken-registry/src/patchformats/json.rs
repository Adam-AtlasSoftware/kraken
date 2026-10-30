//! KRAKEN's JSON patch file: offsets, addresses and hex bytes, with the original's size and
//! SHA-256 so an import can tell it was made for another file.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    Files, FormatError, MAX_RECORD, MAX_RECORDS, Record, WriteRecord, hex_decode, malformed,
};

#[derive(Serialize, Deserialize)]
struct Doc {
    format: String,
    version: u32,
    file: FileInfo,
    patches: Vec<Entry>,
}

#[derive(Serialize, Deserialize)]
struct FileInfo {
    name: String,
    size: u64,
    sha256: String,
}

#[derive(Serialize, Deserialize)]
struct Entry {
    offset: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    original: Option<String>,
    replacement: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    note: String,
}

const MARK: &str = "kraken-patches";

fn sha(data: &[u8]) -> String {
    kraken_proto::hex_bytes(&Sha256::digest(data))
}

pub(super) fn write(files: &Files<'_>, records: &[WriteRecord]) -> Result<Vec<u8>, FormatError> {
    let doc = Doc {
        format: MARK.into(),
        version: 1,
        file: FileInfo {
            name: files
                .name
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or_default()
                .to_string(),
            size: files.original.len() as u64,
            sha256: sha(files.original),
        },
        patches: records
            .iter()
            .map(|r| Entry {
                offset: r.offset,
                address: Some(format!("{:#x}", r.address)),
                original: Some(kraken_proto::hex_bytes(&r.original)),
                replacement: kraken_proto::hex_bytes(&r.replacement),
                note: r.note.clone(),
            })
            .collect(),
    };
    serde_json::to_vec_pretty(&doc).map_err(|e| malformed(e.to_string()))
}

pub(super) fn read(data: &[u8], source: &[u8]) -> Result<Vec<Record>, FormatError> {
    let doc: Doc =
        serde_json::from_slice(data).map_err(|e| malformed(format!("not a patch JSON: {e}")))?;
    if doc.format != MARK || doc.version != 1 {
        return Err(malformed(format!(
            "not a KRAKEN patch file (format {:?}, version {})",
            doc.format, doc.version
        )));
    }
    if doc.file.size != source.len() as u64 || !doc.file.sha256.eq_ignore_ascii_case(&sha(source)) {
        return Err(FormatError::WrongSource(
            "this patch file was made for a different file: the size or SHA-256 of the original \
             does not match the program's binary"
                .into(),
        ));
    }
    if doc.patches.len() > MAX_RECORDS {
        return Err(FormatError::Limit(format!(
            "more than {MAX_RECORDS} records"
        )));
    }
    doc.patches
        .into_iter()
        .map(|e| {
            if e.replacement.len() > MAX_RECORD * 2 {
                return Err(FormatError::Limit(format!(
                    "a record of more than {MAX_RECORD} bytes"
                )));
            }
            let bytes = hex_decode(&e.replacement)
                .filter(|b| !b.is_empty())
                .ok_or_else(|| malformed("a replacement is empty or not hex"))?;
            let original = match e.original {
                Some(o) => Some(
                    hex_decode(&o)
                        .filter(|b| b.len() == bytes.len())
                        .ok_or_else(|| malformed("an original is not hex of the same length"))?,
                ),
                None => None,
            };
            Ok(Record {
                offset: e.offset,
                bytes,
                original,
            })
        })
        .collect()
}
