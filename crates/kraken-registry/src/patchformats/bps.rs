//! BPS: a delta with CRC-32 of the source, the target and the patch.

use super::{Files, FormatError, Record, WriteRecord, crc32, diff_runs, malformed};

pub(super) fn put_varint(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let x = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(0x80 | x);
            return;
        }
        out.push(x);
        v -= 1;
    }
}

fn overflow() -> FormatError {
    malformed("a number in the BPS file is out of range")
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    end: usize,
}

impl Reader<'_> {
    fn varint(&mut self) -> Result<u64, FormatError> {
        let mut value: u64 = 0;
        let mut shift: u64 = 1;
        loop {
            if self.pos >= self.end {
                return Err(malformed("the BPS file ends inside a number"));
            }
            let x = self.data[self.pos];
            self.pos += 1;
            let part = u64::from(x & 0x7f)
                .checked_mul(shift)
                .ok_or_else(overflow)?;
            value = value.checked_add(part).ok_or_else(overflow)?;
            if x & 0x80 != 0 {
                return Ok(value);
            }
            shift = shift.checked_mul(128).ok_or_else(overflow)?;
            value = value.checked_add(shift).ok_or_else(overflow)?;
        }
    }

    fn take(&mut self, n: u64) -> Result<&[u8], FormatError> {
        let n = usize::try_from(n).map_err(|_| overflow())?;
        let end = self
            .pos
            .checked_add(n)
            .filter(|e| *e <= self.end)
            .ok_or_else(|| malformed("the BPS file ends inside a block of data"))?;
        let s = &self.data[self.pos..end];
        self.pos = end;
        Ok(s)
    }
}

pub(super) fn write(files: &Files<'_>, records: &[WriteRecord]) -> Result<Vec<u8>, FormatError> {
    let mut out = b"BPS1".to_vec();
    put_varint(&mut out, files.original.len() as u64);
    put_varint(&mut out, files.patched.len() as u64);
    put_varint(&mut out, 0);
    let mut pos = 0u64;
    for r in records {
        if r.offset > pos {
            put_varint(&mut out, ((r.offset - pos) - 1) << 2);
        }
        let len = r.replacement.len() as u64;
        put_varint(&mut out, ((len - 1) << 2) | 1);
        out.extend_from_slice(&r.replacement);
        pos = r.offset + len;
    }
    let total = files.patched.len() as u64;
    if total > pos {
        put_varint(&mut out, ((total - pos) - 1) << 2);
    }
    out.extend_from_slice(&crc32(files.original).to_le_bytes());
    out.extend_from_slice(&crc32(files.patched).to_le_bytes());
    let patch_crc = crc32(&out);
    out.extend_from_slice(&patch_crc.to_le_bytes());
    Ok(out)
}

pub(super) fn read(data: &[u8], source: &[u8]) -> Result<Vec<Record>, FormatError> {
    if data.len() < 4 + 3 + 12 || !data.starts_with(b"BPS1") {
        return Err(malformed("not a BPS file"));
    }
    let end = data.len() - 12;
    let crc_at = |i: usize| u32::from_le_bytes([data[i], data[i + 1], data[i + 2], data[i + 3]]);
    let (source_crc, target_crc, patch_crc) = (crc_at(end), crc_at(end + 4), crc_at(end + 8));
    if crc32(&data[..data.len() - 4]) != patch_crc {
        return Err(malformed(
            "the BPS file is damaged (its own checksum does not match)",
        ));
    }
    let mut r = Reader { data, pos: 4, end };
    let source_size = r.varint()?;
    let target_size = r.varint()?;
    let meta = r.varint()?;
    r.take(meta)?;
    if source_size != source.len() as u64 || crc32(source) != source_crc {
        return Err(FormatError::WrongSource(
            "this BPS patch was made for a different file: the size or checksum of the \
             original does not match the program's binary"
                .into(),
        ));
    }
    if target_size != source_size {
        return Err(FormatError::Unrepresentable(format!(
            "this BPS patch changes the file size from {source_size} to {target_size} bytes; \
             only patches that keep the size can be imported"
        )));
    }
    let size = source.len();
    let mut target = vec![0u8; size];
    let mut out_pos = 0usize;
    let (mut src_rel, mut tgt_rel) = (0i64, 0i64);
    while out_pos < size {
        let action = r.varint()?;
        let len = (action >> 2)
            .checked_add(1)
            .and_then(|l| usize::try_from(l).ok())
            .filter(|l| *l <= size - out_pos)
            .ok_or_else(|| malformed("a BPS action writes past the end of the file"))?;
        match action & 3 {
            0 => target[out_pos..out_pos + len].copy_from_slice(&source[out_pos..out_pos + len]),
            1 => target[out_pos..out_pos + len].copy_from_slice(r.take(len as u64)?),
            kind => {
                let enc = r.varint()?;
                let delta = i64::try_from(enc >> 1).map_err(|_| overflow())?;
                let delta = if enc & 1 != 0 { -delta } else { delta };
                let rel = if kind == 2 {
                    &mut src_rel
                } else {
                    &mut tgt_rel
                };
                *rel = rel.checked_add(delta).ok_or_else(overflow)?;
                let from = usize::try_from(*rel)
                    .map_err(|_| malformed("a BPS copy starts before the file"))?;
                if kind == 2 {
                    let src = from
                        .checked_add(len)
                        .and_then(|e| source.get(from..e))
                        .ok_or_else(|| malformed("a BPS copy reads past the original"))?;
                    target[out_pos..out_pos + len].copy_from_slice(src);
                } else {
                    if from >= out_pos {
                        return Err(malformed("a BPS copy reads bytes not written yet"));
                    }
                    for i in 0..len {
                        target[out_pos + i] = target[from + i];
                    }
                }
                *rel += len as i64;
            }
        }
        out_pos += len;
    }
    if r.pos != end {
        return Err(malformed("the BPS file has data after its last action"));
    }
    if crc32(&target) != target_crc {
        return Err(malformed(
            "applying the BPS patch does not give the file it promises (checksum mismatch)",
        ));
    }
    Ok(diff_runs(source, &target))
}
