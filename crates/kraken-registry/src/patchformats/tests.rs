use object::read::{Object, ObjectSection};

use super::*;
use crate::patchfile::{FilePatch, patch_file_bytes};

fn corpus() -> Vec<u8> {
    let p =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus/bin/stripped_calc-O0");
    std::fs::read(p).expect("corpus binary")
}

/// Three patches in `.text` of the corpus program, mapped the way `patch_export` maps them.
fn three_patches(image: &[u8]) -> (Vec<u8>, Vec<WriteRecord>) {
    let file = object::File::parse(image).expect("elf");
    let text = file.section_by_name(".text").expect(".text");
    let (off, _) = text.file_range().expect("file range");
    let addr = text.address();
    let mut patches = Vec::new();
    for (delta, len, fill) in [(0x10u64, 2usize, 0x90u8), (0x40, 5, 0xcc), (0x90, 1, 0xc3)] {
        let o = (off + delta) as usize;
        patches.push(FilePatch {
            address: addr + delta,
            original: image[o..o + len].to_vec(),
            replacement: image[o..o + len].iter().map(|b| !b ^ fill).collect(),
        });
    }
    // Every replacement differs from the original at every byte.
    for p in &patches {
        assert!(p.original.iter().zip(&p.replacement).all(|(a, b)| a != b));
    }
    let (patched, applied) = patch_file_bytes(image, &patches).expect("export");
    let records = applied
        .iter()
        .map(|a| {
            let o = a.file_offset as usize;
            WriteRecord {
                address: a.address,
                offset: a.file_offset,
                original: image[o..o + a.len].to_vec(),
                replacement: patched[o..o + a.len].to_vec(),
                note: "test".into(),
            }
        })
        .collect();
    (patched, records)
}

fn apply(image: &[u8], runs: &[Record]) -> Vec<u8> {
    let mut out = image.to_vec();
    for r in runs {
        let o = r.offset as usize;
        out[o..o + r.bytes.len()].copy_from_slice(&r.bytes);
    }
    out
}

#[test]
fn every_importable_format_round_trips_on_the_corpus_program() {
    let image = corpus();
    let (patched, records) = three_patches(&image);
    assert_ne!(image, patched);
    let files = Files {
        original: &image,
        patched: &patched,
        name: "stripped_calc-O0",
    };
    for f in [Format::Ips, Format::Ips32, Format::Bps, Format::Json] {
        let data = write(f, &files, &records).expect("write");
        assert_eq!(detect(&data), Some(f), "{f:?}");
        let read_back = read(f, &data, &image).unwrap_or_else(|e| panic!("{f:?}: {e}"));
        let runs = normalize(&image, &read_back).expect("normalize");
        assert_eq!(runs.len(), 3, "{f:?}");
        assert_eq!(apply(&image, &runs), patched, "{f:?}");
        for (r, w) in runs.iter().zip(&records) {
            assert_eq!((r.offset, &r.bytes), (w.offset, &w.replacement), "{f:?}");
        }
    }
}

#[test]
fn the_text_formats_list_every_changed_byte() {
    let image = corpus();
    let (patched, records) = three_patches(&image);
    let files = Files {
        original: &image,
        patched: &patched,
        name: "/some/dir/stripped_calc-O0",
    };
    let t = String::from_utf8(write(Format::X1337, &files, &records).expect("1337")).expect("text");
    let mut lines = t.lines();
    assert_eq!(lines.next(), Some(">stripped_calc-O0"));
    let body: Vec<&str> = lines.collect();
    assert_eq!(body.len(), 2 + 5 + 1);
    let r = &records[0];
    assert_eq!(
        body[0],
        format!(
            "{:08X}:{:02X}->{:02X}",
            r.offset, r.original[0], r.replacement[0]
        )
    );
    let d = String::from_utf8(write(Format::Dif, &files, &records).expect("dif")).expect("text");
    assert!(d.starts_with("This difference file has been created by KRAKEN\nstripped_calc-O0\n"));
    assert!(d.contains(&format!(
        "{:08X}: {:02X} {:02X}",
        r.offset, r.original[0], r.replacement[0]
    )));
    assert_eq!(d.lines().count(), 2 + 8);
    assert!(read(Format::X1337, t.as_bytes(), &image).is_err());
}

#[test]
fn the_bps_output_is_a_well_formed_bps_file() {
    // The CRC-32 of "123456789" is the standard check value.
    assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    let image = corpus();
    let (patched, records) = three_patches(&image);
    let files = Files {
        original: &image,
        patched: &patched,
        name: "x",
    };
    let data = write(Format::Bps, &files, &records).expect("bps");
    let n = data.len();
    let tail = |i: usize| u32::from_le_bytes(data[n - i..n - i + 4].try_into().expect("4"));
    assert_eq!(tail(12), crc32(&image));
    assert_eq!(tail(8), crc32(&patched));
    assert_eq!(tail(4), crc32(&data[..n - 4]));
}

#[test]
fn a_bps_for_another_file_is_refused() {
    let image = corpus();
    let (patched, records) = three_patches(&image);
    let files = Files {
        original: &image,
        patched: &patched,
        name: "x",
    };
    let data = write(Format::Bps, &files, &records).expect("bps");
    let mut other = image.clone();
    other[0x2000] ^= 1;
    assert!(matches!(
        read(Format::Bps, &data, &other),
        Err(FormatError::WrongSource(_))
    ));
    // A same-size file with a changed byte has a different CRC; a shorter one a different size.
    assert!(matches!(
        read(Format::Bps, &data, &image[..image.len() - 1]),
        Err(FormatError::WrongSource(_))
    ));
    // A damaged patch fails its own checksum.
    let mut bad = data.clone();
    bad[8] ^= 0xff;
    assert!(matches!(
        read(Format::Bps, &bad, &image),
        Err(FormatError::Malformed(_))
    ));
}

#[test]
fn a_json_for_another_file_is_refused() {
    let image = corpus();
    let (patched, records) = three_patches(&image);
    let files = Files {
        original: &image,
        patched: &patched,
        name: "x",
    };
    let data = write(Format::Json, &files, &records).expect("json");
    let mut other = image.clone();
    other[100] ^= 1;
    assert!(matches!(
        read(Format::Json, &data, &other),
        Err(FormatError::WrongSource(_))
    ));
}

// ---- hostile input ----------------------------------------------------------------------

fn ips(records: &[(u32, &[u8])]) -> Vec<u8> {
    let mut v = b"PATCH".to_vec();
    for (o, d) in records {
        v.extend_from_slice(&o.to_be_bytes()[1..]);
        v.extend_from_slice(&(d.len() as u16).to_be_bytes());
        v.extend_from_slice(d);
    }
    v.extend_from_slice(b"EOF");
    v
}

#[test]
fn ips_records_outside_the_file_are_refused() {
    let image = vec![0u8; 100];
    let p = read(Format::Ips, &ips(&[(98, &[1, 2, 3])]), &image).expect("parses");
    assert!(normalize(&image, &p).is_err(), "grows the file");
    let p = read(Format::Ips, &ips(&[(0xFF_FFFF, &[1])]), &image).expect("parses");
    assert!(normalize(&image, &p).is_err(), "far outside");
    let p = read(Format::Ips, &ips(&[(97, &[1, 2, 3])]), &image).expect("parses");
    assert_eq!(normalize(&image, &p).expect("fits").len(), 1);
}

#[test]
fn offset_overflow_does_not_wrap() {
    let image = vec![0u8; 16];
    let records = [Record {
        offset: u64::MAX - 1,
        bytes: vec![1, 2, 3, 4],
        original: None,
    }];
    assert!(normalize(&image, &records).is_err());
}

#[test]
fn truncated_and_oversized_ips_are_refused() {
    let image = vec![0u8; 64];
    let good = ips(&[(4, &[9, 9]), (10, &[7])]);
    assert!(read(Format::Ips, &good, &image).is_ok());
    for cut in 0..good.len() - 3 {
        // A cut inside the stream is an error, never a panic or a partial result.
        assert!(read(Format::Ips, &good[..cut], &image).is_err(), "{cut}");
    }
    // A record claiming 60000 bytes with a few present.
    let mut lie = b"PATCH\0\0\x04".to_vec();
    lie.extend_from_slice(&60000u16.to_be_bytes());
    lie.extend_from_slice(&[1, 2, 3]);
    lie.extend_from_slice(b"EOF");
    assert!(read(Format::Ips, &lie, &image).is_err());
    // The file cap.
    let big = vec![0u8; MAX_PATCH_FILE + 1];
    assert!(matches!(
        read(Format::Ips, &big, &image),
        Err(FormatError::Limit(_))
    ));
    // Garbage after the end marker.
    let mut junk = good.clone();
    junk.extend_from_slice(b"xx");
    assert!(read(Format::Ips, &junk, &image).is_err());
}

#[test]
fn run_length_records_cannot_expand_without_bound() {
    // 3000 run-length records of 65535 bytes: 8 bytes each on disk, 196 MB decoded.
    let mut v = b"PATCH".to_vec();
    for _ in 0..3000 {
        v.extend_from_slice(&[0, 0, 0, 0, 0, 0xff, 0xff, 0xaa]);
    }
    v.extend_from_slice(b"EOF");
    let r = read(Format::Ips, &v, &[0u8; 1000]);
    assert!(matches!(r, Err(FormatError::Limit(_))), "{r:?}");
    // And more records than the record cap.
    let mut v = b"PATCH".to_vec();
    for _ in 0..MAX_RECORDS + 1 {
        v.extend_from_slice(&[0, 0, 0, 0, 1, 0xaa]);
    }
    v.extend_from_slice(b"EOF");
    assert!(matches!(
        read(Format::Ips, &v, &[0u8; 1000]),
        Err(FormatError::Limit(_))
    ));
}

#[test]
fn an_offset_that_spells_eof_survives_a_round_trip() {
    let mut image = vec![0x11u8; 0x45_5000];
    image[0x45_4F_46] = 0x22;
    let mut patched = image.clone();
    patched[0x45_4F_46] = 0x33;
    let records = [WriteRecord {
        address: 0,
        offset: 0x45_4F_46,
        original: vec![0x22],
        replacement: vec![0x33],
        note: String::new(),
    }];
    let files = Files {
        original: &image,
        patched: &patched,
        name: "x",
    };
    let data = write(Format::Ips, &files, &records).expect("ips");
    let runs = normalize(&image, &read(Format::Ips, &data, &image).expect("read")).expect("norm");
    assert_eq!(apply(&image, &runs), patched);
}

#[test]
fn ips_cannot_address_past_16_mib_but_ips32_can() {
    let image = vec![0u8; 17 << 20];
    let mut patched = image.clone();
    patched[(16 << 20) + 5] = 1;
    let records = [WriteRecord {
        address: 0,
        offset: (16 << 20) + 5,
        original: vec![0],
        replacement: vec![1],
        note: String::new(),
    }];
    let files = Files {
        original: &image,
        patched: &patched,
        name: "x",
    };
    assert!(matches!(
        write(Format::Ips, &files, &records),
        Err(FormatError::Unrepresentable(_))
    ));
    let data = write(Format::Ips32, &files, &records).expect("ips32");
    let runs = normalize(&image, &read(Format::Ips32, &data, &image).expect("read")).expect("n");
    assert_eq!(apply(&image, &runs), patched);
}

fn bps_with_actions(source: &[u8], target_size: u64, actions: &[u8], target_crc: u32) -> Vec<u8> {
    let mut v = b"BPS1".to_vec();
    super::bps_put_varint_for_tests(&mut v, source.len() as u64);
    super::bps_put_varint_for_tests(&mut v, target_size);
    v.push(0x80);
    v.extend_from_slice(actions);
    v.extend_from_slice(&crc32(source).to_le_bytes());
    v.extend_from_slice(&target_crc.to_le_bytes());
    let c = crc32(&v);
    v.extend_from_slice(&c.to_le_bytes());
    v
}

#[test]
fn hostile_bps_actions_are_refused() {
    let src = vec![5u8; 32];
    // A SourceRead longer than the file.
    let a = bps_with_actions(&src, 32, &[0x80 | (99 << 2)], 0);
    assert!(read(Format::Bps, &a, &src).is_err());
    // A TargetRead whose data is missing.
    let a = bps_with_actions(&src, 32, &[0x80 | (31 << 2) | 1], 0);
    assert!(read(Format::Bps, &a, &src).is_err());
    // A TargetCopy of bytes not yet written.
    let a = bps_with_actions(&src, 32, &[0x80 | (31 << 2) | 3, 0x80 | (4 << 1)], 0);
    assert!(read(Format::Bps, &a, &src).is_err());
    // A SourceCopy before the start (negative offset).
    let a = bps_with_actions(&src, 32, &[0x80 | (31 << 2) | 2, 0x80 | (3 << 1) | 1], 0);
    assert!(read(Format::Bps, &a, &src).is_err());
    // A target size that does not match the source: refused as size-changing, with no
    // allocation from the claimed size.
    let a = bps_with_actions(&src, u64::MAX / 2, &[0x80], 0);
    assert!(read(Format::Bps, &a, &src).is_err());
    // A varint that runs on forever.
    let mut v = b"BPS1".to_vec();
    v.extend_from_slice(&[0x01; 40]);
    v.extend_from_slice(&[0; 12]);
    assert!(read(Format::Bps, &v, &src).is_err());
    // The honest version of the first case works (SourceRead of the whole file = no change).
    let a = bps_with_actions(&src, 32, &[0x80 | (31 << 2)], crc32(&src));
    assert!(read(Format::Bps, &a, &src).expect("identity").is_empty());
}

/// Cheap deterministic generator for the fuzz-style tests.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

#[test]
fn random_bytes_and_mutated_files_never_panic_or_overallocate() {
    let image = corpus();
    let (patched, records) = three_patches(&image);
    let files = Files {
        original: &image,
        patched: &patched,
        name: "x",
    };
    let mut rng = Lcg(7);
    for f in [Format::Ips, Format::Ips32, Format::Bps, Format::Json] {
        let good = write(f, &files, &records).expect("write");
        for round in 0..400 {
            let mut d = good.clone();
            match round % 4 {
                0 => {
                    let i = rng.next() as usize % d.len();
                    d[i] ^= 1 << (rng.next() % 8);
                }
                1 => d.truncate(rng.next() as usize % d.len()),
                2 => {
                    for _ in 0..4 {
                        let i = rng.next() as usize % d.len();
                        d[i] = rng.next() as u8;
                    }
                }
                _ => {
                    d = (0..(rng.next() % 200) as usize)
                        .map(|_| rng.next() as u8)
                        .collect();
                    d.splice(0..0, good.iter().take(5).copied());
                }
            }
            if let Ok(recs) = read(f, &d, &image) {
                // Whatever parsed is bounded and either normalizes or is refused.
                assert!(recs.len() <= MAX_RECORDS);
                let _ = normalize(&image, &recs);
            }
        }
    }
}
