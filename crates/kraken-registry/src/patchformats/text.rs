//! `.1337` and DIF: one text line per changed byte.

use std::fmt::Write;

use super::{Files, WriteRecord};

fn base_name(name: &str) -> &str {
    name.rsplit(['/', '\\']).next().unwrap_or(name)
}

pub(super) fn write_1337(files: &Files<'_>, records: &[WriteRecord]) -> Vec<u8> {
    let mut s = format!(">{}\n", base_name(files.name));
    for r in records {
        for (i, (o, n)) in r.original.iter().zip(&r.replacement).enumerate() {
            let _ = writeln!(s, "{:08X}:{o:02X}->{n:02X}", r.offset + i as u64);
        }
    }
    s.into_bytes()
}

pub(super) fn write_dif(files: &Files<'_>, records: &[WriteRecord]) -> Vec<u8> {
    let mut s = String::from("This difference file has been created by KRAKEN\n");
    let _ = writeln!(s, "{}", base_name(files.name));
    for r in records {
        for (i, (o, n)) in r.original.iter().zip(&r.replacement).enumerate() {
            let _ = writeln!(s, "{:08X}: {o:02X} {n:02X}", r.offset + i as u64);
        }
    }
    s.into_bytes()
}
