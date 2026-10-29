//! Text encodings of memory images: Intel HEX and Motorola S-records.

use crate::{Identified, Loader};

const MAX_LINE: usize = 1024;

fn first_line(d: &[u8]) -> &[u8] {
    let n = d
        .iter()
        .take(MAX_LINE)
        .position(|&b| b == b'\n' || b == b'\r')
        .unwrap_or(d.len().min(MAX_LINE));
    &d[..n]
}

fn hex_bytes(s: &[u8]) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    s.chunks(2)
        .map(|p| {
            let h = (p[0] as char).to_digit(16)?;
            let l = (p[1] as char).to_digit(16)?;
            Some((h * 16 + l) as u8)
        })
        .collect()
}

pub fn intel_hex(d: &[u8]) -> Option<Identified> {
    let line = first_line(d);
    let body = line.strip_prefix(b":")?;
    let b = hex_bytes(body)?;
    if b.len() < 5 || b.len() != b[0] as usize + 5 || b[3] > 5 {
        return None;
    }
    if b.iter().fold(0u8, |a, &x| a.wrapping_add(x)) != 0 {
        return None;
    }
    Some(
        Identified::new(
            "ihex",
            "Intel HEX",
            "firmware",
            "microcontroller firmware",
            "image",
        )
        .loader(Loader::Convert)
        .detail("text records of address and data; convert to a binary and open it as a raw image"),
    )
}

pub fn srec(d: &[u8]) -> Option<Identified> {
    let line = first_line(d);
    let (&s, rest) = line.split_first()?;
    let (&t, body) = rest.split_first()?;
    if s != b'S' || !t.is_ascii_digit() || t == b'4' {
        return None;
    }
    let b = hex_bytes(body)?;
    if b.len() < 4 || b.len() != b[0] as usize + 1 {
        return None;
    }
    let (data, check) = b.split_at(b.len() - 1);
    if !data.iter().fold(0u8, |a, &x| a.wrapping_add(x)) != check[0] {
        return None;
    }
    Some(
        Identified::new(
            "srec",
            "Motorola S-record",
            "firmware",
            "microcontroller firmware",
            "image",
        )
        .loader(Loader::Convert)
        .detail("text records of address and data; convert to a binary and open it as a raw image"),
    )
}
