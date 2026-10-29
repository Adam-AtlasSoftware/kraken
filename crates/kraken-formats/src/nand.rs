//! Xbox 360 NAND dumps: the `FF 4F` flash header and the spare-area layout (a 16-byte spare
//! after every 512-byte page, with an ECC word in its last four bytes). Nothing is decrypted.

use crate::{Confidence, Identified, kib, rd};

const PAGE: usize = 0x200;
const SPARE: usize = 0x10;
const RAW_SIZES: [usize; 4] = [16 << 20, 64 << 20, 256 << 20, 512 << 20];

/// The ECC the console's flash controller stores in the spare area of a page: a bitwise CRC-like
/// code over the 512 data bytes and the first 12 spare bytes (4198 bits).
fn ecc_word(page_and_spare: &[u8]) -> Option<u32> {
    let mut val: u32 = 0;
    let mut v: u32 = 0;
    for bit in 0..0x1066usize {
        if bit & 31 == 0 {
            v = !rd::u32le(page_and_spare, bit / 8)?;
        }
        val ^= v & 1;
        v >>= 1;
        if val & 1 != 0 {
            val ^= 0x0695_4559;
        }
        val >>= 1;
    }
    Some(!val)
}

/// True when the 16 spare bytes of the 528-byte `block` carry the ECC of its data.
fn ecc_ok(block: &[u8]) -> bool {
    let Some(val) = ecc_word(block) else {
        return false;
    };
    let want = [
        ((val << 6) & 0xc0) as u8,
        (val >> 2) as u8,
        (val >> 10) as u8,
        (val >> 18) as u8,
    ];
    let Some(got) = block.get(PAGE + 0xc..PAGE + SPARE) else {
        return false;
    };
    got[0] & 0xc0 == want[0] && got[1..] == want[1..]
}

pub fn xbox360_nand(d: &[u8]) -> Option<Identified> {
    let magic = rd::at(d, 0, &[0xff, 0x4f]);
    let with_spare = RAW_SIZES
        .iter()
        .any(|&s| s / PAGE * (PAGE + SPARE) == d.len());
    let raw = RAW_SIZES.contains(&d.len());
    if !with_spare && !raw {
        return None;
    }
    let mut checked = 0;
    let mut good = 0;
    if with_spare {
        for p in 0..64usize {
            let Some(block) = d.get(p * (PAGE + SPARE)..(p + 1) * (PAGE + SPARE)) else {
                break;
            };
            let spare = &block[PAGE..];
            if spare.iter().all(|&b| b == 0xff) || spare.iter().all(|&b| b == 0) {
                continue;
            }
            checked += 1;
            if ecc_ok(block) {
                good += 1;
            }
        }
    }
    let ecc_proves = checked >= 4 && good * 4 >= checked * 3;
    let confidence = match (magic, ecc_proves) {
        (true, true) => Confidence::High,
        (true, false) => Confidence::Medium,
        (false, true) => Confidence::Medium,
        (false, false) => return None,
    };
    // without the magic only a spare layout that checks out counts; a raw size alone is no proof
    let layout = if with_spare {
        format!(
            "with spare data (0x210-byte pages), ECC valid on {good} of {checked} sampled pages"
        )
    } else {
        "raw pages without spare data".to_string()
    };
    let size = if with_spare {
        d.len() / (PAGE + SPARE) * PAGE
    } else {
        d.len()
    };
    Some(
        Identified::new(
            "xbox360-nand",
            "Xbox 360 NAND image",
            "xbox360",
            "Xbox 360",
            "image",
        )
        .confidence(confidence)
        .detail(format!(
            "{} of flash, {layout}; contents are encrypted and keyed to the console",
            kib(size as u64)
        )),
    )
}
