//! The minimum-CPU marker of x86 programs.
//!
//! Distribution objects carry a `GNU_PROPERTY_X86_ISA_1_NEEDED` property that the linker ORs
//! into the program's note, so a program that only uses baseline instructions can still say
//! "x86-64-v3 needed". The dynamic loader then refuses to start it on a CPU below that level. The
//! emulated CPU is deliberately baseline x86-64, so the marker is zeroed in the private copy the
//! emulator loads; no instruction of the program changes.

const PT_NOTE: u32 = 4;
const PT_GNU_PROPERTY: u32 = 0x6474_e553;
const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
const GNU_PROPERTY_X86_ISA_1_NEEDED: u32 = 0xc000_8002;
const EM_386: u16 = 3;
const EM_X86_64: u16 = 62;

fn u16_at(d: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        d.get(at..at.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(d: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        d.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(d: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        d.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn align(n: usize, to: usize) -> Option<usize> {
    n.checked_add(to - 1).map(|v| v & !(to - 1))
}

/// File ranges `(offset, size)` of the note segments.
fn note_ranges(d: &[u8], is64: bool) -> Option<Vec<(usize, usize)>> {
    let (phoff, phentsize, phnum) = if is64 {
        (u64_at(d, 0x20)?, u16_at(d, 0x36)?, u16_at(d, 0x38)?)
    } else {
        (
            u64::from(u32_at(d, 0x1c)?),
            u16_at(d, 0x2a)?,
            u16_at(d, 0x2c)?,
        )
    };
    let min = if is64 { 56 } else { 32 };
    if usize::from(phentsize) < min || phnum > 4096 {
        return None;
    }
    let mut out = Vec::new();
    for i in 0..usize::from(phnum) {
        let at = usize::try_from(phoff)
            .ok()?
            .checked_add(i.checked_mul(usize::from(phentsize))?)?;
        let ty = u32_at(d, at)?;
        if ty != PT_NOTE && ty != PT_GNU_PROPERTY {
            continue;
        }
        let (off, size) = if is64 {
            (u64_at(d, at + 8)?, u64_at(d, at + 32)?)
        } else {
            (
                u64::from(u32_at(d, at + 4)?),
                u64::from(u32_at(d, at + 16)?),
            )
        };
        out.push((usize::try_from(off).ok()?, usize::try_from(size).ok()?));
    }
    Some(out)
}

/// Zeroes the value of every ISA-needed property in `d`; the old value (OR of what was cleared)
/// when it was not zero. Anything it does not understand is left as it is.
fn clear(d: &mut [u8]) -> Option<u32> {
    if d.get(..4)? != b"\x7fELF" || *d.get(5)? != 1 {
        return None;
    }
    let is64 = match *d.get(4)? {
        1 => false,
        2 => true,
        _ => return None,
    };
    let machine = u16_at(d, 0x12)?;
    if machine != EM_386 && machine != EM_X86_64 {
        return None;
    }
    let pad = if is64 { 8 } else { 4 };
    let mut found = 0u32;
    let mut at_values = Vec::new();
    for (off, size) in note_ranges(d, is64)? {
        let end = off.checked_add(size)?.min(d.len());
        let mut p = off;
        while p.checked_add(12)? <= end {
            let namesz = usize::try_from(u32_at(d, p)?).ok()?;
            let descsz = usize::try_from(u32_at(d, p + 4)?).ok()?;
            let ty = u32_at(d, p + 8)?;
            let name = align(p + 12, 4)?;
            let desc = align(name.checked_add(namesz)?, 4)?;
            let next = align(desc.checked_add(descsz)?, pad)?;
            if next > end && desc.checked_add(descsz)? > end {
                break;
            }
            if ty == NT_GNU_PROPERTY_TYPE_0 && d.get(name..name.checked_add(namesz)?)? == b"GNU\0" {
                let mut q = desc;
                let desc_end = desc + descsz;
                while q.checked_add(8)? <= desc_end {
                    let pr_type = u32_at(d, q)?;
                    let pr_size = usize::try_from(u32_at(d, q + 4)?).ok()?;
                    let data = q + 8;
                    if data.checked_add(pr_size)? > desc_end {
                        break;
                    }
                    if pr_type == GNU_PROPERTY_X86_ISA_1_NEEDED && pr_size == 4 {
                        at_values.push(data);
                    }
                    q = align(data + pr_size, pad)?;
                }
            }
            p = next;
        }
    }
    for at in at_values {
        found |= u32_at(d, at)?;
        d.get_mut(at..at + 4)?.fill(0);
    }
    (found != 0).then_some(found)
}

/// Clears the x86 minimum-CPU marker of the ELF image `data` and returns the note to show, if
/// the marker was set. Never fails: input it does not understand stays as it is.
pub fn clear_isa_needed(data: &mut [u8]) -> Option<String> {
    let mut scratch = data.to_vec();
    let found = clear(&mut scratch)?;
    data.copy_from_slice(&scratch);
    let level = if found & 8 != 0 {
        "x86-64-v4"
    } else if found & 4 != 0 {
        "x86-64-v3"
    } else if found & 2 != 0 {
        "x86-64-v2"
    } else {
        "x86-64-baseline"
    };
    Some(format!(
        "Cleared the program's minimum-CPU marker ({level} needed) because the emulated CPU is \
         baseline; the program's own instructions are unchanged."
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put16(v: &mut [u8], at: usize, x: u16) {
        v[at..at + 2].copy_from_slice(&x.to_le_bytes());
    }
    fn put32(v: &mut [u8], at: usize, x: u32) {
        v[at..at + 4].copy_from_slice(&x.to_le_bytes());
    }
    fn put64(v: &mut [u8], at: usize, x: u64) {
        v[at..at + 8].copy_from_slice(&x.to_le_bytes());
    }

    /// A 64-bit ELF with one PT_GNU_PROPERTY segment; `props` are (type, value) 4-byte properties.
    fn elf64(props: &[(u32, u32)]) -> Vec<u8> {
        let mut v = vec![0u8; 64 + 56];
        v[..4].copy_from_slice(b"\x7fELF");
        v[4] = 2;
        v[5] = 1;
        put16(&mut v, 0x12, EM_X86_64);
        put64(&mut v, 0x20, 64);
        put16(&mut v, 0x36, 56);
        put16(&mut v, 0x38, 1);
        let descsz = props.len() * 16;
        let mut note = Vec::new();
        note.extend(4u32.to_le_bytes());
        note.extend((descsz as u32).to_le_bytes());
        note.extend(NT_GNU_PROPERTY_TYPE_0.to_le_bytes());
        note.extend(b"GNU\0");
        for (t, val) in props {
            note.extend(t.to_le_bytes());
            note.extend(4u32.to_le_bytes());
            note.extend(val.to_le_bytes());
            note.extend(0u32.to_le_bytes());
        }
        put32(&mut v, 64, PT_GNU_PROPERTY);
        put64(&mut v, 64 + 8, 120);
        put64(&mut v, 64 + 32, note.len() as u64);
        v.extend(note);
        v
    }

    #[test]
    fn the_needed_value_is_zeroed_and_nothing_else_changes() {
        let orig = elf64(&[(0xc000_0002, 3), (GNU_PROPERTY_X86_ISA_1_NEEDED, 7)]);
        let mut d = orig.clone();
        let note = clear_isa_needed(&mut d).expect("cleared");
        assert!(note.contains("x86-64-v3 needed"), "{note}");
        let diff: Vec<usize> = (0..d.len()).filter(|&i| d[i] != orig[i]).collect();
        assert_eq!(diff.len(), 1, "{diff:?}");
        let at = 120 + 12 + 4 + 16 + 8;
        assert_eq!(&orig[at..at + 4], &7u32.to_le_bytes());
        assert_eq!(&d[at..at + 4], &[0; 4]);
        assert!(clear_isa_needed(&mut d).is_none());
    }

    #[test]
    fn an_elf_32_note_is_handled() {
        let mut v = vec![0u8; 52 + 32];
        v[..4].copy_from_slice(b"\x7fELF");
        v[4] = 1;
        v[5] = 1;
        put16(&mut v, 0x12, EM_386);
        put32(&mut v, 0x1c, 52);
        put16(&mut v, 0x2a, 32);
        put16(&mut v, 0x2c, 1);
        let mut note = Vec::new();
        note.extend(4u32.to_le_bytes());
        note.extend(12u32.to_le_bytes());
        note.extend(NT_GNU_PROPERTY_TYPE_0.to_le_bytes());
        note.extend(b"GNU\0");
        note.extend(GNU_PROPERTY_X86_ISA_1_NEEDED.to_le_bytes());
        note.extend(4u32.to_le_bytes());
        note.extend(2u32.to_le_bytes());
        put32(&mut v, 52, PT_NOTE);
        put32(&mut v, 52 + 4, 84);
        put32(&mut v, 52 + 16, note.len() as u32);
        v.extend(note);
        let note = clear_isa_needed(&mut v).expect("cleared");
        assert!(note.contains("x86-64-v2"), "{note}");
        assert_eq!(&v[84 + 24..84 + 28], &[0; 4]);
    }

    #[test]
    fn without_the_property_nothing_changes() {
        let orig = elf64(&[(0xc000_0002, 3)]);
        let mut d = orig.clone();
        assert!(clear_isa_needed(&mut d).is_none());
        assert_eq!(d, orig);
        let orig = elf64(&[(GNU_PROPERTY_X86_ISA_1_NEEDED, 0)]);
        let mut d = orig.clone();
        assert!(clear_isa_needed(&mut d).is_none());
        assert_eq!(d, orig);
    }

    #[test]
    fn garbage_and_truncated_input_is_returned_unchanged() {
        let good = elf64(&[(GNU_PROPERTY_X86_ISA_1_NEEDED, 7)]);
        for len in 0..good.len() - 1 {
            let mut d = good[..len].to_vec();
            let orig = d.clone();
            assert!(clear_isa_needed(&mut d).is_none(), "len {len}");
            assert_eq!(d, orig, "len {len}");
        }
        let mut junk: Vec<u8> = (0..300u32).map(|i| (i * 37 + 11) as u8).collect();
        let orig = junk.clone();
        assert!(clear_isa_needed(&mut junk).is_none());
        assert_eq!(junk, orig);
        let mut huge = good.clone();
        put64(&mut huge, 64 + 32, u64::MAX);
        put32(&mut huge, 120, u32::MAX);
        let orig = huge.clone();
        let _ = clear_isa_needed(&mut huge);
        assert_eq!(huge.len(), orig.len());
    }
}
