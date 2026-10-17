//! Exception-handling frames: `.eh_frame` FDEs (one per function or function part, present even
//! in stripped binaries) and the landing pads of their LSDAs in `.gcc_except_table`. Landing
//! pads are reached only through the unwinder, so recursive descent never finds them on its own;
//! Ghidra needs its GCC exception analyzer for the same code.

use std::collections::BTreeMap;

use gimli::{BaseAddresses, CieOrFde, EhFrame, LittleEndian, Pointer, UnwindSection};

/// What the unwind tables say about code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Frames {
    /// Start addresses of every FDE, ascending (link-time addresses).
    pub fde_starts: Vec<u64>,
    /// Landing pads by the start of the FDE whose LSDA lists them (link-time addresses).
    pub landing_pads: BTreeMap<u64, Vec<u64>>,
}

/// Section addresses and bytes the parser needs, all at link-time addresses.
pub struct Sections<'a> {
    /// `.eh_frame` address and bytes.
    pub eh_frame: (u64, &'a [u8]),
    /// `.text` address, for `DW_EH_PE_textrel`.
    pub text: Option<u64>,
    /// `.got` address, for `DW_EH_PE_datarel`.
    pub got: Option<u64>,
    /// Reads bytes at a link-time address (for LSDAs); `None` when unmapped.
    pub read: &'a dyn Fn(u64, usize) -> Option<Vec<u8>>,
}

/// Parses `.eh_frame`. Malformed entries end the scan; what was read so far is kept.
pub fn parse(s: &Sections<'_>) -> Frames {
    let mut out = Frames::default();
    let (addr, bytes) = s.eh_frame;
    let eh = EhFrame::new(bytes, LittleEndian);
    let mut bases = BaseAddresses::default().set_eh_frame(addr);
    if let Some(t) = s.text {
        bases = bases.set_text(t);
    }
    if let Some(g) = s.got {
        bases = bases.set_got(g);
    }
    let mut entries = eh.entries(&bases);
    while let Ok(Some(entry)) = entries.next() {
        let CieOrFde::Fde(partial) = entry else {
            continue;
        };
        let Ok(fde) = partial.parse(EhFrame::cie_from_offset) else {
            continue;
        };
        let start = fde.initial_address();
        if start == 0 || fde.len() == 0 {
            continue;
        }
        out.fde_starts.push(start);
        let lsda = match fde.lsda() {
            Some(Pointer::Direct(a)) => a,
            Some(Pointer::Indirect(slot)) => match (s.read)(slot, 8) {
                Some(b) if b.len() == 8 => u64::from_le_bytes(b.try_into().unwrap_or([0; 8])),
                _ => continue,
            },
            None => continue,
        };
        let pads = landing_pads(lsda, start, s.read);
        if !pads.is_empty() {
            out.landing_pads.entry(start).or_default().extend(pads);
        }
    }
    out.fde_starts.sort_unstable();
    out.fde_starts.dedup();
    for pads in out.landing_pads.values_mut() {
        pads.sort_unstable();
        pads.dedup();
    }
    out
}

const DW_EH_PE_OMIT: u8 = 0xff;

/// A cursor over LSDA bytes that decodes `DW_EH_PE_*` values.
struct Cursor {
    base: u64,
    bytes: Vec<u8>,
    pos: usize,
}

impl Cursor {
    fn u8(&mut self) -> Option<u8> {
        let b = *self.bytes.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn uleb(&mut self) -> Option<u64> {
        let mut v = 0u64;
        let mut shift = 0;
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= u64::from(b & 0x7f) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
    }

    fn sleb(&mut self) -> Option<i64> {
        let mut v = 0i64;
        let mut shift = 0;
        loop {
            let b = self.u8()?;
            if shift < 64 {
                v |= i64::from(b & 0x7f) << shift;
            }
            shift += 7;
            if b & 0x80 == 0 {
                if shift < 64 && b & 0x40 != 0 {
                    v |= -1i64 << shift;
                }
                return Some(v);
            }
        }
    }

    fn fixed<const N: usize>(&mut self) -> Option<[u8; N]> {
        let s = self.bytes.get(self.pos..self.pos + N)?;
        self.pos += N;
        s.try_into().ok()
    }

    /// Reads one encoded value; only absolute and pc-relative applications are supported, which
    /// is what GCC and Clang emit in LSDAs.
    fn encoded(&mut self, enc: u8) -> Option<u64> {
        let here = self.base + self.pos as u64;
        let raw: u64 = match enc & 0x0f {
            0x00 => u64::from_le_bytes(self.fixed::<8>()?),
            0x01 => self.uleb()?,
            0x02 => u64::from(u16::from_le_bytes(self.fixed::<2>()?)),
            0x03 => u64::from(u32::from_le_bytes(self.fixed::<4>()?)),
            0x04 => u64::from_le_bytes(self.fixed::<8>()?),
            0x09 => self.sleb()? as u64,
            0x0a => i64::from(i16::from_le_bytes(self.fixed::<2>()?)) as u64,
            0x0b => i64::from(i32::from_le_bytes(self.fixed::<4>()?)) as u64,
            0x0c => i64::from_le_bytes(self.fixed::<8>()?) as u64,
            _ => return None,
        };
        match enc & 0x70 {
            0x00 => Some(raw),
            0x10 => Some(here.wrapping_add(raw)),
            _ => None,
        }
    }
}

/// The landing pads of the LSDA at `lsda` for an FDE starting at `fde_start`.
fn landing_pads(
    lsda: u64,
    fde_start: u64,
    read: &dyn Fn(u64, usize) -> Option<Vec<u8>>,
) -> Vec<u64> {
    let Some(bytes) = read(lsda, 4096) else {
        return Vec::new();
    };
    let mut c = Cursor {
        base: lsda,
        bytes,
        pos: 0,
    };
    let mut pads = Vec::new();
    let mut run = || -> Option<()> {
        let lp_enc = c.u8()?;
        let lp_start = if lp_enc == DW_EH_PE_OMIT {
            fde_start
        } else {
            c.encoded(lp_enc)?
        };
        let tt_enc = c.u8()?;
        if tt_enc != DW_EH_PE_OMIT {
            c.uleb()?;
        }
        let cs_enc = c.u8()?;
        let len = c.uleb()? as usize;
        let end = c.pos.checked_add(len)?;
        while c.pos < end {
            let _start = c.encoded(cs_enc)?;
            let _len = c.encoded(cs_enc)?;
            let lp = c.encoded(cs_enc)?;
            let _action = c.uleb()?;
            if lp != 0 {
                pads.push(lp_start.wrapping_add(lp));
            }
        }
        Some(())
    };
    let _ = run();
    pads
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lsda_call_sites_give_landing_pads() {
        // lpstart omitted, ttype omitted, call sites uleb128: two entries, the second with a pad
        let lsda = [
            0xff, 0xff, 0x01, 0x08, //
            0x00, 0x05, 0x00, 0x00, // [0, 5) no pad
            0x10, 0x04, 0x30, 0x01, // [0x10, 0x14) pad at +0x30
        ];
        let read = |a: u64, _n: usize| (a == 0x2000).then(|| lsda.to_vec());
        assert_eq!(landing_pads(0x2000, 0x1000, &read), vec![0x1030]);
        assert!(landing_pads(0x3000, 0x1000, &read).is_empty());
    }

    #[test]
    fn signed_leb_decodes_negative_values() {
        let mut c = Cursor {
            base: 0,
            bytes: vec![0x7f, 0x80, 0x7f],
            pos: 0,
        };
        assert_eq!(c.sleb(), Some(-1));
        assert_eq!(c.sleb(), Some(-128));
    }
}
