// What a pointer result points at, as text that is the same for the original (in the emulator)
// and the translation (in the native runner) when they agree. This file is compiled into KRAKEN
// and pasted verbatim into the function-level test runner, so both sides use the same rules.
//
// `blocks` are the heap blocks the call allocated, in allocation order, with the size asked for.
// A result inside one of them is described by the block's index, the offset and the block's
// bytes, where every aligned 8-byte word that holds an address inside one of the blocks is
// replaced by that block's index and offset (heap addresses differ between the two sides). Any
// other non-null result is described by the C string it points at (up to `STRING_BYTES`): a
// string constant lives in the program image on one side and in the Rust binary on the other,
// and callers only see what it holds.

/// Most bytes of a block shown in a description.
pub const DESCRIBED_BYTES: usize = 4096;
/// Most bytes of a string read through a pointer result.
pub const STRING_BYTES: usize = 256;

/// Describes the pointer result `p`; `read(addr, len)` reads memory.
pub fn describe_pointer(
    p: u64,
    blocks: &[(u64, usize)],
    read: &mut dyn FnMut(u64, usize) -> Vec<u8>,
) -> String {
    use std::fmt::Write as _;
    if p == 0 {
        return "null".to_string();
    }
    let block_of = |v: u64| -> Option<(usize, u64)> {
        blocks
            .iter()
            .enumerate()
            .find(|(_, (base, len))| v >= *base && v < *base + ((*len).max(1) as u64))
            .map(|(i, &(base, _))| (i, v - base))
    };
    let Some((i, off)) = block_of(p) else {
        let mut out = String::from("s:");
        for k in 0..STRING_BYTES as u64 {
            match read(p + k, 1).first() {
                None => {
                    out.push_str("<unreadable>");
                    break;
                }
                Some(0) => break,
                Some(b) => {
                    let _ = write!(out, "{b:02x}");
                }
            }
        }
        return out;
    };
    let (base, len) = blocks[i];
    let n = len.min(DESCRIBED_BYTES);
    let bytes = read(base, n);
    let mut out = format!("a{i}+{off}:{len}:");
    let mut at = 0;
    while at < bytes.len() {
        if at % 8 == 0 && at + 8 <= bytes.len() {
            let mut w = [0u8; 8];
            w.copy_from_slice(&bytes[at..at + 8]);
            if let Some((j, o)) = block_of(u64::from_le_bytes(w)) {
                let _ = write!(out, "[a{j}+{o}]");
                at += 8;
                continue;
            }
        }
        let _ = write!(out, "{:02x}", bytes[at]);
        at += 1;
    }
    out
}
