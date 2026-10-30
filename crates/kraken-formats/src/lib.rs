//! One detector for file format and platform.
//!
//! [`identify`] looks at the first bytes of a file (and, for a few formats, the structure behind
//! them) and says what it is: format, platform, processor, byte order, how KRAKEN can open it and
//! which emulators of the integrations catalogue can run it. It is a pure parser: every read is
//! bounds checked, nothing is allocated from sizes in the file, nothing is decrypted or
//! decompressed, and no input makes it panic.

mod containers;
mod elf;
mod handheld;
mod nand;
mod native;
pub mod scan;
mod text;

/// How sure the detector is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Confidence {
    /// A guess from a layout that can occur by chance.
    Low,
    /// Several structure checks agree, but the format has no magic number.
    Medium,
    /// A magic number, or a checksum that only a real header satisfies.
    High,
}

impl Confidence {
    /// `low`, `medium` or `high`.
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

/// How KRAKEN can open the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Loader {
    /// A program the native or Ghidra loaders read (ELF, PE, Mach-O, .NET).
    Program,
    /// No loader reads the container, but the code inside can be opened as a raw image with the
    /// processor in `language`.
    Raw,
    /// A container or archive: unpack it and open what is inside.
    Unpack,
    /// A text encoding of an image (Intel HEX, S-record): convert it to binary first.
    Convert,
    /// Identified, but KRAKEN has nothing to open it with (encrypted, or no loader yet).
    None,
}

impl Loader {
    /// `program`, `raw`, `unpack`, `convert` or `none`.
    pub fn as_str(self) -> &'static str {
        match self {
            Loader::Program => "program",
            Loader::Raw => "raw",
            Loader::Unpack => "unpack",
            Loader::Convert => "convert",
            Loader::None => "none",
        }
    }
}

/// What a file is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identified {
    /// Format id, such as `xbe`, `xex2`, `dol`, `gba`, `elf`.
    pub format: &'static str,
    /// The format in plain words.
    pub format_name: &'static str,
    /// Platform id, such as `linux`, `windows`, `xbox`, `xbox360`, `gamecube-wii`, `ps1`, `gba`.
    pub platform: &'static str,
    /// The platform in plain words.
    pub platform_name: &'static str,
    /// `executable`, `library`, `object`, `rom`, `image`, `container`, `bytecode`, `module`.
    pub kind: &'static str,
    /// Processor in plain words; `None` when the format does not say.
    pub arch: Option<&'static str>,
    /// 16, 32 or 64.
    pub bits: Option<u8>,
    /// True for big endian, false for little endian.
    pub big_endian: Option<bool>,
    /// A Ghidra language id for opening the code as a raw image or with Ghidra, when one is sure.
    pub language: Option<&'static str>,
    /// The engine that opens it when the loader is [`Loader::Program`]: `native`, `ghidra` or
    /// `dotnet`.
    pub engine: Option<&'static str>,
    /// How it can be opened.
    pub loader: Loader,
    /// True when the code is encrypted; KRAKEN never decrypts anything.
    pub encrypted: bool,
    /// Ids of the catalogue emulators that run it, best first.
    pub emulators: Vec<&'static str>,
    /// Facts read from the header, in a sentence (`mapper 4, 32 KiB PRG`).
    pub detail: String,
    /// How sure the detector is.
    pub confidence: Confidence,
}

impl Identified {
    pub(crate) fn new(
        format: &'static str,
        format_name: &'static str,
        platform: &'static str,
        platform_name: &'static str,
        kind: &'static str,
    ) -> Identified {
        Identified {
            format,
            format_name,
            platform,
            platform_name,
            kind,
            arch: None,
            bits: None,
            big_endian: None,
            language: None,
            engine: None,
            loader: Loader::None,
            encrypted: false,
            emulators: Vec::new(),
            detail: String::new(),
            confidence: Confidence::High,
        }
    }

    pub(crate) fn cpu(mut self, arch: &'static str, bits: u8, big_endian: bool) -> Self {
        self.arch = Some(arch);
        self.bits = Some(bits);
        self.big_endian = Some(big_endian);
        self
    }

    pub(crate) fn language(mut self, id: &'static str) -> Self {
        self.language = Some(id);
        self
    }

    pub(crate) fn loader(mut self, l: Loader) -> Self {
        self.loader = l;
        self
    }

    pub(crate) fn run_with(mut self, ids: &[&'static str]) -> Self {
        self.emulators = ids.to_vec();
        self
    }

    pub(crate) fn detail(mut self, d: impl Into<String>) -> Self {
        self.detail = d.into();
        self
    }

    pub(crate) fn encrypted(mut self) -> Self {
        self.encrypted = true;
        self
    }

    pub(crate) fn confidence(mut self, c: Confidence) -> Self {
        self.confidence = c;
        self
    }

    /// One line for people: `Game Boy Advance ROM (Game Boy Advance): ARM7TDMI, 32-bit`.
    pub fn describe(&self) -> String {
        let mut s = format!("{} ({})", self.format_name, self.platform_name);
        let mut facts = Vec::new();
        if let Some(a) = self.arch {
            facts.push(a.to_string());
        }
        if let Some(b) = self.bits {
            facts.push(format!("{b}-bit"));
        }
        if let Some(be) = self.big_endian {
            facts.push(if be { "big endian" } else { "little endian" }.to_string());
        }
        if !self.detail.is_empty() {
            facts.push(self.detail.clone());
        }
        if self.encrypted {
            facts.push("encrypted".to_string());
        }
        if !facts.is_empty() {
            s.push_str(": ");
            s.push_str(&facts.join(", "));
        }
        s
    }
}

type Detector = fn(&[u8]) -> Option<Identified>;

/// Detectors with a magic number first (cheap and certain), then the layout heuristics.
const DETECTORS: &[Detector] = &[
    elf::elf,
    native::mz,
    native::macho,
    native::java_class,
    handheld::xbe,
    handheld::xex,
    handheld::sce,
    handheld::pbp,
    handheld::psx_exe,
    handheld::nes,
    handheld::switch,
    containers::wasm,
    containers::pyc,
    containers::android_boot,
    containers::uefi,
    containers::archive,
    handheld::gba,
    handheld::nds,
    handheld::gameboy,
    handheld::n64,
    handheld::snes,
    handheld::dol,
    handheld::rel,
    text::intel_hex,
    text::srec,
    nand::xbox360_nand,
];

/// What `data` is, or `None` when no known format matches. `data` is the start of the file, as
/// much as is at hand; formats whose identifying structure lies beyond it are not recognised. The
/// Xbox 360 NAND check also uses the length of `data`, so pass the whole file for it.
pub fn identify(data: &[u8]) -> Option<Identified> {
    DETECTORS.iter().find_map(|d| d(data))
}

/// Little helpers for reading a byte slice without panicking.
pub(crate) mod rd {
    pub fn u8(d: &[u8], o: usize) -> Option<u8> {
        d.get(o).copied()
    }
    pub fn bytes<const N: usize>(d: &[u8], o: usize) -> Option<[u8; N]> {
        d.get(o..o.checked_add(N)?)?.try_into().ok()
    }
    pub fn u16le(d: &[u8], o: usize) -> Option<u16> {
        bytes(d, o).map(u16::from_le_bytes)
    }
    pub fn u16be(d: &[u8], o: usize) -> Option<u16> {
        bytes(d, o).map(u16::from_be_bytes)
    }
    pub fn u32le(d: &[u8], o: usize) -> Option<u32> {
        bytes(d, o).map(u32::from_le_bytes)
    }
    pub fn u32be(d: &[u8], o: usize) -> Option<u32> {
        bytes(d, o).map(u32::from_be_bytes)
    }
    pub fn at(d: &[u8], o: usize, magic: &[u8]) -> bool {
        o.checked_add(magic.len())
            .and_then(|e| d.get(o..e))
            .is_some_and(|s| s == magic)
    }
    /// Printable ASCII text of `d[o..o+n]` with trailing NULs and spaces cut; `None` when a byte
    /// is not printable.
    pub fn ascii(d: &[u8], o: usize, n: usize) -> Option<String> {
        let s = d.get(o..o.checked_add(n)?)?;
        let end = s
            .iter()
            .rposition(|&b| b != 0 && b != b' ')
            .map_or(0, |i| i + 1);
        let s = &s[..end];
        s.iter()
            .all(|b| (0x20..0x7f).contains(b))
            .then(|| String::from_utf8_lossy(s).into_owned())
    }
}

pub(crate) fn kib(n: u64) -> String {
    if n >= 1 << 20 && n.is_multiple_of(1 << 20) {
        format!("{} MiB", n >> 20)
    } else {
        format!("{} KiB", n.div_ceil(1024))
    }
}
