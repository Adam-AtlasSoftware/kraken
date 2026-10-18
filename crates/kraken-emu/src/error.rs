//! Errors of the emulation layer.

/// Why an emulation could not be set up or driven. How a guest run ended (exit, fault, budget)
/// is not an error: see [`crate::Stop`] and [`crate::linux::ProgramOutcome`].
#[derive(Debug, thiserror::Error)]
pub enum EmuError {
    /// The program file could not be read or has the wrong shape.
    #[error("image: {0}")]
    Image(String),
    /// No spec root holds the SLEIGH sources of this architecture.
    #[error(
        "no SLEIGH specification for {arch}: none of these spec roots has `{ldefs}` and its \
         .slaspec: {tried}. Set KRAKEN_NATIVE_SPECS or KRAKEN_GHIDRA_HOME to a Ghidra tree \
         (`kraken setup` provisions one)"
    )]
    NoSpecs {
        /// The architecture.
        arch: crate::Arch,
        /// The `.ldefs` file looked for.
        ldefs: &'static str,
        /// The roots tried, comma separated.
        tried: String,
    },
    /// A dynamically linked program needs its C library and loader, which come from a sysroot.
    #[error(
        "{binary} is dynamically linked (interpreter {interp}) and needs a {arch} sysroot with that \
         loader and its libraries: pass one (RunSpec::sysroot), or run `cargo xtask emu-sysroots` \
         to extract the Debian cross sysroots; statically linked programs need none"
    )]
    NeedsSysroot {
        /// The program.
        binary: String,
        /// Its `PT_INTERP`.
        interp: String,
        /// Its architecture.
        arch: crate::Arch,
    },
    /// The emulator could not be built or driven.
    #[error("emulator: {0}")]
    Emulator(String),
    /// Something outside what the layer supports.
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// Host I/O around the run (the private directory, the confined runner).
    #[error("{0}")]
    Io(String),
}

pub(crate) fn emu(e: impl std::fmt::Debug) -> EmuError {
    EmuError::Emulator(format!("{e:?}"))
}
