# File formats and platforms

`binary_probe` (and the Import dialog) tell you what a file is before a project exists. Beside the
ELF/PE/Mach-O details it returns a `platform` block from the `kraken-formats` detector: the format,
the platform, the processor and byte order, how sure the detector is, what KRAKEN can do with the
file and which emulators from the [integrations catalogue](integrations.md) run it.

```text
$ kraken binary_probe '{"path": "game.gba"}'
description: GBA ROM (Game Boy Advance): ARM7TDMI, 32-bit, little endian, "TESTROM" ...
platform.loader: raw
platform.language: ARM:LE:32:v4t
platform.emulators: ["mgba", "ares"]
```

## What it recognises

| Family | Formats |
| --- | --- |
| Programs | ELF (Linux and the BSDs), PE/MZ/NE (Windows, DOS, UEFI applications), .NET assemblies, Mach-O thin and universal |
| Sony | PS1 PS-X EXE, PS2 ELF and IRX, PSP PRX and EBOOT.PBP, PS3 SELF and ELF, PS4/PS5 SELF and SCE ELF, Vita SELF and ELF |
| Microsoft | Xbox XBE, Xbox 360 XEX1/XEX2 (the encryption flag is read), Xbox 360 NAND images |
| Nintendo | GameCube/Wii DOL and REL, Wii U RPX, DS, GBA, Game Boy and Color, NES (iNES and 2.0), SNES, N64 (z64, v64, n64 byte orders), Switch NSO, NRO, KIP, NSP, XCI and NCA headers |
| Firmware | Intel HEX, Motorola S-records, UEFI capsules and firmware volumes, Intel flash images, Android boot images |
| Containers | zip, jar, apk, tar, gzip, xz, bzip2, zstd, 7z, SquashFS, cpio |
| Bytecode | Java classes, Python `.pyc` (with the Python version), WebAssembly |

Formats with a magic number are `high` confidence. DOL, REL, SNES and the NAND layout checks have
no magic number; they are `medium` and rest on several header checks agreeing (offsets inside the
file, load addresses in console memory, checksum complements, ECC words in the NAND spare area).

## What KRAKEN can do

`platform.loader` says how the file opens:

- `program`: a native or Ghidra loader reads it (`platform.engine` hint, `recommended_engine`).
- `raw`: no loader for the container yet; open the code as a raw image with `platform.language`.
- `unpack`: a container; unpack it and open what is inside.
- `convert`: Intel HEX or S-record; convert to a binary first.
- `none`: identified only.

`platform.emulators` are catalogue ids you can pass to `emulator_run`. Nothing is run by the probe.

## Firmware and ROM images

A flash dump, boot ROM or update file usually has no executable header, so the probe reports it as
a file in no known format. Three things help.

**`firmware_identify`** scans the file for embedded structures and prints each with its file offset:
gzip, xz, LZMA, bzip2, Zstandard, SquashFS, cramfs, U-Boot uImage, FIT and device-tree blobs, ELF,
PE, Intel HEX and UEFI firmware volumes. Where the header gives a length it is shown. It also
returns an entropy map with one character per 4 KiB block (`0` padding to `8` compressed or
encrypted) and the runs that map makes: `padding`, `code_or_data`, `compressed_or_encrypted`.

```
kraken firmware_identify --path router.bin
```

The scan is header checks only: nothing is decompressed or run, at most the first 64 MiB are read,
at most 1000 signatures are listed (`truncated` says when a limit applied), and a hit is a
candidate, not proof. The Import wizard runs it for raw files and shows the result in the "What it
is" step.

**Loader presets** (`crates/kraken-host/data/loader_presets.toml`) are common layouts: ARM
Cortex-M with flash at `0x08000000`, `0x0` or `0x10000000`, A32 and AArch64 boot code, RISC-V RAM at
`0x80000000`, the x86 reset area and a legacy BIOS image. They hold only public architectural
facts. The raw loader page of the Import wizard has a "Preset" choice that fills in the processor and
the base address; both stay editable. A test checks that every preset names a processor the native
engine loads as a raw image (or, marked `engine = "ghidra"`, one Ghidra loads).

**The welcome screen** has "Open a firmware or ROM image...", which opens the wizard with the file
as a raw binary even if it happens to carry a known header. A file in no known format goes to the
same loader page by itself.

## Encrypted images

KRAKEN never decrypts anything. SELF files, encrypted XEX executables, encrypted PRX files and NCA
containers are reported with `platform.encrypted: true`; open a decrypted copy that you made
yourself. The NAND check reads only the flash header and the spare-area ECC; the contents stay
untouched.

## Safety

The detector is a pure parser over the first bytes of the file: every read is bounds checked, no
allocation depends on a size inside the file, and nothing is decompressed. A property test feeds it
random and mutated headers.
