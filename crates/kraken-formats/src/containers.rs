//! Bytecode, firmware containers, archives and file systems.

use crate::{Identified, Loader, rd};

pub fn wasm(d: &[u8]) -> Option<Identified> {
    if !rd::at(d, 0, b"\0asm") {
        return None;
    }
    let v = rd::u32le(d, 4)?;
    let (name, detail) = match v {
        1 => ("WebAssembly module", "core module, version 1"),
        0x0001_000d => ("WebAssembly component", "component model, version 1"),
        _ => return None,
    };
    Some(Identified::new("wasm", name, "wasm", "WebAssembly", "bytecode").detail(detail))
}

pub fn pyc(d: &[u8]) -> Option<Identified> {
    if !rd::at(d, 2, b"\r\n") {
        return None;
    }
    let m = rd::u16le(d, 0)?;
    let ver = match m {
        62211 => "2.7",
        3360..=3379 => "3.6",
        3390..=3399 => "3.7",
        3400..=3419 => "3.8",
        3420..=3429 => "3.9",
        3430..=3449 => "3.10",
        3450..=3499 => "3.11",
        3500..=3549 => "3.12",
        3550..=3599 => "3.13",
        3600..=3699 => "3.14",
        3000..=3359 => "3.0 to 3.5",
        _ => return None,
    };
    Some(
        Identified::new("pyc", "Python bytecode", "python", "CPython", "bytecode")
            .detail(format!("Python {ver} (magic {m})")),
    )
}

pub fn android_boot(d: &[u8]) -> Option<Identified> {
    if rd::at(d, 0, b"ANDROID!") {
        let ver = rd::u32le(d, 0x28)?;
        let kernel = rd::u32le(d, 8)?;
        return Some(
            Identified::new("android-boot", "Android boot image", "android", "Android", "image")
                .loader(Loader::Unpack)
                .detail(format!(
                    "header v{ver}, kernel {} (unpack kernel and ramdisk, then open the kernel as ARM or AArch64)",
                    crate::kib(kernel as u64)
                )),
        );
    }
    if rd::at(d, 0, b"VNDRBOOT") {
        return Some(
            Identified::new(
                "android-vendor-boot",
                "Android vendor boot image",
                "android",
                "Android",
                "image",
            )
            .loader(Loader::Unpack),
        );
    }
    None
}

const CAPSULE_GUIDS: [([u8; 16], &str); 2] = [
    (
        [
            0xbd, 0x86, 0x66, 0x3b, 0x76, 0x0d, 0x30, 0x40, 0xb7, 0x0e, 0xb5, 0x51, 0x9e, 0x2f,
            0xc5, 0xa0,
        ],
        "EFI capsule",
    ),
    (
        [
            0xed, 0xd5, 0xcb, 0x6d, 0x2d, 0xe8, 0x44, 0x4c, 0xbd, 0xa1, 0x71, 0x94, 0x19, 0x9a,
            0xd9, 0x2a,
        ],
        "UEFI firmware-management capsule",
    ),
];

pub fn uefi(d: &[u8]) -> Option<Identified> {
    let mk = |f, n, k| {
        Identified::new(f, n, "uefi", "UEFI / PC firmware", k)
            .loader(Loader::Unpack)
            .cpu("x86", 32, false)
    };
    let guid: [u8; 16] = rd::bytes(d, 0)?;
    if let Some((_, n)) = CAPSULE_GUIDS.iter().find(|(g, _)| *g == guid) {
        let header = rd::u32le(d, 16).unwrap_or(0);
        return Some(
            mk("uefi-capsule", n, "container").detail(format!("header {header:#x} bytes")),
        );
    }
    if rd::at(d, 0x28, b"_FVH") {
        let len = rd::u32le(d, 0x20).unwrap_or(0);
        return Some(
            mk("uefi-fv", "UEFI firmware volume", "container").detail(format!("{} bytes", len)),
        );
    }
    if rd::at(d, 0x10, &[0x5a, 0xa5, 0xf0, 0x0f]) {
        return Some(mk("ifd", "Intel flash image", "image").detail("flash descriptor present"));
    }
    None
}

fn zip_names(d: &[u8]) -> (bool, bool, bool) {
    // (jar, apk, other known); walks local headers while compressed sizes are known
    let (mut jar, mut apk) = (false, false);
    let mut off = 0usize;
    for _ in 0..64 {
        if !rd::at(d, off, b"PK\x03\x04") {
            break;
        }
        let (Some(flags), Some(csize), Some(n), Some(x)) = (
            rd::u16le(d, off + 6),
            rd::u32le(d, off + 18),
            rd::u16le(d, off + 26),
            rd::u16le(d, off + 28),
        ) else {
            break;
        };
        let name = d.get(off + 30..off + 30 + n as usize).unwrap_or(&[]);
        if name.starts_with(b"META-INF/") {
            jar = true;
        }
        if name == b"AndroidManifest.xml" || name == b"classes.dex" {
            apk = true;
        }
        if flags & 8 != 0 {
            break;
        }
        off = off.saturating_add(30 + n as usize + x as usize + csize as usize);
    }
    (jar, apk, false)
}

pub fn archive(d: &[u8]) -> Option<Identified> {
    let unpack = |f, n, detail: &str| {
        Identified::new(f, n, "generic", "any platform", "container")
            .loader(Loader::Unpack)
            .detail(detail.to_string())
    };
    if rd::at(d, 0, b"PK\x03\x04") {
        let (jar, apk, _) = zip_names(d);
        return Some(if apk {
            unpack(
                "apk",
                "Android package (APK)",
                "a ZIP with classes.dex and native libraries",
            )
        } else if jar {
            unpack("jar", "Java archive (JAR)", "a ZIP of .class files")
        } else {
            unpack("zip", "ZIP archive", "")
        });
    }
    if rd::at(d, 0, b"PK\x05\x06") {
        return Some(unpack("zip", "ZIP archive", "empty"));
    }
    if rd::at(d, 0, &[0x1f, 0x8b, 0x08]) {
        return Some(unpack("gzip", "gzip data", ""));
    }
    if rd::at(d, 0, &[0xfd, b'7', b'z', b'X', b'Z', 0]) {
        return Some(unpack("xz", "xz data", ""));
    }
    if rd::at(d, 0, b"7z\xbc\xaf\x27\x1c") {
        return Some(unpack("7z", "7-Zip archive", ""));
    }
    if rd::at(d, 0, b"BZh") && d.get(3).is_some_and(|b| (b'1'..=b'9').contains(b)) {
        return Some(unpack("bzip2", "bzip2 data", ""));
    }
    if rd::at(d, 0, &[0x28, 0xb5, 0x2f, 0xfd]) {
        return Some(unpack("zstd", "Zstandard data", ""));
    }
    if rd::at(d, 0, b"hsqs") {
        return Some(unpack("squashfs", "SquashFS", "little endian file system"));
    }
    if rd::at(d, 0, b"sqsh") {
        return Some(unpack("squashfs", "SquashFS", "big endian file system"));
    }
    if rd::at(d, 0, b"070701") || rd::at(d, 0, b"070702") || rd::at(d, 0, b"070707") {
        return Some(unpack(
            "cpio",
            "cpio archive",
            "ASCII format (an initramfs)",
        ));
    }
    if (rd::at(d, 0, &[0xc7, 0x71]) || rd::at(d, 0, &[0x71, 0xc7])) && d.len() >= 26 {
        return Some(unpack("cpio", "cpio archive", "binary format"));
    }
    if rd::at(d, 257, b"ustar") {
        return Some(unpack("tar", "tar archive", "POSIX ustar"));
    }
    None
}
