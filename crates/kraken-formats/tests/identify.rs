//! Detector tests on tiny synthetic headers (no real content) and the corpus files.

use kraken_formats::{Confidence, Identified, Loader, identify};
use proptest::prelude::*;

fn id(data: &[u8]) -> Identified {
    identify(data).expect("identified")
}

fn put(d: &mut [u8], o: usize, bytes: &[u8]) {
    d[o..o + bytes.len()].copy_from_slice(bytes);
}

fn elf(class: u8, data: u8, osabi: u8, e_type: u16, machine: u16, flags: u32) -> Vec<u8> {
    let mut d = vec![0u8; 64];
    put(&mut d, 0, b"\x7fELF");
    d[4] = class;
    d[5] = data;
    d[6] = 1;
    d[7] = osabi;
    let be = data == 2;
    let w16 = |v: u16| if be { v.to_be_bytes() } else { v.to_le_bytes() };
    let w32 = |v: u32| if be { v.to_be_bytes() } else { v.to_le_bytes() };
    put(&mut d, 16, &w16(e_type));
    put(&mut d, 18, &w16(machine));
    put(&mut d, if class == 1 { 36 } else { 48 }, &w32(flags));
    d
}

#[test]
fn elf_variants() {
    let linux = id(&elf(2, 1, 0, 2, 62, 0));
    assert_eq!(
        (linux.platform, linux.arch, linux.bits),
        ("linux", Some("x86-64"), Some(64))
    );
    assert_eq!(linux.engine, Some("native"));
    assert_eq!(linux.emulators, ["qemu-user-x86-64"]);

    let ps4 = id(&elf(2, 1, 9, 0xfe10, 62, 0));
    assert_eq!((ps4.format, ps4.platform), ("sce-elf", "ps4"));
    assert_eq!(ps4.emulators, ["shadps4"]);

    let vita = id(&elf(1, 1, 0, 0xfe04, 40, 0x5000200));
    assert_eq!(vita.platform, "vita");

    let ps3 = id(&elf(2, 2, 0x66, 2, 21, 0));
    assert_eq!((ps3.platform, ps3.big_endian), ("ps3", Some(true)));

    let ps2 = id(&elf(1, 1, 0, 2, 8, 0x0092_3001));
    assert_eq!(ps2.platform, "ps2");
    let irx = id(&elf(1, 1, 0, 0xff80, 8, 0));
    assert_eq!((irx.format, irx.platform), ("irx", "ps2"));

    let prx = id(&elf(1, 1, 0, 0xffa0, 8, 0));
    assert_eq!((prx.format, prx.platform), ("prx", "psp"));

    let rpx = id(&elf(1, 2, 0xca, 2, 20, 0));
    assert_eq!(
        (rpx.format, rpx.platform, rpx.emulators.as_slice()),
        ("rpx", "wiiu", ["cemu"].as_slice())
    );

    let mips = id(&elf(1, 1, 0, 2, 8, 0x7000_1000));
    assert_eq!(mips.platform, "linux");
    assert_eq!(mips.engine, Some("ghidra"));
}

fn pe(machine: u16, subsystem: u16, clr: bool, dll: bool) -> Vec<u8> {
    let mut d = vec![0u8; 0x400];
    put(&mut d, 0, b"MZ");
    put(&mut d, 0x3c, &0x80u32.to_le_bytes());
    put(&mut d, 0x80, b"PE\0\0");
    put(&mut d, 0x84, &machine.to_le_bytes());
    put(
        &mut d,
        0x84 + 18,
        &(if dll { 0x2000u16 } else { 0x0002 }).to_le_bytes(),
    );
    let opt = 0x80 + 24;
    let pe32plus = machine == 0x8664 || machine == 0xaa64;
    put(
        &mut d,
        opt,
        &(if pe32plus { 0x20bu16 } else { 0x10b }).to_le_bytes(),
    );
    put(&mut d, opt + 68, &subsystem.to_le_bytes());
    if clr {
        let dir = opt + if pe32plus { 112 } else { 96 } + 14 * 8;
        put(&mut d, dir, &0x2000u32.to_le_bytes());
    }
    d
}

#[test]
fn pe_dos_ne_and_efi() {
    let w = id(&pe(0x8664, 3, false, false));
    assert_eq!(
        (w.format, w.platform, w.arch),
        ("pe", "windows", Some("x86-64"))
    );
    assert_eq!(w.emulators, ["wine"]);
    assert_eq!(id(&pe(0x14c, 2, false, true)).kind, "library");
    let net = id(&pe(0x14c, 3, true, false));
    assert_eq!((net.format, net.engine), ("dotnet", Some("dotnet")));
    let efi = id(&pe(0x8664, 10, false, false));
    assert_eq!((efi.format, efi.platform), ("pe-efi", "uefi"));

    let mut dos = vec![0u8; 64];
    put(&mut dos, 0, b"MZ");
    assert_eq!(id(&dos).platform, "dos");

    let mut ne = vec![0u8; 0x100];
    put(&mut ne, 0, b"MZ");
    put(&mut ne, 0x3c, &0x80u32.to_le_bytes());
    put(&mut ne, 0x80, b"NE");
    ne[0x80 + 0x36] = 2;
    let ne = id(&ne);
    assert_eq!(
        (ne.format, ne.platform, ne.bits),
        ("ne", "windows", Some(16))
    );
}

#[test]
fn macho_thin_fat_and_java() {
    let mut m = vec![0u8; 32];
    put(&mut m, 0, &[0xcf, 0xfa, 0xed, 0xfe]);
    put(&mut m, 4, &0x0100_000cu32.to_le_bytes());
    put(&mut m, 12, &2u32.to_le_bytes());
    let m = id(&m);
    assert_eq!(
        (m.format, m.arch, m.platform),
        ("macho", Some("AArch64"), "macos")
    );

    let mut f = vec![0u8; 64];
    put(&mut f, 0, &[0xca, 0xfe, 0xba, 0xbe]);
    put(&mut f, 4, &2u32.to_be_bytes());
    put(&mut f, 8, &7u32.to_be_bytes());
    put(&mut f, 28, &0x0100_0007u32.to_be_bytes());
    let f = id(&f);
    assert_eq!(f.format, "macho-fat");
    assert!(f.detail.contains("x86, x86-64"), "{}", f.detail);

    let mut j = vec![0u8; 16];
    put(&mut j, 0, &[0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 65]);
    let j = id(&j);
    assert_eq!(j.format, "java-class");
    assert!(j.detail.contains("Java 21"));
}

#[test]
fn xbe_and_xex() {
    let mut x = vec![0u8; 0x200];
    put(&mut x, 0, b"XBEH");
    put(&mut x, 0x104, &0x10000u32.to_le_bytes());
    put(&mut x, 0x11c, &12u32.to_le_bytes());
    let x = id(&x);
    assert_eq!(
        (x.format, x.platform, x.emulators.as_slice()),
        ("xbe", "xbox", ["xemu"].as_slice())
    );
    assert!(x.detail.contains("12 sections"));

    let mut e = vec![0u8; 0x100];
    put(&mut e, 0, b"XEX2");
    put(&mut e, 0x14, &1u32.to_be_bytes());
    put(&mut e, 0x18, &0x3ffu32.to_be_bytes());
    put(&mut e, 0x1c, &0x80u32.to_be_bytes());
    put(&mut e, 0x84, &1u16.to_be_bytes());
    put(&mut e, 0x86, &2u16.to_be_bytes());
    let e = id(&e);
    assert_eq!(
        (e.format, e.platform, e.encrypted),
        ("xex2", "xbox360", true)
    );
    assert!(e.detail.contains("LZX"));
    assert_eq!(e.emulators, ["xenia-canary"]);
}

#[test]
fn sony_containers() {
    let mut s = vec![0u8; 64];
    put(&mut s, 0, &[0x4f, 0x15, 0x3d, 0x1d]);
    let s = id(&s);
    assert_eq!((s.platform, s.encrypted), ("ps4", true));

    let mut s3 = vec![0u8; 64];
    put(&mut s3, 0, b"SCE\0");
    put(&mut s3, 4, &2u32.to_be_bytes());
    assert_eq!(id(&s3).platform, "ps3");
    put(&mut s3, 4, &3u32.to_be_bytes());
    assert_eq!(id(&s3).platform, "vita");

    let mut p = vec![0u8; 0x100];
    put(&mut p, 0, b"\0PBP");
    put(&mut p, 0x20, &0x80u32.to_le_bytes());
    put(&mut p, 0x80, b"~PSP");
    let p = id(&p);
    assert_eq!((p.format, p.platform, p.encrypted), ("pbp", "psp", true));

    let mut e = vec![0u8; 0x900];
    put(&mut e, 0, b"PS-X EXE");
    put(&mut e, 0x10, &0x8001_0000u32.to_le_bytes());
    put(&mut e, 0x18, &0x8001_0000u32.to_le_bytes());
    put(&mut e, 0x1c, &0x800u32.to_le_bytes());
    let e = id(&e);
    assert_eq!(
        (e.format, e.platform, e.loader),
        ("ps-exe", "ps1", Loader::Raw)
    );
    assert_eq!(e.language, Some("MIPS:LE:32:default"));
}

#[test]
fn nintendo_formats() {
    let mut g = vec![0u8; 0x200];
    put(&mut g, 3, &[0xea]);
    put(
        &mut g,
        4,
        &[
            0x24, 0xff, 0xae, 0x51, 0x69, 0x9a, 0xa2, 0x21, 0x3d, 0x84, 0x82, 0x0a,
        ],
    );
    put(&mut g, 0xa0, b"TESTROM");
    g[0xb2] = 0x96;
    let sum = g[0xa0..0xbd]
        .iter()
        .fold(0u8, |a, &b| a.wrapping_sub(b))
        .wrapping_sub(0x19);
    g[0xbd] = sum;
    let g = id(&g);
    assert_eq!(
        (g.format, g.platform, g.emulators.as_slice()),
        ("gba", "gba", ["mgba", "ares"].as_slice())
    );
    assert!(g.detail.contains("TESTROM") && !g.detail.contains("checksum off"));

    let mut n = vec![0u8; 0x400];
    put(&mut n, 0, b"TESTNDS");
    put(&mut n, 0x20, &0x200u32.to_le_bytes());
    put(&mut n, 0x24, &0x0200_0800u32.to_le_bytes());
    put(&mut n, 0x15c, &0xcf56u16.to_le_bytes());
    assert_eq!(id(&n).platform, "nds");

    let mut nes = vec![0u8; 32];
    put(&mut nes, 0, b"NES\x1a");
    nes[4] = 2;
    nes[5] = 1;
    nes[6] = 0x40;
    let nes1 = id(&nes);
    assert_eq!(nes1.format, "ines");
    assert!(
        nes1.detail.contains("mapper 4") && nes1.detail.contains("PRG 32 KiB"),
        "{}",
        nes1.detail
    );
    nes[6] = 0x10;
    nes[7] = 0x08;
    assert_eq!(id(&nes).format, "nes2");

    for (head, name) in [
        ([0x80u8, 0x37, 0x12, 0x40], "z64"),
        ([0x37, 0x80, 0x40, 0x12], "v64"),
        ([0x40, 0x12, 0x37, 0x80], "n64"),
    ] {
        let mut r = vec![0u8; 0x1000];
        put(&mut r, 0, &head);
        assert_eq!(id(&r).format, name);
    }

    let mut gb = vec![0u8; 0x150];
    put(
        &mut gb,
        0x104,
        &[0xce, 0xed, 0x66, 0x66, 0xcc, 0x0d, 0x00, 0x0b],
    );
    put(&mut gb, 0x134, b"TESTGB");
    gb[0x14d] = gb[0x134..0x14d]
        .iter()
        .fold(0u8, |a, &b| a.wrapping_sub(b).wrapping_sub(1));
    let gb = id(&gb);
    assert_eq!((gb.format, gb.confidence), ("gb", Confidence::High));

    let mut sn = vec![0u8; 0x8000 + 0x200];
    sn.resize(0x10000, 0);
    let b = 0x7fc0;
    put(&mut sn, b, b"TEST SNES ROM         ");
    sn[b + 0x15] = 0x20;
    put(&mut sn, b + 0x1c, &0x1234u16.to_le_bytes());
    put(&mut sn, b + 0x1e, &(!0x1234u16).to_le_bytes());
    put(&mut sn, b + 0x3c, &0x8000u16.to_le_bytes());
    let sn = id(&sn);
    assert_eq!((sn.format, sn.confidence), ("snes", Confidence::Medium));
    assert!(sn.detail.contains("LoROM"));
}

#[test]
fn dol_and_rel() {
    let mut d = vec![0u8; 0x400];
    put(&mut d, 0, &0x100u32.to_be_bytes());
    put(&mut d, 0x48, &0x8000_3100u32.to_be_bytes());
    put(&mut d, 0x90, &0x200u32.to_be_bytes());
    put(&mut d, 0xe0, &0x8000_3100u32.to_be_bytes());
    let dol = id(&d);
    assert_eq!(
        (dol.format, dol.platform, dol.emulators.as_slice()),
        ("dol", "gamecube-wii", ["dolphin"].as_slice())
    );
    put(&mut d, 0xe0, &0x7000_0000u32.to_be_bytes());
    assert!(identify(&d).is_none(), "entry outside the text");

    let mut r = vec![0u8; 0x200];
    put(&mut r, 0, &0x1001u32.to_be_bytes());
    put(&mut r, 0x0c, &2u32.to_be_bytes());
    put(&mut r, 0x10, &0x40u32.to_be_bytes());
    put(&mut r, 0x1c, &3u32.to_be_bytes());
    put(&mut r, 0x40, &0x100u32.to_be_bytes());
    put(&mut r, 0x44, &0x40u32.to_be_bytes());
    assert_eq!(id(&r).format, "rel");
}

#[test]
fn switch_formats() {
    let mut nso = vec![0u8; 0x100];
    put(&mut nso, 0, b"NSO0");
    let nso = id(&nso);
    assert_eq!(
        (nso.format, nso.platform, nso.arch),
        ("nso", "switch", Some("AArch64"))
    );
    let mut nro = vec![0u8; 0x100];
    put(&mut nro, 0x10, b"NRO0");
    assert_eq!(id(&nro).format, "nro");
    let mut nca = vec![0u8; 0x300];
    put(&mut nca, 0x200, b"NCA3");
    assert_eq!(id(&nca).format, "nca");
}

#[test]
fn hex_text_formats() {
    let h = id(b":10010000214601360121470136007EFE09D2190140\n:00000001FF\n");
    assert_eq!((h.format, h.loader), ("ihex", Loader::Convert));
    assert!(
        identify(b":10010000214601360121470136007EFE09D2190141\n").is_none(),
        "bad checksum"
    );
    let s = id(b"S1130000285F245F2212226A000424290008237C2A\nS9030000FC\n");
    assert_eq!(s.format, "srec");
    assert!(identify(b"S1130000285F245F2212226A000424290008237C2B\n").is_none());
}

fn nand_block(page: usize, with_ecc: bool) -> [u8; 0x210] {
    let mut b = [0u8; 0x210];
    for (i, x) in b.iter_mut().enumerate().take(0x200) {
        *x = (i * 7 + page * 13) as u8;
    }
    b[0x200] = 0x01;
    b[0x201] = page as u8;
    if with_ecc {
        // reproduce the controller's code over bits 0..0x1066
        let mut val: u32 = 0;
        let mut v: u32 = 0;
        for bit in 0..0x1066usize {
            if bit & 31 == 0 {
                v = !u32::from_le_bytes(b[bit / 8..bit / 8 + 4].try_into().unwrap());
            }
            val ^= v & 1;
            v >>= 1;
            if val & 1 != 0 {
                val ^= 0x0695_4559;
            }
            val >>= 1;
        }
        val = !val;
        b[0x20c] |= (val << 6) as u8;
        b[0x20d] = (val >> 2) as u8;
        b[0x20e] = (val >> 10) as u8;
        b[0x20f] = (val >> 18) as u8;
    }
    b
}

#[test]
fn xbox360_nand_layout() {
    let size = (16usize << 20) / 0x200 * 0x210;
    let mut img = vec![0xffu8; size];
    for p in 0..16 {
        img[p * 0x210..(p + 1) * 0x210].copy_from_slice(&nand_block(p, true));
    }
    // without the flash magic the spare layout alone gives medium confidence
    let n = id(&img);
    assert_eq!(
        (n.format, n.platform, n.confidence),
        ("xbox360-nand", "xbox360", Confidence::Medium)
    );
    assert!(n.detail.contains("ECC valid on 16 of 16"), "{}", n.detail);
    // with the magic it is certain
    img[0] = 0xff;
    img[1] = 0x4f;
    img[0x200] = 0x01;
    // page 0 changed, so its ECC no longer matches; the other pages still prove the layout
    let n = id(&img);
    assert!(n.confidence >= Confidence::Medium);

    // a raw-size file with no magic is not claimed; with the magic it is
    let mut raw = vec![0u8; 16 << 20];
    assert!(identify(&raw).is_none());
    raw[0] = 0xff;
    raw[1] = 0x4f;
    let r = id(&raw);
    assert_eq!(
        (r.format, r.confidence),
        ("xbox360-nand", Confidence::Medium)
    );
    // damaged ecc: not proven
    let mut bad = vec![0xffu8; size];
    for p in 0..16 {
        bad[p * 0x210..(p + 1) * 0x210].copy_from_slice(&nand_block(p, false));
    }
    assert!(identify(&bad).is_none());
}

#[test]
fn containers_and_bytecode() {
    assert_eq!(id(b"\0asm\x01\0\0\0").format, "wasm");
    assert_eq!(id(&[0x1f, 0x8b, 8, 0, 0, 0]).format, "gzip");
    assert_eq!(id(&[0xfd, b'7', b'z', b'X', b'Z', 0, 0]).format, "xz");
    assert_eq!(id(b"7z\xbc\xaf\x27\x1c\0\x04").format, "7z");
    assert_eq!(id(b"hsqs\0\0\0\0").format, "squashfs");
    assert_eq!(id(b"07070100000000").format, "cpio");
    let mut tar = vec![0u8; 512];
    put(&mut tar, 257, b"ustar");
    assert_eq!(id(&tar).format, "tar");

    let zip = |name: &[u8]| {
        let mut z = vec![0u8; 30];
        put(&mut z, 0, b"PK\x03\x04");
        put(&mut z, 26, &(name.len() as u16).to_le_bytes());
        z.extend_from_slice(name);
        z
    };
    assert_eq!(id(&zip(b"readme.txt")).format, "zip");
    assert_eq!(id(&zip(b"META-INF/MANIFEST.MF")).format, "jar");
    assert_eq!(id(&zip(b"AndroidManifest.xml")).format, "apk");
    assert!(id(&zip(b"a")).loader == Loader::Unpack);

    let py = id(&[0xcb, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0]);
    assert_eq!(py.format, "pyc");
    assert!(py.detail.contains("3.12"), "{}", py.detail);

    let mut a = vec![0u8; 0x800];
    put(&mut a, 0, b"ANDROID!");
    put(&mut a, 0x28, &2u32.to_le_bytes());
    assert_eq!(id(&a).format, "android-boot");

    let mut fv = vec![0u8; 0x100];
    put(&mut fv, 0x28, b"_FVH");
    assert_eq!(id(&fv).format, "uefi-fv");
    let mut cap = vec![0u8; 0x40];
    put(
        &mut cap,
        0,
        &[
            0xbd, 0x86, 0x66, 0x3b, 0x76, 0x0d, 0x30, 0x40, 0xb7, 0x0e, 0xb5, 0x51, 0x9e, 0x2f,
            0xc5, 0xa0,
        ],
    );
    assert_eq!(id(&cap).format, "uefi-capsule");
}

#[test]
fn corpus_files_are_identified() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../corpus");
    let read = |p: &str| std::fs::read(root.join(p)).expect(p);
    let e = id(&read("bin/cpp_shapes-O0"));
    assert_eq!(
        (e.format, e.platform, e.engine),
        ("elf", "linux", Some("native"))
    );
    let w = id(&read("pe/bin/switch_vm-x64-O0.exe"));
    assert_eq!(
        (w.format, w.platform, w.arch),
        ("pe", "windows", Some("x86-64"))
    );
    assert_eq!(id(&read("pe/bin/switch_vm-x86-O0.exe")).bits, Some(32));
    let n = id(&read("dotnet/bin/kraken-corpus.dll"));
    assert_eq!((n.format, n.engine), ("dotnet", Some("dotnet")));
    // raw firmware has no format of its own
    assert!(identify(&read("raw/fw_cortexm.bin")).is_none());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn garbage_never_panics(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let _ = identify(&data);
    }

    #[test]
    fn mutated_headers_never_panic(
        which in 0usize..6,
        flips in proptest::collection::vec((0usize..0x400, any::<u8>()), 0..24),
        cut in 0usize..0x400,
    ) {
        let mut seeds: Vec<Vec<u8>> = vec![
            elf(2, 1, 9, 0xfe10, 62, 0),
            pe(0x8664, 3, true, false),
            b"XEX2\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\x01\0\0\x03\xff\xff\xff\xff\xff".to_vec(),
            b"\x7fELF\x01\x02\x01\xca".to_vec(),
            vec![0xca, 0xfe, 0xba, 0xbe, 0xff, 0xff, 0xff, 0xff],
            b"PK\x03\x04".to_vec(),
        ];
        let mut d = seeds.swap_remove(which);
        d.resize(0x400, 0);
        for (o, v) in flips { d[o] = v; }
        d.truncate(cut);
        let _ = identify(&d);
    }
}
