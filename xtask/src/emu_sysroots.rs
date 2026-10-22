//! `cargo xtask emu-sysroots`: extract the Debian sysroots (the dynamic loader and shared
//! libraries of armhf, arm64, riscv64, i386 and x86-64 glibc) so kraken-emu can run dynamically
//! linked programs. The first four come from the corpus build images `corpus/build.sh` builds
//! (`kraken-corpus-builder:cross` for the ARM and RISC-V sets, `kraken-corpus-builder:local`
//! with gcc-multilib for `elf32`; `KRAKEN_CORPUS_IMAGE` and `KRAKEN_CORPUS_NATIVE_IMAGE` override
//! them). The `x86_64` set comes from a plain Debian image (`debian:trixie-slim`, override
//! `KRAKEN_EMU_X86_64_IMAGE`): its glibc is built for baseline x86-64, which is what the
//! emulated CPU is; the libraries of the host (often x86-64-v3 with AVX2) cannot be used. The sysroots go to `~/.cache/kraken-dev/emu-sysroots/<set>` (override the parent with
//! `KRAKEN_EMU_SYSROOTS`). Only shared objects are kept (static archives and objects are dropped).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::Result;

const CROSS_IMAGE: &str = "kraken-corpus-builder:cross";
const NATIVE_IMAGE: &str = "kraken-corpus-builder:local";
const DEBIAN_IMAGE: &str = "debian:trixie-slim";

#[derive(PartialEq, Clone, Copy)]
enum Source {
    Cross,
    Native,
    Debian,
}

/// One sysroot: the set, which image it comes from, the directory copied out
/// of the image and where it goes in the sysroot, and relative links to create.
struct Sysroot {
    set: &'static str,
    from: Source,
    src: &'static str,
    dest: &'static str,
    links: &'static [(&'static str, &'static str)],
}

const SYSROOTS: &[Sysroot] = &[
    Sysroot {
        set: "arm32",
        from: Source::Cross,
        src: "/usr/arm-linux-gnueabihf/lib",
        dest: "lib",
        links: &[],
    },
    Sysroot {
        set: "aarch64",
        from: Source::Cross,
        src: "/usr/aarch64-linux-gnu/lib",
        dest: "lib",
        links: &[],
    },
    Sysroot {
        set: "riscv64",
        from: Source::Cross,
        src: "/usr/riscv64-linux-gnu/lib",
        dest: "lib",
        links: &[],
    },
    // gcc-multilib's i386 glibc lives in /usr/lib32; the loader is /lib/ld-linux.so.2.
    Sysroot {
        set: "elf32",
        from: Source::Native,
        src: "/usr/lib32",
        dest: "usr/lib32",
        links: &[
            ("lib32", "usr/lib32"),
            ("lib/ld-linux.so.2", "../usr/lib32/ld-linux.so.2"),
        ],
    },
    // Debian's multiarch glibc, libstdc++ and libgcc_s; the loader is found through /lib64.
    Sysroot {
        set: "x86_64",
        from: Source::Debian,
        src: "/usr/lib/x86_64-linux-gnu",
        dest: "usr/lib/x86_64-linux-gnu",
        links: &[
            ("lib", "usr/lib"),
            (
                "lib64/ld-linux-x86-64.so.2",
                "../usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            ),
        ],
    },
];

fn out_dir() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("KRAKEN_EMU_SYSROOTS").filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(p));
    }
    let home = std::env::var_os("HOME").ok_or("HOME is not set")?;
    Ok(PathBuf::from(home).join(".cache/kraken-dev/emu-sysroots"))
}

fn docker(args: &[&str]) -> Result<String> {
    let out = Command::new("docker")
        .args(args)
        .output()
        .map_err(|e| format!("docker {}: {e}", args.join(" ")))?;
    if !out.status.success() {
        return Err(format!(
            "docker {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Removes everything but shared objects (and the directories that hold them).
fn prune(dir: &Path) -> std::io::Result<u64> {
    let mut kept = 0;
    for e in std::fs::read_dir(dir)?.flatten() {
        let p = e.path();
        let meta = std::fs::symlink_metadata(&p)?;
        let name = e.file_name().to_string_lossy().into_owned();
        if meta.is_dir() {
            kept += prune(&p)?;
            continue;
        }
        if name.contains(".so") {
            kept += meta.len();
        } else {
            std::fs::remove_file(&p)?;
        }
    }
    Ok(kept)
}

fn image_present(image: &str) -> bool {
    docker(&["image", "inspect", "--format", "{{.Id}}", image]).is_ok()
}

#[cfg(unix)]
fn link(target: &str, at: &Path) -> std::io::Result<()> {
    std::os::unix::fs::symlink(target, at)
}

#[cfg(not(unix))]
fn link(_target: &str, _at: &Path) -> std::io::Result<()> {
    Err(std::io::Error::other("symbolic links need a Unix host"))
}

fn extract(image: &str, roots: &[&Sysroot], out: &Path) -> Result<()> {
    let cid = docker(&["create", image, "true"])?;
    let result = (|| -> Result<()> {
        for r in roots {
            let root = out.join(r.set);
            if root.exists() {
                std::fs::remove_dir_all(&root).map_err(|e| format!("{}: {e}", root.display()))?;
            }
            let dest = root.join(r.dest);
            let parent = dest.parent().ok_or("sysroot destination has no parent")?;
            std::fs::create_dir_all(parent).map_err(|e| format!("{}: {e}", parent.display()))?;
            docker(&[
                "cp",
                "-L",
                &format!("{cid}:{}", r.src),
                &dest.display().to_string(),
            ])?;
            let kept = prune(&dest).map_err(|e| format!("{}: {e}", dest.display()))?;
            for (at, target) in r.links {
                let at = root.join(at);
                if let Some(p) = at.parent() {
                    std::fs::create_dir_all(p).map_err(|e| format!("{}: {e}", p.display()))?;
                }
                link(target, &at).map_err(|e| format!("{}: {e}", at.display()))?;
            }
            println!(
                "{}: {} ({} MiB of shared objects)",
                r.set,
                root.display(),
                kept >> 20
            );
        }
        Ok(())
    })();
    let _ = docker(&["rm", "-f", &cid]);
    result
}

pub fn emu_sysroots() -> Result<()> {
    let cross = std::env::var("KRAKEN_CORPUS_IMAGE").unwrap_or_else(|_| CROSS_IMAGE.to_string());
    let native =
        std::env::var("KRAKEN_CORPUS_NATIVE_IMAGE").unwrap_or_else(|_| NATIVE_IMAGE.to_string());
    let out = out_dir()?;
    std::fs::create_dir_all(&out).map_err(|e| format!("{}: {e}", out.display()))?;
    let debian =
        std::env::var("KRAKEN_EMU_X86_64_IMAGE").unwrap_or_else(|_| DEBIAN_IMAGE.to_string());
    let mut done = 0;
    for (image, source, how) in [
        (&cross, Source::Cross, "corpus/build.sh arm32".to_string()),
        (&native, Source::Native, "corpus/build.sh elf32".to_string()),
        (
            &debian,
            Source::Debian,
            format!("docker pull {DEBIAN_IMAGE}"),
        ),
    ] {
        if !image_present(image) {
            eprintln!(
                "skipping the sets of {image}: the image is not present (build it with `{how}`)"
            );
            continue;
        }
        let roots: Vec<&Sysroot> = SYSROOTS.iter().filter(|r| r.from == source).collect();
        extract(image, &roots, &out)?;
        done += roots.len();
    }
    if done == 0 {
        return Err(
            "no image present; build the corpus ones with `corpus/build.sh arm32 elf32`, pull \
             debian:trixie-slim, or set KRAKEN_CORPUS_IMAGE / KRAKEN_CORPUS_NATIVE_IMAGE / \
             KRAKEN_EMU_X86_64_IMAGE"
                .into(),
        );
    }
    println!("kraken-emu finds them at {}", out.display());
    Ok(())
}
