//! Unpacking Debian packages: an `ar` archive whose `data.tar.xz` (or `.gz`) holds the files.
//!
//! Only what a sysroot needs: the data member goes through the same safe tar extraction as the
//! other downloads (no path leaves the directory, no link leads out of it, a size budget).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use crate::provision::{ProvisionError, extract_tar_gz, extract_tar_xz};

fn bad(deb: &Path, what: impl std::fmt::Display) -> ProvisionError {
    ProvisionError::BadArchive(format!("{}: {what}", deb.display()))
}

/// The data member of the package: its name and the byte range of its contents.
fn data_member(deb: &Path, f: &mut File) -> Result<(String, u64, u64), ProvisionError> {
    let mut magic = [0u8; 8];
    f.read_exact(&mut magic)
        .map_err(|_| bad(deb, "not a Debian package"))?;
    if &magic != b"!<arch>\n" {
        return Err(bad(deb, "not a Debian package (no ar header)"));
    }
    loop {
        let mut h = [0u8; 60];
        match f.read(&mut h[..1]) {
            Ok(0) => return Err(bad(deb, "the package has no data member")),
            Ok(_) => {}
            Err(e) => return Err(bad(deb, e)),
        }
        f.read_exact(&mut h[1..])
            .map_err(|_| bad(deb, "truncated ar header"))?;
        if &h[58..60] != b"`\n" {
            return Err(bad(deb, "damaged ar header"));
        }
        let name = String::from_utf8_lossy(&h[..16])
            .trim()
            .trim_end_matches('/')
            .to_string();
        let size: u64 = String::from_utf8_lossy(&h[48..58])
            .trim()
            .parse()
            .map_err(|_| bad(deb, "bad ar member size"))?;
        let start = f.stream_position().map_err(|e| bad(deb, e))?;
        if name.starts_with("data.tar") {
            return Ok((name, start, size));
        }
        f.seek(SeekFrom::Start(start + size + (size & 1)))
            .map_err(|e| bad(deb, e))?;
    }
}

/// Unpacks the files of `deb` into `dest`.
pub fn unpack_deb(deb: &Path, dest: &Path) -> Result<(), ProvisionError> {
    let mut f = File::open(deb).map_err(|e| bad(deb, e))?;
    let (name, start, size) = data_member(deb, &mut f)?;
    let ext = match name.as_str() {
        "data.tar.xz" => "xz",
        "data.tar.gz" => "gz",
        other => {
            return Err(bad(
                deb,
                format!(
                    "its data member {other} is not xz or gzip compressed, which is all KRAKEN unpacks"
                ),
            ));
        }
    };
    f.seek(SeekFrom::Start(start)).map_err(|e| bad(deb, e))?;
    let tmp = deb.with_extension(format!("data.{ext}"));
    let copied = (|| {
        let mut out = File::create(&tmp)?;
        let n = std::io::copy(&mut (&mut f).take(size), &mut out)?;
        out.flush()?;
        Ok::<_, std::io::Error>(n)
    })();
    let result = match copied {
        Ok(n) if n == size => {
            if ext == "xz" {
                extract_tar_xz(&tmp, dest)
            } else {
                extract_tar_gz(&tmp, dest)
            }
        }
        Ok(_) => Err(bad(deb, "truncated data member")),
        Err(e) => Err(bad(deb, e)),
    };
    let _ = std::fs::remove_file(&tmp);
    result
}

fn remove(p: &Path, is_dir: bool) -> std::io::Result<()> {
    if is_dir {
        std::fs::remove_dir_all(p)
    } else {
        std::fs::remove_file(p)
    }
}

/// Keeps what a program needs at run time (`usr/lib*`, `lib*`) and removes the rest of what the
/// packages unpacked (documentation, binaries, configuration). Makes `lib` and `lib64` links to
/// `usr/lib` and `usr/lib64` when the packages did not, so the loader is found at its usual
/// absolute path.
pub fn shape_sysroot(root: &Path) -> std::io::Result<()> {
    for e in std::fs::read_dir(root)?.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name != "usr" && !name.starts_with("lib") {
            remove(&e.path(), e.file_type()?.is_dir())?;
        }
    }
    let usr = root.join("usr");
    if usr.is_dir() {
        for e in std::fs::read_dir(&usr)?.flatten() {
            if !e.file_name().to_string_lossy().starts_with("lib") {
                remove(&e.path(), e.file_type()?.is_dir())?;
            }
        }
    }
    #[cfg(unix)]
    for (link, to) in [("lib", "usr/lib"), ("lib64", "usr/lib64")] {
        if root.join(to).is_dir() && std::fs::symlink_metadata(root.join(link)).is_err() {
            std::os::unix::fs::symlink(to, root.join(link))?;
        }
    }
    Ok(())
}
