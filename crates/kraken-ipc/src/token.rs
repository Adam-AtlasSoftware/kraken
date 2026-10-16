//! Auth token: 32 random bytes, hex encoded, stored 0600, compared in constant time.

use std::io::Write;
use std::path::Path;

use subtle::ConstantTimeEq;

use crate::error::IpcError;

/// Number of random bytes in a token.
pub const TOKEN_BYTES: usize = 32;

/// Fills `buf` with OS randomness.
pub fn random_bytes(buf: &mut [u8]) -> Result<(), IpcError> {
    getrandom::fill(buf).map_err(|e| std::io::Error::other(e.to_string()).into())
}

/// Lower-case hex encoding.
pub fn hex_encode(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Generates a fresh token (64 hex chars).
pub fn generate_token() -> Result<String, IpcError> {
    let mut b = [0u8; TOKEN_BYTES];
    random_bytes(&mut b)?;
    Ok(hex_encode(&b))
}

/// Constant-time token equality (length is not secret).
pub fn tokens_match(expected: &str, presented: &str) -> bool {
    expected.as_bytes().ct_eq(presented.as_bytes()).into()
}

/// Writes `data` to `path` atomically (temp file + rename), mode 0600 on Unix.
pub fn write_private_atomic(path: &Path, data: &[u8]) -> Result<(), IpcError> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(format!(".tmp{}", std::process::id()));
    let tmp = std::path::PathBuf::from(tmp);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let res = (|| {
        let mut f = opts.open(&tmp)?;
        f.write_all(data)?;
        f.sync_all()?;
        std::fs::rename(&tmp, path)
    })();
    if res.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    Ok(res?)
}

/// Writes the token file atomically.
pub fn write_token(path: &Path, token: &str) -> Result<(), IpcError> {
    write_private_atomic(path, token.as_bytes())
}

/// Reads and trims the token file.
pub fn read_token(path: &Path) -> Result<String, IpcError> {
    Ok(std::fs::read_to_string(path)?.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_shape_and_uniqueness() {
        let a = generate_token().unwrap();
        let b = generate_token().unwrap();
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, b);
    }

    #[test]
    fn compare() {
        assert!(tokens_match("abc", "abc"));
        assert!(!tokens_match("abc", "abd"));
        assert!(!tokens_match("abc", "abcd"));
        assert!(!tokens_match("abc", ""));
    }

    #[cfg(unix)]
    #[test]
    fn written_0600_atomically() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("daemon.token");
        write_token(&p, "secret").unwrap();
        write_token(&p, "secret2").unwrap();
        assert_eq!(read_token(&p).unwrap(), "secret2");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(std::fs::read_dir(t.path()).unwrap().count(), 1);
    }
}
