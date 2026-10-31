//! The release signature: `SHA256SUMS` signed with minisign by the release workflow (ADR 0015).
//!
//! The public key is compiled in. The trusted comment must name the version being installed, so
//! an older signed `SHA256SUMS` cannot be passed off as a newer release.

use minisign_verify::{PublicKey, Signature};

use super::UpdateError;

/// The release public key (key id `E9CBFBBF6ECFB91C`).
pub const RELEASE_PUBLIC_KEY: &str = "RWQcuc9uv/vL6fNGCFoY+ea132bmfUHhfczZGY/UgdNbC08hjU6DYmln";

/// The trusted comment a release of `version` carries.
pub fn trusted_comment(version: &str) -> String {
    format!("kraken v{version} SHA256SUMS")
}

/// Checks `signature` (the text of `SHA256SUMS.minisig`) over `sums` with `public_key`, and that
/// it was made for `version`. Only prehashed (`ED`) signatures are accepted, as current minisign
/// makes them.
pub fn verify_sums(
    sums: &[u8],
    signature: &str,
    version: &str,
    public_key: &str,
) -> Result<(), UpdateError> {
    let bad = |m: String| UpdateError::Signature(m);
    let pk = PublicKey::from_base64(public_key)
        .map_err(|e| bad(format!("the compiled-in public key is unusable: {e}")))?;
    let sig = Signature::decode(signature).map_err(|e| {
        bad(format!(
            "SHA256SUMS.minisig is not a minisign signature: {e}"
        ))
    })?;
    pk.verify(sums, &sig, false).map_err(|e| {
        bad(format!(
            "SHA256SUMS is not signed by the KRAKEN release key: {e}"
        ))
    })?;
    let want = trusted_comment(version);
    if sig.trusted_comment() != want {
        return Err(bad(format!(
            "the signature is for \"{}\", not \"{want}\"",
            sig.trusted_comment()
        )));
    }
    Ok(())
}

/// The SHA-256 that `sums` (sha256sum format) lists for exactly `name`.
pub fn sum_for(sums: &str, name: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let (hash, file) = line.split_once(char::is_whitespace)?;
        let file = file.trim_start().trim_start_matches('*');
        (file == name && hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| hash.to_ascii_lowercase())
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::io::Cursor;

    /// A throwaway key made for the test run; never the release key.
    pub(crate) struct TestKey {
        pub pk: minisign::PublicKey,
        pub sk: minisign::SecretKey,
    }

    impl TestKey {
        pub(crate) fn new() -> Self {
            let kp = minisign::KeyPair::generate_unencrypted_keypair().expect("keypair");
            TestKey {
                pk: kp.pk,
                sk: kp.sk,
            }
        }

        pub(crate) fn public(&self) -> String {
            self.pk.to_base64()
        }

        pub(crate) fn sign(&self, data: &[u8], trusted: &str) -> String {
            minisign::sign(
                Some(&self.pk),
                &self.sk,
                Cursor::new(data),
                Some(trusted),
                Some("test signature"),
            )
            .expect("sign")
            .to_string()
        }
    }

    #[test]
    fn a_signature_for_this_version_is_accepted() {
        let k = TestKey::new();
        let sums = b"0000000000000000000000000000000000000000000000000000000000000000  a.tar.gz\n";
        let sig = k.sign(sums, &trusted_comment("0.4.0"));
        verify_sums(sums, &sig, "0.4.0", &k.public()).expect("valid");
    }

    #[test]
    fn tampering_another_key_and_replay_are_rejected() {
        let k = TestKey::new();
        let sums = b"aa  a.tar.gz\n";
        let sig = k.sign(sums, &trusted_comment("0.4.0"));
        // Changed list.
        assert!(verify_sums(b"ab  a.tar.gz\n", &sig, "0.4.0", &k.public()).is_err());
        // Another key.
        let other = TestKey::new();
        assert!(verify_sums(sums, &sig, "0.4.0", &other.public()).is_err());
        // An old signed list offered as a newer release.
        let e = verify_sums(sums, &sig, "0.5.0", &k.public()).expect_err("replay");
        assert!(e.to_string().contains("kraken v0.5.0 SHA256SUMS"), "{e}");
        // An edited trusted comment breaks the global signature.
        let forged = sig.replace("kraken v0.4.0 SHA256SUMS", "kraken v0.5.0 SHA256SUMS");
        assert!(verify_sums(sums, &forged, "0.5.0", &k.public()).is_err());
        // Garbage.
        assert!(verify_sums(sums, "nope", "0.4.0", &k.public()).is_err());
        // The release key does not vouch for a test signature.
        assert!(verify_sums(sums, &sig, "0.4.0", RELEASE_PUBLIC_KEY).is_err());
    }

    #[test]
    fn the_release_key_parses() {
        assert!(PublicKey::from_base64(RELEASE_PUBLIC_KEY).is_ok());
    }

    #[test]
    fn sums_lines_match_exact_names_only() {
        let h = "ab".repeat(32);
        let text =
            format!("{h}  kraken-0.4.0-x.tar.gz\n{h} *KRAKEN-0.4.0-x86_64.AppImage\nzz  bad\n");
        assert_eq!(sum_for(&text, "kraken-0.4.0-x.tar.gz"), Some(h.clone()));
        assert_eq!(sum_for(&text, "KRAKEN-0.4.0-x86_64.AppImage"), Some(h));
        assert_eq!(sum_for(&text, "kraken-0.4.0-x.tar"), None);
        assert_eq!(sum_for(&text, "bad"), None);
    }
}
