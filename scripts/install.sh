#!/usr/bin/env bash
# Installs the latest KRAKEN release (or KRAKEN_VERSION) for Linux x86_64 or macOS arm64.
#
#   curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Adam-AtlasSoftware/kraken/main/scripts/install.sh | bash
#
# Everything goes under $KRAKEN_PREFIX (default ~/.local): bin/ and share/kraken/. No sudo.
# Downloads come from GitHub releases over https only, and the archive is checked against the
# release's SHA256SUMS before anything is extracted or installed.
#
# Authenticity: SHA256SUMS comes from the same origin as the archive, so on its own it only
# guards against corruption. Releases carry a detached minisign signature (SHA256SUMS.minisig)
# made with the release key whose public half is embedded below (the same key KRAKEN's updater
# has compiled in, docs/design/0015-updates.md). The check is mandatory and uses minisign, or
# OpenSSL 3 when minisign is not installed; a missing signature aborts the install. Releases up
# to v0.3.0 were not signed: the SHA-256 of each one's SHA256SUMS is pinned below instead.
#
# The script writes an install receipt, <prefix>/share/kraken/install.json, so that KRAKEN knows
# it was installed this way and can update itself (`kraken update`).
#
# Environment:
#   KRAKEN_VERSION            release to install, e.g. v0.4.0 (default: the latest release)
#   KRAKEN_PREFIX             install prefix (default: $HOME/.local)
set -euo pipefail

# minisign public key of the release signing key (key id E9CBFBBF6ECFB91C).
KRAKEN_MINISIGN_PUBKEY="RWQcuc9uv/vL6fNGCFoY+ea132bmfUHhfczZGY/UgdNbC08hjU6DYmln"

repo="Adam-AtlasSoftware/kraken"
base="https://github.com/$repo/releases"

die() {
  echo "install.sh: $*" >&2
  exit 1
}

need() {
  command -v "$1" >/dev/null 2>&1 || die "required tool not found: $1"
}

fetch() {
  # $1 = https URL, $2 = output file
  curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location \
    --output "$2" "$1"
}

# Verifies the detached minisign signature of the SHA256SUMS file.
# $1 = SHA256SUMS path, $2 = signature path or empty if the release has none,
# $3 = public key (may be empty), $4 = "1" to require a signature even without a key.
verify_signature() {
  local sums=$1 sig=$2 pubkey=$3 require=${4:-0}
  if [ -z "$pubkey" ]; then
    if [ "$require" = "1" ]; then
      die "no release signing key is embedded in this script yet, but KRAKEN_REQUIRE_SIGNATURE=1"
    fi
    echo "Note: no release signing key is embedded yet; authenticity rests on GitHub alone" >&2
    return 0
  fi
  [ -n "$sig" ] && [ -f "$sig" ] || die "release has no SHA256SUMS.minisig; nothing was installed"
  if command -v minisign >/dev/null 2>&1; then
    # minisign 0.11 and later verify the prehashed signatures the release workflow makes.
    minisign -V -P "$pubkey" -m "$sums" -x "$sig" >/dev/null ||
      die "signature check failed for SHA256SUMS; nothing was installed"
  elif openssl_can_verify; then
    verify_with_openssl "$sums" "$sig" "$pubkey" ||
      die "signature check failed for SHA256SUMS; nothing was installed"
  else
    die "minisign (https://jedisct1.github.io/minisign/) or OpenSSL 3 is required to verify this release"
  fi
  echo "Signature OK"
}

# True when OpenSSL 3 with Ed25519 and BLAKE2b-512 is available (LibreSSL is not enough).
openssl_can_verify() {
  command -v openssl >/dev/null 2>&1 || return 1
  case "$(openssl version 2>/dev/null)" in
    "OpenSSL 3."*) ;;
    *) return 1 ;;
  esac
  openssl list -digest-algorithms 2>/dev/null | grep -qi blake2b512
}

# Verifies a prehashed minisign signature with OpenSSL: Ed25519 over the BLAKE2b-512 hash of the
# file, then the global signature over the signature and the trusted comment.
# $1 = file, $2 = .minisig, $3 = public key (base64 line of the .pub file)
verify_with_openssl() {
  local file=$1 sig=$2 pubkey=$3 d rc line3 comment
  d=$(mktemp -d) || return 1
  (
    printf '%s' "$pubkey" | base64 -d > "$d/pk" 2>/dev/null || exit 1
    [ "$(wc -c < "$d/pk")" -eq 42 ] && [ "$(head -c 2 "$d/pk")" = "Ed" ] || exit 1
    sed -n 2p "$sig" | base64 -d > "$d/s" 2>/dev/null || exit 1
    [ "$(wc -c < "$d/s")" -eq 74 ] && [ "$(head -c 2 "$d/s")" = "ED" ] || exit 1
    # The key id in the signature must be the embedded key's.
    [ "$(head -c 10 "$d/pk" | tail -c 8 | od -An -tx1)" = "$(head -c 10 "$d/s" | tail -c 8 | od -An -tx1)" ] || exit 1
    { printf '\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00'; tail -c 32 "$d/pk"; } > "$d/pk.der"
    openssl pkey -pubin -inform DER -in "$d/pk.der" -out "$d/pk.pem" 2>/dev/null || exit 1
    tail -c 64 "$d/s" > "$d/s.bin"
    openssl dgst -blake2b512 -binary "$file" > "$d/h" || exit 1
    openssl pkeyutl -verify -pubin -inkey "$d/pk.pem" -rawin -in "$d/h" -sigfile "$d/s.bin" \
      >/dev/null 2>&1 || exit 1
    line3=$(sed -n 3p "$sig")
    comment=${line3#trusted comment: }
    [ "$line3" != "$comment" ] || exit 1
    { cat "$d/s.bin"; printf '%s' "$comment"; } > "$d/g"
    sed -n 4p "$sig" | base64 -d > "$d/gs" 2>/dev/null || exit 1
    [ "$(wc -c < "$d/gs")" -eq 64 ] || exit 1
    openssl pkeyutl -verify -pubin -inkey "$d/pk.pem" -rawin -in "$d/g" -sigfile "$d/gs" \
      >/dev/null 2>&1 || exit 1
  )
  rc=$?
  rm -rf "$d"
  return $rc
}

# Releases made before signing began, with the SHA-256 of their SHA256SUMS. Only these exact
# lists are accepted without a signature.
unsigned_release_sums() {
  case "$1" in
    v0.1.0) echo 8908b23a5a563dd857b51b6b1a59b4455245aa9ac24f012f3aa28fbb3b4ea668 ;;
    v0.2.0) echo 2d55d438d835a79ac628f8588b8afbeaa5b9b61d98e7482b7e9b1159e396f667 ;;
    v0.3.0) echo 2ae926d3c93952279b73e89de5ac949c102a6b704b9ba4e9bf7353406651d5b6 ;;
    *) return 1 ;;
  esac
}

# Checks that the signature was made for this release: its trusted comment must be
# "kraken <tag> SHA256SUMS", so an older signed list cannot stand in for a newer release.
# $1 = signature path, $2 = tag (v0.4.0)
check_trusted_comment() {
  local sig=$1 tag=$2
  grep -qx "trusted comment: kraken $tag SHA256SUMS" "$sig" ||
    die "the signature is not for $tag; nothing was installed"
}

# Writes the install receipt KRAKEN's updater reads. $1 = prefix, $2 = version (0.4.0)
write_receipt() {
  local prefix=$1 version=$2 escaped
  escaped=$(printf '%s' "$prefix" | sed 's/\\/\\\\/g; s/"/\\"/g')
  mkdir -p "$prefix/share/kraken"
  printf '{"method": "script", "version": "%s", "prefix": "%s"}\n' "$version" "$escaped" \
    > "$prefix/share/kraken/.install.json.new"
  mv -f "$prefix/share/kraken/.install.json.new" "$prefix/share/kraken/install.json"
}

# Rejects archives with absolute or parent-relative names and any link entry (symlink or hard
# link), so extraction cannot write outside the extraction directory.
# $1 = archive path
check_archive_entries() {
  local list
  list=$(tar -tzf "$1") || die "cannot list $1"
  if printf '%s\n' "$list" | grep -E '(^/|(^|/)\.\.(/|$))' >/dev/null; then
    die "archive contains unsafe paths; nothing was installed"
  fi
  # GNU tar -tv starts each line with the entry type (l = symlink, h = hard link); BSD tar
  # (macOS) marks hard links with "link to" and symlinks with " -> ".
  if tar -tvzf "$1" | grep -E '^[lh]| link to | -> ' >/dev/null; then
    die "archive contains links; nothing was installed"
  fi
}

# Tests source this file to reach the functions above without running an install.
if [ -n "${KRAKEN_INSTALL_SOURCE_ONLY:-}" ]; then
  return 0 2>/dev/null || exit 0
fi

need curl
need tar
need uname
need mktemp

[ -n "${HOME:-}" ] || die "HOME is not set"
prefix=${KRAKEN_PREFIX:-$HOME/.local}
case "$prefix" in
  /*) ;;
  *) die "KRAKEN_PREFIX must be an absolute path" ;;
esac

case "$(uname -s)/$(uname -m)" in
  Linux/x86_64) target="x86_64-unknown-linux-gnu" ;;
  Darwin/arm64) target="aarch64-apple-darwin" ;;
  *) die "no release for $(uname -s) $(uname -m); build from source (docs/install.md)" ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  check_sums() { sha256sum -c "$1" >/dev/null; }
  sha256_of() { sha256sum < "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
  check_sums() { shasum -a 256 -c "$1" >/dev/null; }
  sha256_of() { shasum -a 256 < "$1" | cut -d' ' -f1; }
else
  die "need sha256sum or shasum to verify the download"
fi

tag=${KRAKEN_VERSION:-}
if [ -z "$tag" ]; then
  # /releases/latest redirects to /releases/tag/<tag>; read the final URL, not the body.
  url=$(curl --proto '=https' --proto-redir '=https' --tlsv1.2 --fail --silent --show-error --location \
    --output /dev/null --write-out '%{url_effective}' "$base/latest") ||
    die "cannot find the latest release (is there a published release yet?)"
  tag=${url##*/}
fi
case "$tag" in
  v[0-9]*) ;;
  *) die "unexpected release tag: $tag" ;;
esac
case "$tag" in
  *[!A-Za-z0-9._+-]*) die "unexpected characters in release tag: $tag" ;;
esac
version=${tag#v}
archive="kraken-$version-$target.tar.gz"

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

echo "Downloading KRAKEN $tag for $target"
fetch "$base/download/$tag/SHA256SUMS" "$work/SHA256SUMS" || die "cannot download SHA256SUMS for $tag"
fetch "$base/download/$tag/$archive" "$work/$archive" || die "cannot download $archive"
sig_file=""
if fetch "$base/download/$tag/SHA256SUMS.minisig" "$work/SHA256SUMS.minisig" 2>/dev/null; then
  sig_file="$work/SHA256SUMS.minisig"
fi
if pinned=$(unsigned_release_sums "$tag"); then
  # A release from before signing: its SHA256SUMS must be the exact list pinned above.
  [ "$(sha256_of "$work/SHA256SUMS")" = "$pinned" ] ||
    die "SHA256SUMS of $tag is not the published one; nothing was installed"
  echo "Release list OK ($tag predates signed releases; its list is pinned in this script)"
else
  verify_signature "$work/SHA256SUMS" "$sig_file" "$KRAKEN_MINISIGN_PUBKEY" 1
  check_trusted_comment "$sig_file" "$tag"
fi

# Keep only the line for our archive (exact name match), then verify it.
grep -F "  $archive" "$work/SHA256SUMS" | grep -x ".\{64\}  $archive" > "$work/archive.sha256" ||
  die "$archive is not listed in SHA256SUMS"
(cd "$work" && check_sums archive.sha256) || die "checksum mismatch for $archive; nothing was installed"
echo "Checksum OK"

# Refuse archives that would write outside the extraction directory.
check_archive_entries "$work/$archive"
mkdir "$work/x"
tar -xzf "$work/$archive" -C "$work/x" --no-same-owner
src="$work/x/kraken-$version-$target"
[ -x "$src/bin/kraken" ] || die "archive layout is not as expected"

mkdir -p "$prefix/bin" "$prefix/share/kraken"
for f in "$src"/bin/*; do
  name=$(basename "$f")
  cp "$f" "$prefix/bin/.$name.new"
  chmod 755 "$prefix/bin/.$name.new"
  mv -f "$prefix/bin/.$name.new" "$prefix/bin/$name"
done
# Files and directories (the .NET sidecar, the native engine's Sleigh files) alike: copied beside
# the old one first, then swapped in.
for f in "$src"/share/kraken/*; do
  name=$(basename "$f")
  rm -rf "$prefix/share/kraken/.$name.new"
  cp -R "$f" "$prefix/share/kraken/.$name.new"
  rm -rf "$prefix/share/kraken/$name"
  mv -f "$prefix/share/kraken/.$name.new" "$prefix/share/kraken/$name"
done
# The app's desktop entry and icon, so it shows in the application menu.
for f in applications/kraken-gui.desktop icons/hicolor/scalable/apps/kraken-gui.svg; do
  if [ -f "$src/share/$f" ]; then
    mkdir -p "$(dirname "$prefix/share/$f")"
    cp "$src/share/$f" "$prefix/share/$f"
  fi
done

write_receipt "$prefix" "$version"

echo
echo "Installed KRAKEN $tag into $prefix"
case ":$PATH:" in
  *":$prefix/bin:"*) ;;
  *) echo "Add $prefix/bin to your PATH, for example:  export PATH=\"$prefix/bin:\$PATH\"" ;;
esac
if unsigned_release_sums "$tag" >/dev/null; then
  echo "Updates: $tag predates the updater; run this install command again to update."
else
  echo "Updates: KRAKEN tells you when a new version is out; \`kraken update\` installs it."
fi
if [ -d "$prefix/share/kraken/native-sla" ]; then
  cat <<'EOF'

Ready: the native engine is included, no Java needed.
  kraken-gui        start the app
  kraken --help     see the commands
  kraken setup      optional: the Ghidra engine (Mach-O, more processors), with its own JDK
EOF
else
  cat <<'EOF'

Next steps:
  kraken setup      downloads the pinned Ghidra and a JDK (checksum-verified, no root needed)
  kraken --help     see the commands
  kraken-gui        start the GUI
EOF
fi
