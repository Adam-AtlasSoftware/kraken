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
# guards against corruption. Releases are meant to carry a detached minisign signature
# (SHA256SUMS.minisig) made with a release key whose public half is embedded below. That key has
# NOT been generated yet (the project owner must create it and paste the public key into
# KRAKEN_MINISIGN_PUBKEY); until then the signature step is skipped with a notice. Once a key is
# embedded the check is mandatory: a missing minisign tool or signature aborts the install.
#
# Environment:
#   KRAKEN_VERSION            release to install, e.g. v0.1.0 (default: the latest release)
#   KRAKEN_PREFIX             install prefix (default: $HOME/.local)
#   KRAKEN_REQUIRE_SIGNATURE  set to 1 to abort when no release key is embedded yet
set -euo pipefail

# minisign public key of the release signing key (the base64 line of the .pub file).
# EMPTY until the owner generates the key: `minisign -G`, then paste the key here.
KRAKEN_MINISIGN_PUBKEY=""

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
  command -v minisign >/dev/null 2>&1 ||
    die "minisign is required to verify this release (https://jedisct1.github.io/minisign/)"
  minisign -V -P "$pubkey" -m "$sums" -x "$sig" >/dev/null ||
    die "signature check failed for SHA256SUMS; nothing was installed"
  echo "Signature OK"
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
elif command -v shasum >/dev/null 2>&1; then
  check_sums() { shasum -a 256 -c "$1" >/dev/null; }
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
verify_signature "$work/SHA256SUMS" "$sig_file" "$KRAKEN_MINISIGN_PUBKEY" "${KRAKEN_REQUIRE_SIGNATURE:-0}"

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

echo
echo "Installed KRAKEN $tag into $prefix"
case ":$PATH:" in
  *":$prefix/bin:"*) ;;
  *) echo "Add $prefix/bin to your PATH, for example:  export PATH=\"$prefix/bin:\$PATH\"" ;;
esac
cat <<'EOF'

Next steps:
  kraken setup      downloads the pinned Ghidra and a JDK (checksum-verified, no root needed)
  kraken --help     see the commands
  kraken-gui        start the GUI
EOF
