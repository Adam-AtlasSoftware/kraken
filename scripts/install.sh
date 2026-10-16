#!/usr/bin/env bash
# Installs the latest KRAKEN release (or KRAKEN_VERSION) for Linux x86_64 or macOS arm64.
#
#   curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/Adam-AtlasSoftware/kraken/main/scripts/install.sh | bash
#
# Everything goes under $KRAKEN_PREFIX (default ~/.local): bin/ and share/kraken/. No sudo.
# Downloads come from GitHub releases over https only, and the archive is checked against the
# release's SHA256SUMS before anything is extracted or installed.
#
# Environment:
#   KRAKEN_VERSION  release to install, e.g. v0.1.0 (default: the latest published release)
#   KRAKEN_PREFIX   install prefix (default: $HOME/.local)
set -euo pipefail

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
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location --output "$2" "$1"
}

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
  url=$(curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
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

# Keep only the line for our archive (exact name match), then verify it.
grep -F "  $archive" "$work/SHA256SUMS" | grep -x ".\{64\}  $archive" > "$work/archive.sha256" ||
  die "$archive is not listed in SHA256SUMS"
(cd "$work" && check_sums archive.sha256) || die "checksum mismatch for $archive; nothing was installed"
echo "Checksum OK"

# Refuse archives that would write outside the extraction directory.
if tar -tzf "$work/$archive" | grep -E '(^/|(^|/)\.\.(/|$))' >/dev/null; then
  die "archive contains unsafe paths; nothing was installed"
fi
mkdir "$work/x"
tar -xzf "$work/$archive" -C "$work/x"
src="$work/x/kraken-$version-$target"
[ -x "$src/bin/kraken" ] || die "archive layout is not as expected"

mkdir -p "$prefix/bin" "$prefix/share/kraken"
for f in "$src"/bin/*; do
  name=$(basename "$f")
  cp "$f" "$prefix/bin/.$name.new"
  chmod 755 "$prefix/bin/.$name.new"
  mv -f "$prefix/bin/.$name.new" "$prefix/bin/$name"
done
for f in "$src"/share/kraken/*; do
  name=$(basename "$f")
  cp "$f" "$prefix/share/kraken/.$name.new"
  mv -f "$prefix/share/kraken/.$name.new" "$prefix/share/kraken/$name"
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
