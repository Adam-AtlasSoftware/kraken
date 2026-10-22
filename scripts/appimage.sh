#!/usr/bin/env bash
# Builds the Linux AppImage from a packaged release archive.
#
#   scripts/appimage.sh <kraken-<version>-x86_64-unknown-linux-gnu.tar.gz> <out-dir>
#
# The AppImage holds the archive's bin/ and share/ under usr/, the desktop entry and icon from
# packaging/linux, and AppRun (the app by default; `kraken` or `krakend` as the first argument
# runs that program). appimagetool and the AppImage runtime are downloaded at pinned versions and
# checked against their SHA-256 before use; set APPIMAGETOOL / APPIMAGE_RUNTIME to local copies
# to skip the download.
#
# Writes <out-dir>/KRAKEN-<version>-x86_64.AppImage and a sibling .sha256 file.
set -euo pipefail

TOOL_URL=https://github.com/AppImage/appimagetool/releases/download/1.9.1/appimagetool-x86_64.AppImage
TOOL_SHA256=ed4ce84f0d9caff66f50bcca6ff6f35aae54ce8135408b3fa33abfc3cb384eb0
RUNTIME_URL=https://github.com/AppImage/type2-runtime/releases/download/20251108/runtime-x86_64
RUNTIME_SHA256=2fca8b443c92510f1483a883f60061ad09b46b978b2631c807cd873a47ec260d

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <linux release archive> <out-dir>" >&2
  exit 2
fi
archive=$(cd "$(dirname "$1")" && pwd)/$(basename "$1")
out_dir=$2
root=$(cd "$(dirname "$0")/.." && pwd)

name=$(basename "$archive" .tar.gz)
case "$name" in
  kraken-*-x86_64-unknown-linux-gnu) ;;
  *) echo "not a Linux x86_64 release archive: $archive" >&2; exit 2 ;;
esac
version=${name#kraken-}
version=${version%-x86_64-unknown-linux-gnu}

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fetch() { # url sha256 dest
  curl --proto '=https' --tlsv1.2 -fsSL -o "$3" "$1"
  echo "$2  $3" | sha256sum -c - >/dev/null
  chmod 755 "$3"
}
tool=${APPIMAGETOOL:-}
if [ -z "$tool" ]; then
  tool="$work/appimagetool"
  fetch "$TOOL_URL" "$TOOL_SHA256" "$tool"
fi
runtime=${APPIMAGE_RUNTIME:-}
if [ -z "$runtime" ]; then
  runtime="$work/runtime"
  fetch "$RUNTIME_URL" "$RUNTIME_SHA256" "$runtime"
fi
echo "$RUNTIME_SHA256  $runtime" | sha256sum -c - >/dev/null

tar -xzf "$archive" -C "$work"
pkg="$work/$name"
app="$work/KRAKEN.AppDir"
mkdir -p "$app/usr/share/applications" "$app/usr/share/icons/hicolor/scalable/apps" \
  "$app/usr/share/doc/kraken"
cp -R "$pkg/bin" "$app/usr/bin"
cp -R "$pkg/share/." "$app/usr/share/"
cp -R "$pkg/licenses" "$app/usr/share/doc/kraken/licenses"
cp "$pkg/LICENSE" "$pkg/THIRD-PARTY-NOTICES.md" "$pkg/README.md" "$app/usr/share/doc/kraken/"
cp "$root/packaging/linux/AppRun" "$app/AppRun"
chmod 755 "$app/AppRun"
cp "$root/packaging/linux/kraken-gui.desktop" "$app/kraken-gui.desktop"
cp "$root/packaging/linux/kraken-gui.desktop" "$app/usr/share/applications/"
cp "$root/packaging/linux/kraken.svg" "$app/kraken-gui.svg"
cp "$root/packaging/linux/kraken.svg" "$app/usr/share/icons/hicolor/scalable/apps/kraken-gui.svg"

mkdir -p "$out_dir"
out_dir=$(cd "$out_dir" && pwd)
image="$out_dir/KRAKEN-$version-x86_64.AppImage"
# appimagetool is itself an AppImage; extract-and-run avoids needing FUSE on the build machine.
ARCH=x86_64 APPIMAGE_EXTRACT_AND_RUN=1 "$tool" --no-appstream --runtime-file "$runtime" \
  "$app" "$image"
(cd "$out_dir" && sha256sum "$(basename "$image")" > "$(basename "$image").sha256")
echo "built $image"
