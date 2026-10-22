#!/usr/bin/env bash
# Assembles one release archive from already-built release binaries.
#
#   scripts/package.sh <target-triple> <version> <out-dir>
#
# Environment:
#   KRAKEN_GHIDRA_JAR  path of the prebuilt kraken-ghidra.jar (required)
#   KRAKEN_DOTNET_DIR  directory with the prebuilt .NET sidecar (the output of
#                      `cargo xtask dotnet-ext`, holding kraken-dotnet.dll) (required)
#   KRAKEN_DOCS_DIR    path of the built mdBook (required)
#   CARGO_TARGET_DIR   cargo target directory (default: target)
#   KRAKEN_REQUIRE_NATIVE
#                      1: fail unless kraken-native-worker was built (the native engine's
#                      confined decompiler process; Linux release builds link the decompiler)
#                      and KRAKEN_NATIVE_SLA_DIR holds the compiled Sleigh files
#   KRAKEN_NATIVE_SLA_DIR
#                      the tree `cargo xtask native-sla` compiled (Ghidra_<version>_build); shipped
#                      as share/kraken/native-sla so the native engine works without a checkout
#
# The archive always carries THIRD-PARTY-NOTICES.md and licenses/ (the Ghidra decompiler and
# zlib license and notice files from crates/engine-native-sys/licenses), because the binaries
# link the native engine's C++ library whenever it was built with its sources.
#
# Writes <out-dir>/kraken-<version>-<target>.tar.gz (.zip for Windows targets) and a sibling
# .sha256 file. Binaries are expected in $CARGO_TARGET_DIR/release.
set -euo pipefail

if [ "$#" -ne 3 ]; then
  echo "usage: $0 <target-triple> <version> <out-dir>" >&2
  exit 2
fi
target=$1
version=$2
out_dir=$3

case "$target" in
  *[!A-Za-z0-9_.-]* | '') echo "bad target: $target" >&2; exit 2 ;;
esac
case "$version" in
  *[!A-Za-z0-9_.+-]* | '') echo "bad version: $version" >&2; exit 2 ;;
esac

root=$(cd "$(dirname "$0")/.." && pwd)
bins_dir="${CARGO_TARGET_DIR:-$root/target}/release"
jar=${KRAKEN_GHIDRA_JAR:?KRAKEN_GHIDRA_JAR is not set}
dotnet_dir=${KRAKEN_DOTNET_DIR:?KRAKEN_DOTNET_DIR is not set}
docs=${KRAKEN_DOCS_DIR:?KRAKEN_DOCS_DIR is not set}

exe=""
format=tar.gz
case "$target" in
  *windows*) exe=".exe"; format=zip ;;
esac

[ -f "$jar" ] || { echo "missing $jar" >&2; exit 1; }
[ -f "$dotnet_dir/kraken-dotnet.dll" ] || { echo "missing $dotnet_dir/kraken-dotnet.dll" >&2; exit 1; }
[ -d "$docs" ] || { echo "missing $docs" >&2; exit 1; }
for b in kraken krakend kraken-gui; do
  [ -f "$bins_dir/$b$exe" ] || { echo "missing $bins_dir/$b$exe" >&2; exit 1; }
done
native_licenses="$root/crates/engine-native-sys/licenses"
for f in PROVENANCE.txt ghidra/LICENSE ghidra/NOTICE zlib/LICENSE zlib/README.txt; do
  [ -s "$native_licenses/$f" ] || { echo "missing $native_licenses/$f" >&2; exit 1; }
done
for needle in "Compiled-in C and C++ components" "decompiler and Sleigh (Apache License 2.0)" "(zlib License)"; do
  grep -qF "$needle" "$root/THIRD-PARTY-NOTICES.md" || {
    echo "THIRD-PARTY-NOTICES.md lacks \"$needle\"; run cargo xtask notices" >&2
    exit 1
  }
done
worker=""
if [ -f "$bins_dir/kraken-native-worker$exe" ]; then
  worker="kraken-native-worker"
elif [ "${KRAKEN_REQUIRE_NATIVE:-0}" = 1 ]; then
  echo "missing $bins_dir/kraken-native-worker$exe (KRAKEN_REQUIRE_NATIVE=1)" >&2
  exit 1
fi

# The emulator's sandbox child (`emulate_run`); optional like the native worker.
if [ -f "$bins_dir/kraken-emu-run$exe" ]; then
  worker="$worker kraken-emu-run"
fi

name="kraken-$version-$target"
mkdir -p "$out_dir"
out_dir=$(cd "$out_dir" && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
pkg="$stage/$name"
mkdir -p "$pkg/bin" "$pkg/share/kraken" "$pkg/docs"

for b in kraken krakend kraken-gui $worker; do
  cp "$bins_dir/$b$exe" "$pkg/bin/$b$exe"
  chmod 755 "$pkg/bin/$b$exe"
done
cp -R "$native_licenses" "$pkg/licenses"
cp "$jar" "$pkg/share/kraken/kraken-ghidra.jar"
case "$target" in
  *linux*)
    mkdir -p "$pkg/share/applications" "$pkg/share/icons/hicolor/scalable/apps"
    cp "$root/packaging/linux/kraken-gui.desktop" "$pkg/share/applications/"
    cp "$root/packaging/linux/kraken.svg" "$pkg/share/icons/hicolor/scalable/apps/kraken-gui.svg"
    ;;
esac
sla_dir=${KRAKEN_NATIVE_SLA_DIR:-}
if [ -n "$sla_dir" ]; then
  [ -f "$sla_dir/Ghidra/Processors/x86/data/languages/x86-64.sla" ] \
    || { echo "missing compiled Sleigh files in $sla_dir" >&2; exit 1; }
  cp -R "$sla_dir" "$pkg/share/kraken/native-sla"
elif [ "${KRAKEN_REQUIRE_NATIVE:-0}" = 1 ]; then
  echo "KRAKEN_NATIVE_SLA_DIR is not set (KRAKEN_REQUIRE_NATIVE=1)" >&2
  exit 1
fi
# The managed sidecar is platform independent; `kraken setup --dotnet` installs it. Debug symbols
# are left out.
mkdir -p "$pkg/share/kraken/kraken-dotnet"
cp -R "$dotnet_dir/." "$pkg/share/kraken/kraken-dotnet/"
find "$pkg/share/kraken/kraken-dotnet" -name "*.pdb" -delete
cp "$root/dotnet/kraken-dotnet/THIRD-PARTY-NOTICES.txt" "$pkg/share/kraken/kraken-dotnet/"
cp -R "$docs/." "$pkg/docs/"
cp "$root/README.md" "$root/LICENSE" "$root/THIRD-PARTY-NOTICES.md" "$pkg/"
cp "$root/scripts/INSTALL.txt" "$pkg/INSTALL.txt"

# Mach-O binaries must carry at least an ad-hoc signature to launch on Apple silicon (decision 72).
case "$target" in
  *apple-darwin*)
    for b in kraken krakend kraken-gui $worker; do
      codesign --force --sign - "$pkg/bin/$b"
    done
    ;;
esac

archive="$out_dir/$name.$format"
rm -f "$archive"
case "$format" in
  tar.gz)
    COPYFILE_DISABLE=1 tar -czf "$archive" -C "$stage" "$name"
    ;;
  zip)
    if command -v 7z >/dev/null 2>&1; then
      (cd "$stage" && 7z a -tzip -bd "$archive" "$name" >/dev/null)
    elif command -v zip >/dev/null 2>&1; then
      (cd "$stage" && zip -qr "$archive" "$name")
    else
      echo "need 7z or zip to build a .zip" >&2
      exit 1
    fi
    ;;
esac

if command -v sha256sum >/dev/null 2>&1; then
  sum=$(sha256sum "$archive" | cut -d' ' -f1)
else
  sum=$(shasum -a 256 "$archive" | cut -d' ' -f1)
fi
printf '%s  %s\n' "$sum" "$(basename "$archive")" > "$archive.sha256"
echo "packaged $archive"
cat "$archive.sha256"
