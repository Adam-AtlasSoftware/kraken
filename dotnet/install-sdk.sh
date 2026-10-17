#!/usr/bin/env bash
# Installs the pinned .NET SDK into ~/.cache/kraken-dev/dotnet without touching PATH, ~/.dotnet or
# any system package. The archive is downloaded from Microsoft's CDN and verified against the
# sha512 in Microsoft's release metadata (https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/10.0/releases.json)
# before it is unpacked. (The generic dotnet-install script does not verify a hash, so this
# script pins one instead.)
set -euo pipefail

version="10.0.402"
sha512="1904a98dda2db34ba78ba3c4fb1b224455329af91c341d83547843c1839e112b04ae699ee92fa2449a8f62249196a938723078c0c60b9f65c88539d5687729c2"
url="https://builds.dotnet.microsoft.com/dotnet/Sdk/$version/dotnet-sdk-$version-linux-x64.tar.gz"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) ;;
  *) echo "this script pins only the linux-x64 SDK; install a matching SDK into the cache by hand" >&2; exit 1 ;;
esac

cache="${KRAKEN_DEV_CACHE:-$HOME/.cache/kraken-dev}"
dest="$cache/dotnet"
if [ -x "$dest/dotnet" ] && [ -d "$dest/sdk/$version" ]; then
  echo ".NET SDK $version already installed in $dest"
  exit 0
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
curl --proto '=https' --proto-redir '=https' --tlsv1.2 -fsSL -o "$tmp/sdk.tar.gz" "$url"
echo "$sha512  $tmp/sdk.tar.gz" | sha512sum -c -
mkdir -p "$dest"
tar -xzf "$tmp/sdk.tar.gz" -C "$dest"
echo "installed .NET SDK $version into $dest"
