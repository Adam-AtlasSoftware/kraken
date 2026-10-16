#!/usr/bin/env bash
# Builds corpus/dotnet/bin/kraken-corpus.dll with the isolated .NET SDK in ~/.cache/kraken-dev/dotnet
# (nothing global is touched) and regenerates truth/kraken-corpus.json from its metadata with the
# kraken-dotnet sidecar (`cargo xtask dotnet-ext` builds it first).
#
# Rebuilding is a manual job: the built .dll is committed so tests do not need to compile C#.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cache="${KRAKEN_DEV_CACHE:-$HOME/.cache/kraken-dev}"
sdk="$cache/dotnet"
if [ ! -x "$sdk/dotnet" ]; then
  echo "no .NET SDK at $sdk; run dotnet/install-sdk.sh first" >&2
  exit 1
fi

export DOTNET_ROOT="$sdk"
export DOTNET_CLI_HOME="$cache/dotnet-home"
export NUGET_PACKAGES="$cache/nuget"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1

out="$here/out"
rm -rf "$out" "$here/obj"
"$sdk/dotnet" build "$here/kraken-corpus.csproj" -c Release -o "$out" \
  -p:PathMap="$here=/corpus" --nologo -v:q

mkdir -p "$here/bin" "$here/truth"
cp "$out/kraken-corpus.dll" "$here/bin/kraken-corpus.dll"
rm -rf "$out" "$here/obj"

sidecar="$here/../../dotnet/kraken-dotnet/bin/kraken-dotnet.dll"
if [ -f "$sidecar" ]; then
  "$sdk/dotnet" "$sidecar" --dump-truth "$here/bin/kraken-corpus.dll" > "$here/truth/kraken-corpus.json"
else
  echo "sidecar not built (cargo xtask dotnet-ext); truth/kraken-corpus.json not regenerated" >&2
fi
sha256sum "$here/bin/kraken-corpus.dll"
