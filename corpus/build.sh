#!/usr/bin/env bash
# Build the KRAKEN corpus. Host mode (default) builds the image and runs this script
# inside the container; "--inside" is the in-container step.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE=kraken-corpus-builder:local
# Fixed timestamp for reproducibility (2024-01-01T00:00:00Z).
export SOURCE_DATE_EPOCH=1704067200

# name:extra-flags (compiler chosen by source extension).
PROGRAMS=(
  "static_strops:-static -no-pie"
  "pie_list:-fPIE -pie"
  "stripped_calc:"
  "cpp_shapes:"
  "switch_vm:"
)

if [[ "${1:-}" != "--inside" ]]; then
  docker build -q -f "$HERE/Containerfile" -t "$IMAGE" "$HERE" >/dev/null
  docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$HERE:/work" -w /work "$IMAGE" bash /work/build.sh --inside
  cd "$HERE"
  find bin -type f | LC_ALL=C sort | xargs sha256sum > MANIFEST.sha256
  sha256sum src/* tools/groundtruth.py build.sh Containerfile >> MANIFEST.sha256
  echo "corpus built; now run: python3 -I corpus/tools/groundtruth.py"
  exit 0
fi

cd /work
rm -rf bin && mkdir -p bin
{
  echo "base-image: $(sed -n 's/^FROM //p' Containerfile)"
  echo "gcc: $(gcc --version | head -1)"
  echo "g++: $(g++ --version | head -1)"
  echo "ld: $(ld --version | head -1)"
  echo "strip: $(strip --version | head -1)"
  echo "make: $(make --version | head -1)"
  dpkg-query -W gcc g++ make binutils libc6-dev | sed 's/\t/ /;s/^/dpkg: /'
} > TOOLCHAIN.txt

COMMON=(-g -ffile-prefix-map=/work=. -Wl,--build-id=none -Wall)
for entry in "${PROGRAMS[@]}"; do
  name="${entry%%:*}"; extra="${entry#*:}"
  if [[ -f "src/$name.cpp" ]]; then cc=g++; src="src/$name.cpp"; else cc=gcc; src="src/$name.c"; fi
  for opt in O0 O2; do
    out="bin/$name-$opt"
    # shellcheck disable=SC2086
    "$cc" "-$opt" "${COMMON[@]}" $extra "$src" -o "$out"
    strip --strip-all -o "$out-stripped" "$out"
    echo "built $out ($(stat -c %s "$out") bytes)"
  done
done
