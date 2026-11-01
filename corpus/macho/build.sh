#!/usr/bin/env bash
# Builds corpus/macho without a container: the macOS C headers and libSystem.tbd stub of a pinned
# zig release, zig's clang to compile and LLVM's ld64.lld to link. No Apple SDK, no Apple binary.
#   ZIG=/path/to/zig corpus/macho/build.sh
# Names: <program>-<x64|arm64>-<opt>[-stripped|-classic][.dylib]; `-classic` keeps the older
# LC_DYLD_INFO binding tables, the others have chained fixups; pie_list-fat-O2 is a universal
# binary of the two pie_list-*-O2 programs.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
ZIG="${ZIG:-zig}"
LLD="${LLD:-ld64.lld}"
PREFIX="$(dirname "$(readlink -f "$(command -v "$ZIG")")")"
LIBC="$PREFIX/lib/libc/darwin"
export SOURCE_DATE_EPOCH=1704067200 ZERO_AR_DATE=1

rm -rf bin .build && mkdir -p bin .build
{
  echo "zig: $("$ZIG" version)"
  echo "ld64.lld: $("$LLD" --version | head -1)"
  echo "llvm: $(llvm-strip --version | grep -i 'version' | head -1 | sed 's/^ *//')"
} > TOOLCHAIN.txt

cc() { # arch opt source object
  "$ZIG" cc -target "$1-macos.13.0" "-$2" -fno-sanitize=all -fno-stack-protector \
    -ffile-prefix-map="$PWD"=. -c "$3" -o "$4"
}

link() { # lld-arch fixups output object [flags]
  local arch=$1 fixups=$2 out=$3 obj=$4
  shift 4
  "$LLD" -arch "$arch" -platform_version macos 13.0 13.0 -Z -L "$LIBC" -lSystem "$fixups" \
    -o "$out" "$obj" "$@"
}

for pair in x86_64:x86_64:x64 aarch64:arm64:arm64; do
  IFS=: read -r zarch larch name <<< "$pair"
  for opt in O0 O2; do
    for prog in static_strops pie_list stripped_calc switch_vm; do
      o=".build/$prog-$name-$opt.o"
      cc "$zarch" "$opt" "../src/$prog.c" "$o"
      link "$larch" -fixup_chains "bin/$prog-$name-$opt" "$o"
    done
    o=".build/mac_lib-$name-$opt.o"
    cc "$zarch" "$opt" src/mac_lib.c "$o"
    link "$larch" -fixup_chains "bin/mac_lib-$name-$opt.dylib" "$o" -dylib \
      -install_name /usr/local/lib/libmac_lib.dylib
  done
  link "$larch" -no_fixup_chains "bin/pie_list-$name-O2-classic" ".build/pie_list-$name-O2.o"
  llvm-strip -o "bin/stripped_calc-$name-O2-stripped" "bin/stripped_calc-$name-O2"
done
llvm-lipo -create bin/pie_list-x64-O2 bin/pie_list-arm64-O2 -output bin/pie_list-fat-O2
(find bin -type f | LC_ALL=C sort | xargs sha256sum > MANIFEST.sha256
 sha256sum src/* ../src/static_strops.c ../src/pie_list.c ../src/stripped_calc.c \
   ../src/switch_vm.c build.sh >> MANIFEST.sha256)
ls -l bin
