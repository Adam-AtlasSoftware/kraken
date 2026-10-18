#!/usr/bin/env bash
# Build the KRAKEN corpus. Host mode (default) builds the image and runs this script
# inside the container; "--inside" is the in-container step.
#
# Sets: "elf" (x86-64 ELF, corpus/bin), "pe" (PE32 and PE32+ with mingw-w64, corpus/pe/bin),
# "elf32" (32-bit x86 ELF, corpus/elf32/bin), "lib" (libkr as Linux and Windows libraries and
# object files, corpus/lib/bin), and the cross-architecture sets "arm32" (armv7-a hard-float
# Linux), "aarch64", "riscv64" (rv64gc Linux) and "riscv32" (rv32imac, static, picolibc with
# riscv32/src/linux_rt.c), each in corpus/<set>/bin. Default: all eight. Name sets to build only
# those:
#   corpus/build.sh pe elf32
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# The elf, pe, elf32 and lib sets build in the Containerfile's "native" stage, the
# cross-architecture sets in its "cross" stage (see the Containerfile for why there are two).
IMAGE=kraken-corpus-builder:local
XIMAGE=kraken-corpus-builder:cross
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
# 32-bit ELF programs (same sources, gcc -m32).
PROGRAMS32=(
  "pie_list:-fPIE -pie"
  "switch_vm:"
)
# Cross-architecture Linux programs (arm32, aarch64, riscv64): the C programs of the ELF set.
PROGRAMSX=(
  "static_strops:-static -no-pie"
  "pie_list:-fPIE -pie"
  "stripped_calc:"
  "switch_vm:"
)
# riscv32 programs: all static (there is no riscv32 Linux userland to link against).
PROGRAMSRV32=(static_strops pie_list stripped_calc switch_vm)
XSETS=(arm32 aarch64 riscv64 riscv32)

if [[ "${1:-}" != "--inside" ]]; then
  SETS=("$@")
  [[ ${#SETS[@]} -eq 0 ]] && SETS=(elf pe elf32 lib "${XSETS[@]}")
  NATIVE=() CROSS=()
  for set in "${SETS[@]}"; do
    if [[ " ${XSETS[*]} " == *" $set "* ]]; then CROSS+=("$set"); else NATIVE+=("$set"); fi
  done
  if [[ ${#NATIVE[@]} -gt 0 ]]; then
    docker build -q -f "$HERE/Containerfile" --target native -t "$IMAGE" "$HERE" >/dev/null
    docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
      -v "$HERE:/work" -w /work "$IMAGE" bash /work/build.sh --inside "${NATIVE[@]}"
  fi
  if [[ ${#CROSS[@]} -gt 0 ]]; then
    docker build -q -f "$HERE/Containerfile" --target cross -t "$XIMAGE" "$HERE" >/dev/null
    docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
      -v "$HERE:/work" -w /work "$XIMAGE" bash /work/build.sh --inside "${CROSS[@]}"
  fi
  cd "$HERE"
  for set in "${SETS[@]}"; do
    case "$set" in
      elf)
        find bin -type f | LC_ALL=C sort | xargs sha256sum > MANIFEST.sha256
        sha256sum src/* tools/groundtruth.py build.sh Containerfile >> MANIFEST.sha256
        ;;
      pe)
        (cd pe && find bin -type f | LC_ALL=C sort | xargs sha256sum > MANIFEST.sha256 \
          && sha256sum src/* ../src/switch_vm.c ../tools/groundtruth_pe.py ../build.sh \
             ../Containerfile >> MANIFEST.sha256)
        ;;
      elf32)
        (cd elf32 && find bin -type f | LC_ALL=C sort | xargs sha256sum > MANIFEST.sha256 \
          && sha256sum ../src/pie_list.c ../src/switch_vm.c ../tools/groundtruth.py \
             ../build.sh ../Containerfile >> MANIFEST.sha256)
        ;;
      lib)
        (cd lib && find bin -type f | LC_ALL=C sort | xargs sha256sum > MANIFEST.sha256 \
          && sha256sum src/* ../tools/groundtruth_lib.py ../build.sh ../Containerfile \
             >> MANIFEST.sha256)
        ;;
      arm32|aarch64|riscv64|riscv32)
        extra=()
        [[ $set == riscv32 ]] && extra=(src/linux_rt.c)
        (cd "$set" && find bin -type f | LC_ALL=C sort | xargs sha256sum > MANIFEST.sha256 \
          && sha256sum ../src/static_strops.c ../src/pie_list.c ../src/stripped_calc.c \
             ../src/switch_vm.c "${extra[@]}" ../tools/groundtruth.py ../build.sh \
             ../Containerfile >> MANIFEST.sha256)
        ;;
    esac
  done
  echo "corpus built; now run: python3 -I corpus/tools/groundtruth.py [--set <set>]," \
    "python3 -I corpus/tools/groundtruth_pe.py and python3 -I corpus/tools/groundtruth_lib.py"
  exit 0
fi

shift
cd /work
COMMON=(-g -ffile-prefix-map=/work=. -Wl,--build-id=none -Wall)

base_image() {
  sed -n 's/^FROM \(debian:[^ ]*\).*/\1/p' Containerfile
}

build_elf() {
  rm -rf bin && mkdir -p bin
  {
    echo "base-image: $(base_image)"
    echo "gcc: $(gcc --version | head -1)"
    echo "g++: $(g++ --version | head -1)"
    echo "ld: $(ld --version | head -1)"
    echo "strip: $(strip --version | head -1)"
    echo "make: $(make --version | head -1)"
    dpkg-query -W gcc g++ make binutils libc6-dev | sed 's/\t/ /;s/^/dpkg: /'
  } > TOOLCHAIN.txt
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
}

build_elf32() {
  rm -rf elf32/bin && mkdir -p elf32/bin
  {
    echo "base-image: $(base_image)"
    echo "gcc: $(gcc --version | head -1)"
    echo "ld: $(ld --version | head -1)"
    dpkg-query -W gcc gcc-multilib binutils libc6-dev-i386 | sed 's/\t/ /;s/^/dpkg: /'
  } > elf32/TOOLCHAIN.txt
  for entry in "${PROGRAMS32[@]}"; do
    name="${entry%%:*}"; extra="${entry#*:}"
    for opt in O0 O2; do
      out="elf32/bin/$name-i386-$opt"
      # shellcheck disable=SC2086
      gcc -m32 "-$opt" "${COMMON[@]}" $extra "src/$name.c" -o "$out"
      strip --strip-all -o "$out-stripped" "$out"
      echo "built $out ($(stat -c %s "$out") bytes)"
    done
  done
}

# PE: no debug info (a Windows binary without a PDB); the COFF symbol table of the unstripped
# build and the program's own object files are the ground truth (tools/groundtruth_pe.py).
build_pe() {
  rm -rf pe/bin pe/.build && mkdir -p pe/bin pe/.build
  {
    echo "base-image: $(base_image)"
    echo "x86_64-w64-mingw32-gcc: $(x86_64-w64-mingw32-gcc --version | head -1)"
    echo "i686-w64-mingw32-gcc: $(i686-w64-mingw32-gcc --version | head -1)"
    echo "ld: $(x86_64-w64-mingw32-ld --version | head -1)"
    dpkg-query -W gcc-mingw-w64-x86-64-win32 gcc-mingw-w64-i686-win32 binutils-mingw-w64-x86-64 \
      binutils-mingw-w64-i686 mingw-w64-x86-64-dev mingw-w64-i686-dev | sed 's/\t/ /;s/^/dpkg: /'
  } > pe/TOOLCHAIN.txt
  # objects keep DWARF (exact function sizes for the truth); the link drops it, so the images
  # carry no debug information (-g does not change the generated code)
  local flags=(-g -ffile-prefix-map=/work=. -Wall)
  local link=(-Wl,--no-insert-timestamp -Wl,--strip-debug)
  for arch in x64 x86; do
    if [[ $arch == x64 ]]; then t=x86_64-w64-mingw32; else t=i686-w64-mingw32; fi
    for opt in O0 O2; do
      b="pe/.build/$arch-$opt"
      mkdir -p "$b"
      "$t-gcc" "-$opt" "${flags[@]}" -c pe/src/win_dll.c -o "$b/win_dll.o"
      "$t-gcc" -shared "-$opt" "${link[@]}" -o "pe/bin/win_dll-$arch-$opt.dll" "$b/win_dll.o" \
        pe/src/win_dll.def "-Wl,--out-implib,$b/libwin_dll.dll.a"
      "$t-gcc" "-$opt" "${flags[@]}" -c pe/src/win_tls.c -o "$b/win_tls.o"
      "$t-gcc" "-$opt" "${link[@]}" -o "pe/bin/win_tls-$arch-$opt.exe" "$b/win_tls.o" \
        "-L$b" -lwin_dll
      "$t-gcc" "-$opt" "${flags[@]}" -c src/switch_vm.c -o "$b/switch_vm.o"
      "$t-gcc" "-$opt" "${link[@]}" -o "pe/bin/switch_vm-$arch-$opt.exe" "$b/switch_vm.o"
      for f in win_dll-$arch-$opt.dll win_tls-$arch-$opt.exe switch_vm-$arch-$opt.exe; do
        echo "built pe/bin/$f ($(stat -c %s "pe/bin/$f") bytes)"
      done
    done
    "$t-strip" --strip-all -o "pe/bin/win_tls-$arch-O2-stripped.exe" "pe/bin/win_tls-$arch-O2.exe"
  done
}

# libkr (lib/src) as every kind of library and object: for x86-64 Linux a shared library, a static
# library and an object (plus a 32-bit object for the i386 relocations); for x64 and x86 Windows a
# DLL, a static library (a COFF archive), the DLL's import library and an object. Objects and
# archives keep their DWARF; the DLL is linked without it, like the PE set.
build_lib() {
  rm -rf lib/bin lib/.build && mkdir -p lib/bin lib/.build
  {
    echo "base-image: $(base_image)"
    echo "gcc: $(gcc --version | head -1)"
    echo "ar: $(ar --version | head -1)"
    echo "x86_64-w64-mingw32-gcc: $(x86_64-w64-mingw32-gcc --version | head -1)"
    echo "i686-w64-mingw32-gcc: $(i686-w64-mingw32-gcc --version | head -1)"
    dpkg-query -W gcc gcc-multilib binutils gcc-mingw-w64-x86-64-win32 gcc-mingw-w64-i686-win32 \
      binutils-mingw-w64-x86-64 binutils-mingw-w64-i686 | sed 's/\t/ /;s/^/dpkg: /'
  } > lib/TOOLCHAIN.txt
  local flags=(-O2 -g -ffile-prefix-map=/work=. -Wall)
  local b=lib/.build/linux-x64
  mkdir -p "$b"
  for m in kr_core kr_text; do gcc "${flags[@]}" -fPIC -c "lib/src/$m.c" -o "$b/$m.o"; done
  gcc -shared -Wl,--build-id=none -Wl,-soname,libkr.so -o lib/bin/libkr.so "$b/kr_core.o" \
    "$b/kr_text.o"
  ar rcD lib/bin/libkr.a "$b/kr_core.o" "$b/kr_text.o"
  cp "$b/kr_core.o" lib/bin/kr.o
  gcc -m32 "${flags[@]}" -fPIC -c lib/src/kr_core.c -o lib/bin/kr-i386.o
  for arch in x64 x86; do
    if [[ $arch == x64 ]]; then t=x86_64-w64-mingw32; else t=i686-w64-mingw32; fi
    b="lib/.build/$arch"
    mkdir -p "$b"
    for m in kr_core kr_text; do "$t-gcc" "${flags[@]}" -c "lib/src/$m.c" -o "$b/$m.obj"; done
    "$t-gcc" -shared -O2 -Wl,--no-insert-timestamp -Wl,--strip-debug -o "lib/bin/kr-$arch.dll" \
      "$b/kr_core.obj" "$b/kr_text.obj" lib/src/kr.def "-Wl,--out-implib,lib/bin/libkr-$arch.dll.a"
    "$t-ar" rcD "lib/bin/kr-$arch.lib" "$b/kr_core.obj" "$b/kr_text.obj"
    cp "$b/kr_core.obj" "lib/bin/kr-$arch.obj"
  done
  for f in lib/bin/*; do echo "built $f ($(stat -c %s "$f") bytes)"; done
}

# A cross-architecture Linux set: the programs of PROGRAMSX built with the cross compiler of
# triple $2 ($3 is the architecture of its libc6-dev-<arch>-cross package), compiler flags after
# that. Names: <set>/bin/<name>-<set>-<opt>[-stripped].
build_cross() {
  local set=$1 t=$2 debarch=$3
  shift 3
  local archflags=("$@")
  rm -rf "$set/bin" && mkdir -p "$set/bin"
  {
    echo "base-image: $(base_image)"
    echo "$t-gcc: $("$t-gcc" --version | head -1)"
    echo "ld: $("$t-ld" --version | head -1)"
    echo "flags: ${archflags[*]}"
    dpkg-query -W "gcc-$t" "gcc-14-$t" "binutils-$t" "libc6-dev-$debarch-cross" qemu-user \
      | sed 's/\t/ /;s/^/dpkg: /'
  } > "$set/TOOLCHAIN.txt"
  for entry in "${PROGRAMSX[@]}"; do
    name="${entry%%:*}"; extra="${entry#*:}"
    for opt in O0 O2; do
      out="$set/bin/$name-$set-$opt"
      # shellcheck disable=SC2086
      "$t-gcc" "${archflags[@]}" "-$opt" "${COMMON[@]}" $extra "src/$name.c" -o "$out"
      "$t-strip" --strip-all -o "$out-stripped" "$out"
      echo "built $out ($(stat -c %s "$out") bytes)"
    done
  done
}

build_arm32() {
  # Debian's armhf compiler defaults to Thumb-2; the set is A32 (-marm) except one Thumb-2 build.
  build_cross arm32 arm-linux-gnueabihf armhf -march=armv7-a+fp -mfloat-abi=hard -marm
  for opt in O0 O2; do
    out="arm32/bin/switch_vm-arm32-thumb-$opt"
    arm-linux-gnueabihf-gcc -march=armv7-a+fp -mfloat-abi=hard -mthumb "-$opt" "${COMMON[@]}" \
      src/switch_vm.c -o "$out"
    arm-linux-gnueabihf-strip --strip-all -o "$out-stripped" "$out"
    echo "built $out ($(stat -c %s "$out") bytes)"
  done
}

# riscv32: Debian has no riscv32 Linux userland, so the bare-metal compiler links picolibc
# statically and riscv32/src/linux_rt.c supplies _start, stdout/stderr over the Linux write
# syscall, exit_group and a static heap: static executables for Linux user-mode emulation. The
# link uses ld's default ELF script (text at 0x10000) instead of picolibc's embedded layout.
build_riscv32() {
  rm -rf riscv32/bin riscv32/.build && mkdir -p riscv32/bin riscv32/.build
  local t=riscv64-unknown-elf
  {
    echo "base-image: $(base_image)"
    echo "$t-gcc: $("$t-gcc" --version | head -1)"
    echo "ld: $("$t-ld" --version | head -1)"
    echo "flags: -march=rv32imac -mabi=ilp32 --specs=picolibc.specs -nostartfiles -static"
    dpkg-query -W "gcc-$t" "binutils-$t" "picolibc-$t" qemu-user | sed 's/\t/ /;s/^/dpkg: /'
  } > riscv32/TOOLCHAIN.txt
  "$t-ld" -m elf32lriscv --verbose | sed -n '/^=====/,/^=====/p' | sed '1d;$d' \
    > riscv32/.build/elf32lriscv.ld
  for name in "${PROGRAMSRV32[@]}"; do
    for opt in O0 O2; do
      out="riscv32/bin/$name-riscv32-$opt"
      "$t-gcc" -march=rv32imac -mabi=ilp32 --specs=picolibc.specs -nostartfiles -static \
        -T riscv32/.build/elf32lriscv.ld "-$opt" "${COMMON[@]}" "src/$name.c" \
        riscv32/src/linux_rt.c -o "$out"
      # linux_rt.c points tp at a zeroed block, which is only right without initialised TLS
      if "$t-readelf" -lW "$out" | awk '$1 == "TLS" && $5 != "0x00000" { bad = 1 } END { exit !bad }'; then
        echo "$out: initialised thread-local data, linux_rt.c does not set that up" >&2
        exit 1
      fi
      "$t-strip" --strip-all -o "$out-stripped" "$out"
      echo "built $out ($(stat -c %s "$out") bytes)"
    done
  done
}

# Runs every binary of a cross set under qemu-user with no arguments and compares exit status,
# stdout and stderr with the x86-64 build of the same program (bin/<name>-O0 of the ELF set):
# <set>/QEMU-CHECK.txt.
check_cross() {
  local set=$1 qemu=$2 sysroot=$3
  local tmp
  tmp="$(mktemp -d)"
  {
    echo "# $set under $($qemu --version | head -1), compared with the x86-64 build (bin/<name>-O0)"
    for b in $(find "$set/bin" -type f | LC_ALL=C sort); do
      base="$(basename "$b")"; prog="${base%%-*}"
      code=0; ./"bin/$prog-O0" > "$tmp/x.out" 2> "$tmp/x.err" || code=$?
      want="exit $code"
      code=0; QEMU_LD_PREFIX="$sysroot" "$qemu" "$b" > "$tmp/q.out" 2> "$tmp/q.err" || code=$?
      got="exit $code"
      if [[ $got == "$want" ]] && cmp -s "$tmp/x.out" "$tmp/q.out" \
        && cmp -s "$tmp/x.err" "$tmp/q.err"; then
        echo "$base: $got, same output as x86-64"
      else
        echo "$base: $got (x86-64: $want), output differs:"
        diff "$tmp/x.out" "$tmp/q.out" | sed 's/^/  /' || true
        diff "$tmp/x.err" "$tmp/q.err" | sed 's/^/  stderr /' || true
      fi
    done
  } > "$set/QEMU-CHECK.txt"
  rm -rf "$tmp"
  cat "$set/QEMU-CHECK.txt"
}

for set in "$@"; do
  case "$set" in
    elf) build_elf ;;
    elf32) build_elf32 ;;
    pe) build_pe ;;
    lib) build_lib ;;
    arm32) build_arm32 && check_cross arm32 qemu-arm /usr/arm-linux-gnueabihf ;;
    aarch64)
      build_cross aarch64 aarch64-linux-gnu arm64 -march=armv8-a
      check_cross aarch64 qemu-aarch64 /usr/aarch64-linux-gnu
      ;;
    riscv64)
      build_cross riscv64 riscv64-linux-gnu riscv64 -march=rv64gc -mabi=lp64d
      check_cross riscv64 qemu-riscv64 /usr/riscv64-linux-gnu
      ;;
    riscv32) build_riscv32 && check_cross riscv32 qemu-riscv32 /nonexistent ;;
    *) echo "unknown set $set" >&2; exit 2 ;;
  esac
done
