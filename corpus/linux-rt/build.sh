#!/bin/sh
# Builds the linux-rt programs as static, freestanding x86-64 and AArch64 ELF files with clang and
# lld (no libc, no cross sysroot needed) and records the expected output by running the x86-64
# build natively.
#
#   corpus/linux-rt/build.sh          build bin/<name>-x86_64 and bin/<name>-aarch64
#   corpus/linux-rt/build.sh record   also run natively and rewrite expected/
#
# Each program runs with a fresh directory as its working directory that holds a copy of the
# program named `prog` (as /work/prog in the emulator), with a pipe carrying "go" on standard input.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"
names="fd_dup pipes dirs sleeping polling"
mkdir -p bin expected
for n in $names; do
  for t in x86_64:x86_64-linux-gnu aarch64:aarch64-linux-gnu; do
    arch=${t%%:*}
    clang --target="${t#*:}" -O1 -g0 -static -nostdlib -ffreestanding -fno-builtin \
      -fno-stack-protector -fno-pic -fuse-ld=lld -Wl,--build-id=none -Wl,-z,norelro \
      -Wall -Wextra -Wno-unused-function -o "bin/$n-$arch" "src/$n.c"
    llvm-strip --strip-all "bin/$n-$arch" 2>/dev/null || true
  done
done
# The VEX instruction test exists for x86-64 only; `record` needs an x86-64-v3 CPU. Its C part is
# built for baseline x86-64: only the cases and the register loads use newer instructions.
python3 src/gen_vex_cases.py src/vex_cases.S
clang --target=x86_64-linux-gnu -O1 -g0 -static -nostdlib -ffreestanding -fno-builtin \
  -fno-stack-protector -fno-pic -fuse-ld=lld -Wl,--build-id=none -Wl,-z,norelro \
  -Wall -Wextra -Wno-unused-function \
  -o bin/vex_ops-x86_64 src/vex_ops.c src/vex_cases.S
llvm-strip --strip-all bin/vex_ops-x86_64 2>/dev/null || true
if [ "${1:-}" = record ]; then
  ./bin/vex_ops-x86_64 >expected/vex_ops.stdout
  echo $? >expected/vex_ops.exit
  echo "vex_ops: exit $(cat expected/vex_ops.exit), $(wc -l <expected/vex_ops.stdout) lines"
  for n in $names; do
    d=$(mktemp -d)
    cp "bin/$n-x86_64" "$d/prog"
    set +e
    (cd "$d" && printf go | ./prog >"$here/expected/$n.stdout")
    echo $? >"expected/$n.exit"
    set -e
    rm -rf "$d"
    echo "$n: exit $(cat "expected/$n.exit"), $(wc -l <"expected/$n.stdout") lines"
  done
fi
(cd bin && sha256sum -- * >"$here/MANIFEST.sha256")
