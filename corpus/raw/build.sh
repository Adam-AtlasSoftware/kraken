#!/bin/sh
# Builds the raw images in corpus/raw (flat blobs from tiny freestanding programs).
# Needs clang, ld.lld and llvm-objcopy; the outputs are committed, so this is only for changes.
set -eu
cd "$(dirname "$0")"
out="${TMPDIR:-/tmp}"
clang --target=thumbv7m-none-eabi -mcpu=cortex-m3 -Os -ffreestanding -fno-builtin -nostdlib \
  -fuse-ld=lld -Wl,-T,src/fw_cortexm.ld -o "$out/fw_cortexm.elf" src/fw_cortexm.c
llvm-objcopy -O binary "$out/fw_cortexm.elf" fw_cortexm.bin
clang --target=i686-unknown-none -m32 -Os -ffreestanding -fno-builtin -fno-pic -static -nostdlib \
  -fuse-ld=lld -Wl,-T,src/fw_x86.ld -o "$out/fw_x86.elf" src/fw_x86.c
llvm-objcopy -O binary "$out/fw_x86.elf" fw_x86.bin
# the same Cortex-M program as Intel HEX and Motorola S-record text (real addresses, start record)
llvm-objcopy -O ihex "$out/fw_cortexm.elf" fw_cortexm.hex
llvm-objcopy -O srec "$out/fw_cortexm.elf" fw_cortexm.srec
ls -l fw_cortexm.bin fw_x86.bin fw_cortexm.hex fw_cortexm.srec
