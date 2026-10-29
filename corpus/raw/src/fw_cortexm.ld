SECTIONS {
  . = 0x08000000;
  .text : { KEEP(*(.vectors)) *(.text*) *(.rodata*) }
  /DISCARD/ : { *(.ARM.exidx*) *(.comment) *(.note*) }
}
