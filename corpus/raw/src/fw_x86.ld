SECTIONS {
  . = 0x00100000;
  .text : { *(.entry) *(.text*) *(.rodata*) *(.data*) }
  /DISCARD/ : { *(.comment) *(.note*) *(.eh_frame*) *(.interp) *(.dynsym) *(.gnu.hash) *(.hash) *(.dynstr) *(.dynamic) }
}
