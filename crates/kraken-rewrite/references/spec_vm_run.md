# Behavioural spec: vm_run (switch_vm)

## Purpose

`vm_run` interprets a small stack-machine bytecode program against a caller-owned VM state and returns the value on top of the stack when the program halts. Any malformed program or stack misuse ends the whole process with exit status 42.

## Inputs

- `vm`: pointer to a 144-byte `struct vm`: `int32_t stack[32]` at offset 0, `int sp` at 128, `unsigned pc` at 132, `unsigned long steps` at 136. Execution continues from the stored `pc` and `sp`. [@0x101255]
- `code`: pointer to the bytecode. It must be readable one byte past `len`, because a PUSH operand and a JNZ target are fetched without a bounds check. [@0x101255]
- `len`: `unsigned` number of valid opcode bytes. The fetch loop runs while `vm->pc < len`. [@0x101255]

## Outputs

- Returns `int`: on HALT (opcode 0) the value `stack[sp - 1]`, or 0 when `sp == 0`. [@0x101255]
- Updates `*vm` in place: `pc` after every fetched byte and operand, `sp` and `stack` per instruction, and `steps` incremented once per opcode fetched (operands do not count). [@0x101255]
- Opcodes: 1 PUSH (signed 8-bit immediate), 2 ADD, 3 SUB, 4 MUL, 5 DUP, 6 SWAP, 7 DROP, 8 NEG, 9 JNZ, 10 DEC, 11 PRINT, 12 AND, 13 OR, 14 XOR. [@0x101255]

## Side effects

- PRINT writes `out: %d\n` with the signed top of stack to stdout through `printf`, without popping and without checking `sp`. [@0x101255]
- Every failure calls `vm_fail`, which writes `vm error at pc=%u: %s\n` to stderr and calls `exit(42)`; `vm_run` never returns after that. [@0x101159]
- Pushing when `sp >= 32` fails with `stack overflow`, using the current `vm->pc`. [@0x101194]
- Popping when `sp < 1` fails with `stack underflow`, using the current `vm->pc`. [@0x1011f3]
- An unknown opcode fails with `bad opcode` and `pc` of the opcode byte (`vm->pc - 1`). [@0x101255]
- Running off the end (`pc >= len`) without HALT fails with `pc out of range`. [@0x101255]

## Invariants

- `int32` arithmetic wraps: ADD, SUB, MUL, NEG and DEC use two's complement on 32 bits. [@0x101255]
- SUB computes second-from-top minus top; SWAP exchanges the top two values; DUP leaves two copies. [@0x101255]
- JNZ always pops its operand; if it was non-zero `pc` becomes the unsigned byte at `code[pc]`, otherwise `pc` skips that byte. [@0x101255]
- PUSH sign-extends its immediate: byte 0xfb pushes -5. [@0x101255]

## Open questions

- PRINT with `sp == 0` reads `stack[-1]`, outside the array; the result is undefined and probably garbage.
- Whether callers ever start with `vm->pc != 0` is not visible from this function.
