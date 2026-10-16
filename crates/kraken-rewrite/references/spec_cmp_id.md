# Behavioural spec: cmp_id (pie_list)

## Purpose

`cmp_id` is a three-way style comparator for two records. It orders them by their integer id and returns the plain difference of the ids rather than -1, 0 or 1.

## Inputs

- `a`: pointer to a 40-byte `struct record`; only the `int` id at offset 0 is read. [@0x10124e]
- `b`: pointer to a second `struct record`, read the same way. [@0x10124e]

## Outputs

- Returns `int`: `a->id - b->id` computed in 32-bit two's complement, so the result wraps when the true difference does not fit. [@0x10124e]
- A positive result means `a` sorts after `b`, a negative one before, zero means equal ids. [@0x10124e]

## Side effects

- None: nothing is written through either pointer and nothing is printed. [@0x10124e]

## Invariants

- The result depends only on the two ids; the names, positions and weights of the records are never read. [@0x10124e]
- `cmp_id(a, a)` is 0 for every `a`. [@0x10124e]

## Open questions

- none
