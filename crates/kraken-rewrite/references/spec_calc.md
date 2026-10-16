# Behavioural spec: stripped_calc expression evaluator

## Purpose

The program evaluates integer arithmetic expressions given as text and reports either the value or an error. The evaluator is a recursive-descent parser that computes the value while parsing.

## Inputs

- `text`: NUL-terminated string holding the expression. Whitespace (space, tab, newline, vertical tab, form feed, carriage return) is skipped between tokens. [@0x10145b]
- Grammar: an expression is terms joined by `+` or `-`; a term is atoms joined by `*`, `/` or `%`; an atom is a parenthesised expression, a unary minus applied to an atom, or a decimal number. [@0x1013cf] [@0x10130d] [@0x101247]
- Numbers are unsigned decimal digit runs; a leading `+` is not accepted. [@0x101197]

## Outputs

- `evaluate` returns 0 and stores the value through `out` (a `long`) only when the whole input was consumed without error; otherwise it returns -1 and leaves `*out` untouched. [@0x10145b]
- Division and remainder use C `long` semantics: they truncate toward zero, and the remainder takes the sign of the left operand. [@0x10130d]
- Division or remainder by zero sets the error flag instead of trapping. [@0x10130d]

## Side effects

- None in the evaluator: it only reads `text` and writes `*out` on success. [@0x10145b]
- The evaluator calls `isspace` and `isdigit`, which read the C locale character table. [@0x101149] [@0x101197]

## Invariants

- Multiplication, addition, subtraction, negation and digit accumulation wrap on 64 bits. [@0x1013cf]
- Trailing characters after a complete expression (for example `1 2`) make the result an error. [@0x10145b]
- An empty string, a missing operand (`12 +`) or an unbalanced parenthesis is an error. [@0x101247] [@0x101197]

## Open questions

- `LONG_MIN / -1` would trap on x86-64; whether any input can reach it is not settled by this code.
- The recursion depth is unbounded, so very deeply nested input probably overflows the stack.
