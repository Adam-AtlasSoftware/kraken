/* switch_vm: tiny bytecode VM with a dense switch (jump table) and a noreturn error path. */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

enum op {
    OP_HALT, OP_PUSH, OP_ADD, OP_SUB, OP_MUL, OP_DUP, OP_SWAP,
    OP_DROP, OP_NEG, OP_JNZ, OP_DEC, OP_PRINT, OP_AND, OP_OR, OP_XOR,
    OP_COUNT
};

#define STACK_MAX 32

struct vm {
    int32_t stack[STACK_MAX];
    int sp;
    unsigned pc;
    unsigned long steps;
};

__attribute__((noreturn, noinline))
static void vm_fail(const char *msg, unsigned pc)
{
    fprintf(stderr, "vm error at pc=%u: %s\n", pc, msg);
    exit(42);
}

static void push(struct vm *vm, int32_t v)
{
    if (vm->sp >= STACK_MAX)
        vm_fail("stack overflow", vm->pc);
    vm->stack[vm->sp++] = v;
}

static int32_t pop(struct vm *vm)
{
    if (vm->sp <= 0)
        vm_fail("stack underflow", vm->pc);
    return vm->stack[--vm->sp];
}

int vm_run(struct vm *vm, const uint8_t *code, unsigned len)
{
    int32_t a, b;
    for (;;) {
        if (vm->pc >= len)
            vm_fail("pc out of range", vm->pc);
        uint8_t op = code[vm->pc++];
        vm->steps++;
        switch (op) {
        case OP_HALT:  return vm->sp ? vm->stack[vm->sp - 1] : 0;
        case OP_PUSH:  push(vm, (int8_t)code[vm->pc++]); break;
        case OP_ADD:   b = pop(vm); a = pop(vm); push(vm, a + b); break;
        case OP_SUB:   b = pop(vm); a = pop(vm); push(vm, a - b); break;
        case OP_MUL:   b = pop(vm); a = pop(vm); push(vm, a * b); break;
        case OP_DUP:   a = pop(vm); push(vm, a); push(vm, a); break;
        case OP_SWAP:  b = pop(vm); a = pop(vm); push(vm, b); push(vm, a); break;
        case OP_DROP:  (void)pop(vm); break;
        case OP_NEG:   push(vm, -pop(vm)); break;
        case OP_JNZ:
            a = pop(vm);
            if (a)
                vm->pc = code[vm->pc];
            else
                vm->pc++;
            break;
        case OP_DEC:   push(vm, pop(vm) - 1); break;
        case OP_PRINT: printf("out: %d\n", (int)vm->stack[vm->sp - 1]); break;
        case OP_AND:   b = pop(vm); a = pop(vm); push(vm, a & b); break;
        case OP_OR:    b = pop(vm); a = pop(vm); push(vm, a | b); break;
        case OP_XOR:   b = pop(vm); a = pop(vm); push(vm, a ^ b); break;
        default:       vm_fail("bad opcode", vm->pc - 1);
        }
    }
}

const char *op_name(unsigned op)
{
    switch (op) {
    case OP_HALT:  return "halt";
    case OP_PUSH:  return "push";
    case OP_ADD:   return "add";
    case OP_SUB:   return "sub";
    case OP_MUL:   return "mul";
    case OP_DUP:   return "dup";
    case OP_SWAP:  return "swap";
    case OP_DROP:  return "drop";
    case OP_NEG:   return "neg";
    case OP_JNZ:   return "jnz";
    case OP_DEC:   return "dec";
    case OP_PRINT: return "print";
    case OP_AND:   return "and";
    case OP_OR:    return "or";
    case OP_XOR:   return "xor";
    default:       return "?";
    }
}

int main(void)
{
    /* arithmetic prelude, then count down from 5 printing each value. */
    static const uint8_t prog[] = {
        OP_PUSH, 6, OP_PUSH, 7, OP_MUL, OP_PUSH, 3, OP_XOR, OP_DROP,
        /* 9 */ OP_PUSH, 5,
        /* 11 */ OP_PRINT, OP_DEC, OP_DUP, OP_JNZ, 11,
        OP_HALT,
    };
    struct vm vm = { {0}, 0, 0, 0 };
    int r = vm_run(&vm, prog, sizeof prog);
    printf("result=%d steps=%lu first=%s\n", r, vm.steps, op_name(prog[0]));
    return 0;
}
