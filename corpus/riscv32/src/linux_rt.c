/* linux_rt: the startup and system layer of the riscv32 set. Debian has no riscv32 Linux
 * userland, so these programs link against picolibc (bare-metal) and this file supplies what an
 * operating system would: _start reads argc/argv from the Linux initial stack, stdout and stderr
 * write with the raw Linux write syscall, _exit is exit_group, and sbrk hands out a static heap.
 * The result is a static ELF executable that runs under Linux user-mode emulation (qemu-riscv32)
 * and makes no other system calls. */
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv);

#define SYS_write 64
#define SYS_exit_group 94

static long sys3(long n, long a, long b, long c)
{
    register long a0 __asm__("a0") = a;
    register long a1 __asm__("a1") = b;
    register long a2 __asm__("a2") = c;
    register long a7 __asm__("a7") = n;
    __asm__ volatile("ecall" : "+r"(a0) : "r"(a1), "r"(a2), "r"(a7) : "memory");
    return a0;
}

void _exit(int status)
{
    for (;;)
        sys3(SYS_exit_group, status, 0, 0);
}

static int put_fd(char c, int fd)
{
    return sys3(SYS_write, fd, (long)&c, 1) == 1 ? (unsigned char)c : EOF;
}

static int put_out(char c, FILE *f)
{
    (void)f;
    return put_fd(c, 1);
}

static int put_err(char c, FILE *f)
{
    (void)f;
    return put_fd(c, 2);
}

static FILE kr_stdout = FDEV_SETUP_STREAM(put_out, NULL, NULL, _FDEV_SETUP_WRITE);
static FILE kr_stderr = FDEV_SETUP_STREAM(put_err, NULL, NULL, _FDEV_SETUP_WRITE);
FILE *const stdout = &kr_stdout;
FILE *const stderr = &kr_stderr;

static char kr_heap[64 * 1024] __attribute__((aligned(16)));
static size_t kr_brk;

void *sbrk(ptrdiff_t incr)
{
    if (incr < 0 ? (size_t)-incr > kr_brk : (size_t)incr > sizeof kr_heap - kr_brk)
        return (void *)-1;
    void *old = kr_heap + kr_brk;
    kr_brk += incr;
    return old;
}

/* The thread pointer of the only thread: picolibc keeps errno in thread-local storage
 * (local-exec, all of it zero-initialised .tbss, which build.sh checks). */
static char kr_tls[64] __attribute__((aligned(16), used));

__attribute__((used, noreturn)) static void kr_start(int argc, char **argv)
{
    exit(main(argc, argv));
}

__attribute__((naked, noreturn)) void _start(void)
{
    __asm__ volatile(
        ".option push\n"
        ".option norelax\n"
        "la gp, __global_pointer$\n"
        ".option pop\n"
        "la tp, kr_tls\n"
        "lw a0, 0(sp)\n"
        "addi a1, sp, 4\n"
        "andi sp, sp, -16\n"
        "call kr_start\n");
}
