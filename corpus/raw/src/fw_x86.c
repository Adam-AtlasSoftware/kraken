/* Flat 32-bit x86 boot-style blob: no libc, position dependent at 0x00100000. */
static unsigned int table[4] = {3, 5, 7, 11};

__attribute__((noinline)) unsigned int sum_table(void) {
    unsigned int s = 0;
    for (int i = 0; i < 4; i++)
        s += table[i];
    return s;
}

__attribute__((noinline)) unsigned int gcd(unsigned int a, unsigned int b) {
    while (b) {
        unsigned int t = a % b;
        a = b;
        b = t;
    }
    return a;
}

void __attribute__((section(".entry"), noreturn)) start(void) {
    volatile unsigned int *out = (volatile unsigned int *)0xB8000;
    *out = sum_table() + gcd(48, 18);
    for (;;)
        ;
}
