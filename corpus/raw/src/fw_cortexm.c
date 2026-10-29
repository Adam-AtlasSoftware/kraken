/* A tiny Cortex-M3 firmware: vector table, a few functions, a SysTick handler. */
typedef unsigned int u32;

static volatile u32 ticks;
static volatile u32 result;

int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }

int checksum(const unsigned char *p, int n) {
    int s = 0;
    for (int i = 0; i < n; i++)
        s = (s << 1) ^ p[i];
    return s;
}

void SysTick_Handler(void) { ticks++; }

void Default_Handler(void) {
    for (;;)
        ;
}

int main(void) {
    unsigned char buf[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    int r = checksum(buf, 8) + fib(10);
    for (;;)
        result += (u32)r + ticks;
}

void Reset_Handler(void) { main(); }

__attribute__((section(".vectors"), used)) const u32 vectors[16] = {
    0x20008000u,
    (u32)Reset_Handler,
    (u32)Default_Handler, /* NMI */
    (u32)Default_Handler, /* HardFault */
    (u32)Default_Handler, 0, 0, 0, 0, 0, 0, (u32)Default_Handler, /* SVC */
    0, 0, (u32)Default_Handler, /* PendSV */
    (u32)SysTick_Handler,
};
