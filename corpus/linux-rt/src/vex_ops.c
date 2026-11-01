// Runs every case of vex_cases.S from one fixed machine state and prints what each changed: the
// vector and integer registers, the defined flags and two memory buffers. build.sh records the
// output on a real x86-64-v3 CPU; the emulator must print the same.
#include "rt.h"

int memcmp(const void *a, const void *b, unsigned long n) {
  for (unsigned long i = 0; i < n; i++)
    if (((const unsigned char *)a)[i] != ((const unsigned char *)b)[i])
      return 1;
  return 0;
}

struct state {
  unsigned char ymm[16][32];
  unsigned long gpr[9]; // rax rbx rcx rdx r8 r9 r10 r11 r12
  unsigned long flags;
} __attribute__((aligned(64)));

struct kase {
  void (*run)(void);
  const char *name;
  unsigned long flag_mask;
};
extern struct kase cases[];

static struct state in, out;
static unsigned char src[128] __attribute__((aligned(64)));
static unsigned char dst[128] __attribute__((aligned(64)));
static unsigned char table[256] __attribute__((aligned(64)));
static unsigned long rng = 0x9e3779b97f4a7c15UL;

static unsigned long next(void) {
  rng ^= rng << 13;
  rng ^= rng >> 7;
  rng ^= rng << 17;
  return rng;
}

static void fill(void *p, unsigned long n) {
  unsigned char *b = p;
  for (unsigned long i = 0; i < n; i++)
    b[i] = (unsigned char)(next() >> 24);
}

static void floats(int r, float a, float b, float c, float d, float e, float f, float g, float h) {
  float v[8] = {a, b, c, d, e, f, g, h};
  __builtin_memcpy(in.ymm[r], v, 32);
}

static void doubles(int r, double a, double b, double c, double d) {
  double v[4] = {a, b, c, d};
  __builtin_memcpy(in.ymm[r], v, 32);
}

static void setup(void) {
  fill(in.ymm, sizeof in.ymm);
  fill(src, sizeof src);
  fill(table, sizeof table);
  // Selectors, masks and strings the instructions treat specially.
  for (int i = 0; i < 16; i++)
    in.ymm[4][i * 2] &= 0x80;
  __builtin_memcpy(in.ymm[6], "hello, world\0xyz", 16);
  __builtin_memcpy(in.ymm[7], "world\0abcdefghij", 16);
  for (int i = 0; i < 8; i++) {
    unsigned idx = (unsigned)(next() % 64);
    __builtin_memcpy(in.ymm[5] + i * 4, &idx, 4);
  }
  float nan = __builtin_nanf("");
  float inf = __builtin_inff();
  floats(9, 1.5f, -2.25f, 1e10f, 0.0f, nan, inf, -0.0f, 3.0f);
  floats(10, 2.5f, -2.25f, 3.5f, -0.0f, 1.0f, inf, 0.0f, nan);
  floats(11, 0.5f, 4.0f, -1.0f, 2.0f, 8.0f, 1.0f, 2.0f, 2.0f);
  doubles(13, 1.5, -2.25, 1e300, __builtin_nan(""));
  doubles(14, 2.5, -2.25, 3.5, 1.0);
  doubles(15, 0.5, 4.0, -1.0, 2.0);
  __builtin_memcpy(src + 64, in.ymm[9], 32);
  in.gpr[0] = 0x8123456789abcdefUL;
  in.gpr[1] = 0x00ff00f0f00f0100UL;
  in.gpr[2] = 0x0000000000000011UL;
  in.gpr[3] = 0x0000000000000009UL;
  in.gpr[4] = 0x1111111111111111UL;
  in.gpr[5] = 0x2222222222222222UL;
  in.gpr[6] = (unsigned long)table;
  in.gpr[7] = 0;
  in.gpr[8] = 0;
}

extern void run_case(void (*f)(void), struct state *in, struct state *out, void *src, void *dst);
__asm__(".intel_syntax noprefix\n"
        ".text\n"
        "run_case:\n"
        "  push rbx\n  push rbp\n  push r12\n  push r13\n  push r14\n  push r15\n"
        "  mov r13, rdx\n"
        "  mov r14, rdi\n"
        "  mov r15, rsi\n"
        "  mov rsi, rcx\n"
        "  mov rdi, r8\n"
        "  push r13\n"
        "  push rsi\n"
        "  mov r11, r15\n"
        "  .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15\n"
        "  vmovdqa ymm\\n, [r11 + \\n * 32]\n"
        "  .endr\n"
        "  mov rax, [r11 + 512]\n"
        "  mov rbx, [r11 + 520]\n"
        "  mov rcx, [r11 + 528]\n"
        "  mov rdx, [r11 + 536]\n"
        "  mov r8, [r11 + 544]\n"
        "  mov r9, [r11 + 552]\n"
        "  mov r10, [r11 + 560]\n"
        "  mov r12, [r11 + 576]\n"
        "  mov r11, [r11 + 568]\n"
        "  push 0x2\n  popfq\n"
        "  call r14\n"
        "  pushfq\n"
        "  pop r14\n"
        "  pop rsi\n"
        "  pop r13\n"
        "  .irp n,0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15\n"
        "  vmovdqa [r13 + \\n * 32], ymm\\n\n"
        "  .endr\n"
        "  mov [r13 + 512], rax\n"
        "  mov [r13 + 520], rbx\n"
        "  mov [r13 + 528], rcx\n"
        "  mov [r13 + 536], rdx\n"
        "  mov [r13 + 544], r8\n"
        "  mov [r13 + 552], r9\n"
        "  mov [r13 + 560], r10\n"
        "  mov [r13 + 568], r11\n"
        "  mov [r13 + 576], r12\n"
        "  mov [r13 + 584], r14\n"
        "  vzeroupper\n"
        "  pop r15\n  pop r14\n  pop r13\n  pop r12\n  pop rbp\n  pop rbx\n"
        "  ret\n"
        ".att_syntax prefix\n");

static char line[4096];
static unsigned long used;

static void text(const char *s) {
  while (*s)
    line[used++] = *s++;
}

static void hex(const unsigned char *p, unsigned long n) {
  static const char d[] = "0123456789abcdef";
  for (unsigned long i = n; i-- > 0;) {
    line[used++] = d[p[i] >> 4];
    line[used++] = d[p[i] & 15];
  }
}

static int differs(const void *a, const void *b, unsigned long n) {
  return __builtin_memcmp(a, b, n) != 0;
}

void kmain(void) {
  setup();
  static const char *const gpr[9] = {"rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12"};
  for (struct kase *k = cases; k->run; k++) {
    static unsigned char mem[128] __attribute__((aligned(64)));
    __builtin_memcpy(mem, src, sizeof mem);
    __builtin_memset(dst, 0x5a, sizeof dst);
    run_case(k->run, &in, &out, mem, dst);
    used = 0;
    text(k->name);
    text(":");
    for (int r = 0; r < 16; r++)
      if (differs(in.ymm[r], out.ymm[r], 32)) {
        text(" y");
        line[used++] = "0123456789abcdef"[r];
        text("=");
        hex(out.ymm[r], 32);
      }
    for (int r = 0; r < 9; r++)
      if (in.gpr[r] != out.gpr[r]) {
        text(" ");
        text(gpr[r]);
        text("=");
        hex((unsigned char *)&out.gpr[r], 8);
      }
    unsigned char f = (unsigned char)(out.flags & k->flag_mask);
    unsigned char o = (unsigned char)((out.flags & k->flag_mask) >> 8);
    text(" f=");
    hex(&o, 1);
    hex(&f, 1);
    for (unsigned long i = 0; i < sizeof dst; i += 32) {
      static unsigned char blank[32];
      __builtin_memset(blank, 0x5a, 32);
      if (differs(dst + i, blank, 32)) {
        text(" m=");
        hex(dst + i, 32);
      }
    }
    if (differs(mem, src, sizeof mem))
      text(" src-changed");
    text("\n");
    sys3(NR_write, 1, (i64)line, (i64)used);
  }
  sys3(NR_exit_group, 0, 0, 0);
}
