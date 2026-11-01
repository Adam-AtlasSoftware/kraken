/* abi_shapes: one function per System V x86-64 calling-convention shape the rewrite pipeline
 * must place identically in the emulator and in the translated Rust: structures by value in
 * registers (INTEGER, SSE, mixed), structures by value and results in memory, more arguments
 * than registers, variadic callees, and float and double arguments and results.
 *
 * Every function is noinline and external so each stays a function of its own at -O2.
 * No libc call is made, so the oracle runs them without any import stubs. */
#include <stdarg.h>

struct small { int a, b; };           /* one INTEGER eightbyte: rdi */
struct mixed { long id; double w; };  /* INTEGER + SSE: rdi, xmm0 */
struct vec2 { double x, y; };         /* SSE + SSE: xmm0, xmm1 */
struct fpair { float x, y; };         /* one SSE eightbyte: xmm0 */
struct large { long a, b, c, d; };    /* class MEMORY: copied to the stack, result via sret */

#define KEEP __attribute__((noinline))

KEEP struct small small_swap(struct small s) {
  struct small r = {s.b, s.a};
  return r;
}

KEEP long small_dot(struct small s, int k) { return (long)s.a * k + (long)s.b * ((long)k + 1); }

KEEP struct mixed mixed_scale(struct mixed m, long k) {
  struct mixed r = {m.id * k, m.w * (double)k};
  return r;
}

KEEP struct vec2 vec2_rot(struct vec2 v, double c) {
  struct vec2 r = {v.x * c - v.y, v.y * c + v.x};
  return r;
}

KEEP struct fpair fpair_mix(struct fpair p, float k) {
  struct fpair r = {p.x * k + p.y, p.y * k - p.x};
  return r;
}

KEEP struct large large_make(long seed) {
  struct large r = {seed, seed * 2, seed * 3, seed * seed};
  return r;
}

KEEP long large_sum(struct large l, long k) { return l.a * k + l.b - l.c + l.d * 2; }

/* With six integer registers taken a small structure goes to the stack whole, and the
 * argument after it follows it there. */
KEEP long late_struct(long a, long b, long c, long d, long e, long f, struct small s, long g) {
  return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7L * s.a + 8L * s.b + 9 * g;
}

KEEP long eight_args(long a, long b, long c, long d, long e, long f, long g, long h) {
  return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h;
}

KEEP double ten_doubles(double a, double b, double c, double d, double e, double f, double g,
                        double h, double i, double j) {
  return a + 2 * b + 3 * c + 4 * d + 5 * e + 6 * f + 7 * g + 8 * h + 9 * i + 10 * j;
}

KEEP long mixed_stack(int a, double x, int b, double y, int c, int d, int e, int f, int g, int h,
                      double z) {
  return a + 2L * b + 3L * c + 4L * d + 5L * e + 6L * f + 7L * g + 8L * h +
         (long)(x * 10.0 + y * 100.0 + z * 1000.0);
}

KEEP int sum_ints(int n, ...) {
  va_list ap;
  va_start(ap, n);
  int s = 0;
  for (int i = 0; i < n; i++) s += va_arg(ap, int) * (i + 1);
  va_end(ap);
  return s;
}

KEEP double sum_doubles(int n, ...) {
  va_list ap;
  va_start(ap, n);
  double s = 0;
  for (int i = 0; i < n; i++) s += va_arg(ap, double) * (i + 1);
  va_end(ap);
  return s;
}

KEEP float float_fma(float a, float b) { return a * b + a; }

KEEP double poly(double x) { return ((3.0 * x + 2.0) * x - 5.0) * x + 7.0; }

KEEP double sum3(double a, double b, double c) { return (a + b) + c; }

KEEP float fdiv_sum(float a, double b) { return (float)((double)a / (b == 0.0 ? 1.0 : b)); }

int main(void) {
  struct small s = small_swap((struct small){1, 2});
  struct large l = large_make(3);
  return (int)(small_dot(s, 2) + large_sum(l, 2) + eight_args(1, 2, 3, 4, 5, 6, 7, 8) +
               sum_ints(2, 1, 2) + (long)sum_doubles(1, 2.0) + (long)poly(1.0) +
               (long)ten_doubles(1, 2, 3, 4, 5, 6, 7, 8, 9, 10) +
               mixed_stack(1, 2.0, 3, 4.0, 5, 6, 7, 8, 9, 10, 11.0) + (long)float_fma(1, 2) +
               late_struct(1, 2, 3, 4, 5, 6, s, 7) + (long)sum3(1, 2, 3) + (long)fdiv_sum(1, 2) +
               (long)mixed_scale((struct mixed){1, 2.0}, 2).id + (long)vec2_rot((struct vec2){1, 2}, 3).x +
               (long)fpair_mix((struct fpair){1, 2}, 3).x) & 0x7f;
}
