/* A freestanding runtime for the linux-rt programs: raw system calls, no libc, so the same source
   builds for x86-64 and AArch64 and the output depends only on the kernel interface. */
typedef unsigned long u64;
typedef long i64;
typedef unsigned int u32;
typedef int i32;
typedef unsigned short u16;
typedef unsigned char u8;

#if defined(__x86_64__)
#define NR_read 0
#define NR_write 1
#define NR_close 3
#define NR_lseek 8
#define NR_rt_sigaction 13
#define NR_pipe 22
#define NR_sched_yield 24
#define NR_dup 32
#define NR_dup2 33
#define NR_nanosleep 35
#define NR_fcntl 72
#define NR_rename 82
#define NR_mkdir 83
#define NR_poll 7
#define NR_getdents64 217
#define NR_clock_gettime 228
#define NR_clock_nanosleep 230
#define NR_exit_group 231
#define NR_openat 257
#define NR_mkdirat 258
#define NR_renameat 264
#define NR_ppoll 271
#define NR_dup3 292
#define NR_pipe2 293
static inline i64 sys6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  register i64 r10 __asm__("r10") = d;
  register i64 r8 __asm__("r8") = e;
  register i64 r9 __asm__("r9") = f;
  i64 ret;
  __asm__ volatile("syscall" : "=a"(ret) : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9) : "rcx", "r11", "memory");
  return ret;
}
__asm__(".globl _start\n_start:\n xor %ebp,%ebp\n and $-16,%rsp\n call kmain\n");
#elif defined(__aarch64__)
#define NR_dup 23
#define NR_dup3 24
#define NR_fcntl 25
#define NR_mkdirat 34
#define NR_renameat 38
#define NR_openat 56
#define NR_close 57
#define NR_pipe2 59
#define NR_getdents64 61
#define NR_lseek 62
#define NR_read 63
#define NR_write 64
#define NR_ppoll 73
#define NR_exit_group 94
#define NR_nanosleep 101
#define NR_clock_gettime 113
#define NR_clock_nanosleep 115
#define NR_sched_yield 124
#define NR_rt_sigaction 134
static inline i64 sys6(i64 n, i64 a, i64 b, i64 c, i64 d, i64 e, i64 f) {
  register i64 x8 __asm__("x8") = n;
  register i64 x0 __asm__("x0") = a;
  register i64 x1 __asm__("x1") = b;
  register i64 x2 __asm__("x2") = c;
  register i64 x3 __asm__("x3") = d;
  register i64 x4 __asm__("x4") = e;
  register i64 x5 __asm__("x5") = f;
  __asm__ volatile("svc 0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5) : "memory");
  return x0;
}
__asm__(".globl _start\n_start:\n mov x29,#0\n mov x0,sp\n and sp,x0,#-16\n bl kmain\n");
#else
#error unsupported architecture
#endif

#define AT_FDCWD (-100)
#define O_RDONLY 0
#define O_WRONLY 1
#define O_RDWR 2
#define O_CREAT 0100
#define O_TRUNC 01000
#define O_NONBLOCK 04000
#define O_CLOEXEC 02000000
#define F_DUPFD 0
#define F_GETFD 1
#define F_SETFD 2
#define F_GETFL 3
#define F_SETFL 4
#define F_DUPFD_CLOEXEC 1030
#define FD_CLOEXEC 1
#define POLLIN 1
#define POLLOUT 4
#define POLLERR 8
#define POLLHUP 16
#define POLLNVAL 32
#define EBADF 9
#define EAGAIN 11
#define EINVAL 22
#define EPIPE 32
#define CLOCK_MONOTONIC 1
#define TIMER_ABSTIME 1

struct timespec { i64 sec; i64 nsec; };
struct pollfd { i32 fd; short events; short revents; };

static inline i64 sys3(i64 n, i64 a, i64 b, i64 c) { return sys6(n, a, b, c, 0, 0, 0); }
static inline i64 sys1(i64 n, i64 a) { return sys6(n, a, 0, 0, 0, 0, 0); }

static u64 slen(const char *s) { u64 n = 0; while (s[n]) n++; return n; }
void *memcpy(void *d, const void *s, u64 n) { u8 *a = d; const u8 *b = s; while (n--) *a++ = *b++; return d; }
void *memset(void *d, int c, u64 n) { u8 *a = d; while (n--) *a++ = (u8)c; return d; }

static void put(const char *s) { sys3(NR_write, 1, (i64)s, (i64)slen(s)); }
static void putn(i64 v) {
  char b[24]; int i = 23; b[i] = 0; int neg = v < 0; u64 u = neg ? (u64)-v : (u64)v;
  do { b[--i] = '0' + u % 10; u /= 10; } while (u);
  if (neg) b[--i] = '-';
  put(b + i);
}
/* "name = value" lines, so a difference is easy to read. */
static void show(const char *name, i64 v) { put(name); put(" = "); putn(v); put("\n"); }
static int failed;
static void check(const char *name, int ok) { if (!ok) failed++; put(ok ? "ok   " : "FAIL "); put(name); put("\n"); }

static i64 xopen(const char *path, int flags) { return sys6(NR_openat, AT_FDCWD, (i64)path, flags, 0644, 0, 0); }
static i64 xread(i64 fd, void *b, u64 n) { return sys3(NR_read, fd, (i64)b, (i64)n); }
static i64 xwrite(i64 fd, const void *b, u64 n) { return sys3(NR_write, fd, (i64)b, (i64)n); }
static i64 xclose(i64 fd) { return sys1(NR_close, fd); }
static void quit(void) { sys1(NR_exit_group, failed); for (;;) {} }
