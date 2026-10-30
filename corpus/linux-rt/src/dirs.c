/* mkdir, mkdirat, rename, renameat and getdents64 over the working directory. */
#include "rt.h"

struct dirent64 { u64 ino; i64 off; u16 reclen; u8 type; char name[]; };

static void touch(const char *path, const char *text) {
  i64 f = xopen(path, O_WRONLY | O_CREAT | O_TRUNC);
  if (f >= 0) { xwrite(f, text, slen(text)); xclose(f); }
}

static int cmp(const char *a, const char *b) {
  while (*a && *a == *b) { a++; b++; }
  return (u8)*a - (u8)*b;
}

/* Lists a directory: sorted names with their type. */
static void list(const char *path) {
  i64 fd = xopen(path, O_RDONLY);
  put("ls "); put(path); put("\n");
  if (fd < 0) { show("open", fd); return; }
  static char buf[4096];
  const char *names[64]; u8 types[64]; static char store[64][32];
  int n = 0;
  for (;;) {
    i64 got = sys3(NR_getdents64, fd, (i64)buf, sizeof buf);
    if (got <= 0) { if (got < 0) show("getdents64", got); break; }
    for (i64 off = 0; off < got;) {
      struct dirent64 *d = (struct dirent64 *)(buf + off);
      if (n < 64) {
        u64 l = slen(d->name);
        memcpy(store[n], d->name, l + 1);
        names[n] = store[n]; types[n] = d->type; n++;
      }
      off += d->reclen;
    }
  }
  for (int i = 1; i < n; i++)
    for (int j = i; j > 0 && cmp(names[j - 1], names[j]) > 0; j--) {
      const char *t = names[j]; names[j] = names[j - 1]; names[j - 1] = t;
      u8 u = types[j]; types[j] = types[j - 1]; types[j - 1] = u;
    }
  for (int i = 0; i < n; i++) { put("  "); put(names[i]); put(types[i] == 4 ? "/" : types[i] == 8 ? "" : "?"); put("\n"); }
  xclose(fd);
}

static i64 mk(const char *p) {
#if defined(__x86_64__)
  return sys3(NR_mkdir, (i64)p, 0755, 0);
#else
  return sys3(NR_mkdirat, AT_FDCWD, (i64)p, 0755);
#endif
}

static i64 mv(const char *a, const char *b) {
#if defined(__x86_64__)
  return sys3(NR_rename, (i64)a, (i64)b, 0);
#else
  return sys6(NR_renameat, AT_FDCWD, (i64)a, AT_FDCWD, (i64)b, 0, 0);
#endif
}

void kmain(void) {
  put("dirs\n");
  show("mkdir sub", mk("sub"));
  show("mkdir sub again (EEXIST)", mk("sub"));
  show("mkdirat", sys3(NR_mkdirat, AT_FDCWD, (i64)"sub/inner", 0755));
  show("mkdir without a parent (ENOENT)", mk("nope/child"));
  touch("a.txt", "alpha");
  touch("sub/b.txt", "beta");
  list(".");
  list("sub");

  show("rename a file", mv("a.txt", "c.txt"));
  show("renameat into a directory", sys6(NR_renameat, AT_FDCWD, (i64)"c.txt", AT_FDCWD, (i64)"sub/d.txt", 0, 0));
  show("rename a missing file (ENOENT)", mv("a.txt", "z.txt"));
  show("rename a directory", mv("sub/inner", "inner2"));
  list(".");
  list("sub");

  char b[8];
  i64 f = xopen("sub/d.txt", O_RDONLY);
  show("renamed file keeps its content", xread(f, b, 8));
  b[5] = 0; put(b); put("\n");
  xclose(f);

  /* Nothing outside the working directory can be changed. */
  check("mkdir outside the work directory fails", mk("/proc/kraken-linux-rt-outside") < 0);
  check("rename out of the work directory fails", mv("sub/b.txt", "/proc/kraken-linux-rt-out.txt") < 0);

  i64 d = xopen(".", O_RDONLY);
  static char buf[64];
  show("getdents64 with a tiny buffer (EINVAL)", sys3(NR_getdents64, d, (i64)buf, 8));
  sys3(NR_lseek, d, 0, 0);
  show("getdents64 after rewinding", sys3(NR_getdents64, d, (i64)buf, sizeof buf) > 0);
  xclose(d);
  show("getdents64 on a file (ENOTDIR)", sys3(NR_getdents64, xopen("sub/b.txt", O_RDONLY), (i64)buf, sizeof buf));
  show("getdents64 on a bad descriptor", sys3(NR_getdents64, 99, (i64)buf, sizeof buf));
  quit();
}
