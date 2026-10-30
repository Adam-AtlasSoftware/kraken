/* dup, dup2, dup3 and fcntl: shared offsets, descriptor and status flags, F_DUPFD. */
#include "rt.h"

void kmain(void) {
  put("fd_dup\n");
  i64 f = xopen("dup.txt", O_RDWR | O_CREAT | O_TRUNC);
  check("open", f >= 3);
  xwrite(f, "abcdefghij", 10);
  sys3(NR_lseek, f, 0, 0);

  i64 d = sys1(NR_dup, f);
  check("dup returns the lowest free descriptor", d == f + 1);
  char b[8];
  show("read via original", xread(f, b, 3));
  show("read via dup continues the shared offset", xread(d, b, 3));
  check("offset shared", b[0] == 'd' && b[2] == 'f');
  show("offset after both", sys3(NR_lseek, f, 0, 1));

#if defined(__x86_64__)
  i64 e = sys3(NR_dup2, f, 20, 0);
#else
  i64 e = sys3(NR_dup3, f, 20, 0);
#endif
  show("dup2 target", e);
  show("dup3 onto itself is EINVAL", sys3(NR_dup3, f, f, O_CLOEXEC));
  i64 same = f;
#if defined(__x86_64__)
  same = sys3(NR_dup2, f, f, 0);
#endif
  check("dup2 onto itself returns the descriptor", same == f);
  i64 g = sys3(NR_dup3, f, 21, O_CLOEXEC);
  show("dup3 target", g);
  show("FD_CLOEXEC of dup3 with O_CLOEXEC", sys3(NR_fcntl, g, F_GETFD, 0));
  show("FD_CLOEXEC of dup2 copy", sys3(NR_fcntl, e, F_GETFD, 0));
  show("dup of a bad descriptor", sys1(NR_dup, 99));

  /* A descriptor flag belongs to the descriptor, not to the file description. */
  sys3(NR_fcntl, e, F_SETFD, FD_CLOEXEC);
  show("F_SETFD then F_GETFD", sys3(NR_fcntl, e, F_GETFD, 0));
  show("original untouched", sys3(NR_fcntl, f, F_GETFD, 0));

  show("F_GETFL access mode", sys3(NR_fcntl, f, F_GETFL, 0) & 3);
  sys3(NR_fcntl, f, F_SETFL, O_NONBLOCK);
  show("F_GETFL nonblock bit", (sys3(NR_fcntl, f, F_GETFL, 0) & O_NONBLOCK) != 0);
  show("nonblock bit on the dup (shared description)", (sys3(NR_fcntl, d, F_GETFL, 0) & O_NONBLOCK) != 0);

  i64 m = sys3(NR_fcntl, f, F_DUPFD, 30);
  show("F_DUPFD at or above 30", m);
  i64 n = sys3(NR_fcntl, f, F_DUPFD_CLOEXEC, 30);
  show("F_DUPFD_CLOEXEC next free above 30", n);
  show("its close-on-exec flag", sys3(NR_fcntl, n, F_GETFD, 0));
  show("F_DUPFD on a bad descriptor", sys3(NR_fcntl, 77, F_DUPFD, 0));
  show("unknown fcntl command", sys3(NR_fcntl, f, 9999, 0));

  /* Writing through a duplicate of standard output reaches standard output. */
  i64 so = sys1(NR_dup, 1);
  xwrite(so, "through a dup of stdout\n", 24);
  xclose(1);
  show("write after closing 1", xwrite(1, "x", 1));
  sys3(NR_dup3, so, 1, 0);
  put("stdout is back\n");

  xclose(f);
  show("dup still reads after the original closed", xread(d, b, 2));
  show("close twice", xclose(f));
  quit();
}
