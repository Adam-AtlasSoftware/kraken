/* pipe and pipe2: in-process buffers, end of file, EPIPE, non-blocking reads, flags. */
#include "rt.h"

static void ignore_sigpipe(void) {
  struct { u64 handler; u64 flags; u64 restorer; u64 mask; } sa = { 1, 0, 0, 0 };
  sys6(NR_rt_sigaction, 13, (i64)&sa, 0, 8, 0, 0);
}

void kmain(void) {
  put("pipes\n");
  ignore_sigpipe();
  int p[2];
  show("pipe2", sys3(NR_pipe2, (i64)p, 0, 0));
  check("two new descriptors", p[0] >= 3 && p[1] == p[0] + 1);
  show("write", xwrite(p[1], "hello pipe", 10));
  char b[32];
  show("short read", xread(p[0], b, 5));
  b[5] = 0;
  put(b); put("\n");
  show("rest", xread(p[0], b, 32));
  b[5] = 0;
  put(b); put("\n");

  /* Nothing buffered and a writer open: a non-blocking read says EAGAIN. */
  sys3(NR_fcntl, p[0], F_SETFL, O_NONBLOCK);
  show("empty non-blocking read", xread(p[0], b, 4));
  check("pipe read end is not seekable", sys3(NR_lseek, p[0], 0, 0) < 0);

  show("write 3", xwrite(p[1], "abc", 3));
  xclose(p[1]);
  show("drain after the writer closed", xread(p[0], b, 32));
  show("end of file", xread(p[0], b, 32));
  show("write to a read end", xwrite(p[0], "x", 1));
  xclose(p[0]);

  int q[2];
  show("pipe2 with flags", sys3(NR_pipe2, (i64)q, O_CLOEXEC | O_NONBLOCK, 0));
  show("read end FD_CLOEXEC", sys3(NR_fcntl, q[0], F_GETFD, 0));
  show("write end nonblock bit", (sys3(NR_fcntl, q[1], F_GETFL, 0) & O_NONBLOCK) != 0);
  show("read from the write end", xread(q[1], b, 1));
  xclose(q[0]);
  show("write with no reader (EPIPE)", xwrite(q[1], "x", 1));
  xclose(q[1]);

  int r[2] = { -1, -1 };
  i64 old_pipe = 0;
#if defined(__x86_64__)
  old_pipe = sys1(NR_pipe, (i64)r);
  xwrite(r[1], "z", 1);
  old_pipe += xread(r[0], b, 4) - 1;
  xclose(r[0]);
  xclose(r[1]);
#endif
  check("the old pipe call works where it exists", old_pipe == 0);

  /* A duplicate of the write end keeps the pipe open. */
  int s[2];
  sys3(NR_pipe2, (i64)s, 0, 0);
  i64 w2 = sys1(NR_dup, s[1]);
  xclose(s[1]);
  sys3(NR_fcntl, s[0], F_SETFL, O_NONBLOCK);
  show("writer still open through a dup", xread(s[0], b, 1));
  xclose(w2);
  show("all writers closed", xread(s[0], b, 1));
  quit();
}
