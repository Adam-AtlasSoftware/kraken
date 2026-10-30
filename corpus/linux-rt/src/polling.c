/* poll and ppoll on pipes, a file, standard input and descriptors that are not open. The harness
   feeds standard input a pipe holding "go". */
#include "rt.h"

static i64 poll1(i64 fd, int events, int timeout_ms, int *revents) {
  struct pollfd p = { (i32)fd, (short)events, 0 };
#if defined(__x86_64__)
  i64 r = sys3(NR_poll, (i64)&p, 1, timeout_ms);
#else
  struct timespec ts = { timeout_ms / 1000, (timeout_ms % 1000) * 1000000 };
  i64 r = sys6(NR_ppoll, (i64)&p, 1, (i64)&ts, 0, 8, 0);
#endif
  *revents = p.revents;
  return r;
}

static void report(const char *what, i64 fd, int events, int timeout_ms) {
  int rev;
  i64 r = poll1(fd, events, timeout_ms, &rev);
  put(what); put(": ready = "); putn(r); put(", revents = "); putn(rev); put("\n");
}

void kmain(void) {
  put("polling\n");
  int p[2];
  sys3(NR_pipe2, (i64)p, 0, 0);
  report("empty pipe, read end", p[0], POLLIN, 0);
  report("empty pipe, write end", p[1], POLLOUT, 0);
  report("empty pipe, read end, 250 ms timeout", p[0], POLLIN, 250);
  xwrite(p[1], "data", 4);
  report("pipe with data, read end", p[0], POLLIN, 0);
  report("pipe with data, read end, POLLIN|POLLOUT asked", p[0], POLLIN | POLLOUT, 0);
  char b[8];
  xread(p[0], b, 4);
  report("drained pipe", p[0], POLLIN, 0);
  xclose(p[1]);
  report("writer closed, read end", p[0], POLLIN, 0);
  xclose(p[0]);

  i64 f = xopen("poll.txt", O_RDWR | O_CREAT | O_TRUNC);
  report("regular file", f, POLLIN | POLLOUT, 0);
  xclose(f);

  report("standard input holding data", 0, POLLIN, 0);
  xread(0, b, 8);
  report("a descriptor that is not open", 55, POLLIN, 0);
  report("a negative descriptor is skipped", -1, POLLIN, 0);

  /* Two descriptors at once: only the one with data is ready. */
  int q[2], r[2];
  sys3(NR_pipe2, (i64)q, 0, 0);
  sys3(NR_pipe2, (i64)r, 0, 0);
  xwrite(r[1], "x", 1);
  struct pollfd two[2] = { { q[0], POLLIN, 0 }, { r[0], POLLIN, 0 } };
#if defined(__x86_64__)
  i64 n = sys3(NR_poll, (i64)two, 2, 0);
#else
  struct timespec zero = { 0, 0 };
  i64 n = sys6(NR_ppoll, (i64)two, 2, (i64)&zero, 0, 8, 0);
#endif
  show("two pipes, one with data", n);
  show("  first revents", two[0].revents);
  show("  second revents", two[1].revents);
  quit();
}
