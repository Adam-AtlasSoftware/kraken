/* nanosleep, clock_nanosleep and sched_yield. The program only prints whether the clock moved at
   least as far as it slept, so the output is the same natively and under emulation (where a
   sleep advances virtual time and returns at once). */
#include "rt.h"

static i64 now_ns(void) {
  struct timespec t;
  sys3(NR_clock_gettime, CLOCK_MONOTONIC, (i64)&t, 0);
  return t.sec * 1000000000 + t.nsec;
}

void kmain(void) {
  put("sleeping\n");
  show("sched_yield", sys1(NR_sched_yield, 0));

  struct timespec req = { 0, 30 * 1000000 };
  i64 t0 = now_ns();
  show("nanosleep 30 ms", sys3(NR_nanosleep, (i64)&req, 0, 0));
  check("the clock advanced by at least 30 ms", now_ns() - t0 >= 30 * 1000000);

  struct timespec two = { 2, 500000000 };
  t0 = now_ns();
  show("nanosleep 2.5 s", sys3(NR_nanosleep, (i64)&two, 0, 0));
  check("the clock advanced by at least 2.5 s", now_ns() - t0 >= 2500000000);

  struct timespec rem = { 77, 77 };
  struct timespec one = { 0, 1000000 };
  show("nanosleep with a remainder pointer", sys3(NR_nanosleep, (i64)&one, (i64)&rem, 0));
  check("remainder untouched when the sleep finished", rem.sec == 77 && rem.nsec == 77);

  struct timespec bad = { 0, 1000000000 };
  show("nanosleep with tv_nsec out of range (EINVAL)", sys3(NR_nanosleep, (i64)&bad, 0, 0));
  struct timespec neg = { -1, 0 };
  show("nanosleep with a negative second (EINVAL)", sys3(NR_nanosleep, (i64)&neg, 0, 0));

  struct timespec rel = { 1, 0 };
  t0 = now_ns();
  show("clock_nanosleep relative 1 s", sys6(NR_clock_nanosleep, CLOCK_MONOTONIC, 0, (i64)&rel, 0, 0, 0));
  check("the clock advanced by at least 1 s", now_ns() - t0 >= 1000000000);

  struct timespec abs;
  sys3(NR_clock_gettime, CLOCK_MONOTONIC, (i64)&abs, 0);
  abs.sec += 3;
  t0 = now_ns();
  show("clock_nanosleep absolute, 3 s ahead", sys6(NR_clock_nanosleep, CLOCK_MONOTONIC, TIMER_ABSTIME, (i64)&abs, 0, 0, 0));
  check("the clock reached the deadline", now_ns() - t0 >= 2900000000);

  struct timespec past = { 0, 1 };
  show("clock_nanosleep absolute in the past returns at once", sys6(NR_clock_nanosleep, CLOCK_MONOTONIC, TIMER_ABSTIME, (i64)&past, 0, 0, 0));
  show("clock_nanosleep with an unknown clock (EINVAL)", sys6(NR_clock_nanosleep, 99, 0, (i64)&rel, 0, 0, 0));
  quit();
}
