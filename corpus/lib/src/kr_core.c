/* kr_core: a dense switch (a jump table), calls into the other object (kr_text) and calls to the
   C library (externals in an object file, imports in a shared library). */
#include <stdio.h>
#include <string.h>
#include "kr.h"

int kr_calls;

static __attribute__((noinline)) int bump(int by)
{
    kr_calls += by;
    return kr_calls;
}

int kr_classify(int c)
{
    bump(1);
    switch (c) {
    case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9':
        return 1;
    case ' ': case '\t': case '\n':
        return 2;
    case '.': case ',': case ';': case ':': case '!': case '?':
        return 3;
    default:
        return 0;
    }
}

int kr_report(const char *s)
{
    int counts[4] = {0, 0, 0, 0};
    int n = (int)strlen(s);
    for (int i = 0; i < n; i++)
        counts[kr_classify((unsigned char)s[i])]++;
    int best = 0;
    for (int k = 1; k < 4; k++)
        if (counts[k] > counts[best])
            best = k;
    char *upper = kr_dup_upper(s);
    puts(upper ? upper : s);
    puts(kr_kind_name(best));
    return (int)(kr_checksum(s) & 0xffff) + n;
}
