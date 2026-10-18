/* kr_text: strings, a switch over them, a loop and calls to malloc and toupper. */
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "kr.h"

const char *kr_kind_name(int kind)
{
    switch (kind) {
    case 0: return "letters";
    case 1: return "digits";
    case 2: return "spaces";
    case 3: return "punctuation";
    case 4: return "symbols";
    default: return "unknown";
    }
}

unsigned kr_checksum(const char *s)
{
    unsigned h = 2166136261u;
    while (*s)
        h = (h ^ (unsigned char)*s++) * 16777619u;
    return h;
}

char *kr_dup_upper(const char *s)
{
    size_t n = strlen(s);
    char *out = malloc(n + 1);
    if (!out)
        return NULL;
    for (size_t i = 0; i < n; i++)
        out[i] = (char)toupper((unsigned char)s[i]);
    out[n] = 0;
    kr_calls++;
    return out;
}
