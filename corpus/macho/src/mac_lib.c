/* A small macOS shared library: exported functions and data, a private helper, an import. */
#include <stdio.h>
#include <string.h>

int kr_counter = 7;
const char kr_version[] = "kr-1.2";

static unsigned mix(unsigned h, unsigned char c) {
    return (h ^ c) * 16777619u;
}

unsigned kr_hash(const char *s) {
    unsigned h = 2166136261u;
    while (*s)
        h = mix(h, (unsigned char)*s++);
    return h;
}

int kr_add(int a, int b) {
    kr_counter++;
    return a + b;
}

int kr_show(const char *s) {
    char line[64];
    snprintf(line, sizeof line, "%s:%u", kr_version, kr_hash(s));
    return puts(line);
}

int (*kr_add_ptr)(int, int) = kr_add;
