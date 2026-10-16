/* static_strops: statically linked C, helper functions and string operations. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define BUF_LEN 128

static unsigned long hash_str(const char *s)
{
    unsigned long h = 5381;
    while (*s)
        h = ((h << 5) + h) ^ (unsigned char)*s++;
    return h;
}

void str_reverse(char *s)
{
    size_t n = strlen(s);
    for (size_t i = 0; i < n / 2; i++) {
        char t = s[i];
        s[i] = s[n - 1 - i];
        s[n - 1 - i] = t;
    }
}

int str_count_char(const char *s, char c)
{
    int count = 0;
    for (; *s; s++)
        if (*s == c)
            count++;
    return count;
}

void str_upper(char *s)
{
    for (; *s; s++)
        if (*s >= 'a' && *s <= 'z')
            *s = (char)(*s - 'a' + 'A');
}

int is_palindrome(const char *s)
{
    size_t n = strlen(s);
    for (size_t i = 0; i < n / 2; i++)
        if (s[i] != s[n - 1 - i])
            return 0;
    return 1;
}

static int caesar(char *s, int shift)
{
    int changed = 0;
    for (; *s; s++) {
        if (*s >= 'a' && *s <= 'z') {
            *s = (char)('a' + (*s - 'a' + shift) % 26);
            changed++;
        }
    }
    return changed;
}

int join_words(char *out, size_t cap, const char *const *words, int n, char sep)
{
    size_t used = 0;
    for (int i = 0; i < n; i++) {
        size_t wl = strlen(words[i]);
        if (used + wl + 2 > cap)
            return -1;
        memcpy(out + used, words[i], wl);
        used += wl;
        if (i + 1 < n)
            out[used++] = sep;
    }
    out[used] = '\0';
    return (int)used;
}

int main(void)
{
    const char *words[] = { "static", "linking", "keeps", "libc", "inside" };
    char buf[BUF_LEN];
    char tmp[BUF_LEN];
    unsigned long total = 0;

    int len = join_words(buf, sizeof buf, words, 5, ' ');
    if (len < 0)
        return 1;
    printf("joined: %s (%d)\n", buf, len);
    total += hash_str(buf);

    strcpy(tmp, buf);
    str_reverse(tmp);
    printf("reversed: %s\n", tmp);
    total += hash_str(tmp);

    str_upper(tmp);
    printf("upper: %s\n", tmp);
    printf("count of i: %d\n", str_count_char(buf, 'i'));
    printf("palindrome(level)=%d palindrome(buf)=%d\n",
           is_palindrome("level"), is_palindrome(buf));

    int ch = caesar(buf, 3);
    printf("caesar changed %d chars: %s\n", ch, buf);

    char *heap = malloc(64);
    if (!heap)
        return 2;
    snprintf(heap, 64, "hash=%lu", total % 100000UL);
    printf("%s\n", heap);
    free(heap);
    return 0;
}
