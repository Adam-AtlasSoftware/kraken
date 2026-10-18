/* win_tls: a Windows console program with a TLS callback, Win32 and CRT imports by name, imports
   from win_dll.dll by name and by ordinal (kr_secret), a jump-table switch, a function-pointer
   table and qsort with comparators. Needs win_dll.dll next to it to run. */
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__declspec(dllimport) int kr_add(int a, int b);
__declspec(dllimport) int kr_mul(int a, int b);
__declspec(dllimport) int kr_secret(int x);
__declspec(dllimport) const char *kr_version(void);
__declspec(dllimport) int kr_counter;

static volatile LONG tls_hits;

static void NTAPI on_tls(PVOID module, DWORD reason, PVOID reserved)
{
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH || reason == DLL_THREAD_ATTACH)
        InterlockedIncrement(&tls_hits);
}

/* mingw-w64's CRT emits the TLS directory; callbacks go between .CRT$XLA and .CRT$XLZ */
__attribute__((section(".CRT$XLB"), used)) const PIMAGE_TLS_CALLBACK tls_callback = on_tls;

struct item {
    int key;
    const char *name;
};

static int by_key(const void *a, const void *b)
{
    const struct item *x = a, *y = b;
    return x->key - y->key;
}

static int by_name(const void *a, const void *b)
{
    const struct item *x = a, *y = b;
    return strcmp(x->name, y->name);
}

static const char *classify(int c)
{
    switch (c) {
    case 0: return "zero";
    case 1: return "one";
    case 2: return "two";
    case 3: return "three";
    case 4: return "four";
    case 5: return "five";
    case 6: return "six";
    case 7: return "seven";
    default: return "many";
    }
}

static unsigned checksum(const char *s)
{
    unsigned h = 2166136261u;
    while (*s)
        h = (h ^ (unsigned char)*s++) * 16777619u;
    return h;
}

typedef int (*binop)(int, int);

static int apply_all(const binop *table, int n, int a, int b)
{
    int acc = 0;
    for (int i = 0; i < n; i++)
        acc += table[i](a, b);
    return acc;
}

static DWORD probe_kernel(void)
{
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    FARPROC tick = k32 ? GetProcAddress(k32, "GetTickCount") : NULL;
    DWORD pid = GetCurrentProcessId();
    return tick ? pid ^ 1u : pid;
}

static char *copy_upper(const char *s)
{
    size_t n = (size_t)lstrlenA(s);
    char *p = VirtualAlloc(NULL, n + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (p == NULL)
        return NULL;
    for (size_t i = 0; i < n; i++)
        p[i] = (s[i] >= 'a' && s[i] <= 'z') ? (char)(s[i] - 32) : s[i];
    p[n] = 0;
    return p;
}

int main(void)
{
    struct item items[] = { {5, "eel"}, {2, "bat"}, {9, "yak"}, {1, "ant"}, {7, "cow"} };
    const int n = (int)(sizeof items / sizeof items[0]);
    binop table[2];
    table[0] = kr_add;
    table[1] = kr_mul;

    qsort(items, (size_t)n, sizeof items[0], by_key);
    for (int i = 0; i < n; i++)
        printf("%d %s %s\n", items[i].key, items[i].name, classify(items[i].key));
    qsort(items, (size_t)n, sizeof items[0], by_name);
    printf("first by name: %s\n", items[0].name);

    char *up = copy_upper("kraken pe corpus");
    if (up != NULL) {
        printf("%s %08x\n", up, checksum(up));
        VirtualFree(up, 0, MEM_RELEASE);
    }
    printf("apply_all=%d secret=%d version=%s\n", apply_all(table, 2, 6, 7), kr_secret(5),
           kr_version());
    printf("counter=%d tls=%ld probe=%d\n", kr_counter, (long)tls_hits, probe_kernel() != 0);
    Sleep(0);
    return 0;
}
