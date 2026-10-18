/* win_dll: a small DLL with exports by name, one export by ordinal only (NONAME in win_dll.def),
   an exported variable and DllMain; base relocations come from its absolute pointers. */
#include <windows.h>

int kr_counter = 0;

static int op_sub(int a, int b) { return a - b; }
static int op_xor(int a, int b) { return a ^ b; }
static int op_min(int a, int b) { return a < b ? a : b; }

static int (*const ops[3])(int, int) = { op_sub, op_xor, op_min };

int kr_add(int a, int b)
{
    kr_counter++;
    return a + b;
}

int kr_mul(int a, int b)
{
    int r = 0;
    for (int i = 0; i < b; i++)
        r = kr_add(r, a);
    return r;
}

/* exported by ordinal 3 only */
int kr_secret(int x)
{
    return ops[x & 1](x * 7, 3) + ops[2](x, 100);
}

const char *kr_version(void)
{
    return "win_dll 1.0";
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH)
        kr_counter = 1;
    return TRUE;
}
