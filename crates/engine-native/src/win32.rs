//! A starter set of Win32 API and Microsoft C runtime prototypes, and the Windows typedefs they
//! use, for PE programs. Like the C library table ([`crate::libc`]) they are applied by name to
//! import thunks and to statically linked functions, so `GetModuleHandleA("kernel32.dll")` and
//! `VirtualAlloc((LPVOID)0x0,n,0x3000,4)` read with their types. The Win32 functions use
//! `__stdcall` (WINAPI), which matters on 32-bit x86 (the callee pops its arguments); on x86-64
//! there is one convention and the marker is ignored. Type names follow the Windows headers (and
//! Ghidra's Windows data types): `DWORD`, `HMODULE`, `LPCSTR`.

use kraken_proto::{Composite, Primitive, PrimitiveClass, TypeDef, TypeRef, TypedefDef};

use crate::ctypes::DataModel;

/// The table, one prototype per entry (the syntax of [`crate::ctypes::parse_prototype_in`]).
pub const PROTOTYPES: &[&str] = &[
    // modules
    "__stdcall HMODULE GetModuleHandleA(LPCSTR lpModuleName)",
    "__stdcall HMODULE GetModuleHandleW(LPCWSTR lpModuleName)",
    "__stdcall BOOL GetModuleHandleExA(DWORD dwFlags, LPCSTR lpModuleName, HMODULE *phModule)",
    "__stdcall BOOL GetModuleHandleExW(DWORD dwFlags, LPCWSTR lpModuleName, HMODULE *phModule)",
    "__stdcall FARPROC GetProcAddress(HMODULE hModule, LPCSTR lpProcName)",
    "__stdcall HMODULE LoadLibraryA(LPCSTR lpLibFileName)",
    "__stdcall HMODULE LoadLibraryW(LPCWSTR lpLibFileName)",
    "__stdcall HMODULE LoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)",
    "__stdcall HMODULE LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)",
    "__stdcall BOOL FreeLibrary(HMODULE hLibModule)",
    "__stdcall DWORD GetModuleFileNameA(HMODULE hModule, LPSTR lpFilename, DWORD nSize)",
    "__stdcall DWORD GetModuleFileNameW(HMODULE hModule, LPWSTR lpFilename, DWORD nSize)",
    // memory
    "__stdcall LPVOID VirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)",
    "__stdcall BOOL VirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType)",
    "__stdcall BOOL VirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect)",
    "__stdcall SIZE_T VirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)",
    "__stdcall HANDLE GetProcessHeap(void)",
    "__stdcall LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes)",
    "__stdcall LPVOID HeapReAlloc(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem, SIZE_T dwBytes)",
    "__stdcall BOOL HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)",
    "__stdcall HANDLE HeapCreate(DWORD flOptions, SIZE_T dwInitialSize, SIZE_T dwMaximumSize)",
    "__stdcall BOOL HeapDestroy(HANDLE hHeap)",
    "__stdcall HLOCAL LocalAlloc(UINT uFlags, SIZE_T uBytes)",
    "__stdcall HLOCAL LocalFree(HLOCAL hMem)",
    "__stdcall HGLOBAL GlobalAlloc(UINT uFlags, SIZE_T dwBytes)",
    "__stdcall HGLOBAL GlobalFree(HGLOBAL hMem)",
    // errors and process
    "__stdcall DWORD GetLastError(void)",
    "__stdcall void SetLastError(DWORD dwErrCode)",
    "noreturn __stdcall void ExitProcess(UINT uExitCode)",
    "noreturn __stdcall void ExitThread(DWORD dwExitCode)",
    "__stdcall BOOL TerminateProcess(HANDLE hProcess, UINT uExitCode)",
    "__stdcall HANDLE GetCurrentProcess(void)",
    "__stdcall DWORD GetCurrentProcessId(void)",
    "__stdcall HANDLE GetCurrentThread(void)",
    "__stdcall DWORD GetCurrentThreadId(void)",
    "__stdcall LPSTR GetCommandLineA(void)",
    "__stdcall LPWSTR GetCommandLineW(void)",
    "__stdcall DWORD GetEnvironmentVariableA(LPCSTR lpName, LPSTR lpBuffer, DWORD nSize)",
    "__stdcall DWORD GetEnvironmentVariableW(LPCWSTR lpName, LPWSTR lpBuffer, DWORD nSize)",
    "__stdcall BOOL SetEnvironmentVariableA(LPCSTR lpName, LPCSTR lpValue)",
    "__stdcall void GetStartupInfoA(LPSTARTUPINFOA lpStartupInfo)",
    "__stdcall void GetStartupInfoW(LPSTARTUPINFOW lpStartupInfo)",
    "__stdcall BOOL CreateProcessA(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)",
    "__stdcall BOOL IsDebuggerPresent(void)",
    "__stdcall void OutputDebugStringA(LPCSTR lpOutputString)",
    "__stdcall void OutputDebugStringW(LPCWSTR lpOutputString)",
    "__stdcall LPTOP_LEVEL_EXCEPTION_FILTER SetUnhandledExceptionFilter(LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter)",
    "__stdcall LONG UnhandledExceptionFilter(PEXCEPTION_POINTERS ExceptionInfo)",
    "__stdcall void RaiseException(DWORD dwExceptionCode, DWORD dwExceptionFlags, DWORD nNumberOfArguments, ULONG_PTR *lpArguments)",
    "__stdcall void GetSystemInfo(LPSYSTEM_INFO lpSystemInfo)",
    "__stdcall void GetSystemTimeAsFileTime(LPFILETIME lpSystemTimeAsFileTime)",
    "__stdcall UINT GetACP(void)",
    // time
    "__stdcall void Sleep(DWORD dwMilliseconds)",
    "__stdcall DWORD GetTickCount(void)",
    "__stdcall ULONGLONG GetTickCount64(void)",
    "__stdcall BOOL QueryPerformanceCounter(LARGE_INTEGER *lpPerformanceCount)",
    "__stdcall BOOL QueryPerformanceFrequency(LARGE_INTEGER *lpFrequency)",
    // files and console
    "__stdcall HANDLE CreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)",
    "__stdcall HANDLE CreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)",
    "__stdcall BOOL ReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)",
    "__stdcall BOOL WriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped)",
    "__stdcall BOOL CloseHandle(HANDLE hObject)",
    "__stdcall DWORD GetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)",
    "__stdcall DWORD SetFilePointer(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod)",
    "__stdcall BOOL DeleteFileA(LPCSTR lpFileName)",
    "__stdcall BOOL DeleteFileW(LPCWSTR lpFileName)",
    "__stdcall BOOL CreateDirectoryA(LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes)",
    "__stdcall DWORD GetFileAttributesA(LPCSTR lpFileName)",
    "__stdcall HANDLE FindFirstFileA(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData)",
    "__stdcall BOOL FindNextFileA(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData)",
    "__stdcall BOOL FindClose(HANDLE hFindFile)",
    "__stdcall HANDLE GetStdHandle(DWORD nStdHandle)",
    "__stdcall BOOL WriteConsoleA(HANDLE hConsoleOutput, void *lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved)",
    "__stdcall BOOL WriteConsoleW(HANDLE hConsoleOutput, void *lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved)",
    // synchronization and threads
    "__stdcall HANDLE CreateThread(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)",
    "__stdcall DWORD WaitForSingleObject(HANDLE hHandle, DWORD dwMilliseconds)",
    "__stdcall DWORD WaitForMultipleObjects(DWORD nCount, HANDLE *lpHandles, BOOL bWaitAll, DWORD dwMilliseconds)",
    "__stdcall HANDLE CreateEventA(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCSTR lpName)",
    "__stdcall HANDLE CreateEventW(LPSECURITY_ATTRIBUTES lpEventAttributes, BOOL bManualReset, BOOL bInitialState, LPCWSTR lpName)",
    "__stdcall BOOL SetEvent(HANDLE hEvent)",
    "__stdcall BOOL ResetEvent(HANDLE hEvent)",
    "__stdcall HANDLE CreateMutexA(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName)",
    "__stdcall BOOL ReleaseMutex(HANDLE hMutex)",
    "__stdcall void InitializeCriticalSection(LPCRITICAL_SECTION lpCriticalSection)",
    "__stdcall BOOL InitializeCriticalSectionAndSpinCount(LPCRITICAL_SECTION lpCriticalSection, DWORD dwSpinCount)",
    "__stdcall void EnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)",
    "__stdcall BOOL TryEnterCriticalSection(LPCRITICAL_SECTION lpCriticalSection)",
    "__stdcall void LeaveCriticalSection(LPCRITICAL_SECTION lpCriticalSection)",
    "__stdcall void DeleteCriticalSection(LPCRITICAL_SECTION lpCriticalSection)",
    "__stdcall DWORD TlsAlloc(void)",
    "__stdcall BOOL TlsFree(DWORD dwTlsIndex)",
    "__stdcall LPVOID TlsGetValue(DWORD dwTlsIndex)",
    "__stdcall BOOL TlsSetValue(DWORD dwTlsIndex, LPVOID lpTlsValue)",
    "__stdcall LONG InterlockedIncrement(LONG *Addend)",
    "__stdcall LONG InterlockedDecrement(LONG *Addend)",
    "__stdcall LONG InterlockedExchange(LONG *Target, LONG Value)",
    "__stdcall LONG InterlockedCompareExchange(LONG *Destination, LONG Exchange, LONG Comperand)",
    // strings
    "__stdcall int lstrlenA(LPCSTR lpString)",
    "__stdcall int lstrlenW(LPCWSTR lpString)",
    "__stdcall LPSTR lstrcpyA(LPSTR lpString1, LPCSTR lpString2)",
    "__stdcall int lstrcmpA(LPCSTR lpString1, LPCSTR lpString2)",
    "__stdcall int lstrcmpiA(LPCSTR lpString1, LPCSTR lpString2)",
    "__stdcall int MultiByteToWideChar(UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar)",
    "__stdcall int WideCharToMultiByte(UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar)",
    "__stdcall BOOL IsDBCSLeadByteEx(UINT CodePage, BYTE TestChar)",
    "__stdcall DWORD FormatMessageA(DWORD dwFlags, LPCVOID lpSource, DWORD dwMessageId, DWORD dwLanguageId, LPSTR lpBuffer, DWORD nSize, va_list *Arguments)",
    // user32 and advapi32
    "__stdcall int MessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType)",
    "__stdcall int MessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType)",
    "int wsprintfA(LPSTR param_1, LPCSTR param_2, ...)",
    "__stdcall LONG RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, DWORD samDesired, HKEY *phkResult)",
    "__stdcall LONG RegQueryValueExA(HKEY hKey, LPCSTR lpValueName, LPDWORD lpReserved, LPDWORD lpType, BYTE *lpData, LPDWORD lpcbData)",
    "__stdcall LONG RegCloseKey(HKEY hKey)",
    // the Microsoft C runtime (msvcrt.dll, ucrtbase.dll) beyond the C standard
    "noreturn void _amsg_exit(int rterrnum)",
    "void _cexit(void)",
    "void _c_exit(void)",
    "void _initterm(_PVFV *ppfn, _PVFV *end)",
    "int _initterm_e(_PIFV *ppfn, _PIFV *end)",
    "int __getmainargs(int *_Argc, char ***_Argv, char ***_Env, int _DoWildCard, _startupinfo *_StartInfo)",
    "int __wgetmainargs(int *_Argc, wchar_t ***_Argv, wchar_t ***_Env, int _DoWildCard, _startupinfo *_StartInfo)",
    "void __set_app_type(int _Type)",
    "int *__p__fmode(void)",
    "int *__p__commode(void)",
    "int *_errno(void)",
    "void _lock(int _File)",
    "void _unlock(int _File)",
    "_onexit_t _onexit(_onexit_t _Func)",
    "FILE *__iob_func(void)",
    "FILE *__acrt_iob_func(unsigned int index)",
    "uintptr_t _beginthreadex(void *_Security, unsigned int _StackSize, _beginthreadex_proc_type _StartAddress, void *_ArgList, unsigned int _InitFlag, unsigned int *_ThrdAddr)",
    "char *_strdup(const char *_Src)",
    "int _stricmp(const char *_Str1, const char *_Str2)",
    "int _strnicmp(const char *_Str1, const char *_Str2, size_t _MaxCount)",
    "int _snprintf(char *_Dest, size_t _Count, const char *_Format, ...)",
    "int _vsnprintf(char *_Dest, size_t _Count, const char *_Format, va_list _Args)",
    "int _fileno(FILE *_File)",
    "int _setmode(int _FileHandle, int _Mode)",
    "intptr_t _get_osfhandle(int _FileHandle)",
    "UINT ___lc_codepage_func(void)",
    "int ___mb_cur_max_func(void)",
    "noreturn void _assert(const char *_Message, const char *_File, unsigned int _Line)",
    "noreturn void _wassert(const wchar_t *_Message, const wchar_t *_File, unsigned int _Line)",
    "void _lock_file(FILE *_File)",
    "void _unlock_file(FILE *_File)",
    "void _fpreset(void)",
    // the mingw start-up code (`pseudo-reloc.c`, `crt_handler.c`, `tlssup.c`), as Ghidra's
    // function identification names it; x86-64 drops one underscore
    "BOOL __ValidateImageBase(PBYTE pImageBase)",
    "PIMAGE_SECTION_HEADER __FindPESection(PBYTE pImageBase, DWORD_PTR rva)",
    "PIMAGE_SECTION_HEADER _FindPESection(PBYTE pImageBase, DWORD_PTR rva)",
    "BOOL __IsNonwritableInCurrentImage(PBYTE pTarget)",
    "int __matherr(_exception *_Except)",
];

/// The parameter names of the Microsoft C runtime headers for C library functions, which the
/// C library table names as glibc's do (`printf(char *_Format, ...)` on Windows).
pub const CRT_PARAMETER_NAMES: &[(&str, &[&str])] = &[
    ("printf", &["_Format"]),
    ("fprintf", &["_File", "_Format"]),
    ("sprintf", &["_Dest", "_Format"]),
    ("snprintf", &["_Dest", "_Count", "_Format"]),
    ("vprintf", &["_Format", "_ArgList"]),
    ("vfprintf", &["_File", "_Format", "_ArgList"]),
    ("vsprintf", &["_Dest", "_Format", "_Args"]),
    ("puts", &["_Str"]),
    ("fputs", &["_Str", "_File"]),
    ("putchar", &["_Ch"]),
    ("fputc", &["_Ch", "_File"]),
    ("putc", &["_Ch", "_File"]),
    ("fgetc", &["_File"]),
    ("getc", &["_File"]),
    ("fgets", &["_Buf", "_MaxCount", "_File"]),
    ("fopen", &["_Filename", "_Mode"]),
    ("fclose", &["_File"]),
    ("fflush", &["_File"]),
    ("fread", &["_DstBuf", "_ElementSize", "_Count", "_File"]),
    ("fwrite", &["_Str", "_Size", "_Count", "_File"]),
    ("fseek", &["_File", "_Offset", "_Origin"]),
    ("ftell", &["_File"]),
    ("malloc", &["_Size"]),
    ("calloc", &["_Count", "_Size"]),
    ("realloc", &["_Memory", "_NewSize"]),
    ("free", &["_Memory"]),
    ("exit", &["_Code"]),
    ("_exit", &["_Code"]),
    ("atexit", &["param_1"]),
    ("getenv", &["_VarName"]),
    ("atoi", &["_Str"]),
    ("atol", &["_Str"]),
    ("strtol", &["_Str", "_EndPtr", "_Radix"]),
    ("strtoul", &["_Str", "_EndPtr", "_Radix"]),
    (
        "qsort",
        &[
            "_Base",
            "_NumOfElements",
            "_SizeOfElements",
            "_PtFuncCompare",
        ],
    ),
    ("memcpy", &["_Dst", "_Src", "_Size"]),
    ("memmove", &["_Dst", "_Src", "_Size"]),
    ("memset", &["_Dst", "_Val", "_Size"]),
    ("memcmp", &["_Buf1", "_Buf2", "_Size"]),
    ("memchr", &["_Buf", "_Val", "_MaxCount"]),
    ("strlen", &["_Str"]),
    ("strnlen", &["_Str", "_MaxCount"]),
    ("wcslen", &["_Str"]),
    ("wcsnlen", &["_Src", "_MaxCount"]),
    ("strcmp", &["_Str1", "_Str2"]),
    ("strncmp", &["_Str1", "_Str2", "_MaxCount"]),
    ("strcpy", &["_Dest", "_Source"]),
    ("strncpy", &["_Dest", "_Source", "_Count"]),
    ("strcat", &["_Dest", "_Source"]),
    ("strncat", &["_Dest", "_Source", "_Count"]),
    ("strchr", &["_Str", "_Val"]),
    ("strrchr", &["_Str", "_Ch"]),
    ("strstr", &["_Str", "_SubStr"]),
    ("strdup", &["_Src"]),
    ("toupper", &["_C"]),
    ("tolower", &["_C"]),
    ("isalpha", &["_C"]),
    ("isdigit", &["_C"]),
    ("isspace", &["_C"]),
    ("isalnum", &["_C"]),
    ("setlocale", &["_Category", "_Locale"]),
    ("time", &["_Time"]),
    ("rand", &[]),
    ("srand", &["_Seed"]),
    ("abs", &["_X"]),
    ("labs", &["_X"]),
];

fn prim(class: PrimitiveClass, size: u32, signed: bool) -> TypeRef {
    TypeRef::Primitive(Primitive {
        class,
        size,
        signed,
    })
}

/// The Windows typedefs and opaque structs the table refers to, for `model` (LLP64 or ILP32).
pub fn base_definitions(model: DataModel) -> Vec<TypeDef> {
    use PrimitiveClass::*;
    let ptr = model.pointer;
    let td = |name: &str, target: TypeRef| {
        TypeDef::Typedef(TypedefDef {
            name: name.into(),
            target,
        })
    };
    let to = |t: TypeRef| TypeRef::Pointer {
        target: Box::new(t),
        size: ptr,
    };
    let named = |n: &str| TypeRef::Named { name: n.into() };
    let opaque = |name: &str, size: u64| {
        TypeDef::Struct(Composite {
            name: name.into(),
            size,
            align: ptr,
            fields: Vec::new(),
        })
    };
    let code = || {
        to(TypeRef::Function(Box::new(
            kraken_proto::FunctionPrototype {
                name: None,
                return_type: Box::new(prim(Void, 0, false)),
                params: Vec::new(),
                calling_convention: String::new(),
                varargs: false,
                noreturn: false,
            },
        )))
    };
    let void = || prim(Void, 0, false);
    // the mingw start-up code's structures, defined before the typedefs that point at them
    let field = |name: &str, offset: u64, ty: TypeRef| kraken_proto::Field {
        name: name.into(),
        offset,
        ty,
        bitfield: None,
    };
    let dword = || named("DWORD");
    // Ghidra numbers its anonymous unions; these are the ones of the mingw section header
    let misc = if ptr == 8 { "_union_238" } else { "_union_226" };
    let mut defs = vec![
        TypeDef::Union(Composite {
            name: misc.into(),
            size: 4,
            align: 4,
            fields: vec![
                field("PhysicalAddress", 0, dword()),
                field("VirtualSize", 0, dword()),
            ],
        }),
        TypeDef::Struct(Composite {
            name: "_IMAGE_SECTION_HEADER".into(),
            size: 40,
            align: 4,
            fields: vec![
                field(
                    "Name",
                    0,
                    TypeRef::Array {
                        element: Box::new(named("BYTE")),
                        count: 8,
                    },
                ),
                field("Misc", 8, named(misc)),
                field("VirtualAddress", 12, dword()),
                field("SizeOfRawData", 16, dword()),
                field("PointerToRawData", 20, dword()),
                field("PointerToRelocations", 24, dword()),
                field("PointerToLinenumbers", 28, dword()),
                field("NumberOfRelocations", 32, named("WORD")),
                field("NumberOfLinenumbers", 34, named("WORD")),
                field("Characteristics", 36, dword()),
            ],
        }),
        TypeDef::Struct(Composite {
            name: "_exception".into(),
            size: if ptr == 8 { 40 } else { 32 },
            align: 8,
            fields: vec![
                field("type", 0, prim(Int, 4, true)),
                field("name", u64::from(ptr), to(prim(Char, 1, true))),
                field("arg1", 8 + u64::from(ptr), prim(Float, 8, true)),
                field("arg2", 16 + u64::from(ptr), prim(Float, 8, true)),
                field("retval", 24 + u64::from(ptr), prim(Float, 8, true)),
            ],
        }),
        td("BYTE", prim(Int, 1, false)),
        td("WORD", prim(Int, 2, false)),
        td("DWORD", prim(Int, 4, false)),
        td("BOOL", prim(Int, 4, true)),
        td("UINT", prim(Int, 4, false)),
        td("LONG", prim(Int, 4, true)),
        td("ULONG", prim(Int, 4, false)),
        td("ULONGLONG", prim(Int, 8, false)),
        td("WCHAR", prim(Char, 2, true)),
        td("SIZE_T", prim(Int, ptr, false)),
        td("ULONG_PTR", prim(Int, ptr, false)),
        td("DWORD_PTR", prim(Int, ptr, false)),
        td("LONG_PTR", prim(Int, ptr, true)),
        td("HANDLE", to(void())),
        td("HMODULE", to(void())),
        td("HINSTANCE", to(void())),
        td("HLOCAL", to(void())),
        td("HGLOBAL", to(void())),
        td("HWND", to(void())),
        td("HKEY", to(void())),
        td("LPVOID", to(void())),
        td("PVOID", to(void())),
        td("LPCVOID", to(void())),
        td("LPSTR", to(prim(Char, 1, true))),
        td("LPCSTR", to(prim(Char, 1, true))),
        td("LPWSTR", to(prim(Char, 2, true))),
        td("LPCWSTR", to(prim(Char, 2, true))),
        td("LPDWORD", to(prim(Int, 4, false))),
        td("PDWORD", to(prim(Int, 4, false))),
        td("PLONG", to(prim(Int, 4, true))),
        td("LPBOOL", to(prim(Int, 4, true))),
        td("FARPROC", code()),
        td("LPTHREAD_START_ROUTINE", code()),
        td("LPTOP_LEVEL_EXCEPTION_FILTER", code()),
        td("_PVFV", code()),
        td("_PIFV", code()),
        td("_onexit_t", code()),
        td("_beginthreadex_proc_type", code()),
        opaque("LARGE_INTEGER", 8),
        opaque("CRITICAL_SECTION", if ptr == 8 { 40 } else { 24 }),
        opaque("SECURITY_ATTRIBUTES", if ptr == 8 { 24 } else { 12 }),
        opaque("OVERLAPPED", if ptr == 8 { 32 } else { 20 }),
        opaque("SYSTEM_INFO", if ptr == 8 { 48 } else { 36 }),
        opaque("FILETIME", 8),
        opaque("MEMORY_BASIC_INFORMATION", if ptr == 8 { 48 } else { 28 }),
        opaque("STARTUPINFOA", if ptr == 8 { 104 } else { 68 }),
        opaque("STARTUPINFOW", if ptr == 8 { 104 } else { 68 }),
        opaque("PROCESS_INFORMATION", if ptr == 8 { 24 } else { 16 }),
        opaque("EXCEPTION_POINTERS", u64::from(2 * ptr)),
        opaque("WIN32_FIND_DATAA", 320),
        opaque("_startupinfo", 4),
    ];
    for (alias, target) in [
        ("LPCRITICAL_SECTION", "CRITICAL_SECTION"),
        ("LPSECURITY_ATTRIBUTES", "SECURITY_ATTRIBUTES"),
        ("LPOVERLAPPED", "OVERLAPPED"),
        ("LPSYSTEM_INFO", "SYSTEM_INFO"),
        ("LPFILETIME", "FILETIME"),
        ("PMEMORY_BASIC_INFORMATION", "MEMORY_BASIC_INFORMATION"),
        ("LPSTARTUPINFOA", "STARTUPINFOA"),
        ("LPSTARTUPINFOW", "STARTUPINFOW"),
        ("LPPROCESS_INFORMATION", "PROCESS_INFORMATION"),
        ("PEXCEPTION_POINTERS", "EXCEPTION_POINTERS"),
        ("LPWIN32_FIND_DATAA", "WIN32_FIND_DATAA"),
    ] {
        defs.push(td(alias, to(named(target))));
    }
    defs.push(td("CHAR", prim(Char, 1, true)));
    defs.push(td("PBYTE", to(named("BYTE"))));
    defs.push(td(
        "PIMAGE_SECTION_HEADER",
        to(named("_IMAGE_SECTION_HEADER")),
    ));
    defs
}

/// Functions of the table that never return, by name.
pub fn noreturn_names() -> impl Iterator<Item = &'static str> {
    PROTOTYPES.iter().filter_map(|p| {
        let rest = p.strip_prefix("noreturn ")?;
        let open = rest.find('(')?;
        rest[..open].split_whitespace().last()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ctypes::parse_prototype_in;

    #[test]
    fn every_entry_parses_with_known_types_and_names_are_unique() {
        let mut defined: std::collections::BTreeSet<String> = base_definitions(DataModel::LLP64)
            .iter()
            .filter_map(|d| kraken_engine::type_def_name(d).map(str::to_string))
            .collect();
        for d in crate::ctypes::base_definitions_in(DataModel::LLP64) {
            if let Some(n) = kraken_engine::type_def_name(&d) {
                defined.insert(n.to_string());
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        for p in PROTOTYPES {
            let (name, proto) =
                parse_prototype_in(p, DataModel::ILP32).unwrap_or_else(|e| panic!("{e}"));
            assert!(seen.insert(name.clone()), "{name} twice");
            let mut tys = vec![proto.return_type.as_ref().clone()];
            tys.extend(proto.params.iter().map(|p| p.ty.clone()));
            while let Some(t) = tys.pop() {
                match t {
                    TypeRef::Named { name: n } => {
                        assert!(defined.contains(&n), "{name}: {n} is not defined")
                    }
                    TypeRef::Pointer { target, size } => {
                        assert_eq!(size, 4);
                        tys.push(*target);
                    }
                    _ => {}
                }
            }
        }
        // no clash with the C library table: one prototype per name
        for p in crate::libc::PROTOTYPES {
            let (name, _) = crate::ctypes::parse_prototype(p).expect("libc");
            assert!(!seen.contains(&name), "{name} is in both tables");
        }
        assert!(noreturn_names().any(|n| n == "ExitProcess"));
    }

    #[test]
    fn win32_functions_are_stdcall() {
        let (_, p) = parse_prototype_in(PROTOTYPES[0], DataModel::ILP32).expect("first");
        assert_eq!(p.calling_convention, "__stdcall");
        let (_, p) = parse_prototype_in("int *_errno(void)", DataModel::ILP32).expect("crt");
        assert!(p.calling_convention.is_empty());
    }
}
