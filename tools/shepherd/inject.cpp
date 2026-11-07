// Tiny arch-matched injector. Spawned by shepherd when it needs to inject a
// DLL into a child whose architecture differs from shepherd's own. Built as
// inject32.exe (x86) and inject64.exe (x64). Does standard
// CreateRemoteThread(LoadLibraryW) injection. Exits 0 on success.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cwchar>

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3)
    {
        wprintf(L"Usage: inject.exe <pid> <dll_path>\n");
        return 1;
    }
    DWORD pid = (DWORD)_wtoi(argv[1]);
    const wchar_t* dll_path = argv[2];

    HANDLE proc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
        FALSE, pid);
    if (!proc)
    {
        wprintf(L"OpenProcess failed: %lu\n", GetLastError());
        return 2;
    }

    size_t bytes = (wcslen(dll_path) + 1) * sizeof(wchar_t);
    LPVOID remote = VirtualAllocEx(proc, nullptr, bytes,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote)
    {
        wprintf(L"VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(proc);
        return 3;
    }
    SIZE_T written = 0;
    if (!WriteProcessMemory(proc, remote, dll_path, bytes, &written))
    {
        wprintf(L"WriteProcessMemory failed: %lu\n", GetLastError());
        CloseHandle(proc);
        return 4;
    }

    HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
    FARPROC load_lib = GetProcAddress(k32, "LoadLibraryW");
    HANDLE th = CreateRemoteThread(proc, nullptr, 0,
                                   reinterpret_cast<LPTHREAD_START_ROUTINE>(load_lib),
                                   remote, 0, nullptr);
    if (!th)
    {
        wprintf(L"CreateRemoteThread failed: %lu\n", GetLastError());
        CloseHandle(proc);
        return 5;
    }

    WaitForSingleObject(th, 20000);
    DWORD code = 0;
    GetExitCodeThread(th, &code);
    wprintf(L"LoadLibraryW returned HMODULE=0x%x\n", code);
    CloseHandle(th);
    CloseHandle(proc);
    return (code != 0 && code != STILL_ACTIVE) ? 0 : 6;
}
