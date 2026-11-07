// Watcher: polls for PlayGTAV.exe (or any specified parent process) and
// injects shepherd.dll into it the moment it appears. Must be started BEFORE
// the user clicks Play in Steam, so we beat BEDaisy's load.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdio>
#include <cwchar>
#include <string>

namespace
{
    void print_err(const char* ctx)
    {
        DWORD err = GetLastError();
        wchar_t* msg = nullptr;
        FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, err, 0, reinterpret_cast<wchar_t*>(&msg), 0, nullptr);
        wprintf(L"[!] %hs failed: 0x%08lx %s\n", ctx, err, msg ? msg : L"(no message)");
        if (msg) LocalFree(msg);
    }

    DWORD find_process(const wchar_t* name)
    {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return 0;
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        DWORD pid = 0;
        if (Process32FirstW(snap, &pe))
        {
            do {
                if (_wcsicmp(pe.szExeFile, name) == 0)
                {
                    pid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return pid;
    }

    using PNtSuspendProcess = LONG(WINAPI*)(HANDLE);
    using PNtResumeProcess  = LONG(WINAPI*)(HANDLE);

    bool inject(DWORD pid, const wchar_t* dll_path)
    {
        HANDLE proc = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME,
            FALSE, pid);
        if (!proc)
        {
            print_err("OpenProcess");
            return false;
        }
        wprintf(L"[+] OpenProcess OK for PID %lu\n", pid);

        // NOTE: do NOT NtSuspendProcess here. It freezes threads that may hold
        // the loader lock or heap lock, which our shepherd's DllMain then
        // deadlocks on when MinHook calls VirtualAlloc/VirtualProtect. We rely
        // on fast synchronous install in DllMain + inline hooking of
        // NtCreateUserProcess to win the race against the host's next spawn.

        size_t bytes = (wcslen(dll_path) + 1) * sizeof(wchar_t);
        LPVOID remote = VirtualAllocEx(proc, nullptr, bytes,
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote)
        {
            print_err("VirtualAllocEx");
            CloseHandle(proc);
            return false;
        }
        SIZE_T written = 0;
        if (!WriteProcessMemory(proc, remote, dll_path, bytes, &written))
        {
            print_err("WriteProcessMemory");
            CloseHandle(proc);
            return false;
        }
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        FARPROC load_lib = GetProcAddress(k32, "LoadLibraryW");
        HANDLE th = CreateRemoteThread(proc, nullptr, 0,
                                       reinterpret_cast<LPTHREAD_START_ROUTINE>(load_lib),
                                       remote, 0, nullptr);
        if (!th)
        {
            print_err("CreateRemoteThread");
            CloseHandle(proc);
            return false;
        }
        WaitForSingleObject(th, 15000);
        DWORD code = 0;
        GetExitCodeThread(th, &code);
        wprintf(L"[+] LoadLibrary returned HMODULE=0x%x\n", code);
        CloseHandle(th);
        CloseHandle(proc);
        return code != 0 && code != STILL_ACTIVE;
    }

    bool write_reg(const wchar_t* val, const wchar_t* data)
    {
        HKEY k;
        LONG r = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\YimMenuV2Shepherd",
                                 0, nullptr, 0, KEY_WRITE, nullptr, &k, nullptr);
        if (r != ERROR_SUCCESS) return false;
        r = RegSetValueExW(k, val, 0, REG_SZ, (const BYTE*)data,
                           (DWORD)((wcslen(data) + 1) * sizeof(wchar_t)));
        RegCloseKey(k);
        return r == ERROR_SUCCESS;
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3)
    {
        wprintf(L"Usage: watcher.exe <shepherd_dll> <payload_dll> [--target <exe_name>]\n");
        wprintf(L"\n");
        wprintf(L"  shepherd_dll     Full path to shepherd.dll\n");
        wprintf(L"  payload_dll      Full path to YimMenuV2.dll\n");
        wprintf(L"  --target <name>  Process to watch for (default: PlayGTAV.exe)\n");
        wprintf(L"\n");
        wprintf(L"Start this BEFORE clicking Play in Steam. It will poll for\n");
        wprintf(L"the target process every 50ms and inject shepherd the moment\n");
        wprintf(L"it appears, before BattlEye's kernel driver is loaded.\n");
        return 1;
    }

    const wchar_t* shepherd = argv[1];
    const wchar_t* payload = argv[2];
    const wchar_t* target = L"PlayGTAV.exe";
    for (int i = 3; i + 1 < argc; i++)
    {
        if (wcscmp(argv[i], L"--target") == 0)
        {
            target = argv[i + 1];
            i++;
        }
    }

    if (GetFileAttributesW(shepherd) == INVALID_FILE_ATTRIBUTES)
    {
        wprintf(L"[!] shepherd dll missing: %s\n", shepherd);
        return 2;
    }
    if (GetFileAttributesW(payload) == INVALID_FILE_ATTRIBUTES)
    {
        wprintf(L"[!] payload dll missing: %s\n", payload);
        return 2;
    }

    // Write paths to registry so shepherd can read them when it chains.
    wchar_t log_path[MAX_PATH]{};
    ExpandEnvironmentStringsW(L"%LOCALAPPDATA%\\YimMenuV2Shepherd.log", log_path, MAX_PATH);
    if (!write_reg(L"PayloadPath", payload)) wprintf(L"[!] failed to write PayloadPath\n");
    if (!write_reg(L"LogPath", log_path))    wprintf(L"[!] failed to write LogPath\n");
    wprintf(L"[+] Registry: HKCU\\Software\\YimMenuV2Shepherd\n");
    wprintf(L"[+]   PayloadPath = %s\n", payload);
    wprintf(L"[+]   LogPath     = %s\n", log_path);
    DeleteFileW(log_path);  // start fresh
    wprintf(L"[+] Watching for %s (50ms poll). Click Play in Steam now.\n", target);
    wprintf(L"[+] Press Ctrl-C to abort.\n");

    for (;;)
    {
        DWORD pid = find_process(target);
        if (pid)
        {
            wprintf(L"[+] %s appeared as PID %lu — injecting shepherd\n", target, pid);
            bool ok = inject(pid, shepherd);
            wprintf(L"[+] Injection %s. Exiting.\n", ok ? L"OK" : L"FAILED");
            return ok ? 0 : 3;
        }
        Sleep(50);
    }
}
