// Direct GTA launcher. Bypasses BELauncher and PlayGTAV so BattlEye's kernel
// driver (BEDaisy) is never loaded, then injects YimMenuV2.dll into the
// suspended GTA process via standard LoadLibraryW remote-thread injection.
//
// Rationale: BEDaisy is a Manual-start driver. It only exists when BELauncher
// starts it. If we launch GTA5_Enhanced.exe ourselves, BEDaisy stays asleep,
// no ObRegisterCallbacks filter is active, and external injection succeeds
// with no 0xC0000022 ACCESS_DENIED.
//
// Known unknowns we only learn from running it:
// - Whether GTA's own Arxan tamper check fires on parent-process mismatch
// - Whether Rockstar's Social Club refuses auth without BE's handshake
// - Whether Steam terminates a GTA child not spawned via its own chain

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <cwchar>
#include <string>

namespace
{
    void print_last_error(const wchar_t* ctx)
    {
        DWORD err = GetLastError();
        wchar_t* msg = nullptr;
        FormatMessageW(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr, err, 0, reinterpret_cast<wchar_t*>(&msg), 0, nullptr);
        wprintf(L"[!] %s failed: 0x%08lx %s\n", ctx, err, msg ? msg : L"(no message)");
        if (msg) LocalFree(msg);
    }

    bool inject_dll(HANDLE process, const wchar_t* dll_path)
    {
        size_t path_bytes = (wcslen(dll_path) + 1) * sizeof(wchar_t);
        LPVOID remote_path = VirtualAllocEx(process, nullptr, path_bytes,
                                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote_path)
        {
            print_last_error(L"VirtualAllocEx");
            return false;
        }
        wprintf(L"[+] Allocated %zu bytes in target at 0x%p\n", path_bytes, remote_path);

        SIZE_T written = 0;
        if (!WriteProcessMemory(process, remote_path, dll_path, path_bytes, &written))
        {
            print_last_error(L"WriteProcessMemory");
            return false;
        }
        wprintf(L"[+] Wrote DLL path (%zu bytes)\n", written);

        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        FARPROC load_lib = GetProcAddress(k32, "LoadLibraryW");
        if (!load_lib)
        {
            print_last_error(L"GetProcAddress(LoadLibraryW)");
            return false;
        }

        HANDLE thread = CreateRemoteThread(process, nullptr, 0,
                                            reinterpret_cast<LPTHREAD_START_ROUTINE>(load_lib),
                                            remote_path, 0, nullptr);
        if (!thread)
        {
            print_last_error(L"CreateRemoteThread");
            return false;
        }
        wprintf(L"[+] Remote LoadLibraryW thread started\n");

        DWORD wait = WaitForSingleObject(thread, 15000);
        if (wait == WAIT_TIMEOUT)
        {
            wprintf(L"[!] Remote LoadLibraryW timed out after 15s (DLL may have started a long-running DllMain)\n");
        }
        else
        {
            DWORD exit_code = 0;
            GetExitCodeThread(thread, &exit_code);
            wprintf(L"[+] Remote LoadLibraryW returned HMODULE = 0x%x\n", exit_code);
            if (exit_code == 0)
            {
                wprintf(L"[!] LoadLibraryW returned 0 - target DLL failed to load. Check %%APPDATA%%\\YimMenuV2\\cout.log\n");
            }
        }
        CloseHandle(thread);
        return true;
    }
}

int wmain(int argc, wchar_t** argv)
{
    if (argc < 3)
    {
        wprintf(L"Usage: launcher.exe <gta_exe_path> <dll_path> [--no-inject] [--parent <path>]\n");
        wprintf(L"\n");
        wprintf(L"  gta_exe_path       Full path to GTA5_Enhanced.exe\n");
        wprintf(L"  dll_path           Full path to YimMenuV2.dll to inject\n");
        wprintf(L"  --no-inject        Launch without injection, for a control test\n");
        wprintf(L"  --parent <path>    Spoof parent process using <path> (launched suspended)\n");
        return 1;
    }

    const wchar_t* gta_path = argv[1];
    const wchar_t* dll_path = argv[2];
    bool do_inject = true;
    const wchar_t* parent_path = nullptr;
    for (int i = 3; i < argc; i++)
    {
        if (wcscmp(argv[i], L"--no-inject") == 0)
            do_inject = false;
        else if (wcscmp(argv[i], L"--parent") == 0 && i + 1 < argc)
            parent_path = argv[++i];
    }

    if (GetFileAttributesW(gta_path) == INVALID_FILE_ATTRIBUTES)
    {
        wprintf(L"[!] GTA path does not exist: %s\n", gta_path);
        return 2;
    }
    if (do_inject && GetFileAttributesW(dll_path) == INVALID_FILE_ATTRIBUTES)
    {
        wprintf(L"[!] DLL path does not exist: %s\n", dll_path);
        return 2;
    }
    if (parent_path && GetFileAttributesW(parent_path) == INVALID_FILE_ATTRIBUTES)
    {
        wprintf(L"[!] Parent path does not exist: %s\n", parent_path);
        return 2;
    }

    // Working directory = GTA's own directory so its sibling DLLs resolve.
    wchar_t working_dir[MAX_PATH];
    wcscpy_s(working_dir, gta_path);
    wchar_t* last_slash = wcsrchr(working_dir, L'\\');
    if (last_slash) *last_slash = 0;

    wprintf(L"[+] Target: %s\n", gta_path);
    wprintf(L"[+] Working dir: %s\n", working_dir);
    if (do_inject) wprintf(L"[+] Will inject: %s\n", dll_path);
    if (parent_path) wprintf(L"[+] Spoofing parent: %s\n", parent_path);

    // Optionally spawn a suspended "parent" process whose handle we pass to
    // PROC_THREAD_ATTRIBUTE_PARENT_PROCESS. GTA's Arxan/launcher check queries
    // the reported parent; Windows reports whatever we hand it.
    PROCESS_INFORMATION parent_pi{};
    if (parent_path)
    {
        STARTUPINFOW parent_si{};
        parent_si.cb = sizeof(parent_si);
        wchar_t parent_dir[MAX_PATH];
        wcscpy_s(parent_dir, parent_path);
        wchar_t* p_slash = wcsrchr(parent_dir, L'\\');
        if (p_slash) *p_slash = 0;
        if (!CreateProcessW(parent_path, nullptr, nullptr, nullptr, FALSE,
                            CREATE_SUSPENDED, nullptr, parent_dir, &parent_si, &parent_pi))
        {
            print_last_error(L"CreateProcessW(parent)");
            return 3;
        }
        wprintf(L"[+] Spawned suspended parent PID=%lu for PPID spoof\n", parent_pi.dwProcessId);
    }

    STARTUPINFOEXW si{};
    si.StartupInfo.cb = sizeof(STARTUPINFOEXW);
    PROCESS_INFORMATION pi{};
    DWORD create_flags = CREATE_SUSPENDED;

    SIZE_T attr_size = 0;
    LPPROC_THREAD_ATTRIBUTE_LIST attr_list = nullptr;
    if (parent_pi.hProcess)
    {
        InitializeProcThreadAttributeList(nullptr, 1, 0, &attr_size);
        attr_list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(HeapAlloc(GetProcessHeap(), 0, attr_size));
        InitializeProcThreadAttributeList(attr_list, 1, 0, &attr_size);
        UpdateProcThreadAttribute(attr_list, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                                  &parent_pi.hProcess, sizeof(HANDLE), nullptr, nullptr);
        si.lpAttributeList = attr_list;
        create_flags |= EXTENDED_STARTUPINFO_PRESENT;
    }

    if (!CreateProcessW(gta_path, nullptr, nullptr, nullptr, FALSE,
                        create_flags, nullptr, working_dir,
                        &si.StartupInfo, &pi))
    {
        print_last_error(L"CreateProcessW");
        if (attr_list) HeapFree(GetProcessHeap(), 0, attr_list);
        if (parent_pi.hProcess)
        {
            TerminateProcess(parent_pi.hProcess, 0);
            CloseHandle(parent_pi.hThread);
            CloseHandle(parent_pi.hProcess);
        }
        return 3;
    }
    wprintf(L"[+] GTA spawned suspended, PID=%lu TID=%lu\n", pi.dwProcessId, pi.dwThreadId);

    if (do_inject)
    {
        if (!inject_dll(pi.hProcess, dll_path))
        {
            wprintf(L"[!] Injection failed, terminating GTA\n");
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return 4;
        }
    }

    wprintf(L"[+] Resuming main thread. Watch the game for crash, update message, or normal start.\n");
    DWORD resumed = ResumeThread(pi.hThread);
    if (resumed == (DWORD)-1)
    {
        print_last_error(L"ResumeThread");
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        return 5;
    }
    wprintf(L"[+] ResumeThread succeeded (previous suspend count = %lu)\n", resumed);

    // Poll for 20 seconds to see if the process survives.
    wprintf(L"[+] Monitoring process for 20 seconds...\n");
    for (int i = 0; i < 20; i++)
    {
        Sleep(1000);
        DWORD exit_code = STILL_ACTIVE;
        if (GetExitCodeProcess(pi.hProcess, &exit_code) && exit_code != STILL_ACTIVE)
        {
            wprintf(L"[!] GTA exited at t+%ds with code 0x%lx\n", i + 1, exit_code);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return 6;
        }
        if ((i + 1) % 5 == 0)
            wprintf(L"    t+%ds: still running\n", i + 1);
    }

    wprintf(L"[+] GTA survived 20 seconds. Letting it run. Exiting launcher.\n");
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (attr_list) HeapFree(GetProcessHeap(), 0, attr_list);
    if (parent_pi.hProcess)
    {
        // Keep the spoofed parent alive for GTA's ancestry walk, or terminate
        // once we're clear of the check. Terminate is safer: fewer dangling
        // processes if the user Ctrl-Cs the launcher.
        TerminateProcess(parent_pi.hProcess, 0);
        CloseHandle(parent_pi.hThread);
        CloseHandle(parent_pi.hProcess);
    }
    return 0;
}
