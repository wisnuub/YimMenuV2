// Shepherd DLL: once injected into any process in the launch chain, inline-hooks
// the real CreateProcess implementations in kernelbase.dll (and the ANSI variant)
// so every child the host spawns gets shepherd re-injected via the fresh handle
// Windows hands the parent. BattlEye's ObRegisterCallbacks (BEDaisy) cannot
// retroactively strip rights from a handle that already exists.
//
// Why inline rather than IAT: PlayGTAV routes CreateProcess through kernelbase
// directly (or through api-ms-win shims that forward to kernelbase), so an IAT
// hook on kernel32 never fires. Inline hooking of the real implementation
// catches every call regardless of which forwarder the caller imports from.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <MinHook.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <cstdarg>
#include <set>
#include <mutex>

namespace
{
    constexpr const wchar_t* k_RegKey     = L"Software\\YimMenuV2Shepherd";
    constexpr const wchar_t* k_RegVal     = L"PayloadPath";
    constexpr const wchar_t* k_LogRegVal  = L"LogPath";

    using PCreateProcessW = BOOL (WINAPI*)(
        LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
        BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    using PCreateProcessA = BOOL (WINAPI*)(
        LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
        BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    // Undocumented but stable. Every CreateProcess*, ShellExecute, and
    // CreateProcessAsUser variant funnels through this in kernelbase.
    using PCreateProcessInternalW = BOOL (WINAPI*)(
        HANDLE hToken,
        LPCWSTR lpApplicationName,
        LPWSTR lpCommandLine,
        LPSECURITY_ATTRIBUTES lpProcessAttributes,
        LPSECURITY_ATTRIBUTES lpThreadAttributes,
        BOOL bInheritHandles,
        DWORD dwCreationFlags,
        LPVOID lpEnvironment,
        LPCWSTR lpCurrentDirectory,
        LPSTARTUPINFOW lpStartupInfo,
        LPPROCESS_INFORMATION lpProcessInformation,
        PHANDLE hNewToken);

    // Minimal RTL_USER_PROCESS_PARAMETERS layout — only the fields we need.
    struct UNICODE_STRING_mini {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    };
    struct RTL_USER_PROCESS_PARAMETERS_mini {
        BYTE                  Padding1[0x60];  // MaximumLength..CurrentDirectory
        UNICODE_STRING_mini   DllPath;         // +0x30
        UNICODE_STRING_mini   ImagePathName;   // +0x60
        UNICODE_STRING_mini   CommandLine;     // +0x70
    };

    using PNtCreateUserProcess = LONG (NTAPI*)(
        PHANDLE ProcessHandle,
        PHANDLE ThreadHandle,
        ACCESS_MASK ProcessDesiredAccess,
        ACCESS_MASK ThreadDesiredAccess,
        LPVOID ProcessObjectAttributes,
        LPVOID ThreadObjectAttributes,
        ULONG ProcessFlags,
        ULONG ThreadFlags,
        LPVOID ProcessParameters,
        LPVOID CreateInfo,
        LPVOID AttributeList);

    PCreateProcessW         g_orig_CreateProcessW         = nullptr;
    PCreateProcessA         g_orig_CreateProcessA         = nullptr;
    PCreateProcessInternalW g_orig_CreateProcessInternalW = nullptr;
    PNtCreateUserProcess    g_orig_NtCreateUserProcess    = nullptr;
    HMODULE g_self_module = nullptr;
    wchar_t g_self_path[MAX_PATH]{};
    wchar_t g_log_path[MAX_PATH]{};
    bool g_log_enabled = false;

    void log(const char* fmt, ...)
    {
        if (!g_log_enabled) return;
        FILE* f = nullptr;
        _wfopen_s(&f, g_log_path, L"ab");
        if (!f) return;
        va_list ap; va_start(ap, fmt);
        char buf[1536];
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        DWORD pid = GetCurrentProcessId();
        fprintf(f, "[pid %lu] %s\n", pid, buf);
        fclose(f);
    }

    bool read_reg_str(const wchar_t* val_name, wchar_t* out, size_t out_chars)
    {
        HKEY k;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, k_RegKey, 0, KEY_READ, &k) != ERROR_SUCCESS)
            return false;
        DWORD type = 0;
        DWORD bytes = (DWORD)(out_chars * sizeof(wchar_t));
        LONG r = RegQueryValueExW(k, val_name, nullptr, &type, (BYTE*)out, &bytes);
        RegCloseKey(k);
        return r == ERROR_SUCCESS && (type == REG_SZ || type == REG_EXPAND_SZ);
    }

    // Direct injection using the already-open child_process handle. Works only
    // when shepherd and target are the same arch. The handle is the fresh one
    // returned by CreateProcess inside the host — BEDaisy's object callback
    // cannot strip rights from it.
    using PNtAllocateVirtualMemory = LONG (NTAPI*)(
        HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits,
        PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
    using PNtWriteVirtualMemory = LONG (NTAPI*)(
        HANDLE ProcessHandle, PVOID BaseAddress, const VOID* Buffer,
        SIZE_T NumberOfBytesToWrite, PSIZE_T NumberOfBytesWritten);

    bool inject_direct(HANDLE child_process, const wchar_t* dll_path, const char* tag)
    {
        size_t bytes = (wcslen(dll_path) + 1) * sizeof(wchar_t);

        // Try VirtualAllocEx first (the user-mode wrapper).
        LPVOID remote = VirtualAllocEx(child_process, nullptr, bytes,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote)
        {
            log("  inject[%s] VirtualAllocEx failed: 0x%lx, trying NtAllocateVirtualMemory",
                tag, GetLastError());

            HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
            auto NtAllocateVirtualMemory = reinterpret_cast<PNtAllocateVirtualMemory>(
                GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
            if (NtAllocateVirtualMemory)
            {
                PVOID base = nullptr;
                SIZE_T sz = bytes;
                LONG s = NtAllocateVirtualMemory(child_process, &base, 0, &sz,
                                                 MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (s == 0 && base)
                {
                    remote = base;
                    log("  inject[%s] NtAllocateVirtualMemory succeeded: %p", tag, remote);
                }
                else
                {
                    log("  inject[%s] NtAllocateVirtualMemory status=0x%lx", tag, s);
                }
            }
        }
        HANDLE owned_handle = nullptr;
        if (!remote)
        {
            // Last resort: re-open the process ourselves and try NtAlloc again.
            DWORD child_pid = GetProcessId(child_process);
            owned_handle = OpenProcess(
                PROCESS_CREATE_THREAD | PROCESS_QUERY_LIMITED_INFORMATION |
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
                FALSE, child_pid);
            if (owned_handle)
            {
                HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
                auto NtAlloc = reinterpret_cast<PNtAllocateVirtualMemory>(
                    GetProcAddress(ntdll, "NtAllocateVirtualMemory"));
                PVOID base = nullptr;
                SIZE_T sz = bytes;
                LONG s = NtAlloc ? NtAlloc(owned_handle, &base, 0, &sz,
                                            MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE) : -1;
                if (s == 0 && base)
                {
                    remote = base;
                    child_process = owned_handle;
                    log("  inject[%s] NtAlloc on fresh handle succeeded: %p", tag, remote);
                }
                else
                {
                    log("  inject[%s] NtAlloc on fresh handle status=0x%lx", tag, s);
                    CloseHandle(owned_handle);
                    owned_handle = nullptr;
                }
            }
            else
            {
                log("  inject[%s] OpenProcess(%lu) failed: 0x%lx", tag, child_pid, GetLastError());
            }
        }
        if (!remote) return false;
        SIZE_T written = 0;
        if (!WriteProcessMemory(child_process, remote, dll_path, bytes, &written))
        {
            log("  inject[%s] direct WriteProcessMemory failed: 0x%lx", tag, GetLastError());
            return false;
        }
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        FARPROC load_lib = GetProcAddress(k32, "LoadLibraryW");
        HANDLE th = CreateRemoteThread(child_process, nullptr, 0,
                                       (LPTHREAD_START_ROUTINE)load_lib,
                                       remote, 0, nullptr);
        if (!th)
        {
            log("  inject[%s] direct CreateRemoteThread failed: 0x%lx", tag, GetLastError());
            return false;
        }
        WaitForSingleObject(th, 20000);
        DWORD code = 0;
        GetExitCodeThread(th, &code);
        log("  inject[%s] direct LoadLibrary returned HMODULE=0x%x", tag, code);
        CloseHandle(th);
        if (owned_handle) CloseHandle(owned_handle);
        return code != 0 && code != STILL_ACTIVE;
    }

    // Inject via helper exe of the matching arch. Only needed for cross-arch
    // (shepherd64 injecting into 32-bit child, or shepherd32 into 64-bit).
    bool inject_via_helper(DWORD target_pid, bool target_is_32bit,
                           const wchar_t* dll_path, const char* tag)
    {
        wchar_t helper_path[MAX_PATH]{};
        wcscpy_s(helper_path, g_self_path);
        wchar_t* last_slash = wcsrchr(helper_path, L'\\');
        if (!last_slash) return false;
        *(last_slash + 1) = 0;
        wcscat_s(helper_path, target_is_32bit ? L"inject32.exe" : L"inject64.exe");

        wchar_t cmd[2048]{};
        swprintf_s(cmd, L"\"%s\" %lu \"%s\"", helper_path, target_pid, dll_path);
        log("  inject[%s] via helper: %ls", tag, cmd);

        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        // Must call the ORIGINAL CreateProcessW — if we call the public one
        // our own hook catches it and tries to inject shepherd into the
        // helper, which spawns another helper, infinite recursion. The orig
        // pointer may be null if the hook isn't installed, in which case we
        // fall back (safe here because handle_child skips our own helpers).
        auto cpw = g_orig_CreateProcessW ? g_orig_CreateProcessW : &CreateProcessW;
        if (!cpw(helper_path, cmd, nullptr, nullptr, FALSE,
                 CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
        {
            log("  inject[%s] helper spawn failed: 0x%lx", tag, GetLastError());
            return false;
        }
        WaitForSingleObject(pi.hProcess, 20000);
        DWORD exit_code = 0;
        GetExitCodeProcess(pi.hProcess, &exit_code);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        log("  inject[%s] helper exit=%lu", tag, exit_code);
        return exit_code == 0;
    }

    bool target_is_wow64(HANDLE process)
    {
        BOOL wow = FALSE;
        IsWow64Process(process, &wow);
        return wow == TRUE;
    }

    bool inject_dll(HANDLE process, const wchar_t* dll_path, const char* tag)
    {
        size_t bytes = (wcslen(dll_path) + 1) * sizeof(wchar_t);
        LPVOID remote = VirtualAllocEx(process, nullptr, bytes,
                                       MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote)
        {
            log("  inject[%s] VirtualAllocEx failed: 0x%lx", tag, GetLastError());
            return false;
        }
        SIZE_T written = 0;
        if (!WriteProcessMemory(process, remote, dll_path, bytes, &written))
        {
            log("  inject[%s] WriteProcessMemory failed: 0x%lx", tag, GetLastError());
            return false;
        }
        HMODULE k32 = GetModuleHandleW(L"kernel32.dll");
        FARPROC load_lib = GetProcAddress(k32, "LoadLibraryW");
        HANDLE th = CreateRemoteThread(process, nullptr, 0,
                                       (LPTHREAD_START_ROUTINE)load_lib,
                                       remote, 0, nullptr);
        if (!th)
        {
            log("  inject[%s] CreateRemoteThread failed: 0x%lx", tag, GetLastError());
            return false;
        }
        WaitForSingleObject(th, 20000);
        DWORD code = 0;
        GetExitCodeThread(th, &code);
        log("  inject[%s] LoadLibrary returned HMODULE=0x%x", tag, code);
        CloseHandle(th);
        return code != 0;
    }

    // Case-insensitive tail match on a path or command line against a short exe name.
    bool is_target_exe_w(LPCWSTR appname, LPCWSTR cmdline, const wchar_t* target)
    {
        auto tail_eq = [&](const wchar_t* p) -> bool {
            if (!p) return false;
            wchar_t copy[MAX_PATH]{};
            size_t j = 0;
            // Skip leading quote/space on cmdline
            while (*p == L'"' || *p == L' ') p++;
            while (p[j] && p[j] != L'"' && p[j] != L' ' && j + 1 < MAX_PATH) { copy[j] = p[j]; j++; }
            copy[j] = 0;
            const wchar_t* slash = wcsrchr(copy, L'\\');
            const wchar_t* name = slash ? slash + 1 : copy;
            return _wcsicmp(name, target) == 0;
        };
        return tail_eq(appname) || tail_eq(cmdline);
    }

    bool is_target_exe_a(LPCSTR appname, LPCSTR cmdline, const wchar_t* target)
    {
        auto to_w = [](const char* s, wchar_t* out, int out_sz) -> bool {
            if (!s) { out[0] = 0; return false; }
            MultiByteToWideChar(CP_UTF8, 0, s, -1, out, out_sz);
            return true;
        };
        wchar_t wapp[MAX_PATH]{}; wchar_t wcmd[MAX_PATH]{};
        to_w(appname, wapp, MAX_PATH);
        to_w(cmdline, wcmd, MAX_PATH);
        return is_target_exe_w(wapp, wcmd, target);
    }

    // Pick the right-arch shepherd for the target.
    bool get_shepherd_variant_for(bool target_is_32bit, wchar_t* out, size_t out_chars)
    {
        wchar_t dir[MAX_PATH]{};
        wcscpy_s(dir, g_self_path);
        wchar_t* slash = wcsrchr(dir, L'\\');
        if (!slash) return false;
        *(slash + 1) = 0;
        swprintf_s(out, out_chars, L"%s%s", dir,
                   target_is_32bit ? L"shepherd32.dll" : L"shepherd64.dll");
        return true;
    }

    std::set<DWORD> g_injected_pids;
    std::mutex g_injected_mutex;

    void handle_child(HANDLE child_process, DWORD child_pid, LPCWSTR appname, LPCWSTR cmdline)
    {
        // Belt-and-suspenders against the recursion we just fixed: any child
        // that IS one of our own binaries gets skipped entirely.
        if (is_target_exe_w(appname, cmdline, L"inject32.exe") ||
            is_target_exe_w(appname, cmdline, L"inject64.exe") ||
            is_target_exe_w(appname, cmdline, L"watcher.exe"))
        {
            log("  PID=%lu is our own helper, skip", child_pid);
            return;
        }

        {
            std::lock_guard<std::mutex> lock(g_injected_mutex);
            if (!g_injected_pids.insert(child_pid).second)
            {
                log("  PID=%lu already handled, skipping duplicate hook fire", child_pid);
                return;
            }
        }

        bool child_is_32bit = target_is_wow64(child_process);
        // Our own arch: x64 if sizeof(void*)==8 else x86.
        bool self_is_32bit = (sizeof(void*) == 4);
        bool same_arch = (child_is_32bit == self_is_32bit);
        log("  child PID=%lu arch=%s (self=%s, same_arch=%d)",
            child_pid,
            child_is_32bit ? "x86 (wow64)" : "x64",
            self_is_32bit ? "x86" : "x64",
            (int)same_arch);

        wchar_t shepherd_for_child[MAX_PATH]{};
        if (get_shepherd_variant_for(child_is_32bit, shepherd_for_child, MAX_PATH))
        {
            if (GetFileAttributesW(shepherd_for_child) != INVALID_FILE_ATTRIBUTES)
            {
                if (same_arch)
                    inject_direct(child_process, shepherd_for_child, "shepherd");
                else
                    inject_via_helper(child_pid, child_is_32bit, shepherd_for_child, "shepherd");
            }
            else
            {
                log("  shepherd variant missing: %ls — chain will break here", shepherd_for_child);
            }
        }

        if (is_target_exe_w(appname, cmdline, L"GTA5_Enhanced.exe"))
        {
            wchar_t payload[MAX_PATH]{};
            if (read_reg_str(k_RegVal, payload, MAX_PATH))
            {
                log("  >>> target is GTA5_Enhanced.exe, injecting payload %ls", payload);
                // YimMenuV2.dll is always x64. If GTA is x64 (same arch when we
                // are also x64) direct; otherwise helper.
                if (!child_is_32bit && !self_is_32bit)
                    inject_direct(child_process, payload, "payload");
                else
                    inject_via_helper(child_pid, child_is_32bit, payload, "payload");
            }
            else
            {
                log("  >>> target is GTA5_Enhanced.exe, but no PayloadPath in registry");
            }
        }
    }

    BOOL WINAPI Hooked_CreateProcessW(
        LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES psa, LPSECURITY_ATTRIBUTES tsa,
        BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir,
        LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
    {
        OutputDebugStringW(L"[shepherd] Hooked_CreateProcessW entered\n");
        log("Hooked_CreateProcessW ENTER");
        bool caller_wanted_suspended = (flags & CREATE_SUSPENDED) != 0;
        DWORD new_flags = flags | CREATE_SUSPENDED;

        log("CreateProcessW: app=%ls cmd=%ls",
            app ? app : L"(null)", cmd ? cmd : L"(null)");

        BOOL ret = g_orig_CreateProcessW(app, cmd, psa, tsa, inherit, new_flags, env, dir, si, pi);
        if (!ret) return FALSE;
        log("  spawned PID=%lu suspended (via CreateProcessW)", pi->dwProcessId);

        handle_child(pi->hProcess, pi->dwProcessId, app, cmd);

        if (!caller_wanted_suspended)
            ResumeThread(pi->hThread);
        return TRUE;
    }

    BOOL WINAPI Hooked_CreateProcessA(
        LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES psa, LPSECURITY_ATTRIBUTES tsa,
        BOOL inherit, DWORD flags, LPVOID env, LPCSTR dir,
        LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi)
    {
        bool caller_wanted_suspended = (flags & CREATE_SUSPENDED) != 0;
        DWORD new_flags = flags | CREATE_SUSPENDED;

        log("CreateProcessA: app=%hs cmd=%hs",
            app ? app : "(null)", cmd ? cmd : "(null)");

        BOOL ret = g_orig_CreateProcessA(app, cmd, psa, tsa, inherit, new_flags, env, dir, si, pi);
        if (!ret) return FALSE;
        log("  spawned PID=%lu suspended (via CreateProcessA)", pi->dwProcessId);

        wchar_t wapp[MAX_PATH]{}, wcmd[MAX_PATH]{};
        if (app) MultiByteToWideChar(CP_UTF8, 0, app, -1, wapp, MAX_PATH);
        if (cmd) MultiByteToWideChar(CP_UTF8, 0, cmd, -1, wcmd, MAX_PATH);
        handle_child(pi->hProcess, pi->dwProcessId, app ? wapp : nullptr, cmd ? wcmd : nullptr);

        if (!caller_wanted_suspended)
            ResumeThread(pi->hThread);
        return TRUE;
    }

    BOOL WINAPI Hooked_CreateProcessInternalW(
        HANDLE hToken, LPCWSTR app, LPWSTR cmd,
        LPSECURITY_ATTRIBUTES psa, LPSECURITY_ATTRIBUTES tsa,
        BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir,
        LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi, PHANDLE newToken)
    {
        bool caller_wanted_suspended = (flags & CREATE_SUSPENDED) != 0;
        DWORD new_flags = flags | CREATE_SUSPENDED;

        log("CreateProcessInternalW: app=%ls cmd=%ls",
            app ? app : L"(null)", cmd ? cmd : L"(null)");

        BOOL ret = g_orig_CreateProcessInternalW(hToken, app, cmd, psa, tsa, inherit,
                                                  new_flags, env, dir, si, pi, newToken);
        if (!ret) return FALSE;
        log("  spawned PID=%lu suspended (via CreateProcessInternalW)", pi->dwProcessId);

        handle_child(pi->hProcess, pi->dwProcessId, app, cmd);

        if (!caller_wanted_suspended)
            ResumeThread(pi->hThread);
        return TRUE;
    }

    // THREAD_CREATE_FLAGS_CREATE_SUSPENDED (from ntpsapi.h — undocumented constant)
    constexpr ULONG k_ThreadFlag_Suspended = 0x00000001;

    LONG NTAPI Hooked_NtCreateUserProcess(
        PHANDLE ProcessHandle, PHANDLE ThreadHandle,
        ACCESS_MASK ProcessDesiredAccess, ACCESS_MASK ThreadDesiredAccess,
        LPVOID ProcessObjectAttributes, LPVOID ThreadObjectAttributes,
        ULONG ProcessFlags, ULONG ThreadFlags,
        LPVOID ProcessParameters, LPVOID CreateInfo, LPVOID AttributeList)
    {
        bool caller_wanted_suspended = (ThreadFlags & k_ThreadFlag_Suspended) != 0;
        ULONG new_thread_flags = ThreadFlags | k_ThreadFlag_Suspended;

        // Extract image path and command line from ProcessParameters
        wchar_t image_buf[MAX_PATH]{};
        wchar_t cmd_buf[MAX_PATH]{};
        if (ProcessParameters)
        {
            auto p = reinterpret_cast<RTL_USER_PROCESS_PARAMETERS_mini*>(ProcessParameters);
            if (p->ImagePathName.Buffer && p->ImagePathName.Length > 0)
            {
                size_t n = min((size_t)(p->ImagePathName.Length / sizeof(wchar_t)), (size_t)(MAX_PATH - 1));
                wcsncpy_s(image_buf, p->ImagePathName.Buffer, n);
            }
            if (p->CommandLine.Buffer && p->CommandLine.Length > 0)
            {
                size_t n = min((size_t)(p->CommandLine.Length / sizeof(wchar_t)), (size_t)(MAX_PATH - 1));
                wcsncpy_s(cmd_buf, p->CommandLine.Buffer, n);
            }
        }

        log("NtCreateUserProcess: image=%ls cmd=%ls thread_flags=0x%lx",
            image_buf[0] ? image_buf : L"(none)",
            cmd_buf[0] ? cmd_buf : L"(none)",
            ThreadFlags);

        // Force full access on the returned handles so our later VirtualAllocEx
        // etc. don't hit ACCESS_DENIED. BE's loader asks for restricted rights
        // which we need to widen for injection to work.
        ACCESS_MASK forced_process_access = PROCESS_ALL_ACCESS;
        ACCESS_MASK forced_thread_access  = THREAD_ALL_ACCESS;

        LONG status = g_orig_NtCreateUserProcess(
            ProcessHandle, ThreadHandle, forced_process_access, forced_thread_access,
            ProcessObjectAttributes, ThreadObjectAttributes, ProcessFlags, new_thread_flags,
            ProcessParameters, CreateInfo, AttributeList);
        if (status != 0)
        {
            log("  real NtCreateUserProcess failed: 0x%lx", status);
            return status;
        }
        log("  spawned PH=%p TH=%p suspended",
            ProcessHandle ? *ProcessHandle : nullptr,
            ThreadHandle ? *ThreadHandle : nullptr);

        if (ProcessHandle && *ProcessHandle)
        {
            DWORD child_pid = GetProcessId(*ProcessHandle);
            handle_child(*ProcessHandle, child_pid,
                         image_buf[0] ? image_buf : nullptr,
                         cmd_buf[0] ? cmd_buf : nullptr);
        }

        if (!caller_wanted_suspended && ThreadHandle && *ThreadHandle)
        {
            ResumeThread(*ThreadHandle);
        }
        return status;
    }

    bool install_inline_hooks()
    {
        if (MH_Initialize() != MH_OK)
        {
            log("MH_Initialize failed");
            return false;
        }

        HMODULE kb = LoadLibraryW(L"kernelbase.dll");
        if (!kb) kb = GetModuleHandleW(L"kernelbase.dll");
        if (!kb)
        {
            log("kernelbase.dll not available");
            return false;
        }

        void* cpw   = GetProcAddress(kb, "CreateProcessW");
        void* cpa   = GetProcAddress(kb, "CreateProcessA");
        void* cpiw  = GetProcAddress(kb, "CreateProcessInternalW");

        HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
        void* ncup = ntdll ? GetProcAddress(ntdll, "NtCreateUserProcess") : nullptr;

        log("resolved: W=%p A=%p InternalW=%p NtCreateUserProcess=%p",
            cpw, cpa, cpiw, ncup);

        if (cpw)
            MH_CreateHook(cpw, &Hooked_CreateProcessW,
                          reinterpret_cast<LPVOID*>(&g_orig_CreateProcessW));
        if (cpa)
            MH_CreateHook(cpa, &Hooked_CreateProcessA,
                          reinterpret_cast<LPVOID*>(&g_orig_CreateProcessA));
        if (cpiw)
            MH_CreateHook(cpiw, &Hooked_CreateProcessInternalW,
                          reinterpret_cast<LPVOID*>(&g_orig_CreateProcessInternalW));
        if (ncup)
            MH_CreateHook(ncup, &Hooked_NtCreateUserProcess,
                          reinterpret_cast<LPVOID*>(&g_orig_NtCreateUserProcess));

        if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
        {
            log("MH_EnableHook failed");
            return false;
        }

        // Verify jmp is actually at the hooked address. On x64 MinHook emits
        // either a direct jmp (0xE9) or a mov rax, imm64 + jmp rax
        // (0x48 0xB8 + 8 bytes + 0xFF 0xE0). Original CreateProcessW starts
        // with 0x48 0x89 (mov qword ptr). If we see 0xE9 or 0x48 0xB8, hook
        // is installed. Otherwise it is not.
        if (cpw)
        {
            unsigned char b[2];
            memcpy(b, cpw, 2);
            log("post-install CreateProcessW bytes: %02x %02x (expect E9 ? or 48 B8 if hooked)",
                b[0], b[1]);
        }

        log("inline hooks enabled");
        return true;
    }

    void shepherd_init(HINSTANCE self)
    {
        g_self_module = self;
        GetModuleFileNameW(g_self_module, g_self_path, MAX_PATH);

        g_log_enabled = read_reg_str(k_LogRegVal, g_log_path, MAX_PATH);

        wchar_t host_path[MAX_PATH]{};
        GetModuleFileNameW(nullptr, host_path, MAX_PATH);
        log("shepherd loaded in host=%ls self=%ls", host_path, g_self_path);

        install_inline_hooks();
    }
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(inst);
        // Install synchronously so LoadLibrary doesn't return until hooks are active.
        // MinHook only does memory patches, which are safe under loader lock.
        shepherd_init(inst);
    }
    return TRUE;
}
