// Shepherd DLL: once injected into any process in the launch chain, hooks
// CreateProcessW so that every child the process spawns has:
//   (a) shepherd re-injected into it, carrying the behavior down the tree
//   (b) if that child is GTA5_Enhanced.exe, the YimMenuV2 payload injected too
//
// Hooks run inside the parent and use the fresh handle returned by its own
// CreateProcess call. BattlEye's ObRegisterCallbacks (BEDaisy) cannot
// retroactively strip rights from an already-open handle.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstring>
#include <cwchar>

namespace
{
    constexpr const wchar_t* k_RegKey  = L"Software\\YimMenuV2Shepherd";
    constexpr const wchar_t* k_RegVal  = L"PayloadPath";
    constexpr const wchar_t* k_LogRegVal = L"LogPath";

    using PCreateProcessW = BOOL (WINAPI*)(
        LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES,
        BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

    PCreateProcessW g_real_CreateProcessW = nullptr;
    HMODULE g_self_module = nullptr;
    wchar_t g_self_path[MAX_PATH]{};
    wchar_t g_log_path[MAX_PATH]{};

    void log(const char* fmt, ...)
    {
        if (!g_log_path[0]) return;
        FILE* f = nullptr;
        _wfopen_s(&f, g_log_path, L"ab");
        if (!f) return;
        va_list ap; va_start(ap, fmt);
        char buf[1024];
        int n = vsnprintf(buf, sizeof(buf), fmt, ap);
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
        WaitForSingleObject(th, 15000);
        DWORD code = 0;
        GetExitCodeThread(th, &code);
        log("  inject[%s] ok, HMODULE=0x%x", tag, code);
        CloseHandle(th);
        return code != 0;
    }

    bool exe_name_is(LPCWSTR appname, LPCWSTR cmdline, const wchar_t* target)
    {
        auto tail_eq = [&](const wchar_t* p) {
            if (!p) return false;
            const wchar_t* slash = wcsrchr(p, L'\\');
            const wchar_t* name = slash ? slash + 1 : p;
            // strip any trailing quote
            wchar_t buf[MAX_PATH]{};
            size_t j = 0;
            for (size_t i = 0; name[i] && j + 1 < MAX_PATH; i++)
            {
                if (name[i] == L'"' || name[i] == L' ') break;
                buf[j++] = name[i];
            }
            buf[j] = 0;
            return _wcsicmp(buf, target) == 0;
        };
        if (appname && tail_eq(appname)) return true;
        if (cmdline && tail_eq(cmdline)) return true;
        return false;
    }

    BOOL WINAPI Hooked_CreateProcessW(
        LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES psa, LPSECURITY_ATTRIBUTES tsa,
        BOOL inherit, DWORD flags, LPVOID env, LPCWSTR dir,
        LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
    {
        bool caller_wanted_suspended = (flags & CREATE_SUSPENDED) != 0;
        DWORD new_flags = flags | CREATE_SUSPENDED;

        log("CreateProcessW hook: app=%ls cmd=%ls flags=0x%lx",
            app ? app : L"(null)", cmd ? cmd : L"(null)", flags);

        BOOL ret = g_real_CreateProcessW(app, cmd, psa, tsa, inherit, new_flags, env, dir, si, pi);
        if (!ret)
        {
            log("  real CreateProcessW failed: 0x%lx", GetLastError());
            return FALSE;
        }
        log("  spawned PID=%lu suspended", pi->dwProcessId);

        // Always re-inject shepherd so the chain continues.
        inject_dll(pi->hProcess, g_self_path, "shepherd");

        // If this is GTA, also inject the YimMenuV2 payload.
        if (exe_name_is(app, cmd, L"GTA5_Enhanced.exe"))
        {
            wchar_t payload[MAX_PATH]{};
            if (read_reg_str(k_RegVal, payload, MAX_PATH))
            {
                log("  this is GTA, injecting payload %ls", payload);
                inject_dll(pi->hProcess, payload, "payload");
            }
            else
            {
                log("  this is GTA, but no PayloadPath in registry");
            }
        }

        if (!caller_wanted_suspended)
            ResumeThread(pi->hThread);

        return TRUE;
    }

    // IAT hook: walk the main module's imports and overwrite the CreateProcessW slot.
    bool install_iat_hook(HMODULE target_module)
    {
        auto base = reinterpret_cast<BYTE*>(target_module);
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
        auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
        DWORD imp_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (!imp_rva) return false;
        auto desc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(base + imp_rva);
        bool hooked = false;
        for (; desc->Name; desc++)
        {
            auto dll_name = reinterpret_cast<const char*>(base + desc->Name);
            if (_stricmp(dll_name, "KERNEL32.dll") != 0 &&
                _stricmp(dll_name, "KERNELBASE.dll") != 0 &&
                _stricmp(dll_name, "api-ms-win-core-processthreads-l1-1-0.dll") != 0 &&
                _stricmp(dll_name, "api-ms-win-core-processthreads-l1-1-1.dll") != 0 &&
                _stricmp(dll_name, "api-ms-win-core-processthreads-l1-1-2.dll") != 0 &&
                _stricmp(dll_name, "api-ms-win-core-processthreads-l1-1-3.dll") != 0)
                continue;

            auto orig_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk);
            auto iat_thunk = reinterpret_cast<IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
            for (; orig_thunk->u1.AddressOfData; orig_thunk++, iat_thunk++)
            {
                if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;
                auto imp = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(base + orig_thunk->u1.AddressOfData);
                if (strcmp(reinterpret_cast<const char*>(imp->Name), "CreateProcessW") != 0) continue;

                DWORD old = 0;
                if (!VirtualProtect(&iat_thunk->u1.Function, sizeof(void*), PAGE_READWRITE, &old))
                    continue;
                if (!g_real_CreateProcessW)
                    g_real_CreateProcessW = reinterpret_cast<PCreateProcessW>(iat_thunk->u1.Function);
                iat_thunk->u1.Function = reinterpret_cast<ULONGLONG>(&Hooked_CreateProcessW);
                VirtualProtect(&iat_thunk->u1.Function, sizeof(void*), old, &old);
                hooked = true;
                log("  IAT hook installed in %ls import of CreateProcessW (dll=%s)",
                    L"(main module)", dll_name);
            }
        }
        return hooked;
    }

    // Walk every loaded module and hook its IAT. Covers the main EXE plus every
    // dependency that might call CreateProcessW independently.
    void install_hooks_everywhere()
    {
        HMODULE mods[512];
        DWORD needed = 0;
        HANDLE proc = GetCurrentProcess();
        if (!EnumProcessModules(proc, mods, sizeof(mods), &needed))
            return;
        DWORD count = needed / sizeof(HMODULE);
        for (DWORD i = 0; i < count && i < 512; i++)
        {
            wchar_t name[MAX_PATH];
            if (GetModuleFileNameExW(proc, mods[i], name, MAX_PATH) == 0) continue;
            install_iat_hook(mods[i]);
        }
    }

    DWORD WINAPI shepherd_init(LPVOID)
    {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&shepherd_init),
            &g_self_module);
        GetModuleFileNameW(g_self_module, g_self_path, MAX_PATH);
        read_reg_str(k_LogRegVal, g_log_path, MAX_PATH);

        log("shepherd loaded, self=%ls", g_self_path);

        g_real_CreateProcessW = reinterpret_cast<PCreateProcessW>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "CreateProcessW"));

        install_hooks_everywhere();
        return 0;
    }
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(inst);
        CreateThread(nullptr, 0, shepherd_init, nullptr, 0, nullptr);
    }
    return TRUE;
}
