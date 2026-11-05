// VERSION.dll proxy that loads YimMenuV2.dll early at process startup.
//
// Mechanism: Windows's loader searches the application directory before
// System32 when resolving dependent DLLs. By dropping this file (built as
// VERSION.dll) next to GTA5_Enhanced.exe, the game loads our proxy instead of
// the real one. We forward every version.dll export to the real system DLL at
// runtime and, as a side effect of DllMain, LoadLibrary the menu payload.
//
// BattlEye's kernel driver loads after the initial user-mode DLL resolution,
// so the payload is already resident in the process by the time BE could
// block an injection from outside.

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Rename every exported symbol via linker so we don't collide with winver.h
// prototypes while still presenting the real version.dll ABI to the loader.
#pragma comment(linker, "/EXPORT:GetFileVersionInfoA=proxy_GetFileVersionInfoA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoW=proxy_GetFileVersionInfoW")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExA=proxy_GetFileVersionInfoExA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoExW=proxy_GetFileVersionInfoExW")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeA=proxy_GetFileVersionInfoSizeA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeW=proxy_GetFileVersionInfoSizeW")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExA=proxy_GetFileVersionInfoSizeExA")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoSizeExW=proxy_GetFileVersionInfoSizeExW")
#pragma comment(linker, "/EXPORT:GetFileVersionInfoByHandle=proxy_GetFileVersionInfoByHandle")
#pragma comment(linker, "/EXPORT:VerFindFileA=proxy_VerFindFileA")
#pragma comment(linker, "/EXPORT:VerFindFileW=proxy_VerFindFileW")
#pragma comment(linker, "/EXPORT:VerInstallFileA=proxy_VerInstallFileA")
#pragma comment(linker, "/EXPORT:VerInstallFileW=proxy_VerInstallFileW")
#pragma comment(linker, "/EXPORT:VerLanguageNameA=proxy_VerLanguageNameA")
#pragma comment(linker, "/EXPORT:VerLanguageNameW=proxy_VerLanguageNameW")
#pragma comment(linker, "/EXPORT:VerQueryValueA=proxy_VerQueryValueA")
#pragma comment(linker, "/EXPORT:VerQueryValueW=proxy_VerQueryValueW")

namespace
{
    HMODULE g_real = nullptr;

    FARPROC resolve(const char* name)
    {
        return GetProcAddress(g_real, name);
    }

    DWORD WINAPI load_payload(LPVOID)
    {
        wchar_t override_path[MAX_PATH]{};
        DWORD n = GetEnvironmentVariableW(L"YIMMENUV2_PATH", override_path, MAX_PATH);
        if (n > 0 && n < MAX_PATH)
        {
            LoadLibraryW(override_path);
            return 0;
        }

        wchar_t module_path[MAX_PATH]{};
        HMODULE self{};
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            reinterpret_cast<LPCWSTR>(&load_payload),
            &self);
        if (GetModuleFileNameW(self, module_path, MAX_PATH) == 0)
            return 0;

        wchar_t* last_slash = wcsrchr(module_path, L'\\');
        if (!last_slash)
            return 0;
        wcscpy_s(last_slash + 1, MAX_PATH - (last_slash + 1 - module_path), L"YimMenuV2.dll");
        LoadLibraryW(module_path);
        return 0;
    }
}

BOOL WINAPI DllMain(HINSTANCE inst, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(inst);

        wchar_t system_path[MAX_PATH]{};
        UINT len = GetSystemDirectoryW(system_path, MAX_PATH);
        if (len == 0 || len >= MAX_PATH - 16)
            return FALSE;
        wcscat_s(system_path, MAX_PATH, L"\\version.dll");
        g_real = LoadLibraryW(system_path);
        if (!g_real)
            return FALSE;

        CreateThread(nullptr, 0, load_payload, nullptr, 0, nullptr);
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        if (g_real)
            FreeLibrary(g_real);
    }
    return TRUE;
}

extern "C" {

using Fn4_BOOL_cstr  = BOOL (WINAPI*)(LPCSTR, DWORD, DWORD, LPVOID);
using Fn4_BOOL_wstr  = BOOL (WINAPI*)(LPCWSTR, DWORD, DWORD, LPVOID);
using Fn5_BOOL_cstr  = BOOL (WINAPI*)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
using Fn5_BOOL_wstr  = BOOL (WINAPI*)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
using Fn2_DWORD_cstr = DWORD(WINAPI*)(LPCSTR, LPDWORD);
using Fn2_DWORD_wstr = DWORD(WINAPI*)(LPCWSTR, LPDWORD);
using Fn3_DWORD_cstr = DWORD(WINAPI*)(DWORD, LPCSTR, LPDWORD);
using Fn3_DWORD_wstr = DWORD(WINAPI*)(DWORD, LPCWSTR, LPDWORD);
using FnLangA        = DWORD(WINAPI*)(DWORD, LPSTR, DWORD);
using FnLangW        = DWORD(WINAPI*)(DWORD, LPWSTR, DWORD);
using FnQueryA       = BOOL (WINAPI*)(LPCVOID, LPCSTR, LPVOID*, PUINT);
using FnQueryW       = BOOL (WINAPI*)(LPCVOID, LPCWSTR, LPVOID*, PUINT);
using FnFindA        = DWORD(WINAPI*)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
using FnFindW        = DWORD(WINAPI*)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
using FnInstallA     = DWORD(WINAPI*)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
using FnInstallW     = DWORD(WINAPI*)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
using FnByHandle     = DWORD(WINAPI*)(DWORD, DWORD, DWORD, LPVOID);

BOOL WINAPI proxy_GetFileVersionInfoA(LPCSTR f, DWORD h, DWORD l, LPVOID d)
{ static auto p = reinterpret_cast<Fn4_BOOL_cstr>(resolve("GetFileVersionInfoA")); return p(f, h, l, d); }

BOOL WINAPI proxy_GetFileVersionInfoW(LPCWSTR f, DWORD h, DWORD l, LPVOID d)
{ static auto p = reinterpret_cast<Fn4_BOOL_wstr>(resolve("GetFileVersionInfoW")); return p(f, h, l, d); }

BOOL WINAPI proxy_GetFileVersionInfoExA(DWORD fl, LPCSTR f, DWORD h, DWORD l, LPVOID d)
{ static auto p = reinterpret_cast<Fn5_BOOL_cstr>(resolve("GetFileVersionInfoExA")); return p(fl, f, h, l, d); }

BOOL WINAPI proxy_GetFileVersionInfoExW(DWORD fl, LPCWSTR f, DWORD h, DWORD l, LPVOID d)
{ static auto p = reinterpret_cast<Fn5_BOOL_wstr>(resolve("GetFileVersionInfoExW")); return p(fl, f, h, l, d); }

DWORD WINAPI proxy_GetFileVersionInfoSizeA(LPCSTR f, LPDWORD h)
{ static auto p = reinterpret_cast<Fn2_DWORD_cstr>(resolve("GetFileVersionInfoSizeA")); return p(f, h); }

DWORD WINAPI proxy_GetFileVersionInfoSizeW(LPCWSTR f, LPDWORD h)
{ static auto p = reinterpret_cast<Fn2_DWORD_wstr>(resolve("GetFileVersionInfoSizeW")); return p(f, h); }

DWORD WINAPI proxy_GetFileVersionInfoSizeExA(DWORD fl, LPCSTR f, LPDWORD h)
{ static auto p = reinterpret_cast<Fn3_DWORD_cstr>(resolve("GetFileVersionInfoSizeExA")); return p(fl, f, h); }

DWORD WINAPI proxy_GetFileVersionInfoSizeExW(DWORD fl, LPCWSTR f, LPDWORD h)
{ static auto p = reinterpret_cast<Fn3_DWORD_wstr>(resolve("GetFileVersionInfoSizeExW")); return p(fl, f, h); }

DWORD WINAPI proxy_VerFindFileA(DWORD fl, LPCSTR fn, LPCSTR wd, LPCSTR ad, LPSTR cfd, PUINT cfdl, LPSTR dd, PUINT ddl)
{ static auto p = reinterpret_cast<FnFindA>(resolve("VerFindFileA")); return p(fl, fn, wd, ad, cfd, cfdl, dd, ddl); }

DWORD WINAPI proxy_VerFindFileW(DWORD fl, LPCWSTR fn, LPCWSTR wd, LPCWSTR ad, LPWSTR cfd, PUINT cfdl, LPWSTR dd, PUINT ddl)
{ static auto p = reinterpret_cast<FnFindW>(resolve("VerFindFileW")); return p(fl, fn, wd, ad, cfd, cfdl, dd, ddl); }

DWORD WINAPI proxy_VerInstallFileA(DWORD fl, LPCSTR sfn, LPCSTR dfn, LPCSTR sd, LPCSTR dd, LPCSTR cd, LPSTR tfn, PUINT tfnl)
{ static auto p = reinterpret_cast<FnInstallA>(resolve("VerInstallFileA")); return p(fl, sfn, dfn, sd, dd, cd, tfn, tfnl); }

DWORD WINAPI proxy_VerInstallFileW(DWORD fl, LPCWSTR sfn, LPCWSTR dfn, LPCWSTR sd, LPCWSTR dd, LPCWSTR cd, LPWSTR tfn, PUINT tfnl)
{ static auto p = reinterpret_cast<FnInstallW>(resolve("VerInstallFileW")); return p(fl, sfn, dfn, sd, dd, cd, tfn, tfnl); }

DWORD WINAPI proxy_VerLanguageNameA(DWORD lang, LPSTR b, DWORD n)
{ static auto p = reinterpret_cast<FnLangA>(resolve("VerLanguageNameA")); return p(lang, b, n); }

DWORD WINAPI proxy_VerLanguageNameW(DWORD lang, LPWSTR b, DWORD n)
{ static auto p = reinterpret_cast<FnLangW>(resolve("VerLanguageNameW")); return p(lang, b, n); }

BOOL WINAPI proxy_VerQueryValueA(LPCVOID b, LPCSTR q, LPVOID* buf, PUINT len)
{ static auto p = reinterpret_cast<FnQueryA>(resolve("VerQueryValueA")); return p(b, q, buf, len); }

BOOL WINAPI proxy_VerQueryValueW(LPCVOID b, LPCWSTR q, LPVOID* buf, PUINT len)
{ static auto p = reinterpret_cast<FnQueryW>(resolve("VerQueryValueW")); return p(b, q, buf, len); }

DWORD WINAPI proxy_GetFileVersionInfoByHandle(DWORD handle, DWORD a, DWORD b, LPVOID data)
{ static auto p = reinterpret_cast<FnByHandle>(resolve("GetFileVersionInfoByHandle")); return p ? p(handle, a, b, data) : 0; }

} // extern "C"
