"""
External process memory dumper for BEClient_x64.dll.

Reads the live decrypted bytes of BEClient_x64.dll from the GTA5_Enhanced.exe
process and writes them to a new PE on disk. Must run while the game is at the
main menu or lobby (BE must have unpacked itself).
"""
import ctypes
import ctypes.wintypes as wt
import struct
import sys
import argparse
from pathlib import Path

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_VM_READ = 0x0010
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
INVALID_HANDLE_VALUE = wt.HANDLE(-1).value

kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)

kernel32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]
kernel32.OpenProcess.restype = wt.HANDLE
kernel32.ReadProcessMemory.argtypes = [
    wt.HANDLE, wt.LPCVOID, wt.LPVOID, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)
]
kernel32.ReadProcessMemory.restype = wt.BOOL
kernel32.CloseHandle.argtypes = [wt.HANDLE]
kernel32.CloseHandle.restype = wt.BOOL

kernel32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wt.HANDLE

MAX_MODULE_NAME32 = 255
MAX_PATH = 260

class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD),
                ("th32ModuleID", wt.DWORD),
                ("th32ProcessID", wt.DWORD),
                ("GlblcntUsage", wt.DWORD),
                ("ProccntUsage", wt.DWORD),
                ("modBaseAddr", ctypes.POINTER(ctypes.c_ubyte)),
                ("modBaseSize", wt.DWORD),
                ("hModule", wt.HMODULE),
                ("szModule", wt.WCHAR * (MAX_MODULE_NAME32 + 1)),
                ("szExePath", wt.WCHAR * MAX_PATH)]

kernel32.Module32FirstW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32FirstW.restype = wt.BOOL
kernel32.Module32NextW.argtypes = [wt.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
kernel32.Module32NextW.restype = wt.BOOL


def find_module(pid, target_name):
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == INVALID_HANDLE_VALUE or snap == 0:
        raise RuntimeError(f"CreateToolhelp32Snapshot failed: {ctypes.get_last_error()}")
    try:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(MODULEENTRY32W)
        if not kernel32.Module32FirstW(snap, ctypes.byref(me)):
            raise RuntimeError(f"Module32FirstW failed: {ctypes.get_last_error()}")
        while True:
            if me.szModule.lower() == target_name.lower():
                base = ctypes.cast(me.modBaseAddr, wt.LPVOID).value
                return base, me.modBaseSize
            if not kernel32.Module32NextW(snap, ctypes.byref(me)):
                break
    finally:
        kernel32.CloseHandle(snap)
    return None, None


def read_mem(h_proc, addr, size):
    buf = (ctypes.c_ubyte * size)()
    read = ctypes.c_size_t(0)
    if not kernel32.ReadProcessMemory(h_proc, addr, buf, size, ctypes.byref(read)):
        raise RuntimeError(f"ReadProcessMemory @ 0x{addr:x} failed: {ctypes.get_last_error()}")
    return bytes(buf[:read.value])


def dump(pid, out_path):
    base, size = find_module(pid, "BEClient_x64.dll")
    if not base:
        raise RuntimeError("BEClient_x64.dll not found in the process module list (run as admin if the game is elevated)")

    h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h:
        raise RuntimeError(f"OpenProcess({pid}) failed: {ctypes.get_last_error()}. Run as admin?")

    try:

        print(f"[+] BEClient_x64.dll @ 0x{base:x}, SizeOfImage = 0x{size:x} ({size/1024/1024:.1f} MB)")

        # Read the whole image at once
        print(f"[+] Reading {size} bytes from process memory...")
        image = read_mem(h, base, size)
        print(f"[+] Read {len(image)} bytes")

        # Parse DOS header -> NT headers so we can fix section pointers
        e_lfanew = struct.unpack_from("<I", image, 0x3C)[0]
        nt_sig = image[e_lfanew:e_lfanew+4]
        if nt_sig != b"PE\x00\x00":
            raise RuntimeError(f"Bad PE signature at e_lfanew={e_lfanew:#x}: {nt_sig!r}")

        file_header_off = e_lfanew + 4
        num_sections = struct.unpack_from("<H", image, file_header_off + 2)[0]
        size_opt = struct.unpack_from("<H", image, file_header_off + 16)[0]
        opt_header_off = file_header_off + 20
        section_table_off = opt_header_off + size_opt

        image = bytearray(image)

        # For each section, overwrite PointerToRawData and SizeOfRawData so the
        # dump maps the in-memory layout directly (VirtualAddress == PointerToRawData).
        for i in range(num_sections):
            s_off = section_table_off + i * 40
            name = bytes(image[s_off:s_off+8]).rstrip(b"\x00").decode("ascii", "replace")
            vsize = struct.unpack_from("<I", image, s_off + 8)[0]
            vaddr = struct.unpack_from("<I", image, s_off + 12)[0]
            struct.pack_into("<I", image, s_off + 16, vsize)   # SizeOfRawData = VirtualSize
            struct.pack_into("<I", image, s_off + 20, vaddr)   # PointerToRawData = VirtualAddress
            print(f"    section {name:<8} vaddr=0x{vaddr:08x} vsize=0x{vsize:08x}")

        Path(out_path).write_bytes(image)
        print(f"[+] Wrote {len(image)} bytes to {out_path}")
    finally:
        kernel32.CloseHandle(h)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--pid", type=int, required=True, help="GTA5_Enhanced.exe PID")
    ap.add_argument("--out", type=str, default="BEClient_x64_dumped.dll", help="Output path")
    args = ap.parse_args()
    dump(args.pid, args.out)
