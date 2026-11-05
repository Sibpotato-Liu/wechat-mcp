"""Minimal Windows process-memory reader used for key extraction.

The reader is intentionally small and read-only: it opens the WeChat process
with PROCESS_VM_READ, walks readable regions, and never writes to it.
"""

from __future__ import annotations

import ctypes
import sys
from dataclasses import dataclass
from typing import Iterator, Protocol

from .errors import UnsupportedPlatform

if sys.platform == "win32":
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    version = ctypes.WinDLL("version", use_last_error=True)

    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    PAGE_NOACCESS = 0x01
    PAGE_GUARD = 0x100
    READABLE_PROTECTIONS = (
        0x02  # PAGE_READONLY
        | 0x04  # PAGE_READWRITE
        | 0x08  # PAGE_WRITECOPY
        | 0x20  # PAGE_EXECUTE_READ
        | 0x40  # PAGE_EXECUTE_READWRITE
        | 0x80  # PAGE_EXECUTE_WRITECOPY
    )
    TH32CS_SNAPPROCESS = 0x00000002
    TH32CS_SNAPMODULE = 0x00000008
    TH32CS_SNAPMODULE32 = 0x00000010
    INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    class PROCESSENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.c_void_p),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", wintypes.WCHAR * 260),
        ]

    class MODULEENTRY32W(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("th32ModuleID", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("GlblcntUsage", wintypes.DWORD),
            ("ProccntUsage", wintypes.DWORD),
            ("modBaseAddr", ctypes.c_void_p),
            ("modBaseSize", wintypes.DWORD),
            ("hModule", ctypes.c_void_p),
            ("szModule", wintypes.WCHAR * 256),
            ("szExePath", wintypes.WCHAR * 260),
        ]

    class VS_FIXEDFILEINFO(ctypes.Structure):
        _fields_ = [
            ("dwSignature", wintypes.DWORD),
            ("dwStrucVersion", wintypes.DWORD),
            ("dwFileVersionMS", wintypes.DWORD),
            ("dwFileVersionLS", wintypes.DWORD),
            ("dwProductVersionMS", wintypes.DWORD),
            ("dwProductVersionLS", wintypes.DWORD),
            ("dwFileFlagsMask", wintypes.DWORD),
            ("dwFileFlags", wintypes.DWORD),
            ("dwFileOS", wintypes.DWORD),
            ("dwFileType", wintypes.DWORD),
            ("dwFileSubtype", wintypes.DWORD),
            ("dwFileDateMS", wintypes.DWORD),
            ("dwFileDateLS", wintypes.DWORD),
        ]

    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.Module32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32FirstW.restype = wintypes.BOOL
    kernel32.Module32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(MODULEENTRY32W)]
    kernel32.Module32NextW.restype = wintypes.BOOL
    kernel32.IsWow64Process.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.BOOL)]
    kernel32.IsWow64Process.restype = wintypes.BOOL
    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    version.GetFileVersionInfoSizeW.argtypes = [
        wintypes.LPCWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    version.GetFileVersionInfoSizeW.restype = wintypes.DWORD
    version.GetFileVersionInfoW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
    ]
    version.GetFileVersionInfoW.restype = wintypes.BOOL
    version.VerQueryValueW.argtypes = [
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.UINT),
    ]
    version.VerQueryValueW.restype = wintypes.BOOL


@dataclass(frozen=True)
class Region:
    base: int
    size: int
    protect: int
    type: int

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    name: str
    exe_path: str | None = None


@dataclass(frozen=True)
class ModuleInfo:
    name: str
    base: int
    size: int
    path: str | None = None


class MemoryReader(Protocol):
    def regions(self) -> Iterator[Region]: ...
    def read(self, address: int, size: int) -> bytes | None: ...
    def iter_chunks(self, chunk_size: int = 4 * 1024 * 1024, overlap: int = 0) -> Iterator[tuple[int, bytes]]: ...
    def find_all(self, needle: bytes) -> Iterator[int]: ...
    def close(self) -> None: ...


def _require_windows() -> None:
    if sys.platform != "win32":
        raise UnsupportedPlatform("微信密钥提取仅支持 Windows；也可以在工具参数中直接提供 key。")


def list_processes(names: list[str] | None = None) -> list[ProcessInfo]:
    _require_windows()
    wanted = {name.lower() for name in names} if names else None
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snapshot in (None, INVALID_HANDLE_VALUE):
        return []
    result: list[ProcessInfo] = []
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        if not kernel32.Process32FirstW(snapshot, ctypes.byref(entry)):
            return []
        while True:
            name = entry.szExeFile
            if wanted is None or name.lower() in wanted:
                result.append(ProcessInfo(pid=int(entry.th32ProcessID), name=name))
            if not kernel32.Process32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)
    return result


def process_image_path(pid: int) -> str | None:
    """Return the executable path of a process without reading its memory."""
    _require_windows()
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return None
    try:
        size = wintypes.DWORD(32768)
        buffer = ctypes.create_unicode_buffer(size.value)
        if not kernel32.QueryFullProcessImageNameW(
            handle, 0, buffer, ctypes.byref(size)
        ):
            return None
        return buffer.value or None
    finally:
        kernel32.CloseHandle(handle)


def file_version(path: str | None) -> str | None:
    """Read the numeric file version from a Windows PE without extra packages."""
    if not path:
        return None
    _require_windows()
    try:
        size = version.GetFileVersionInfoSizeW(path, None)
        if not size:
            return None
        data = ctypes.create_string_buffer(size)
        if not version.GetFileVersionInfoW(path, 0, size, data):
            return None
        pointer = ctypes.c_void_p()
        length = wintypes.UINT()
        if not version.VerQueryValueW(
            data, "\\", ctypes.byref(pointer), ctypes.byref(length)
        ):
            return None
        if not pointer or length.value < ctypes.sizeof(VS_FIXEDFILEINFO):
            return None
        info = ctypes.cast(pointer, ctypes.POINTER(VS_FIXEDFILEINFO)).contents
        if info.dwSignature != 0xFEEF04BD:
            return None
        high, low = int(info.dwFileVersionMS), int(info.dwFileVersionLS)
        return f"{high >> 16}.{high & 0xFFFF}.{low >> 16}.{low & 0xFFFF}"
    except (AttributeError, OSError):
        return None


def list_modules(pid: int) -> list[ModuleInfo]:
    _require_windows()
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snapshot in (None, INVALID_HANDLE_VALUE):
        return []
    result: list[ModuleInfo] = []
    try:
        entry = MODULEENTRY32W()
        entry.dwSize = ctypes.sizeof(MODULEENTRY32W)
        if not kernel32.Module32FirstW(snapshot, ctypes.byref(entry)):
            return []
        while True:
            result.append(
                ModuleInfo(
                    name=entry.szModule,
                    base=int(entry.modBaseAddr or 0),
                    size=int(entry.modBaseSize),
                    path=entry.szExePath or None,
                )
            )
            if not kernel32.Module32NextW(snapshot, ctypes.byref(entry)):
                break
    finally:
        kernel32.CloseHandle(snapshot)
    return result


def process_pointer_size(pid: int) -> int:
    _require_windows()
    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, pid)
    if not handle:
        return 8
    try:
        wow64 = wintypes.BOOL()
        if kernel32.IsWow64Process(handle, ctypes.byref(wow64)):
            return 4 if wow64.value else 8
    finally:
        kernel32.CloseHandle(handle)
    return 8


class ProcessMemory:
    def __init__(self, pid: int):
        _require_windows()
        self.pid = pid
        self.handle = kernel32.OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid
        )
        if not self.handle:
            raise OSError(
                f"无法打开微信进程 (pid={pid})，错误码 {ctypes.get_last_error()}。"
                "请尝试以管理员身份运行服务。"
            )
        self.pointer_size = process_pointer_size(pid)
        self._modules: list[ModuleInfo] | None = None

    def close(self) -> None:
        if self.handle:
            kernel32.CloseHandle(self.handle)
            self.handle = None  # type: ignore[assignment]

    def __enter__(self) -> "ProcessMemory":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @property
    def modules(self) -> list[ModuleInfo]:
        if self._modules is None:
            self._modules = list_modules(self.pid)
        return self._modules

    def find_module(self, name: str) -> ModuleInfo | None:
        lowered = name.lower()
        for module in self.modules:
            if module.name.lower() == lowered:
                return module
        return None

    def regions(self) -> Iterator[Region]:
        address = 0
        max_address = (1 << (self.pointer_size * 8)) - 1
        while address < max_address:
            info = MEMORY_BASIC_INFORMATION()
            written = kernel32.VirtualQueryEx(
                self.handle, ctypes.c_void_p(address), ctypes.byref(info), ctypes.sizeof(info)
            )
            if not written:
                break
            base = int(info.BaseAddress or 0)
            size = int(info.RegionSize or 0)
            if size <= 0:
                break
            if info.State == MEM_COMMIT:
                yield Region(base=base, size=size, protect=int(info.Protect), type=int(info.Type))
            address = base + size

    def readable_regions(self) -> Iterator[Region]:
        for region in self.regions():
            if region.protect & PAGE_NOACCESS or region.protect & PAGE_GUARD:
                continue
            if region.protect & READABLE_PROTECTIONS:
                yield region

    def read(self, address: int, size: int) -> bytes | None:
        if address <= 0 or size <= 0:
            return None
        buffer = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        ok = kernel32.ReadProcessMemory(
            self.handle,
            ctypes.c_void_p(address),
            buffer,
            size,
            ctypes.byref(read),
        )
        if not ok and read.value == 0:
            return None
        return buffer.raw[: read.value]

    def iter_chunks(
        self,
        chunk_size: int = 4 * 1024 * 1024,
        overlap: int = 0,
        start: int | None = None,
        end: int | None = None,
    ) -> Iterator[tuple[int, bytes]]:
        low = 0 if start is None else start
        high = (1 << (self.pointer_size * 8)) - 1 if end is None else end
        for region in self.readable_regions():
            address = max(region.base, low)
            region_end = min(region.end, high)
            while address < region_end:
                size = min(chunk_size, region_end - address)
                data = self.read(address, size)
                if data:
                    yield address, data
                if size <= overlap:
                    break
                address += size - overlap

    def find_all(
        self, needle: bytes, start: int | None = None, end: int | None = None
    ) -> Iterator[int]:
        if not needle:
            return
        overlap = max(0, len(needle) - 1)
        last = -1
        for base, data in self.iter_chunks(overlap=overlap, start=start, end=end):
            index = 0
            while True:
                index = data.find(needle, index)
                if index < 0:
                    break
                address = base + index
                if address > last:
                    yield address
                    last = address
                index += 1
