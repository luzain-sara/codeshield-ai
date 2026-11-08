"""Restrictive temporary-file permissions, including Windows DACLs."""

import ctypes
import os
from pathlib import Path

from codeshield.errors import ScanError


def _windows():
    from ctypes import wintypes as w
    api = ctypes.WinDLL("advapi32", use_last_error=True)
    api.GetFileSecurityW.argtypes = [w.LPCWSTR, w.DWORD, ctypes.c_void_p, w.DWORD, ctypes.POINTER(w.DWORD)]
    api.GetFileSecurityW.restype = w.BOOL
    api.SetFileSecurityW.argtypes = [w.LPCWSTR, w.DWORD, ctypes.c_void_p]
    api.SetFileSecurityW.restype = w.BOOL
    api.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [w.LPCWSTR, w.DWORD, ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(w.DWORD)]
    api.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = w.BOOL
    return api, w


def read_acl(path: Path) -> bytes | None:
    if os.name != "nt":
        return None
    api, w = _windows()
    size = w.DWORD()
    api.GetFileSecurityW(str(path), 4, None, 0, ctypes.byref(size))
    if not size.value:
        raise ScanError("Cannot inspect file permissions safely.")
    buffer = ctypes.create_string_buffer(size.value)
    if not api.GetFileSecurityW(str(path), 4, buffer, size, ctypes.byref(size)):
        raise ScanError("Cannot inspect file permissions safely.")
    return buffer.raw


def set_permissions(path: Path, mode: int, acl: bytes | None = None, *, private: bool = False):
    os.chmod(path, (0o700 if path.is_dir() else 0o600) if private else mode)
    if os.name != "nt":
        return
    api, w = _windows()
    if private:
        pointer = ctypes.c_void_p()
        # Protected DACL: full access only for the file owner and SYSTEM.
        if not api.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            "D:P(A;;FA;;;OW)(A;;FA;;;SY)", 1, ctypes.byref(pointer), None
        ):
            raise ScanError("Cannot restrict environment-file permissions.")
        try:
            if not api.SetFileSecurityW(str(path), 4 | 0x80000000, pointer):
                raise ScanError("Cannot restrict environment-file permissions.")
        finally:
            kernel = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel.LocalFree.argtypes = [ctypes.c_void_p]
            kernel.LocalFree(pointer)
    elif acl:
        buffer = ctypes.create_string_buffer(acl)
        # SECURITY_DESCRIPTOR_CONTROL is the uint16 at byte offset two.
        protected = bool(int.from_bytes(acl[2:4], "little") & 0x1000)
        flags = 4 | (0x80000000 if protected else 0x20000000)
        if not api.SetFileSecurityW(str(path), flags, buffer):
            raise ScanError("Cannot preserve file permissions.")
