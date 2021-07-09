from ctypes import *
from ctypes import wintypes

# Generic DataTypes
BOOL    = wintypes.BOOL
HANDLE  = c_void_p

# Bindings
k32_dll = windll.kernel32

CloseHandle = k32_dll.CloseHandle
CloseHandle.restype = BOOL
CloseHandle.argtypes = [HANDLE]


# -- Helpers --
def _close_handle(h_object):
    return CloseHandle(h_object)

# -- API --

def close_handle(h_object):
    return _close_handle(h_object)
