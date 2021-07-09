from ctypes import *
from ctypes.wintypes import *

k32_dll = CDLL("kernel32.dll")
GetLastError = k32_dll.GetLastError
GetLastError.restype = DWORD