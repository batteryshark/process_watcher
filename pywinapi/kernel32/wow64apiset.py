from ctypes import *
from ctypes import wintypes

# Datatypes
BOOL   = wintypes.BOOL
PBOOL  = POINTER(wintypes.BOOL)
HANDLE = c_void_p

# Bindings
k32_dll = windll.kernel32

# Function Definitions
IsWow64Process = k32_dll.IsWow64Process
IsWow64Process.restype = BOOL
IsWow64Process.argtypes = [HANDLE,PBOOL]

# -- Helpers --
def _iswow64process(h_process):
    bwow64_process = BOOL(False)
    if(not IsWow64Process(h_process,bwow64_process)):
        return False,False
    return True,bwow64_process

# -- API --
def is_32_bit_process(h_process):
    res,is_wow64 = _iswow64process(h_process)
    if(not res):
        return False,False
    return True,is_wow64

def is_64_bit_process(h_process):
    res,is_wow64 = _iswow64process(h_process)
    if(not res):
        return False,False
    return True,not is_wow64

def is_wow64_process(h_process):
    return is_32_bit_process(h_process)

