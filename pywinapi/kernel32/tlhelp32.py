from ctypes import *
from ctypes import wintypes
from .handleapi import close_handle

# Generic DataTypes
HANDLE          = c_void_p
DWORD           = wintypes.DWORD
BOOL            = wintypes.BOOL

# Bindings
k32_dll = windll.kernel32



# Defines 
INVALID_HANDLE_VALUE      = -1
TH32CS_SNAPTHREAD         = 0x00000004

class THREADENTRY32(Structure):
    _fields_ = [
        ('dwSize',              DWORD),
        ('cntUsage',            DWORD),
        ('th32ThreadID',        DWORD),
        ('th32OwnerProcessID',  DWORD),
        ('tpBasePri',           DWORD),
        ('tpDeltaPri',          DWORD),
        ('dwFlags',             DWORD)
    ]
LPTHREADENTRY32 = POINTER(THREADENTRY32)


# Definitions

CreateToolhelp32Snapshot = k32_dll.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.restype = HANDLE
CreateToolhelp32Snapshot.argtypes = [DWORD,DWORD]

Thread32First = k32_dll.Thread32First
Thread32First.restype = BOOL
Thread32First.argtypes = [HANDLE,LPTHREADENTRY32]

Thread32Next  = k32_dll.Thread32Next
Thread32Next.restype = BOOL
Thread32Next.argtypes = [HANDLE,LPTHREADENTRY32]

# -- Helpers --
def _create_toolhelp32_snapshot(flags,process_id = 0):
    h_snapshot = CreateToolhelp32Snapshot(flags,process_id)
    if(h_snapshot == INVALID_HANDLE_VALUE):
        return False,INVALID_HANDLE_VALUE
    return True,h_snapshot

def _thread32_next(h_snapshot,te32):
    if(not Thread32Next(h_snapshot,byref(te32))):
        return False,te32
    return True,te32

def _thread32_first(h_snapshot):
    te32 = THREADENTRY32()
    te32.dwSize = sizeof(THREADENTRY32)
    if(not Thread32First(h_snapshot,byref(te32))):
        return False,None
    return True,te32

# -- API --

def create_toolhelp32_snapshot_threads(pid=0):
    return _create_toolhelp32_snapshot(TH32CS_SNAPTHREAD,pid)

def thread32_first(h_snapshot):
    return _thread32_first(h_snapshot)

def thread32_next(h_snapshot,te32):
    return _thread32_next(h_snapshot,te32)

# Get the Thread ID from our Main Thread of a given PID
def get_main_thread_id(pid):
    res,h_snapshot = create_toolhelp32_snapshot_threads(pid)
    if(not res):
        return False,0
    res,te32 = thread32_first(h_snapshot)
    if(not res):
        return False,0
    if(te32.th32OwnerProcessID == pid):
        close_handle(h_snapshot)
        return True,te32.th32ThreadID
    while(res):
        res,te32 = thread32_next(h_snapshot,te32)
        if(not res):
            close_handle(h_snapshot)
            return False,0
        if(te32.th32OwnerProcessID == pid):
            close_handle(h_snapshot)
            return True,te32.th32ThreadID
    
    close_handle(h_snapshot)
    return False,0


