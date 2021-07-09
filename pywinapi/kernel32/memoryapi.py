# Submodule that Handles MemoryAPI Stuff
from ctypes import *
from ctypes import wintypes

# Generic DataTypes
BOOL    = wintypes.BOOL
DWORD   = wintypes.DWORD
PDWORD  = wintypes.PDWORD
HANDLE  = wintypes.HANDLE
SIZE_T  = c_size_t
PSIZE_T = POINTER(c_size_t)
LPVOID  = c_void_p
LPCVOID = c_void_p

# Bindings
k32_dll = windll.kernel32

# Function Definitions
VirtualAllocEx = k32_dll.VirtualAllocEx
VirtualAllocEx.restype = LPVOID
VirtualAllocEx.argtypes = [HANDLE,LPVOID,SIZE_T,DWORD,DWORD]

WriteProcessMemory = k32_dll.WriteProcessMemory
WriteProcessMemory.restype = BOOL
WriteProcessMemory.argtypes = [HANDLE,LPVOID,LPCVOID,SIZE_T,PSIZE_T]

VirtualProtectEx = k32_dll.VirtualProtectEx
VirtualProtectEx.restype = BOOL
VirtualProtectEx.argtypes = [HANDLE,LPVOID,SIZE_T,DWORD,PDWORD]

# Specific Defines
PAGE_SZ = 0x1000

# -- flAllocationType
MEM_COMMIT     = 0x00001000
MEM_RESERVE    = 0x00002000
MEM_DECOMMIT   = 0x00004000
MEM_RELEASE    = 0x00008000

# -- flProtect
PAGE_NOACCESS          = 0x00000001
PAGE_READONLY          = 0x00000002
PAGE_READWRITE         = 0x00000004
PAGE_WRITECOPY         = 0x00000008
PAGE_EXECUTE           = 0x00000010
PAGE_EXECUTE_READ      = 0x00000020
PAGE_EXECUTE_READWRITE = 0x00000040
PAGE_EXECUTE_WRITECOPY = 0x00000080
PAGE_GUARD             = 0x00000100
PAGE_NOCACHE           = 0x00000200
PAGE_WRITECOMBINE      = 0x00000400


# -- Helpers --

def _allocate_memory(h_process,num_bytes,protect_flags):
    # Figure out the amt padding.
    mod_amt = PAGE_SZ % num_bytes
    pad_amt = PAGE_SZ - mod_amt
    allocation_type = MEM_COMMIT | MEM_RESERVE
    ptr = VirtualAllocEx(h_process,0,num_bytes+pad_amt,allocation_type,protect_flags)
    if(not ptr):
        return False, 0
    return True, ptr

def _set_memory_protect_flags(h_process,addr,num_bytes,protect_flags):
    lpf_old_protect = DWORD(0)
        # Figure out the amt padding.
    mod_amt = PAGE_SZ % num_bytes
    pad_amt = PAGE_SZ - mod_amt

    if(VirtualProtectEx(h_process,addr,num_bytes+pad_amt,protect_flags,byref(lpf_old_protect))):
        return True,lpf_old_protect
    return False,0

# -- API --

# Allocate some RWX Memory on the Heap [Page Aligned]
def allocate_rwx_memory(h_process,amt):
    return _allocate_memory(h_process,amt,PAGE_EXECUTE_READWRITE)

# Allocate some RW Memory on the Heap [Page Aligned]
def allocate_rw_memory(h_process,amt):
    return _allocate_memory(h_process,amt,PAGE_READWRITE)


def write_memory(h_process,addr,data):
    num_bytes = len(data)
    num_written = SIZE_T(0)
    if(WriteProcessMemory(h_process,addr,data,num_bytes,byref(num_written))):
        return True,num_written.value
    return False,0

def set_memory_protect_rw(h_process,addr,num_bytes):
    return _set_memory_protect_flags(h_process,addr,num_bytes,PAGE_READWRITE)

def set_memory_protect_rwx(h_process,addr,num_bytes):
    return _set_memory_protect_flags(h_process,addr,num_bytes,PAGE_EXECUTE_READWRITE)

def set_memory_protect_ro(h_process,addr,num_bytes):
    return _set_memory_protect_flags(h_process,addr,num_bytes,PAGE_READONLY)

def set_memory_protect_x(h_process,addr,num_bytes):
    return _set_memory_protect_flags(h_process,addr,num_bytes,PAGE_EXECUTE)

