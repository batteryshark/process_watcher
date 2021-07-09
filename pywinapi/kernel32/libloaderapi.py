from ctypes import *
from ctypes import wintypes

# Generic DataTypes
BOOL    = wintypes.BOOL
HANDLE  = c_void_p
HMODULE = c_void_p
LPCSTR  = wintypes.LPCSTR
FARPROC = c_void_p

# Bindings
k32_dll = windll.kernel32

GetProcAddress = k32_dll.GetProcAddress
GetProcAddress.restype = FARPROC
GetProcAddress.argtypes = [HMODULE,LPCSTR]

LoadLibraryA = k32_dll.LoadLibraryA
LoadLibraryA.restype = HMODULE
LoadLibraryA.argtypes = [LPCSTR]

# -- Helpers --
def _get_proc_address(h_module,proc_name):
    cproc_name = create_string_buffer(proc_name.encode('ascii'))
    proc_address = GetProcAddress(h_module,cproc_name)
    if(not proc_address):
        return False,0
    return True,proc_address

def _load_library_a(lib_file_name):
    clib_file_name = create_string_buffer(lib_file_name.encode('ascii'))
    h_module = LoadLibraryA(clib_file_name)
    if(not h_module):
        return False,0
    return True,h_module

# -- API --
def get_proc_address(h_module,proc_name):
    return _get_proc_address(h_module,proc_name)

def get_library_address(library_name,proc_name):
    # Get our Library Handle, Load if it doesn't exist yet.
    res,h_module = _load_library_a(library_name)
    if(not res):
        return False,0
    return get_proc_address(h_module,proc_name)
