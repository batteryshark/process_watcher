# PSAPI Binding Module

from ctypes import *
from ctypes import wintypes

# Library Load
psapi_dll = WinDLL('Psapi.dll')

# Datatype Defines
BOOL    = wintypes.BOOL
DWORD   = wintypes.DWORD
LPDWORD = POINTER(wintypes.DWORD) 
PDWORD  = wintypes.PDWORD
HANDLE  = c_void_p
HMODULE = c_void_p
LPWSTR  = POINTER(c_wchar)

# Constant Defines
MAX_PATH = 1024
MAX_PROCESS = 4096 # -- Not really?
# Function Definitions
EnumProcesses = psapi_dll.EnumProcesses
EnumProcesses.restype = BOOL
EnumProcesses.argtypes = [PDWORD,DWORD,LPDWORD]

GetModuleFileNameExW = psapi_dll.GetModuleFileNameExW
GetModuleFileNameExW.restype = DWORD
GetModuleFileNameExW.argtypes = [HANDLE,HMODULE,LPWSTR,DWORD]

GetModuleBaseNameW = psapi_dll.GetModuleBaseNameW
GetModuleBaseNameW.restype = DWORD
GetModuleBaseNameW.argtypes = [HANDLE,HMODULE,LPWSTR,DWORD]

# -- Helpers --
def _enum_processes(id_processes):
    cb_needed = DWORD(0)
    cb = sizeof(id_processes)
    if(not EnumProcesses(cast(id_processes, PDWORD),cb,byref(cb_needed))):
        return False,[]
    num_entries = int(cb_needed.value / sizeof(DWORD))
    return True,id_processes[:num_entries]

def _get_module_filename_ex_w(h_process,h_module,lpw_filename,n_size):
    buf_sz = GetModuleFileNameExW(h_process,h_module,lpw_filename,n_size)
    if(not buf_sz):
        return False,0
    return True,lpw_filename[:buf_sz]

def _get_module_base_name_w(h_process,h_module,lpw_filename,n_size):
    buf_sz = GetModuleBaseNameW(h_process,h_module,lpw_filename,n_size)
    if(not buf_sz):
        return False,0
    return True,lpw_filename[:buf_sz]

# -- API --

def enum_processes():
    dword_array = (DWORD * MAX_PROCESS)
    return _enum_processes(dword_array())

def get_module_filename_ex_w(h_process,h_module=None):
    name = create_unicode_buffer(MAX_PATH)
    return _get_module_filename_ex_w(h_process,h_module,name,MAX_PATH)
    
def get_module_base_name_w(h_process,h_module=None):
    name = create_unicode_buffer(MAX_PATH)
    return _get_module_base_name_w(h_process,h_module,name,MAX_PATH)    