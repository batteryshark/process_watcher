# ntdll Binding Module

from ctypes import *
from ctypes import wintypes

# Library Load
dll = WinDLL('ntdll.dll')



# Structured Defines
NTSTATUS = c_int32
PPEB = c_void_p
ULONG_PTR = POINTER(c_ulong)
KPRIORITY = c_long
HANDLE = c_void_p
PVOID = c_void_p

# Enumerations
ProcessBasicInformation = 0

class PROCESS_BASIC_INFORMATION(Structure):
    _fields_ = [
        ('ExitStatus',  NTSTATUS),
        ('PebBaseAddress', PPEB),
        ('AffinityMask', ULONG_PTR),
        ('BasePriority', KPRIORITY),
        ('UniqueProcessId', HANDLE),
        ('InheritedFromUniqueProcessId', HANDLE)
    ]



NtQueryInformationProcess = dll.NtQueryInformationProcess
NtQueryInformationProcess.argtypes = [HANDLE,c_int32,PVOID,c_ulong,ULONG_PTR]
NtQueryInformationProcess.restype = NTSTATUS

# -- Helpers --
def _NtQueryInformationProcess(h_process,pi_class,pi,pi_length):
    rt_length = c_ulong(0)
    status = NtQueryInformationProcess(h_process,pi_class,pi,pi_length,byref(rt_length))
    if(status != 0):
        return False,0
    return True,rt_length.value


# -- API --

def GetProcessBasicInfo(h_process):
    pbi = PROCESS_BASIC_INFORMATION()
    status,rtv = _NtQueryInformationProcess(h_process,ProcessBasicInformation,byref(pbi),sizeof(pbi))
    if(status is True):
        return True,pbi
    return False,None

if(__name__=="__main__"):
    from kernel32.processthreadsapi import open_process_queryinfo
    status,h_process = open_process_queryinfo(13960)
    if(status is False):
        print("Open Process Failed!")
    status,pbi = GetProcessBasicInfo(h_process)
    if(status is False):
        print("GetPBI Failed!")
        exit(-1)
    print("Parent Process ID: %d" % pbi.InheritedFromUniqueProcessId)