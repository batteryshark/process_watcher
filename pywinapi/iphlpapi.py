# IPHLPAPI Bindings
from ctypes import *
from ctypes.wintypes import *
import binascii
MAX_ADAPTER_NAME = 128

class IP_ADAPTER_INDEX_MAP(Structure):
	_fields_ = [('Index', c_ulong), ('Name', c_wchar * MAX_ADAPTER_NAME)]
PIP_ADAPTER_INDEX_MAP = POINTER(IP_ADAPTER_INDEX_MAP)

class IP_INTERFACE_INFO(Structure):
	_fields_ = [('NumAdapters', c_long), ('Adapter', IP_ADAPTER_INDEX_MAP)]

PIP_INTERFACE_INFO = POINTER(IP_INTERFACE_INFO)
PULONG = POINTER(c_ulong)
dll = CDLL("iphlpapi.dll")
GetInterfaceInfo = dll.GetInterfaceInfo
GetInterfaceInfo.restype = DWORD
GetInterfaceInfo.argtypes = [POINTER(c_ubyte),PULONG]



def _GetInterfaceInfo(piftable,iflen):
    return GetInterfaceInfo(piftable, iflen)
    
    
    
def GetAllInterfaces():
    # Get Buffer Size
    out_buffer_size = c_ulong(0)
    _GetInterfaceInfo(None,byref(out_buffer_size))
    if(out_buffer_size.value == 0):
        print("_GetInterfaceInfo[0] Failed!")
        return False,[]
    
    out_buffer = (c_ubyte * out_buffer_size.value)()
    
    if(_GetInterfaceInfo(out_buffer,byref(out_buffer_size))):
        print("_GetInterfaceInfo[1] Failed!")
        return False,[]
    print(binascii.hexlify(out_buffer))
    print("OK!")
    ifi =  cast(pointer(out_buffer), POINTER(IP_INTERFACE_INFO)).contents

    print("Num Adapters: %d" % ifi.NumAdapters)
    
if(__name__=="__main__"):
    GetAllInterfaces()
    