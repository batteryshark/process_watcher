# Loopback Exemption for AppContainers
from ctypes import *

NETISO_FLAG_FORCE_COMPUTE_BINARIES = 0x01

lib = CDLL("FirewallAPI.dll")

PISID = PSID = POINTER(c_char)
LPCWSTR = LPWSTR = c_wchar_p
INET_FIREWALL_AC_CAPABILITIES = c_void_p
INET_FIREWALL_AC_BINARIES = c_void_p
DWORD = c_uint32

class INET_FIREWALL_APP_CONTAINER(Structure):
    _fields_ = [
    ('appContainerSid',PSID),
    ('userSid',PSID),
    ('appContainerName',LPWSTR),
    ('displayName',LPWSTR),
    ('description',LPWSTR),
    ('capabilities',INET_FIREWALL_AC_CAPABILITIES),
    ('binaries',INET_FIREWALL_AC_BINARIES),
    ('workingDirectory',LPWSTR),
    ('packageFullName',LPWSTR)
    ]
    
    
class SID_AND_ATTRIBUTES(Structure):
        _fields_ = [
        ('Sid',PSID),
        ('Attributes',DWORD)
    ]
    
    
PSID_AND_ATTRIBUTES = POINTER(SID_AND_ATTRIBUTES)
PPSID_AND_ATTRIBUTES = POINTER(PSID_AND_ATTRIBUTES)

SIZEOF_INET_FIREWALL_APP_CONTAINER = 88


def get_app_containers():
    num_app_containers = c_uint32(0)
    ac_pptr = c_void_p(0)
    if(lib.NetworkIsolationEnumAppContainers(NETISO_FLAG_FORCE_COMPUTE_BINARIES,byref(num_app_containers),byref(ac_pptr))):
        return False,0,None
    return True,num_app_containers.value,ac_pptr


def list_app_containers():
    ac_name_lst = []
    res,num_app_containers,ac_pptr = get_app_containers()
    if(res is False):
        print("Get App Containers Failed!")
        return False,[]
        
    for i in range(0,num_app_containers):
        offset = i * SIZEOF_INET_FIREWALL_APP_CONTAINER
        entry_address = ac_pptr.value + offset
        entry = INET_FIREWALL_APP_CONTAINER.from_address(entry_address)
        ac_name_lst.append(entry.appContainerName)
        
    return True,ac_name_lst

def get_appcontainer_sid(appcontainer_name):
    found = False
    appcontainer_sid = None
    res,num_app_containers,ac_pptr = get_app_containers()
    if(res is False):
        print("Get App Containers Failed!")
        return False

    for i in range(0,num_app_containers):
        offset = i * SIZEOF_INET_FIREWALL_APP_CONTAINER
        entry_address = ac_pptr.value + offset
        entry = INET_FIREWALL_APP_CONTAINER.from_address(entry_address)
        if(entry.appContainerName == appcontainer_name):
            print(f"Entry {appcontainer_name} Found")
            found = True
            appcontainer_sid = entry.appContainerSid
            break
            
    #if(lib.NetworkIsolationFreeAppContainers(ac_pptr)):
    #    print("Free App Container Enum Failed!")
    #    return False,None
            
    return found,appcontainer_sid

def enable_network_isolation_exemption(appcontainer_name):
    res,acsid = get_appcontainer_sid(appcontainer_name)
    if(res is False):
        print("AC Not Found!")
        return False
    
    sid_lst = (SID_AND_ATTRIBUTES * 1)()
    sid_lst[0].Sid = acsid
    sid_lst[0].Attributes = 0

    if(lib.NetworkIsolationSetAppContainerConfig(1,byref(sid_lst))):
        print("NetworkIsolationSetAppContainerConfig Fail")
        return False
    print("NetworkIsolationSetAppContainerConfig OK!")
    return True
    

def backup_original_network_isolation_exemption():
    num_app_containers = c_uint32(0)
    ppacsids = c_void_p(0)
    res = lib.NetworkIsolationGetAppContainerConfig(byref(num_app_containers),byref(ppacsids))
    if(res):
        return False,0,None
    return True,num_app_containers.value,ppacsids
    
def restore_original_network_isolation_exemption(netiso_num_entries,netiso_lst):
    if(lib.NetworkIsolationSetAppContainerConfig(netiso_num_entries,netiso_lst)):
        return False
    return True
    
def disable_all_network_isolation_exemption():
    if(lib.NetworkIsolationSetAppContainerConfig(0,None)):
        print("NetworkIsolationSetAppContainerConfig Fail")
        return False
    print("NetworkIsolationSetAppContainerConfig OK!")
    return True

    
if(__name__ == "__main__"):
    
    print("Listing AppContainers...")
    res,ac_name_lst = list_app_containers()
    if(res is False):
        print("AppContainer List Failed!")
    else:
        print("AppContainer List OK!")
    for entry in ac_name_lst:
        print(entry)
        
    res = enable_network_isolation_exemption("microsoft.xboxspeechtotextoverlay_8wekyb3d8bbwe")
    if(res is False):
        print("Enable Network Isolation Exemption Failed!")
    else:
        print("Enable Network Isolation Exemption OK!")

    res = disable_all_network_isolation_exemption()
    if(res is False):
        print("Disable Network Isolation Exemption Failed!")
    else:
        print("Disable Network Isolation Exemption OK!")
