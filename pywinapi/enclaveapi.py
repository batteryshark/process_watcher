# Enclave API and WinEnclaveAPI Bindings
from ctypes import *
from ctypes.wintypes import *

vert_dll = CDLL("Vertdll.dll")
kbase_dll = CDLL("kernelbase.dll")

# -- WIN Defines
ULONGLONG = c_ulonglong
UINT32 = c_uint32
PVOID = c_void_p
SIZE_T = c_size_t
PSIZE_T = POINTER(SIZE_T)

# -- Defines
ENCLAVE_REPORT_DATA_LENGTH    = 64
IMAGE_ENCLAVE_LONG_ID_LENGTH  = 32
IMAGE_ENCLAVE_SHORT_ID_LENGTH = 16

ENCLAVE_TYPE_SGX       = 0x00000001
ENCLAVE_TYPE_VBS       = 0x00000010
ENCLAVE_TYPE_VBS_BASIC = 0x00000011

VBS_ENCLAVE_VARDATA_INVALID = 0x00000000
VBS_ENCLAVE_VARDATA_MODULE  = 0x00000001

ENCLAVE_VBS_FLAG_DEBUG = 0x00000001

IMAGE_ENCLAVE_POLICY_DEBUGGABLE = 0x00000001


# ENCLAVE_SEALING_IDENTITY_POLICY Enum
# -- Invalid. Do Not Use
ENCLAVE_IDENTITY_POLICY_SEAL_INVALID = 0
# -- All bytes must match to decrypt.
ENCLAVE_IDENTITY_POLICY_SEAL_EXACT_CODE = 1
# -- All bytes in the primary modules must match to decrypt.
ENCLAVE_IDENTITY_POLICY_SEAL_SAME_PRIMARY_CODE = 2
# -- The author id, family id, and image id must match.
ENCLAVE_IDENTITY_POLICY_SEAL_SAME_IMAGE = 3
# -- The author and family id must match.
ENCLAVE_IDENTITY_POLICY_SEAL_SAME_FAMILY = 4
# -- The author id of the primary image must match.
ENCLAVE_IDENTITY_POLICY_SEAL_SAME_AUTHOR = 5

# Match Types
IMAGE_ENCLAVE_IMPORT_MATCH_NONE      = 0
IMAGE_ENCLAVE_IMPORT_MATCH_UNIQUE_ID = 1
IMAGE_ENCLAVE_IMPORT_MATCH_AUTHOR_ID = 2
IMAGE_ENCLAVE_IMPORT_MATCH_FAMILY_ID = 3 
IMAGE_ENCLAVE_IMPORT_MATCH_IMAGE_ID  = 4

LPENCLAVE_ROUTINE = c_void_p

ERROR_ENCLAVE_NOT_TERMINATED = 814

# -- Structures

class IMAGE_ENCLAVE_CONFIG32(Structure):
    _fields_ = [
    ('Size',DWORD),
    ('MinimumRequiredConfigSize',DWORD),
    ('PolicyFlags',DWORD),
    ('NumberOfImports',DWORD),
    ('ImportList',DWORD),
    ('ImportEntrySize',DWORD),
    ('FamilyID',BYTE*IMAGE_ENCLAVE_SHORT_ID_LENGTH),
    ('ImageID',BYTE*IMAGE_ENCLAVE_SHORT_ID_LENGTH),
    ('ImageVersion',DWORD),
    ('SecurityVersion',DWORD),
    ('EnclaveSize',DWORD),
    ('NumberOfThreads',DWORD),
    ('EnclaveFlags',DWORD),
    ]
    
class IMAGE_ENCLAVE_CONFIG64(Structure):
    _fields_ = [
    ('Size',ULONG),
    ('MinimumRequiredConfigSize',ULONG),
    ('PolicyFlags',ULONG),
    ('NumberOfImports',ULONG),
    ('ImportList',ULONG),
    ('ImportEntrySize',ULONG),
    ('FamilyID',BYTE*IMAGE_ENCLAVE_SHORT_ID_LENGTH),
    ('ImageID',BYTE*IMAGE_ENCLAVE_SHORT_ID_LENGTH),
    ('ImageVersion',ULONG),
    ('SecurityVersion',ULONG),
    ('EnclaveSize',ULONGLONG),
    ('NumberOfThreads',ULONG),
    ('EnclaveFlags',ULONG),    
    ]

class ENCLAVE_CREATE_INFO_SGX(Structure):
    _fields_ = [
    ('Secs',BYTE * 4096)
    ]
    
class ENCLAVE_INIT_INFO_SGX(Structure):
    _fields_ = [
    ('BigStruct',  BYTE*1808),
    ('Reserved1',  BYTE*240),
    ('EInitToken', BYTE*304),
    ('Reserved2',  BYTE*1744)
    ]
    
class ENCLAVE_CREATE_INFO_VBS(Structure):
    _fields_ = [
    ('Flags',DWORD),
    ('OwnerID',BYTE * 32)
    ]

class ENCLAVE_INIT_INFO_VBS(Structure):
    _fields_ = [
    ('Length',DWORD),
    ('ThreadCount',DWORD)
    ]

class VBS_ENCLAVE_REPORT_VARDATA_HEADER (Structure):
    _fields_ = [
    ('DataType',UINT32),
    ('Size',UINT32)
    ]
    
class VBS_ENCLAVE_REPORT_PKG_HEADER (Structure):
    _fields_ = [
    ('PackageSize',UINT32),
    ('Version', UINT32),
    ('SignatureScheme', UINT32),
    ('SignedStatementSize', UINT32),
    ('SignatureSize', UINT32),
    ('Reserved', UINT32)
    ]
    
class IMAGE_ENCLAVE_IMPORT(Structure):
    _fields_ = [
    ('MatchType',DWORD),
    ('MinimumSecurityVersion',DWORD),
    ('UniqueOrAuthorID',BYTE*IMAGE_ENCLAVE_LONG_ID_LENGTH),
    ('FamilyID',BYTE*IMAGE_ENCLAVE_SHORT_ID_LENGTH),
    ('ImageID',BYTE*IMAGE_ENCLAVE_SHORT_ID_LENGTH),
    ('ImportName',DWORD),
    ('Reserved',DWORD)
    ]
    
class ENCLAVE_IDENTITY (Structure):
    _fields_= [
    ('OwnerId',BYTE*IMAGE_ENCLAVE_LONG_ID_LENGTH),
    ('UniqueId',BYTE*IMAGE_ENCLAVE_LONG_ID_LENGTH),
    ('AuthorId',BYTE*IMAGE_ENCLAVE_LONG_ID_LENGTH),
    ('FamilyId',BYTE*IMAGE_ENCLAVE_SHORT_ID_LENGTH),
    ('ImageId',BYTE*IMAGE_ENCLAVE_SHORT_ID_LENGTH),
    ('EnclaveSvn',UINT32),
    ('SecureKernelSvn',UINT32),
    ('PlatformSvn',UINT32),
    ('Flags',UINT32),
    ('SigningLevel',UINT32),
    ('EnclaveType',UINT32)
    ]

class VBS_ENCLAVE_REPORT(Structure):
    _fields_ = [
    ('ReportSize',UINT32),
    ('ReportVersion',UINT32),
    ('EnclaveData',BYTE * ENCLAVE_REPORT_DATA_LENGTH),
    ('EnclaveIdentity',ENCLAVE_IDENTITY)
    ]

class ENCLAVE_INFORMATION (Structure):
    _fields_ = [
    ('EnclaveType',ULONG), # Type of Enclave (SGX/VBS)
    ('Reserved',ULONG),    # Reserved
    ('BaseAddress',PVOID), # Pointer to Base Address of Enclave
    ('Size',SIZE_T),       # Size of Enclave in Bytes
    ('Identity',ENCLAVE_IDENTITY) # Identity of Primary Enclave Module.
    ]
    
class VBS_ENCLAVE_REPORT_MODULE (Structure):
    _fields_ = [
    ('Header',VBS_ENCLAVE_REPORT_VARDATA_HEADER),
    ('UniqueId',BYTE*IMAGE_ENCLAVE_LONG_ID_LENGTH),
    ('AuthorId',BYTE*IMAGE_ENCLAVE_LONG_ID_LENGTH),
    ('FamilyId',BYTE*IMAGE_ENCLAVE_SHORT_ID_LENGTH),
    ('ImageId',BYTE*IMAGE_ENCLAVE_SHORT_ID_LENGTH),
    ('Svn', UINT32),
    ('ModuleName',POINTER(c_wchar))
    ]



# -- Function Prototypes

# -- [ enclaveapi.h via kernelbase] --
CallEnclave = kbase_dll.CallEnclave
CallEnclave.restype = BOOL
CallEnclave.argtypes = [LPENCLAVE_ROUTINE,LPVOID,BOOL,POINTER(LPVOID)]

CreateEnclave = kbase_dll.CreateEnclave
CreateEnclave.restype = LPVOID
CreateEnclave.argtypes = [HANDLE,LPVOID,SIZE_T,SIZE_T,DWORD,LPCVOID,DWORD,LPDWORD]

# Version 1703 and Later Uses a Different Approach
# Instead, you wipe an enclave like every other heap allocated area.
# https://docs.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-createenclave
try:
    DeleteEnclave = kbase_dll.DeleteEnclave
    DeleteEnclave.restype = BOOL
    DeleteEnclave.argtypes = [LPVOID]
except AttributeError:    
    def DeleteEnclave(lp_address):
        return kbase_dll.VirtualFree(lp_address,0,0x00008000)

InitializeEnclave = kbase_dll.InitializeEnclave
InitializeEnclave.restype = BOOL
InitializeEnclave.argtypes = [HANDLE,LPVOID,LPCVOID,DWORD,LPDWORD]

IsEnclaveTypeSupported = kbase_dll.IsEnclaveTypeSupported
IsEnclaveTypeSupported.restype = BOOL
IsEnclaveTypeSupported.argtypes = [DWORD]

LoadEnclaveData = kbase_dll.LoadEnclaveData
LoadEnclaveData.restype = BOOL
LoadEnclaveData.argtypes = [HANDLE,LPVOID,LPCVOID,SIZE_T,DWORD,LPCVOID,DWORD,PSIZE_T,LPDWORD]


LoadEnclaveImageW = kbase_dll.LoadEnclaveImageW
LoadEnclaveImageW.restype = BOOL
LoadEnclaveImageW.argtypes = [LPVOID,LPCWSTR]

LoadEnclaveImageA = kbase_dll.LoadEnclaveImageA
LoadEnclaveImageA.restype = BOOL
LoadEnclaveImageA.argtypes = [LPVOID,LPCSTR]


TerminateEnclave = kbase_dll.TerminateEnclave
TerminateEnclave.restype = BOOL
TerminateEnclave.argtypes = [LPVOID,BOOL]

# -- [ winenclaveapi.h via virtlib] --
EnclaveGetAttestationReport = vert_dll.EnclaveGetAttestationReport
EnclaveGetAttestationReport.restype = HRESULT
EnclaveGetAttestationReport.argtypes = [POINTER(BYTE),PVOID,UINT32,UINT32]

EnclaveGetEnclaveInformation = vert_dll.EnclaveGetEnclaveInformation
EnclaveGetEnclaveInformation.restype = HRESULT
EnclaveGetEnclaveInformation.argtypes = [UINT32,POINTER(ENCLAVE_INFORMATION)]

EnclaveSealData = vert_dll.EnclaveSealData
EnclaveSealData.restype = HRESULT
EnclaveSealData.argtypes = [c_void_p,UINT32,c_int,UINT32,PVOID,UINT32,POINTER(UINT32)]

EnclaveUnsealData = vert_dll.EnclaveUnsealData
EnclaveUnsealData.restype = HRESULT
EnclaveUnsealData.argtypes = [c_void_p,UINT32,PVOID,UINT32,POINTER(UINT32),POINTER(ENCLAVE_IDENTITY),POINTER(UINT32)]


EnclaveVerifyAttestationReport = vert_dll.EnclaveVerifyAttestationReport
EnclaveVerifyAttestationReport.restype = HRESULT
EnclaveVerifyAttestationReport.argtypes = [UINT32,c_void_p,UINT32]

# -- Helpers


# -- API


# -- Test Suites

def true_ish(val):
    if(val):
        return "True"
    return "False"
    
if(__name__=='__main__'):
    print("Loaded!")
    print("VBS Supported: %s" % true_ish(IsEnclaveTypeSupported(ENCLAVE_TYPE_VBS)))
    print("SGX Supported: %s" % true_ish(IsEnclaveTypeSupported(ENCLAVE_TYPE_SGX)))
