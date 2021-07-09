from ctypes import *
crypt32 = WinDLL("crypt32.dll")

# Some Crypt32 Constants
X509_ASN_ENCODING = 1
PKCS_7_ASN_ENCODING = 0x10000
NULL = 0
CERT_STORE_READONLY_FLAG = 0x8000
CERT_STORE_PROV_SYSTEM = 10
CERT_STORE_PROV_FILENAME = 8
CERT_STORE_OPEN_EXISTING_FLAG = 0x4000
CERT_SYSTEM_STORE_LOCAL_MACHINE =  0x20000
CERT_FIND_EXISTING = 0xD0000
CERT_STORE_ADD_REPLACE_EXISTING = 3

class CERT_CONTEXT(Structure):
    _fields_ = [
        ('dwCertEncodingType', c_uint32),
        ('pbCertEncoded', POINTER(c_ubyte)),
        ('cbCertEncoded', c_uint32),
        ('pCertInfo', c_void_p),
        ('hCertStore', c_void_p)
    ]

PCCERT_CONTEXT = POINTER(CERT_CONTEXT)
HCERTSTORE = c_void_p
HANDLE = c_void_p
DWORD = c_uint32
BOOL = c_long

# Native Definitions
CertCloseStore = crypt32.CertCloseStore
CertCloseStore.argtypes = [HCERTSTORE, DWORD]
CertCloseStore.restype = BOOL

CertEnumCertificatesInStore = crypt32.CertEnumCertificatesInStore
CertEnumCertificatesInStore.argtypes = [HCERTSTORE, PCCERT_CONTEXT]
CertEnumCertificatesInStore.restype = PCCERT_CONTEXT


crypt32.CertOpenStore.restype = HANDLE
crypt32.CertOpenStore.argtypes = [c_void_p, DWORD,HANDLE, DWORD,c_void_p]

CertOpenStore = crypt32.CertOpenStore


crypt32.CertFindCertificateInStore.restype = POINTER(CERT_CONTEXT)
crypt32.CertFindCertificateInStore.argtypes = [
    HANDLE,
    DWORD,
    DWORD,
    DWORD,
    c_void_p,
    c_void_p]
CertFindCertificateInStore = crypt32.CertFindCertificateInStore



CertDeleteCertificateFromStore = crypt32.CertDeleteCertificateFromStore
CertDeleteCertificateFromStore.restype = BOOL
CertDeleteCertificateFromStore.argtypes = [PCCERT_CONTEXT]


crypt32.CertAddEncodedCertificateToStore.restype = BOOL
crypt32.CertAddEncodedCertificateToStore.argtypes = [
    HANDLE,
    DWORD,
    POINTER(c_ubyte),
    DWORD,
    DWORD,
    POINTER(POINTER(CERT_CONTEXT))]
CertAddEncodedCertificateToStore = crypt32.CertAddEncodedCertificateToStore