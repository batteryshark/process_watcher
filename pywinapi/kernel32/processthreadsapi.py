# Submodule that Handles processthreadsapi Stuff
from ctypes import *
from ctypes import wintypes

# Bindings
k32_dll = windll.kernel32

# Generic DataTypes
BOOL           = wintypes.BOOL
DWORD          = wintypes.DWORD
BYTE           = wintypes.BYTE
LPBYTE         = c_void_p
LPCSTR         = POINTER(c_char)
LPSTR          = POINTER(c_char)
DWORD64        = c_ulonglong
ULONGLONG      = c_ulonglong
LONGLONG       = c_longlong 
WORD           = wintypes.WORD
LPCONTEXT      = c_void_p
PWOW64_CONTEXT = c_void_p
LPVOID         = c_void_p
HANDLE         = c_void_p

class STARTUPINFOA(Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPCSTR),
        ("lpDesktop", LPCSTR),
        ("lpTitle", LPCSTR),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute",DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", WORD),
        ("cbReserved2", WORD),
        ("lpReserved2", LPBYTE),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),        
    ]

class PROCESS_INFORMATION(Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]
    
class SECURITY_ATTRIBUTES(Structure):
	_fields_ = [
		('nLength', DWORD),
		('lpSecurityDescriptor', LPVOID),
		('bInheritHandle', BOOL),
    ]


LPSECURITY_ATTRIBUTES = c_void_p
LPSTARTUPINFOA = POINTER(STARTUPINFOA)
LPPROCESS_INFORMATION = POINTER(PROCESS_INFORMATION)


# Process Defines
PROCESS_VM_OPERATION              = 0x0008
PROCESS_VM_READ                   = 0x0010
PROCESS_VM_WRITE                  = 0x0020
PROCESS_QUERY_INFORMATION         = 0x0400
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000


CREATE_SUSPENDED           = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400
CREATE_SECURE_PROCESS      = 0x00400000



# Thread Defines
THREAD_SUSPEND_RESUME    = 0x00000002
THREAD_SET_CONTEXT       = 0x00000010
THREAD_GET_CONTEXT       = 0x00000008
THREAD_QUERY_INFORMATION = 0x00000040

# Context Defines
WOW64_MAXIMUM_SUPPORTED_EXTENSION = 0x00000200
WOW64_SIZE_OF_80387_REGISTERS     = 0x00000050
CONTEXT_FULL                      = 0x00010007
CONTEXT_CONTROL                   = 0x00100001
CONTEXT_CONTROL_WOW64             = 0x00010001


#define CONTEXT_CONTROL (CONTEXT_AMD64 | 0x1L)
class M128A(Structure):
    _fields_ = [
        ('Low',  ULONGLONG),
        ('High', LONGLONG)
    ]

class XMM_SAVE_AREA32(Structure):
    _pack_ = 1
    _fields_ = [
        ('ControlWord',     WORD),
        ('StatusWord',      WORD),
        ('TagWord',         BYTE),
        ('Reserved1',       BYTE),
        ('ErrorOpcode',     WORD),
        ('ErrorOffset',     DWORD),
        ('ErrorSelector',   WORD),
        ('Reserved2',       WORD),
        ('DataOffset',      DWORD),
        ('DataSelector',    WORD),
        ('Reserved3',       WORD),
        ('MxCsr',           DWORD),
        ('MxCsr_Mask',      DWORD),
        ('FloatRegisters',  M128A * 8),
        ('XmmRegisters',    M128A * 16),
        ('Reserved4',       BYTE *  96)
    ]

class CONTEXT_FLTSAVE_STRUCT(Structure):
    _fields_ = [
        ('Header',                  M128A * 2),
        ('Legacy',                  M128A * 8),
        ('Xmm0',                    M128A),
        ('Xmm1',                    M128A),
        ('Xmm2',                    M128A),
        ('Xmm3',                    M128A),
        ('Xmm4',                    M128A),
        ('Xmm5',                    M128A),
        ('Xmm6',                    M128A),
        ('Xmm7',                    M128A),
        ('Xmm8',                    M128A),
        ('Xmm9',                    M128A),
        ('Xmm10',                   M128A),
        ('Xmm11',                   M128A),
        ('Xmm12',                   M128A),
        ('Xmm13',                   M128A),
        ('Xmm14',                   M128A),
        ('Xmm15',                   M128A)
    ]

class CTX_FLTSAVE_UNION(Union):
    _fields_ = [
    ('FltSave',    XMM_SAVE_AREA32),    
    ('xmm',        CONTEXT_FLTSAVE_STRUCT)
    ]

class WOW64_FLOATING_SAVE_AREA(Structure):
    _fields_ = [
    ('ControlWord',   DWORD),
    ('StatusWord',    DWORD),
    ('TagWord',       DWORD),
    ('ErrorOffset',   DWORD),
    ('ErrorSelector', DWORD),
    ('DataOffset',    DWORD),
    ('DataSelector',  DWORD),
    ('RegisterArea',  BYTE * WOW64_SIZE_OF_80387_REGISTERS),
    ('Cr0NpxState',   DWORD)]

class WOW64_CONTEXT(Structure):
    _pack_ = 1
    _fields_ = [
    ('ContextFlags',      DWORD),
    ('Dr0',               DWORD),
    ('Dr1',               DWORD),
    ('Dr2',               DWORD),
    ('Dr3',               DWORD),
    ('Dr6',               DWORD),
    ('Dr7',               DWORD),
    ('FloatSave',         WOW64_FLOATING_SAVE_AREA),
    ('SegGs',             DWORD),
    ('SegFs',             DWORD),
    ('SegEs',             DWORD),
    ('SegDs',             DWORD),
    ('Edi',               DWORD),
    ('Esi',               DWORD),
    ('Ebx',               DWORD),
    ('Edx',               DWORD),
    ('Ecx',               DWORD),
    ('Eax',               DWORD),
    ('Ebp',               DWORD),
    ('Eip',               DWORD),
    ('SegCs',             DWORD),
    ('EFlags',            DWORD),
    ('Esp',               DWORD),
    ('SegSs',             DWORD),
    ('ExtendedRegisters', BYTE * WOW64_MAXIMUM_SUPPORTED_EXTENSION)]

class CONTEXT(Structure):
    _pack_ = 16
    _fields_ = [
        ('P1Home',                  DWORD64),
        ('P2Home',                  DWORD64),
        ('P3Home',                  DWORD64),
        ('P4Home',                  DWORD64),
        ('P5Home',                  DWORD64),
        ('P6Home',                  DWORD64),
        ('ContextFlags',            DWORD),
        ('MxCsr',                   DWORD),
        ('SegCs',                   WORD),
        ('SegDs',                   WORD),
        ('SegEs',                   WORD),
        ('SegFs',                   WORD),
        ('SegGs',                   WORD),
        ('SegSs',                   WORD),
        ('EFlags',                  DWORD),
        ('Dr0',                     DWORD64),
        ('Dr1',                     DWORD64),
        ('Dr2',                     DWORD64),
        ('Dr3',                     DWORD64),
        ('Dr6',                     DWORD64),
        ('Dr7',                     DWORD64),
        ('Rax',                     DWORD64),
        ('Rcx',                     DWORD64),
        ('Rdx',                     DWORD64),
        ('Rbx',                     DWORD64),
        ('Rsp',                     DWORD64),
        ('Rbp',                     DWORD64),
        ('Rsi',                     DWORD64),
        ('Rdi',                     DWORD64),
        ('R8',                      DWORD64),
        ('R9',                      DWORD64),
        ('R10',                     DWORD64),
        ('R11',                     DWORD64),
        ('R12',                     DWORD64),
        ('R13',                     DWORD64),
        ('R14',                     DWORD64),
        ('R15',                     DWORD64),
        ('Rip',                     DWORD64),
        ('FltSave',                 CTX_FLTSAVE_UNION),
        ('VectorRegister',          M128A * 26),
        ('VectorControl',           DWORD64),
        ('DebugControl',            DWORD64),
        ('LastBranchToRip',         DWORD64),
        ('LastBranchFromRip',       DWORD64),
        ('LastExceptionToRip',      DWORD64),
        ('LastExceptionFromRip',    DWORD64)
    ]

# Function Definitions
Wow64GetThreadContext = k32_dll.Wow64GetThreadContext
Wow64GetThreadContext.restype = BOOL
Wow64GetThreadContext.argtypes = [HANDLE,PWOW64_CONTEXT]

GetThreadContext = k32_dll.GetThreadContext
GetThreadContext.restype = BOOL
GetThreadContext.argtypes = [HANDLE,LPCONTEXT]

Wow64SetThreadContext = k32_dll.Wow64SetThreadContext
Wow64SetThreadContext.restype = BOOL
Wow64SetThreadContext.argtypes = [HANDLE,PWOW64_CONTEXT]

SetThreadContext = k32_dll.SetThreadContext
SetThreadContext.restype = BOOL
SetThreadContext.argtypes = [HANDLE,LPCONTEXT]

OpenProcess = k32_dll.OpenProcess
OpenProcess.restype = HANDLE
OpenProcess.argtypes = [DWORD,BOOL,DWORD]

OpenThread = k32_dll.OpenThread
OpenThread.restype = HANDLE
OpenThread.argtypes = [DWORD,BOOL,DWORD]

SuspendThread = k32_dll.SuspendThread
SuspendThread.restype = DWORD
SuspendThread.argtypes = [HANDLE]

Wow64SuspendThread = k32_dll.Wow64SuspendThread
Wow64SuspendThread.restype = DWORD
Wow64SuspendThread.argtypes = [HANDLE]

ResumeThread = k32_dll.ResumeThread
ResumeThread.restype = DWORD
ResumeThread.argtypes = [HANDLE]

CreateProcessA = k32_dll.CreateProcessA
CreateProcessA.restype = BOOL
CreateProcessA.argtypes = [LPCSTR,LPSTR,LPSECURITY_ATTRIBUTES,LPSECURITY_ATTRIBUTES,BOOL,DWORD,LPVOID,LPCSTR,LPSTARTUPINFOA,LPPROCESS_INFORMATION]


GetCurrentProcessId = k32_dll.GetCurrentProcessId
GetCurrentProcessId.restype = DWORD

# -- Helpers --
def _get_current_process_id():
    return GetCurrentProcessId()
    
def _get_thread_context(h_thread,is_wow64):
    if(is_wow64):
        ctx = WOW64_CONTEXT()
        func = Wow64GetThreadContext
        ctx.ContextFlags = CONTEXT_CONTROL_WOW64
    else:
        ctx = CONTEXT()
        func = GetThreadContext
        ctx.ContextFlags = CONTEXT_CONTROL
    
    if(func(h_thread,byref(ctx))):
        return True,ctx
    return False,None

def _set_thread_context(h_thread,ctx,is_wow64):
    if(is_wow64):
        ctx.ContextFlags = CONTEXT_CONTROL_WOW64
        return Wow64SetThreadContext(h_thread,byref(ctx))
    else:
        ctx.ContextFlags = CONTEXT_CONTROL
        return SetThreadContext(h_thread,byref(ctx))

def _open_process(desired_access,inherit_handle,process_id):
    h_process = OpenProcess(desired_access,inherit_handle,process_id)
    if(not h_process):
        return False,0
    return True,h_process

def _create_process_a(application_name,cmd_line,process_attr,thread_attr,inherit_handles,create_flags,env,cdir,startup_info,process_info):
    return CreateProcessA(application_name,cmd_line,process_attr,thread_attr,inherit_handles,create_flags,env,cdir,startup_info,process_info)


def _open_thread(desired_access,inherit_handle,thread_id):
    h_thread = OpenThread(desired_access,inherit_handle,thread_id)
    if(not h_thread):
        return False,0
    return True,h_thread

def _suspend_thread(h_thread,is_wow64):
    if(is_wow64):
        sc = Wow64SuspendThread(h_thread)
    else:
        sc = SuspendThread(h_thread)
    if(sc == -1):
        return False,0
    return True,sc

def _resume_thread(h_thread):
    rc = ResumeThread(h_thread)
    if(rc == -1):
        return False,0
    return True,rc

# -- API --
def get_thread_context(h_thread,is_wow64):
    return _get_thread_context(h_thread,is_wow64)

def set_thread_context(h_thread,ctx,is_wow64):
    return _set_thread_context(h_thread,ctx,is_wow64)

def open_process_queryinfo(pid):
    return _open_process(PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION,False,pid)

def open_process_ro(pid):
    return _open_process(PROCESS_VM_READ ,False,pid)

def open_process_rw(pid):
    return _open_process(PROCESS_VM_READ|PROCESS_VM_OPERATION|PROCESS_VM_WRITE ,False,pid)

def open_process_w(pid):
    return _open_process(PROCESS_VM_OPERATION|PROCESS_VM_WRITE ,False,pid)

def create_process_suspended(target_path,cmdline="",env=[]):
    startupinfo = STARTUPINFOA()
    processinfo = PROCESS_INFORMATION()
    ctarget_path = create_string_buffer(target_path.encode('ascii'))
    ccmdline = create_string_buffer(cmdline.encode('ascii'))
    if(not _create_process_a(ctarget_path,ccmdline,None,None,False,CREATE_SUSPENDED,None,None,byref(startupinfo),byref(processinfo))):
        print("CreateProcessA Failed: %04X" % k32_dll.GetLastError())
        return False,None,None
    return True,startupinfo,processinfo

def open_thread_ctx_ro(tid):
    return _open_thread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT,False,tid)

def open_thread_ctx_rw(tid):
    # we need THREAD_QUERY_INFORMATION for WOW64...
    return _open_thread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,False,tid)

def suspend_thread(h_thread,is_wow64):
    return _suspend_thread(h_thread,is_wow64)

def resume_thread(h_thread):
    return _resume_thread(h_thread)

# Resume thread until the suspend count is 0
def super_resume_thread(h_thread):
    suspend_count = -1
    while(suspend_count != 0):
        res,suspend_count = resume_thread(h_thread)
        if(not res):
            return False
    return True

# Super Hacky way to Determine if thread is/was suspended.
def is_thread_suspended(h_thread,is_wow64):
    res,sc = suspend_thread(h_thread,is_wow64)
    if(not res):
        return False,False

    if(not resume_thread(h_thread)[0]):
        return False,False

    return True,sc > 0

# Determine the Current Instruction Pointer for a given Thread [MUST BE SUSPENDED!]
def get_thread_cip(ctx,is_wow64):
    if(is_wow64):
        return ctx.Eip
    return ctx.Rip

def set_thread_cip(ctx,addr,is_wow64):
    if(is_wow64):
        ctx.Eip = addr & 0xFFFFFFFF
    else:
        ctx.Rip = addr & 0xFFFFFFFFFFFFFFFF
    return ctx

def get_current_process_id():
    return _get_current_process_id()
