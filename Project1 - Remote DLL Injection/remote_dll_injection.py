from ctypes import wintypes
from ctypes import *


kernel32 = windll.kernel32
LPCTSTR = c_char_p
SIZE_T = c_size_t

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (wintypes.DWORD,wintypes.BOOL,wintypes.DWORD)
OpenProcess.restype = wintypes.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE,wintypes.LPVOID,SIZE_T,wintypes.DWORD,wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID,SIZE_T,POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL

GetModuleHandleA = kernel32.GetModuleHandleA
GetModuleHandleA.argtypes = (LPCTSTR,)
GetModuleHandleA.restype = wintypes.HANDLE

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = (wintypes.HANDLE, LPCTSTR)
GetProcAddress.restype = wintypes.LPVOID


class _SECURITY_ATTRIBUTES(Structure):
	_fields_ = [('nLength',wintypes.DWORD),('lpSecurityDescriptor',wintypes.LPVOID),('bInheritHandle',wintypes.BOOL),]

SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = wintypes.LPVOID




CreateRemoteThread = kernel32.CreateRemoteThread
CreateRemoteThread.argtypes = (wintypes.HANDLE,LPSECURITY_ATTRIBUTES,SIZE_T,LPTHREAD_START_ROUTINE,wintypes.LPVOID,wintypes.DWORD,wintypes.LPDWORD)
CreateRemoteThread.restype = wintypes.HANDLE


MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x40
EXECUTE_IMMEDIATELY = 0X0
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)

# Add path to your dll
dll = b'{path-to-dll}'

# Find PID of process which you want to inject dll
pid = 3328

handle = OpenProcess(PROCESS_ALL_ACCESS,False,3328)

if not handle:
	raise WinError()

print('Handle obtained => {0:X}'.format(handle))

remote_memory = VirtualAllocEx(handle,False, len(dll) +1,MEM_COMMIT | MEM_RESERVE,PAGE_READWRITE)
if not remote_memory:
	raise WinError()

print('Memory allocated => ', hex(remote_memory))

write = WriteProcessMemory(handle,remote_memory,dll,len(dll)+1, None)

if not write:
	raise WinError()

print('Bytes written => {}'.format(dll))

load_lib = GetProcAddress(GetModuleHandleA(b"kernel32.dll"), b"LoadLibraryA")

print("LoadLibrary address => ", hex(load_lib))

rthread = CreateRemoteThread(handle, None,0,load_lib,remote_memory,EXECUTE_IMMEDIATELY,None)
