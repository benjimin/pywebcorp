"""

Uses ctypes to wrap API for win32 SSPI

The two basic calls are:
    AcquireCredentialsHandle
    InitializeSecurityContext

The main complexity is management of the memory structures which must be passed
back and forth with these calls. In particular, a third call is necessary to 
ascertain the size of the buffer for receiving the security token (or
otherwise to deallocate it).

"""
import ctypes

from ctypes import Structure, POINTER, pointer, c_void_p as PVOID
from ctypes.wintypes import ULONG


# call API to get max token size, or..
maxtoken = 2880 # bytes

########################  TYPE DECLARATIONS #########################

SecStatus = ULONG # Security status type

TimeStamp = ctypes.c_int64 # SECURITY_INTEGER type: 100ns intervals since 1601 UTC.

class SecHandle(Structure): # typedef for CredHandle and CtxtHandle
    _fields_ = [('dwLower',POINTER(ULONG)),('dwUpper',POINTER(ULONG))]
    def __init__(self): # populate deeply (empty memory fields) rather than shallow null pointers.
        Structure.__init__(self, pointer(ULONG()), pointer(ULONG()))
      
class SecBuffer(Structure):
    _fields_ = [('cbBuffer',ULONG),('BufferType',ULONG),('pvBuffer',PVOID)]
    # size of buffer (bytes), type flags (empty=0, token=2), buffer pointer
    def __init__(self, buf):
        print "initialising secbuffer"
        # InitializeSecurityContext will modify the token-flagged buffer and
        # update the size, or else fail 0x80090321 SEC_E_BUFFER_TOO_SMALL
        Structure.__init__(self,sizeof(buf),2,cast(pointer(buf),PVOID))
        # instead of cast, why not ctypes.from_address(buf)
    @property
    def Buffer(self):
        return ctypes.string_at(self.pvBuffer, size=self.cbBuffer)
    @Buffer.setter
    def Buffer(self, value):
        assert len(bytestring) <= maxtoken
    
class SecBufferDesc(ctypes.Structure):
    _fields_ = [('ulVersion',ULONG),('cBuffers',ULONG),('pBuffers',POINTER(SecBuffer))]
    # SECBUFFER_VERSION=0, # of buffers, ptr to array of SecBuffer structs
    def __init__(self, sb):
        Structure.__init__(self,0,1,pointer(sb))        
    def __getitem__(self, index):
        assert index == 0 # one buffer suffices
        return self.pBuffers[index]    



























