"""
Here is the SSPI authentication.

Compartmentalised here to permit testing ctypes/pywin32 versions.
"""

import base64

try:
    from sspi import ClientAuth
except ImportError:
    raise ImportError # TODO: ctypes! (nb. should do that in a try block too)
  
def sspiauth(scheme='NTLM'):
    handle = ClientAuth(scheme)
    def generate_answer(challenge=None):
        if challenge is not None:
            assert challenge.startswith(scheme) # or, could be a series of challenge options?
            challenge = base64.b64decode(challenge[len(scheme):])
        status, token_buffer = handle.authorize(challenge)
        token = scheme + ' ' + base64.b64encode(token_buffer[0].Buffer)
        return token
    return generate_answer
    
"""
What follows (work-in-progres) is designed to get SSPI working when
pywin32 is unavailable. That is, accessing the API via ctypes.
However, there may be an intermediate step, of using the win32security
module (which is less wrapped than the sspi module).
"""

import win32security
import sspicon
class w32sCA():
    def __init__(self,scheme=u'NTLM'):
        self.credential = self.acquire(scheme)
        self.context = None
    def authorize(self,challenge=None):
        self.context, status, token_buffer = self.initialize(self.context, challenge)
        print 'STATUS',status,hex(status)
        # winerror.h : SEC_E_OK = 0 (unqualified success)
        #              SEC_I_CONTINUE_NEEDED = 0x00090312 = 590610 (success but must call again)
        return status, token_buffer
    def acquire(self,scheme):
        credentials, expiry = win32security.AcquireCredentialsHandle(
                    None, scheme, sspicon.SECPKG_CRED_OUTBOUND, None, None)
        print "acquired expiry",expiry.__repr__(),type(expiry)
        self.maxtoken = win32security.QuerySecurityPackageInfo(scheme)['MaxToken']
        print "maxtoken",self.maxtoken
        return credentials
    def initialize(self,context, token):

        # create output buffer       
        
        tokenbuf = win32security.PySecBufferType(self.maxtoken,sspicon.SECBUFFER_TOKEN)
        if token is not None: 
            tokenbuf.Buffer = token
        sec_buffer_out = win32security.PySecBufferDescType()
        sec_buffer_out.append(tokenbuf)
        
        # set arguments
        
        targetspn = None
        scflags = sspicon.ISC_REQ_INTEGRITY|sspicon.ISC_REQ_SEQUENCE_DETECT|sspicon.ISC_REQ_REPLAY_DETECT|sspicon.ISC_REQ_CONFIDENTIALITY
        print 'scflags',scflags
        datarep = sspicon.SECURITY_NETWORK_DREP
        print 'datarep',datarep
        newcontext = context if context is not None else win32security.PyCtxtHandleType()
        sec_buffer_in = sec_buffer_out if token is not None else None        

        # call

        err, attr, exp=win32security.InitializeSecurityContext(
            self.credential, context, targetspn, 0, 0, sec_buffer_in, newcontext, sec_buffer_out)
            
        # return
        
        print "init status", err
        print "init flags", attr
        print "init expiry", exp        
        return newcontext, err, sec_buffer_out


"""
What follows is the ctypes magic, that certainly isn't working yet.

WinAPI:
    CHAR = 8 bit ANSI
    DWORD = 32 bit uint, i.e. ulong. Similar to DWORD32 = uint
    HANDLE = pvoid
    INT = 32 bit (signed) int
    LONG = also a 32 bit (signed) int, i.e., long.
    LONGLONG = 64bit signed int, i.e. int64
    PVOID = pointer to any type, i.e., void *
    QWORD = 64bit unsigned int
    SC_HANDLE = HANDLE
    SHORT = 16 bit int
    VOID = any type
    WCHAR = 16bit unicode character i.e. wchar_t
    
Looks like originally, int 16 long 32 longlong 64. 
Then int got upgraded once.
But it wasn't upgraded again, so in windows it caught up with long, and
in unix the long was also upgraded to catch up with longlong.
Significance is that in windows, only pointers got bigger this time.
(So everything compiles without change, but behaves the old way.)
Also, float vs double, should differ in precision but ?

Extra issue. python ctypes uses 32bit/64bit pointers according to
whether it is a 32bit/64bit python build. (The platform is win32 regardless.)
The winAPI on 64bit OS should have both 32 and 64 bit versions of each
system DLL, and should auto-select according to software (i.e. python).
So it should just work. Ignore for now.



"""



import ctypes
from ctypes import POINTER, byref, pointer, Structure, sizeof, cast # convenience..
from ctypes.wintypes import ULONG, LONG # int and long are both 32 for windows
from ctypes import c_wchar_p, c_void_p, c_longlong, c_int32, c_uint32 # should use other types instead?

SecStatus = ULONG
PVOID = c_void_p



class SecInt(Structure):
    _fields_ = [('LowPart',c_uint32),('HighPart',c_int32)]
class uLargeInt(ctypes.Union):
    _fields_ = [('QuadPart',ctypes.c_uint64),('u',SecInt)]
    # note, "value" is redundant when asking for parts from union   

class SecHandle(Structure): # typedef for CredHandle/CtxtHandle
    _fields_ = [('dwLower',POINTER(ULONG)),('dwUpper',POINTER(ULONG))] # each part is ULONG_PTR
    def __init__(self): # rather than shallow null pointers, populate deeply with blank memory fields
        Structure.__init__(self, pointer(ULONG()), pointer(ULONG()))

class SecBuffer(Structure):
    # size (bytes) of buffer, type flags (empty=0,token=2), PVOID to buffer
    _fields_ = [('cbBuffer',ULONG),('BufferType',ULONG),('pvBuffer',PVOID)]
    def __init__(self, buf):
        # instead of cast, should try PVOID.from_buffer(buf)? wait, or not?
        #Structure.__init__(self,sizeof(buf),2*(not empty),cast(pointer(buf),PVOID))
        # Type must be token (2) not blank (0)
        Structure.__init__(self,sizeof(buf),2,cast(pointer(buf),PVOID))
        
class SecBufferDesc(ctypes.Structure):
    # SECBUFFER_VERSION=0, # of buffers, ptr to array (although an array of 1 might suffice)
    _fields_ = [('ulVersion',ULONG),('cBuffers',ULONG),('pBuffers',POINTER(SecBuffer))]
    def __init__(self, sb):
        Structure.__init__(self,0,1,pointer(sb))

class ctypes_sspi(w32sCA):
    maxtoken = 100000000 # let's say.
    def acquire(self,scheme):
        f = ctypes.windll.secur32.AcquireCredentialsHandleW
        f.argtypes = [c_wchar_p]*2 + [ULONG] + [c_void_p]*4 + [POINTER(SecHandle), POINTER(uLargeInt)]
        f.restype = SecStatus
        
        cred = SecHandle()
        pcred = ctypes.pointer(cred)
        time = uLargeInt()
        
        print 'acqtime', time.u.LowPart, time.u.HighPart, time.QuadPart
        print 'incred', cred.dwLower.contents.value, cred.dwUpper.contents.value
        r = f(None,u'NTLM',2,None,None,None,None,pcred,byref(time))
        print 'return status',type(r),r,hex(r)
        print 'acqtime', hex(time.u.LowPart), time.u.LowPart, hex(time.u.HighPart), time.u.HighPart, hex(time.QuadPart)
        print 'outcred',cred.dwLower.contents.value, cred.dwUpper.contents.value
        # Status = SEC_E_OK (zero)
        # Time 0x7fffff36d5969fff probably = "Never expires" (e.g. max time converted to local timezone)
        # Specifically, is about 24hrs shy of the two's complement max signed value of 0x7fff...
        
        return cred
        
    def initialize(self,context,token):
        f = ctypes.windll.secur32.InitializeSecurityContextW
        f.restype = SecStatus
        f.argtypes = [c_void_p]*2 + [c_wchar_p] + [ULONG]*3 + [c_void_p,ULONG] + [c_void_p]*4
        
        print 'maxtoken',self.maxtoken
        
        buf = ctypes.create_string_buffer("hello",self.maxtoken)
        print ctypes.sizeof(buf)
        sb = SecBuffer(buf)
        sbd = SecBufferDesc(sb)
        
        
        print 'oldcontext',context        
        newcontext = context if context is not None else SecHandle()
        print 'newcontext', newcontext.dwLower.contents.value, newcontext.dwUpper.contents.value
                        
        outputflags = ULONG()
        
        # below here needs attention        
        
        print self.credential
        
        pcred = pointer(self.credential)
        
        print 'cred', pcred.contents.dwLower.contents.value, pcred.contents.dwUpper.contents.value
        
        print
        print
        print  ctypes.addressof(sbd.pBuffers[0])
        print  ctypes.addressof(sbd.pBuffers[0])
        print  ctypes.addressof(sbd.pBuffers[1])
        print sbd.ulVersion
        print sbd.cBuffers
        print sbd.pBuffers[0].cbBuffer
        print sbd.pBuffers[0].BufferType
        print
        for i in range(10):
            print cast(sbd.pBuffers[0].pvBuffer,POINTER(ctypes.c_byte))[i]
        print
        print

        psecbyfferdesc = pointer(sbd)     
        time = uLargeInt()
        print 'inittime', time.u.LowPart, time.u.HighPart, time.QuadPart
        
        r = f(pcred,None,None,65564,0,0,None,0,byref(newcontext),psecbyfferdesc,byref(outputflags),byref(time))
        print 'init', r, hex(r)
        print 'inittime', time.u.LowPart, time.u.HighPart, time.QuadPart        
        
        print 'cred', pcred.contents.dwLower.contents.value, pcred.contents.dwUpper.contents.value
        print 'newcontext', newcontext.dwLower.contents.value, newcontext.dwUpper.contents.value        
        

        print
        print  ctypes.addressof(sbd.pBuffers[0])
        print  ctypes.addressof(sbd.pBuffers[0])
        print  ctypes.addressof(sbd.pBuffers[1])
        print sbd.ulVersion
        print sbd.cBuffers
        print sbd.pBuffers[0].cbBuffer
        print sbd.pBuffers[0].BufferType
        print
        for i in range(10):
            print cast(sbd.pBuffers[0].pvBuffer,POINTER(ctypes.c_byte))[i]
        print
        print

      
        print "ok"
        
        return newcontext,r,sbd

"""
init.argtypes = [c_void_p]*2 + [c_wchar_p] + [c_ulong]*3 + [c_void_p,c_ulong] + [c_void_p]*4
init.restype = c_short ######?

maxtokensize = 2888
buf = ctypes.create_string_buffer(maxtokensize)
buf1 = SecBuffer(maxtokensize,0,ctypes.cast(ctypes.pointer(buf),c_void_p))
bufdesc = SecBufferDesc(0,1,ctypes.pointer(buf1))
context = SecHandle()
outputflags = ULONG()

#print repr(buf.raw)
result = init(byref(cred),None,None,0,0,0,None,0,byref(context),byref(bufdesc),byref(outputflags),None)
#print repr(buf.raw)
print result
print outputflags
print bufdesc
print buf1
print buf1.BufferType
"""



ClientAuth = w32sCA # testing! ********************************
ClientAuth = ctypes_sspi

if __name__ == '__main__': import demo