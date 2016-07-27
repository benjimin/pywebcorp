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
"""

import ctypes
from ctypes import POINTER, byref # convenience..
from ctypes.wintypes import ULONG
from ctypes import c_wchar_p, c_void_p, c_longlong # should use other types instead?


class SecHandle(ctypes.Structure): # typedef for CredHandle/CtxtHandle
    _fields_ = [('dwLower',POINTER(ULONG)),('dwUpper',POINTER(ULONG))] # each part is ULONG_PTR
"""class SecBuffer(ctypes.Structure):
    # size (bytes) of buffer, type flags (empty=0,token=2), ptr to buffer
    _fields_ = [('cbBuffer',ULONG),('BufferType',ULONG),('pvBuffer',c_void_p)]
class SecBufferDesc(ctypes.Structure):
    # SECBUFFER_VERSION=0, # of buffers, ptr to array (although an array of 1 might suffice)
    _fields_ = [('ulVersion',ULONG),('cBuffers',ULONG),('pBuffers',POINTER(SecBuffer))]"""

class ctypes_sspi(w32sCA):
    maxtoken = 10000 # let's say.
    def acquire(self,scheme):
        f = ctypes.windll.secur32.AcquireCredentialsHandleW
        f.argtypes = [c_wchar_p]*2 + [ULONG] + [c_void_p]*4 + [POINTER(SecHandle), POINTER(c_longlong)]
        #f.restype = c_long ??
        
        cred = SecHandle() # NOTE!!! Does this even initialise those pointers, to point anywhere?
        pcred = ctypes.pointer(cred)
        time = ctypes.c_longlong()
        
        print 'acqtime', hex(time.value)
        print cred.dwLower, cred.dwUpper
        r = f(None,u'NTLM',2,None,None,None,None,pcred,byref(time))
        print 'acqtime', hex(time.value)
        print cred.dwLower, cred.dwUpper
        
        return cred
        
    def initialize(self,context,token):
        f = ctypes.windll.secur32.InitializeSecurityContextW

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
"""
l1 = ULONG(7)
l2 = ULONG(42)
p1 = ctypes.pointer(l1)
p2 = ctypes.pointer(l2)
cred = SecHandle(p1,p2)
cred.dwLower.value # is this my bug?


ClientAuth = w32sCA # testing! ********************************
ClientAuth = ctypes_sspi"""

if __name__ == '__main__': import demo