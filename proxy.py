"""

HTTP downloads via NTLM-authenticated proxy using SSPI for "single sign-on"
===========================================================================

The motivation for this code:
    
Presently in large organisations ("corporate" domains), python software 
(particularly installers such as pip and conda) is often unable to access the 
internet, despite that other software can (e.g. all common web browsers).
This is not a policy issue; the obstacle is that the necessary protocols are
not fully supported by the usual python web access libraries (e.g. requests
and urllib2).

The aim is to resolve this in httplib, urllib/urllib2, urllib3, or requests
(or respective python 3 equivalents), so that downstream software just works
(or can be made to work with minimal modification).

What currently (i.e. previously) exists:
-   In pywin32 (popular library) there is sspi module accompanied by a demo
    for http download using NTLM/SSPI with no proxy (and other code relevent
    for testing SSPI). The win32security module also wraps SSPI API.
-   Detailed NTLM (including proxies and SSPI API) documentation at 
    http://davenport.sourceforge.net/ntlm.html
-   The SSPI API is also accessible using ctypes.windll (from the standard 
    library, potentially mitagating pywin32 vendoring in installers, which
    is a concern expressed e.g. by pip developers).
-   HTTP overview at https://www.jmarshall.com/easy/http/ 
-   SSPI API documentation (old) also describes NTLM authentication
    https://msdn.microsoft.com/en-us/library/bb742535.aspx
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa374712(v=vs.85).aspx
    https://msdn.microsoft.com/en-us/library/windows/desktop/aa375512(v=vs.85).aspx
-   Ntlmaps (a python equivalent of CNTLM) is a local proxy for forwarding 
    connections through an NTLM authenticated proxy without SSPI.
-   An example of python instead using native windows HTTP API to automagically
    support any necessary protocols http://serverfault.com/a/755936
-   Other attempts at supporting NTLM (without SSPI and generally excluding
    proxies) include ntlmpool (in urllib3.contrib), python-ntlm (for urllib2)
    and requests-ntlm (which does not currently seek integration).
-   Python web access libraries already support proxy autodetection, which
    on Windows gets "Internet Options" from registry (i.e. as set by 
    OS in control panel and iexplorer) or is overridden by env vars.

The recommended approach for python web access (and used by pip and conda) is
the requests library. This incorporates the urllib3 library, which 
differentiates from previous urllibs in support for connection reuse (which is
appropriate to NTLM). All urllibs utilise httplib.

"""



import httplib
import base64
import sspi # part of pywin32
import urllib
import urlparse
import os


import sspi


import ctypes

acquire = ctypes.windll.secur32.AcquireCredentialsHandleW
init = ctypes.windll.secur32.InitializeSecurityContextW

from ctypes import *
from ctypes.wintypes import *

class SecHandle(ctypes.Structure): # typedef for CredHandle/CtxtHandle
    _fields_ = [('dwLower',POINTER(c_ulong)),('dwUpper',POINTER(c_ulong))] # each part is ULONG_PTR
class SecBuffer(ctypes.Structure):
    # size (bytes) of buffer, type flags (empty=0,token=2), ptr to buffer
    _fields_ = [('cbBuffer',ULONG),('BufferType',ULONG),('pvBuffer',c_void_p)]
class SecBufferDesc(ctypes.Structure):
    # SECBUFFER_VERSION=0, # of buffers, ptr to array (although an array of 1 might suffice)
    _fields_ = [('ulVersion',ULONG),('cBuffers',ULONG),('pBuffers',POINTER(SecBuffer))]


acquire.argtypes = [c_wchar_p]*2 + [c_ulong] + [c_void_p]*4 + [POINTER(SecHandle), POINTER(c_longlong)]
acquire.restype = c_long ######?

init.argtypes = [c_void_p]*2 + [c_wchar_p] + [c_ulong]*3 + [c_void_p,c_ulong] + [c_void_p]*4
init.restype = c_short ######?


cred = SecHandle()
time = c_longlong()

print time
print cred.dwLower
result = acquire(None,u'NTLM',2,None,None,None,None,byref(cred),byref(time))
print result
print "ok"
print time.value*1.0
print hex(time.value)
#import datetime
#print datetime.datetime(1601,1,1) + datetime.timedelta(microseconds=int('0xd5969fff7fffff36',0)/10)
#import time as t
#print t.time()
print 
print cred.dwLower
print '-'*40 # ------------------------------

# The SSPI API requires a number of structs.
# If these are allocated by the system, must let the system deallocate after.
# Alternatively, can construct ourselves.

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


#print sspi.ClientAuth('NTLM').pkg_info # maxtoken = 2888

print '-'*40 # ------------------------------


# Difficult to get working... let's try using the win32security module as an intermediate step
# with comparison to sspi.py


import win32security
import sspicon

print sspicon.SECPKG_CRED_OUTBOUND

#Note, win32sec A.C.H. can take a user/dom/pass tuple if desired.
credentials, expiry = win32security.AcquireCredentialsHandle(
    None, u'NTLM', sspicon.SECPKG_CRED_OUTBOUND, None, None)

# Note the int argument has flags for validating what the server gets,
# versus preparing a client's output.

print credentials
print expiry.__repr__()
print type(expiry)
print dir(expiry)
print help(expiry)

sec_buffer_in = None

maxtoken = win32security.QuerySecurityPackageInfo('NTLM')['MaxToken']
tokenbuf = win32security.PySecBufferType(maxtoken,sspicon.SECBUFFER_TOKEN)
sec_buffer_out = win32security.PySecBufferDescType()
sec_buffer_out.append(tokenbuf)

targetspn = None
scflags = sspicon.ISC_REQ_INTEGRITY|sspicon.ISC_REQ_SEQUENCE_DETECT|sspicon.ISC_REQ_REPLAY_DETECT|sspicon.ISC_REQ_CONFIDENTIALITY
datarep = sspicon.SECURITY_NETWORK_DREP
ctxtin = None
ctxt = win32security.PyCtxtHandleType()

err, attr, exp=win32security.InitializeSecurityContext(
    credentials, ctxtin, targetspn, scflags, datarep, sec_buffer_in, ctxt, sec_buffer_out)

print err
print attr
print exp


#------------------- Try again with more primitive inputs.



credentials, expiry = win32security.AcquireCredentialsHandle(
    None, u'NTLM', sspicon.SECPKG_CRED_OUTBOUND, None, None)

print credentials
print expiry.__repr__()

sec_buffer_in = None

maxtoken = win32security.QuerySecurityPackageInfo('NTLM')['MaxToken']
tokenbuf = win32security.PySecBufferType(maxtoken,sspicon.SECBUFFER_TOKEN)
sec_buffer_out = win32security.PySecBufferDescType()
sec_buffer_out.append(tokenbuf)

targetspn = None
scflags = sspicon.ISC_REQ_INTEGRITY|sspicon.ISC_REQ_SEQUENCE_DETECT|sspicon.ISC_REQ_REPLAY_DETECT|sspicon.ISC_REQ_CONFIDENTIALITY
datarep = sspicon.SECURITY_NETWORK_DREP
ctxtin = None
ctxt = win32security.PyCtxtHandleType()

err, attr, exp=win32security.InitializeSecurityContext(
    credentials, ctxtin, targetspn, 0, 0, sec_buffer_in, ctxt, sec_buffer_out)

print err
print attr
print exp

# So, skipping the input scflags zeroes attr, the output context attribute flags?
# Not obvious if datarep has any effect. It is only meant to indicate endianness.


#"""
