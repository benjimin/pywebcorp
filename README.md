
HTTP web access via NTLM-authenticated proxy using SSPI for "single sign-on"
============================================================================

Motivation
----------

Presently in large organisations ("corporate" domains), python software 
(particularly installers such as pip and conda) often is unable to access the 
internet, despite that other software can (e.g. all common web browsers).
This is not a policy issue; the obstacle is that the necessary protocols are
not fully supported by the usual python web access libraries (e.g. requests
and urllib2).

### Goal

The aim is to resolve this in httplib, urllib/urllib2, urllib3, or requests
(or respective python 3 equivalents), so that downstream software just works
(or can be made to work with minimal modification).

### Status

Successfully demonstrating download from the web through an authenticated proxy,
without needing to prompt for credentials. It is not dependent on pywin32
because it contains an alternative implementation of SSPI using ctypes.
Next, needs adapting to the interface of an existing connection/request library.

Background
----------

There appears to be no previous python implementation of NTLM web proxy 
authentication with SSPI credentials. 

What currently (i.e. previously) exists:

### Relevant projects or code
-   In pywin32 (popular library) there is sspi module accompanied by a demo
    for http download using NTLM/SSPI with no proxy (and other code relevent
    for testing SSPI). The win32security module also wraps SSPI API.
-   Ntlmaps (a python equivalent of CNTLM) is a local proxy for forwarding 
    connections through an NTLM authenticated proxy without SSPI.
-   Other attempts at supporting NTLM (without SSPI and generally excluding
    proxies) include ntlmpool (in urllib3.contrib), python-ntlm (for urllib2)
    and requests-ntlm (which does not currently seek integration).
-   An example of python instead using native windows HTTP API to automagically
    support any necessary protocols http://serverfault.com/a/755936
-   The SSPI API is also accessible using ctypes.windll (from the standard 
    library, potentially mitagating pywin32 vendoring in installers, which
    is a concern expressed e.g. by
    [pip developers](https://github.com/pypa/pip/pull/3419)).
    There already exists an attempt at reimplementing pywin32 using ctypes 
    but it does not yet include SSPI. 
    https://github.com/enthought/pywin32-ctypes
-   Python web access libraries (e.g. urllib) already support proxy host/port
    autodetection, which on Windows gets "Internet Options" from registry (i.e.
    as set by OS in control panel and iexplorer) or is overridden by env vars.

### Resources
-   Detailed NTLM (including proxies and SSPI API) documentation at 
    http://davenport.sourceforge.net/ntlm.html
-   MSDN SSPI documentation (old) describes 
    [NTLM authentication](https://msdn.microsoft.com/en-us/library/bb742535.aspx)
    and the [API](https://msdn.microsoft.com/en-us/library/windows/desktop/aa375512(v=vs.85).aspx).
-   HTTP overview at https://www.jmarshall.com/easy/http/ 
-   There is an open source re-implementation of the win32 API, which includes
    a permissively-licensed version of the API header file.
    https://github.com/FreeRDP/FreeRDP/blob/master/winpr/include/winpr/sspi.h

The recommended approach for python web access (and used by pip and conda) is
the requests library. This incorporates the urllib3 library, which 
differentiates from previous urllibs in support for connection reuse (which is
particularly appropriate to NTLM because the handshake is once per usable
connection). All urllibs employ httplib.
