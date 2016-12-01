
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

Failing that, the goal is to produce an easily-distributable patch for conda,
to enable installing python behind a corporate firewall.

### Status

Successfully demonstrating (demo.py) download from the web through an 
authenticated proxy, without needing to prompt for credentials. 
It is not dependent on pywin32 because it contains an alternative 
implementation of SSPI using ctypes.

Next steps:
-   Create detailed test script to analyse and report how a network is behaving
-   Support HTTPS
-   Adapt to the interface of urllib3
-   Create patch for conda
-   Try to replace python-ntlm using standard crypto libraries

Testing
-------

If you would like to begin helping with this effort, simply download this 
repository, run "python demo.py" (and similarly for test.py), and report back 
whether it is able to access the internet from your network.

Background
----------

There appears to be no previous python implementation of NTLM web proxy 
authentication with SSPI credentials. 

What currently (i.e. previously) exists:

### Relevant projects or code
-   In pywin32 (popular library) there is an sspi module, accompanied by a demo
    for http download using NTLM/SSPI with no proxy (and other code relevent
    for testing SSPI). Its win32security module also wraps SSPI API.
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

### Python ecosystem

The recommended approach for python web access (and used by pip and conda) is
the requests library. This incorporates the urllib3 library, which 
differentiates from previous urllibs in support for connection reuse (which is
particularly appropriate to NTLM because the handshake is once per usable
connection). All urllibs employ httplib.

The relevent existing libraries (requests-ntlm, ntlmpool, ..) all rely on
python-ntlm (or a fork thereof). Note that python-ntlm is LGPL, and appears
to include a python reimplementation of cryptography algorithms. 

### HTTPS and CONNECT

The http protocol consists of opening a socket (with or without secure
wrapping) and sending, then receiving, dispatches (client requests and server 
responses) which consist of:
- Preface line.
- Headers.
- Blank separator.
- Optional message body.

The preface line in a request always features one of 
the *verbs* from a set which includes GET, POST and CONNECT.
The preface line in a response always features some kind of *status* 
which acknowledges (and relates to) the preceding request.
Aside from the preface line, each dispatch follows the pattern of an 
internet message standard (which also applies to email protocols).

Frequently, either party closes the connection after sending a dispatch.
The CONNECT verb is exceptional only in that, after the response is
dispatched, the underlying socket is potentially turned over for a different use
(i.e. the server makes it a tunnel to another host, and the client typically
applies a wrapper layer and uses it as the socket for a HTTPS connection to
the other host).

The NTLM proxy handshake protocol still depends on the content of the
CONNECT response headers (not just the status). Unfortunately, a current 
[bug](https://bugs.python.org/issue24964) in the python standard library
makes this unavailable in httplib. Part of the problem is that the API treats
CONNECT entirely differently from other request verbs. 
(It would seem more natural if it were just a normal verb, and if responses
included socket handles that could also be passed to http connection 
constructors. This ought also keep the https connection subclass simple.)
