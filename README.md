
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

Goal
----

The aim is to resolve this in httplib, urllib/urllib2, urllib3, or requests
(or respective python 3 equivalents), so that downstream software just works
(or can be made to work with minimal modification).

Background
----------

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
