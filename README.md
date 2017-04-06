
HTTP and HTTPS web access via NTLM-authenticated proxy using SSPI for "single sign-on"
======================================================================================

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

Successfully demonstrating download from the web through an
authenticated (NTLM) proxy, without needing to prompt for credentials.
It is not dependent on pywin32 because it contains an alternative
implementation of SSPI using ctypes.
Conda works.

Possible future steps are to seek integration into requests or urllib3, or
to try to replace python-ntlm (using standard crypto libraries).

Instructions
------------

*__Disclaimer__: Use at own risk.* Still under development!

The main steps involved are:
 - ensure your python installation is able to detect your web proxy.
 - make the `pywebcorp` package available to your system.
 - ensure `pywebcorp.patch` gets imported before python software tries to
   access the web.

### Installation for conda

Conda is the recommended "best-practice" python package manager (e.g. it
manages dependencies including compiled libraries and the interpreter itself,
and uses seperated virtual environments to manage dependency conflicts).
Install [miniconda](https://conda.io/miniconda.html) for single-user.

Download the pywebcorp zip
[archive](https://github.com/benjimin/pywebcorp/archive/master.zip) from GitHub,
and copy the pywebcorp sub-directory into your conda global site-packages
(e.g.
`C:\Users\YourName\AppData\Local\Continuum\Miniconda3\Lib\site-packages\pywebcorp`).

In Internet Explorer - Internet Options - Connections - LAN Settings - Proxy
server: ensure "Use proxy" is checked and the address/port are correct. These
settings will also be inherited within python.

Also in the conda global site-packages, locate the requests package and its
initialisation module (e.g.
`...\Continuum\Miniconda3\Lib\site-packages\requests\__init__.py`), open it
in a text editor (such as IDLE or WordPad), and append the line
`import pywebcorp.patch` to the end of it.

Finally, in a cmd.exe terminal,  `activate` the root conda environment, use
the `conda create` and `conda install` commands to download libraries into a
fresh python environment.

### Installation for pip

*Note: untested.*

If you are using a non-conda python installation, first locate where it is
installed. (e.g. at a cmd.exe prompt,
`for %i in (python.exe) do @echo. %~$PATH:i`)

From this python location, navigate to `Lib\site-packages` and copy
pywebcorp as described above (e.g. to
`C:\Python27\Lib\site-packages\pywebcorp`).

Pip may be using its own separate copy of the requests library. Append the
`import pywebcorp.patch` line to e.g.
`C:\Python27\Lib\site-packages\pip\_vendor\requests\__init__.py`.


Testing
-------

Please report back whether pywebcorp assists to access
the internet from your network.

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
-   There is a gssapi (cross-platform analog of SSPI) python library, but it
    does not support MS-Windows.

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
