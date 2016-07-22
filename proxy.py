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


try:
    import sspi
except ImportError:
    raise ImportError # TODO: ctypes! (nb. should do that in a try block too)
  
def sspiauth(scheme='NTLM'):
    handle = sspi.ClientAuth(scheme)
    def generate_answer(challenge=None):
        if challenge is not None:
            assert challenge.startswith(scheme) # or, could be a series of challenge options?
            challenge = base64.b64decode(challenge[len(scheme):])
        status, token_buffer = handle.authorize(challenge)
        token = scheme + ' ' + base64.b64encode(token_buffer[0].Buffer)
        return token
    return generate_answer

class ntlm_http:
    def __init__(self, host, port, credentials=None, isproxy=False):
        self.unauth = 407 if isproxy else 401
        self.toserver = ('Proxy-' if isproxy else '') + 'Authorization'
        self.fromserv = ('Proxy-' if isproxy else '') + 'Authenticate'
        
        self.credentials = sspiauth() if credentials is None else credentials

        self.destination = host, port        
        self.conn = httplib.HTTPConnection(*self.destination)     

    def _http(self,kind,url,headers={}):
        """ standard (non-NTLM) HTTP request and response """
        self.conn.request(kind,url,headers=headers)
        return self.conn.getresponse()
        
    def do_request_and_get_response(self,kind,url):
        """
        NTLM HTTP handshake protocol:
            Client: try to connect and request resource
            Server: reject the request and close connection
            Client: reattempt and send negotiation token (NTLM type 1 message)
            Server: reject and send challenge token (NTLM type 2 message)
            Client: respond with authorisation token (NTLM type 3 message)
            Server: deliver resource
            Client: request another resource
            Server: deliver resource
            ...
        """        
        r = self._http(kind,url) # knock first
        
        if r.status == self.unauth: # perform NTLM handshake if necessary            
            r.read()
            assert r.isclosed()            
            self.conn = httplib.HTTPConnection(*self.destination)   # reconnect
            r = self._http(kind,url,
                           headers={self.toserver:self.credentials()}) # negotiate
            r.read()
            challenge = r.getheader(self.fromserv)
            r = self._http(kind,url,
                           headers={self.toserver:self.credentials(challenge)}) # authenticate
        # handshake either completed or was never necessary so now fall
        # back to standard implementation until connection closed
        self.do_request_and_get_response = self._http
        return r
            
#proxyhost,proxyport = "proxy.mydomain.org",8080
autodetect = urlparse.urlparse(urllib.getproxies()['http'])
proxyhost = autodetect.hostname
proxyport = autodetect.port       
    
connection_via_proxy = ntlm_http(proxyhost,proxyport,isproxy=True)
for url in ["http://www.google.com.au","http://www.bbc.com/news"]:
    r = connection_via_proxy.do_request_and_get_response('GET',url)
    assert r.status == 200 # OK
    print r.read().lower().split('title')[1]


# ==================================== Refactor?
"""
With an open socket, use conn.request and conn.getresponse.

Should have a ntlm object, that takes requests and produces responses.
It could be implemented simply as a factory function.
Can defer deciding which to subclass among httplib, urllib 1-3, & requests
Structure in a way so that the same ntlm handshake code isn't just for proxies.

Regarding credentials, wish to have a stateful thing
that takes a challenge (or none) and produces a token.
This can also be implemented as a factory function, without needing a class.
However, imply that it should be a subclass of a general credential
thing, of which a sister class would take manually input user/pass.
This only involves two subfunction calls (corresponding with the winapi).
Should have two implementations, pywin32(sspi) and ctypes.

So ultimately, the user is saying: do normal GETs, but use a connection
to my autodetected proxy, and use ntlm for the proxy, with single sign-on.
But imply they could use a different proxy, or a different signon,
or an authenticated host with no proxy, and with or without pywin32 dependency.
At minimum. Ideally should be extendable to other authentication protocols,
and enabling single sign-on from other operating systems.
"""
# ==================================== ctypes instead of pywin32 (sspi) ?
"""
def ntlm(isproxy=False):
    unauth = 407 if isproxy else 401
    toserver = ('Proxy-' if isproxy else '') + 'Authorization'
    fromserv = ('Proxy-' if isproxy else '') + 'Authenticate'
    yield {} # knock first with no auth
    # if ntlm then need to reconnect
    yield {toserver:token}# type 1
    # read type 2
    yield {toserver:token}# type 3 
    while True:
        yield {} # no further auth needed
        
try:
    import sspi
    def win32sspi(scheme='NTLM'):
        handle = sspi.ClientAuth(scheme)
        def generate_answer(challenge=None):
            status, token_buffer = handle.authorize(challenge)
            token = base64.b64encode(token_buffer[0].Buffer)
            return status, token
        return generate_answer
except ImportError:
    raise ImportError # TODO: ctypes!
    
status, token_buffer = credentials.authorize(None)
assert status # authentication incomplete
#token = base64.encodestring(token_buffer[0].Buffer).replace("\012", "")
token = 

negotiate = {'Proxy-Authorization': scheme + ' ' + token}
"""