import urllib
import socket
import contextlib
import threading

try:
    from . import sspiauth
except ValueError:
    import sspiauth

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

import requests.packages.urllib3 as urllib3


class NTLMmixin(object):
    def request(self, method, url, body=None, headers={}):
        """Cache request"""
        self._latest_request = method, url, body, headers
        return super(NTLMmixin, self).request(method, url, body, headers)
    def getresponse(self):
        # NTLM handshake does not occur for subsequent requests
        self.getresponse = super(NTLMmixin, self).getresponse

        # Response to knock
        r = self.getresponse()
        if not r.status == 407: # bypass if NTLM not needed
            return r

        def rerequest(headers):
            """Repeat previous request with updated headers"""
            self._latest_request[-1].update(headers)
            return self.request(*self._latest_request)

        # Reconnect and Negotiate
        self.sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)
        credentials = sspiauth.sspi_ntlm_auth()
        rerequest(headers={'Proxy-Authorization':credentials()})

        # Obtain challenge from server
        r = self.getresponse()
        challenge = r.getheader('Proxy-Authenticate')
        r.read(amt=0) # change state (finish with this response to permit the next)
        assert challenge.startswith('NTLM ') # note, this assertion is excessively restrictive; ".contains" might be preferable
        assert r.getheader('Connection').lower() == 'Keep-Alive'.lower()

        # Answer challenge
        rerequest(headers={'Proxy-Authorization':credentials(challenge)})
        try:
            self.close = lambda : None
            return self.getresponse()
        finally:
            del self.close # or, self.close = super(NTLMmixin, self).close

HTTP = urllib3.connection.HTTPConnection
HTTPS = urllib3.connectionpool.HTTPSConnectionPool.ConnectionCls
# Note, HTTPS may or may not be verified subclass.

class NTLM_HTTP(NTLMmixin, HTTP):
    def _tunnel(self):
        """Treat tunnels like any other HTTP request"""
        tunnel_resource = '%s:%i' % (self._tunnel_host, self._tunnel_port)
        self.request('CONNECT', tunnel_resource)
        r = self.getresponse()
        assert r.status == 200
        r.read(amt=0)

threadsafety = threading.Lock()

class NTLM_HTTPS(NTLMmixin, HTTPS):
    def _tunnel(self):
        """Negotiate tunnel before adding secure layer"""
        try:
            original, self.__class__ = self.__class__, NTLM_HTTP
            return self._tunnel()
        finally:
            self.__class__ = original
    def connect(self):
        """Ensure correct (not expired) socket receives secure wrapping"""
        # The base connection class assumed the socket does not change when
        # tunnelling (between opening the socket-connection and applying
        # secure wrapper), so may (during .connect() method) inadvertently
        # apply wrapper to expired socket instead. Tricky patch since multiple
        # HTTPS classes need fixing, socket not very amenable to adding
        # attributes, and ssl wrapper is a global.
        with threadsafety:
            original = urllib3.connection.ssl_wrap_socket
            def wrap_latest_socket(sock, *args, **kwargs): # discard old sock
                return original(self.sock, *args, **kwargs)
            try:
                urllib3.connection.ssl_wrap_socket = wrap_latest_socket
                return super(NTLM_HTTPS, self).connect()
            finally:
                urllib3.connection.ssl_wrap_socket = original
    def request(self, method, url, *args, **kwargs):
        """Ensure absolute URI (client must name host, not only path)"""
        # Required by HTTP1.1 when using proxies, and by later HTTP always.
        u = urllib3.util.parse_url(url)
        if u.scheme is None:
            u = u._replace(scheme='https')
        if u.host is None:
            u = u._replace(host = self._tunnel_host or self.host)
        return super(NTLM_HTTPS, self).request(method, u.url, *args, **kwargs)


# apply patch to urllib3 package for remainder of this python session
urllib3.connectionpool.HTTPSConnectionPool.ConnectionCls = NTLM_HTTPS
urllib3.connectionpool.HTTPConnectionPool.ConnectionCls = NTLM_HTTP


if __name__ == '__main__':
    example = "https://repo.continuum.io/"
    import requests
    response = requests.get(example)
    print(response.text)
