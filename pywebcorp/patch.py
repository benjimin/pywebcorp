import urllib
import socket
import contextlib

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
    def request(self, *args, **kwargs):
        """Cache first request"""
        if not hasattr(self, 'original_request'):
            self.original_request = args
        return super(NTLMmixin, self).request(*args, **kwargs)
    def getresponse(self):
        self.getresponse = super(NTLMmixin, self).getresponse

        # Response to knock
        r = self.getresponse()

        assert r.status == 407
        self.sock = socket.create_connection((self.host, self.port), self.timeout, self.source_address)

        credentials = sspiauth.sspi_ntlm_auth()

        # Negotiate:
        self.request(*self.original_request, headers={'Proxy-Authorization':credentials()})
        r = self.getresponse()

        challenge = r.getheader('Proxy-Authenticate')
        r.read(amt=0) # change state (finish with this response to permit the next)

        assert challenge.startswith('NTLM ') # note, this assertion is excessively restrictive; ".contains" might be preferable
        assert r.getheader('Connection').lower() == 'Keep-Alive'.lower()

        self.request(*self.original_request, headers={'Proxy-Authorization':credentials(challenge)})

        try:
            self.close = lambda : None
            return self.getresponse()
        finally:
            del self.close # or, self.close = super(NTLMmixin, self).close


class NTLM_HTTP(NTLMmixin, urllib3.connection.HTTPConnection):
    def _tunnel(self):
        tunnel_resource = '%s:%i' % (self._tunnel_host, self._tunnel_port)
        self.request('CONNECT', tunnel_resource)
        r = self.getresponse()
        assert r.status == 200
        r.read(amt=0)


# Use Verified connection base if supported:
Parent = urllib3.connectionpool.HTTPSConnectionPool.ConnectionCls

class NTLM_HTTPS(NTLMmixin, Parent):
    def _tunnel(self):
        try:
            self.__class__ = NTLM_HTTP
            self._tunnel()
        finally:
            self.__class__ = NTLM_HTTPS
    def connect(self):
        """Ensure correct (not expired) socket receives secure wrapping"""
        original = urllib3.connection.ssl_wrap_socket
        def wrap_latest_socket(sock, *args, **kwargs):
            return original(self.sock, *args, **kwargs)
        with patch('requests.packages.urllib3.connection.ssl_wrap_socket',
                   new=wrap_latest_socket):
            return super(NTLM_HTTPS, self).connect()
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


if __name__ == '__main__':
    example = "https://repo.continuum.io/"
    import requests
    response = requests.get(example)
    print(response.text)