"""
This is the logic for NTLM HTTP connections.
"""

from sspiauth import sspiauth
import httplib

class ntlm_http:
    def __init__(self, host, port, credentials=None, isproxy=False):
        self.unauth = 407 if isproxy else 401
        self.toserver = 'Proxy-'*isproxy + 'Authorization'
        self.fromserv = ('Proxy-' if isproxy else 'WWW-') + 'Authenticate'
        
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
  