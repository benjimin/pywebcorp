"""
Demonstration of NTLM HTTPS

A walk-through of the handshake (fully unwrapped flow-control loops)
"""

example = "https://repo.continuum.io/"


import urllib
import urlparse
proxyhost, proxyport = (lambda x: (x.hostname, x.port))(urlparse.urlparse(urllib.getproxies()['https']))
desthost, destport = urlparse.urlparse(example).hostname, 443
tunnel_resource = '%s:%i' % (desthost, destport)

import httplib
conn = httplib.HTTPConnection(proxyhost, proxyport)
conn.request('CONNECT', tunnel_resource) # treat tunnelling like any other request verb

conn._method = 'HEAD' # response class should not try to consume a message body
r = conn.getresponse()

assert r.status == 407 # ---- knock is complete

import sspiauth
credentials = sspiauth.sspi_ntlm_auth()

# refresh connection
import socket
conn.sock = socket.create_connection((proxyhost, proxyport), conn.timeout, conn.source_address)
#conn = httplib.HTTPConnection(proxyhost, proxyport) # can we achieve this without actually doing this?

conn.request('CONNECT', tunnel_resource, headers={'Proxy-Authorization':credentials()}) # Negotiate.

conn._method = 'HEAD' # response class should not try to consume a message body
r = conn.getresponse()
challenge = r.getheader('Proxy-Authenticate')
r.read() # change state (finish with this response to permit the next)

assert challenge.startswith('NTLM ') # note, this assertion is excessively restrictive; ".contains" might be preferable
assert r.getheader('Connection').lower() == 'Keep-Alive'.lower()

conn.request('CONNECT', tunnel_resource, headers={'Proxy-Authorization':credentials(challenge)})
conn._method = 'HEAD' # response class should not try to consume a message body
r = conn.getresponse()
r.read() # change state
#r.read(amt=0)
assert r.status == 200

conn2 = httplib.HTTPSConnection(desthost, destport) # Now switch to Secure
import mock
with mock.patch('socket.create_connection') as creator: # don't create a new socket
    creator.return_value = conn.sock # use the same socket
    conn2.connect() # apply TLS/SSL wrapper now
assert conn2.sock is not None
assert conn2.sock is not conn.sock
assert conn2.sock.fileno() == conn.sock.fileno()

conn2.request('GET', example)
r = conn2.getresponse()

assert r.status == 200

print r.read()