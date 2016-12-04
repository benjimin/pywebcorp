"""



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

conn = httplib.HTTPConnection(proxyhost, proxyport)
conn.request('CONNECT', tunnel_resource, headers={'Proxy-Authorization':credentials()}) 

conn._method = 'HEAD' # response class should not try to consume a message body
r = conn.getresponse()
challenge = r.getheader('Proxy-Authenticate')
r.read() # change state (finish with this response to permit the next)

assert challenge.startswith('NTLM ') # note, this is overly restrictive
assert r.getheader('Connection').lower() == 'Keep-Alive'.lower()

conn.request('CONNECT', tunnel_resource, headers={'Proxy-Authorization':credentials(challenge)}) 
conn._method = 'HEAD' # response class should not try to consume a message body
r = conn.getresponse()
r.read() # change state

assert r.status == 200

conn2 = httplib.HTTPSConnection(desthost, destport) # Now switch to Secure
#conn2.create_connection = lambda *a,**kw: conn.sock # but use same socket
import mock
with mock.patch('socket.create_connection') as creator:
    creator.return_value = conn.sock
    conn2.connect()
assert conn2.sock is not None
assert conn2.sock is not conn.sock
assert conn2.sock.fileno() == conn.sock.fileno()

conn2.request('GET', example)
r = conn2.getresponse()

assert r.status == 200

print r.read()



'''
import logging 
logging.basicConfig(level=logging.INFO)

class Debugger:
    dtype = None # is this an IDE bug?
    def __init__(self, target, name=None):
        self.wrapped = target
        self.logger = logging.getLogger(name or target.__name__)
    def __repr__(self): # don't be noisy about this one
        return self.wrapped.__repr__()
    def __getattr__(self, attr):
        log = self.logger
        log.debug('wrapping '+str(attr))
        original = self.wrapped.__getattribute__(attr)        
        def decorated(*args, **kwargs):
            try:
                ret = original(*args, **kwargs)
                if str(attr) == 'makefile':
                    log.debug('!!!')
                    # how does this get used?
                    ret = Debugger(ret, 'filepointer')
                return ret
            except Exception as err:
                ret = err
                raise err
            finally:
                log.info([attr, args, kwargs, ret])
        return decorated
def debugfactory(cls):
    def wrapper(*args, **kwargs):
        instance = cls(*args, **kwargs)
        return Debugger(instance, 'sock')
    return wrapper
def debug():
    """
    Normally, the first signal that something is wrong is the 407.
    
    That is, knock complete, connection closing.
    
    To do NTLM, must then retry, offering earlier to authenticate.
    Thus, HTTPS-CONNECT is not so different from plain HTTP-proxy.
    """
    import urllib
    import urlparse
    import socket
    proxy = urlparse.urlparse(urllib.getproxies()['https'])
    url = urlparse.urlparse(examples['https'])
    
    import mock
    fakesocket = debugfactory(socket.socket)
    with mock.patch('socket.socket', new=fakesocket) as patch:
        conn = httplib.HTTPSConnection(proxy.hostname, proxy.port)
        conn.set_tunnel(url.hostname)
        try:
            conn.request('GET',url.path)
        except socket.error as err:
            if '407' not in err.message:
                raise err
            return '407'
        return conn.getresponse().status    
'''