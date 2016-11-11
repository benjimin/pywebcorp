"""  
Question: does my proxy use NTLM? (For HTTP/S?)

"""



def req(url):
    """using requests as-is"""
    import requests
    try:
        return requests.get(url).status_code
    except requests.exceptions.ProxyError:
        return "Proxy error"


def do_test(f):
    examples = {'http': "http://stackoverflow.com",
                'https': "https://repo.continuum.io/"}
    print
    print f.__doc__
    for key,url in examples.items():
        print key+'\t', f(url)

import httplib
cls = {'http':httplib.HTTPConnection,'https':httplib.HTTPSConnection}

def direct(url):
    """direct with no proxy"""
    import urlparse
    u = urlparse.urlparse(url)
    conn = cls[u.scheme](u.hostname, timeout=2)
    try:
        conn.request('GET',u.path)
    except httplib.socket.timeout:#httplib.socket.errno.ETIMEDOUT:
        return "No response"
    else:
        return conn.getresponse().status
        


def viaproxy(url, host, port, scheme):
    """
    
    Different kinds of proxy:
        
    CONNECT: used for https destinations
    GET: used for http destinations
    
    Does not depend on which scheme used to access the proxy.
    
    """
    conn = cls[scheme](host, port)
    if 'http:' in url:
        # HTTPGET style proxying
        conn.request('GET',url)
        return conn.getresponse().status
    elif 'https' in url:
        # CONNECT tunnel
        return "CONNECT not implemented yet"
    else:
        raise NotImplementedError

def proxyfactory(proxyscheme):
    import urllib
    import urlparse
    proxy = urlparse.urlparse(urllib.getproxies()[proxyscheme])
    def wrapper(url):
        return viaproxy(url, proxy.hostname, proxy.port, proxyscheme)
    wrapper.__doc__ = "via " + proxyscheme + '://' \
                      + proxy.hostname + ':' + str(proxy.port)
    return wrapper

if  __name__ == '__main__':
    #do_test(req)
    #do_test(direct)
    do_test(proxyfactory('http'))
    #do_test(proxyfactory('https'))