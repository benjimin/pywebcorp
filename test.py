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


examples = {'http': "http://stackoverflow.com",
            'https': "https://repo.continuum.io/"}
def do_test(f):
    print f.__doc__
    for key,url in examples.items():
        print key+'\t', f(url)
    print

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
    #assert scheme == 'http'
    if 'http:' in url:
        # HTTPGET style proxying
        conn = cls[scheme](host, port)
        try:
            conn.request('GET',url)
        except httplib.ssl.SSLError:
            return "SSL error"
        return conn.getresponse().status
    elif 'https' in url:
        import urlparse
        u = urlparse.urlparse(url)
        conn = cls[scheme](host, port, timeout=2)
        conn.set_tunnel(u.hostname)
        try:
            conn.request('GET', u.path)
        except httplib.socket.timeout:
            return "Timeout"
        except httplib.socket.error as err:
            if err.errno == httplib.socket.errno.ETIMEDOUT:
                return "Time-out"
            if '407' in err.message:
                return "Proxy auth error"
            if '502' in err.message:
                return "Bad gateway " + ("(SSL port blocked)" if "SSL) port is not allowed" in err.message else '')
            raise err
        return conn.getresponse().status # currently timing out...
    else:
        raise NotImplementedError

def proxyfactory(proxyscheme):
    import urllib
    import urlparse
    proxy = urlparse.urlparse(urllib.getproxies()[proxyscheme])
    def wrapper(url):
        return viaproxy(url, proxy.hostname, proxy.port, proxyscheme)
    wrapper.__doc__ = "via " + proxyscheme + '  ' + proxy.hostname + ':' + str(proxy.port)
    return wrapper

if  __name__ == '__main__':
    do_test(req)
    do_test(direct)
    do_test(proxyfactory('http'))  
    do_test(proxyfactory('https'))