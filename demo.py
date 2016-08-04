"""
For test purposes: a demo of downloading webpages through the proxy.
"""

import urlparse
import urllib


#proxyhost,proxyport = "proxy.mydomain.org",8080
autodetect = urlparse.urlparse(urllib.getproxies()['http'])
proxyhost = autodetect.hostname
proxyport = autodetect.port       

from ntlmconn import ntlm_http
connection_via_proxy = ntlm_http(proxyhost,proxyport,isproxy=True)

for url in ["http://www.google.com.au","http://www.bbc.com/news"]:
    r = connection_via_proxy.do_request_and_get_response('GET',url)
    assert r.status == 200 # OK
    print r.read().lower().split('title')[1]
