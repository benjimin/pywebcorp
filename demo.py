"""
For test purposes: a demo of downloading webpages through the proxy.

Expected output should resemble:
    google
    home - bbc news

"""

import urlparse
import urllib
import logging
logging.basicConfig(level=logging.DEBUG)

autodetect = urlparse.urlparse(urllib.getproxies()['http'])
proxyhost = autodetect.hostname # e.g. "proxy.mydomain.org"
proxyport = autodetect.port     # e.g. 8080

from ntlmconn import ntlm_http
connection_via_proxy = ntlm_http(proxyhost,proxyport,isproxy=True)

for url in ["http://www.google.com.au","http://www.bbc.com/news"]:
    r = connection_via_proxy.do_request_and_get_response('GET',url)
    assert r.status == 200 # OK
    print r.read().lower().split('title')[1][1:-2] # parse webpage content
    
"""  
import requests
#r = requests.get("http://stackoverflow.com")
r = requests.get("https://repo.continuum.io/")
print r.status_code
print r.text.lower().split('title')[1]
"""