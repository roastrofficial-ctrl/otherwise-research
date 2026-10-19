"""Two independent byte transports; neither decides protocol facts.
HTTP is allowed only on the explicitly enabled isolated laboratory network.
"""
import http.client
import os
import ssl
import urllib.request
import urllib.error
from urllib.parse import urlsplit
from Bounded.wire import strict_json
from Engine.protocol import canonical

class UrllibTransport:
    def __init__(self,cafile=None):self.context=ssl.create_default_context(cafile=cafile)
    def call(self,url,body=None):
        check_url(url)
        req=urllib.request.Request(url,data=None if body is None else canonical(body),headers={'Content-Type':'application/json'})
        try:
            with urllib.request.urlopen(req,timeout=3,context=self.context) as r:return strict_json(r.read())
        except urllib.error.HTTPError as exc:raise ValueError(exc.read().decode()) from exc

class HttpClientTransport:
    def __init__(self,cafile=None):self.context=ssl.create_default_context(cafile=cafile)
    def call(self,url,body=None):
        check_url(url)
        u=urlsplit(url)
        cls=http.client.HTTPSConnection if u.scheme=='https' else http.client.HTTPConnection
        c=cls(u.hostname,u.port,timeout=3,**({'context':self.context} if u.scheme=='https' else {}))
        try:
            c.request('GET' if body is None else 'POST',u.path+('?' +u.query if u.query else ''),None if body is None else canonical(body),{'Content-Type':'application/json'})
            r=c.getresponse();raw=r.read()
            if r.status!=200:raise ValueError(raw.decode())
            return strict_json(raw)
        finally:c.close()

def check_url(url):
    u=urlsplit(url)
    if u.scheme!='https' and not(u.scheme=='http' and os.environ.get('OTHERWISE_LAB_HTTP')=='1'):
        raise ValueError('HTTPS required outside isolated laboratory')
    if u.username or u.password:raise ValueError('URL credentials forbidden')
