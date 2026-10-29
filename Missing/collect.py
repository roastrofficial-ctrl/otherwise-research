"""Bounded concurrent collection. Timeout is uncertainty, never evidence of absence.
Workers only do bounded I/O; validation and state changes remain on the caller thread.
"""
import concurrent.futures
import time
import ssl
import http.client
import threading
import socket
from urllib.parse import urlsplit
from Engine.protocol import canonical
from Bounded.wire import strict_json
from Available.transport import check_url
from Available.proofs import require

class Transport:
    def __init__(self,timeout=1.5):self.timeout=timeout;self.context=ssl.create_default_context()
    def call(self,url,body=None):
        check_url(url);u=urlsplit(url);stop=time.monotonic()+self.timeout
        cls=http.client.HTTPSConnection if u.scheme=='https' else http.client.HTTPConnection
        c=cls(u.hostname,u.port,timeout=self.timeout,**({'context':self.context} if u.scheme=='https' else {}));expired=threading.Event()
        def abort():
            expired.set()
            if c.sock is not None:
                try:c.sock.shutdown(socket.SHUT_RDWR)
                except OSError:pass
                c.close()
        timer=threading.Timer(self.timeout,abort);timer.daemon=True;timer.start()
        try:
            c.connect();require(not expired.is_set() and time.monotonic()<stop,'transport absolute deadline')
            c.request('GET' if body is None else 'POST',u.path+('?' +u.query if u.query else ''),None if body is None else canonical(body),{'Content-Type':'application/json'})
            r=c.getresponse();raw=r.read(1_000_001)
            require(len(raw)<=1_000_000,'response exceeds one-megabyte bound')
            require(not expired.is_set() and time.monotonic()<stop,'transport absolute deadline')
            if r.status!=200:raise ValueError(raw.decode())
            return strict_json(raw)
        finally:timer.cancel();c.close()

def gather(items,fetch,validate,needed,deadline=2.2,workers=6):
    """Return independently validated results sorted by configured source identity.
    Await all responses until deadline, so quick minority data cannot select the head.
    Payload evidence is retained for invalid replies; pending work cannot mutate state.
    Socket timeout must bound underlying I/O; arbitrary callbacks may outlive return.
    """
    require(1<=workers<=12 and len(items)<=12 and 0<deadline<=30,'collector resource bounds')
    pool=concurrent.futures.ThreadPoolExecutor(max_workers=min(workers,max(1,len(items))))
    futures={pool.submit(fetch,item):item for item in items};good={};bad=[];stop=time.monotonic()+deadline
    pending=set(futures)
    while pending:
        remaining=stop-time.monotonic()
        if remaining<=0:break
        done,pending=concurrent.futures.wait(pending,timeout=remaining,return_when=concurrent.futures.FIRST_COMPLETED)
        for f in done:
            item=futures[f];raw=None
            try:
                raw=f.result();value=validate(item,raw);require(item not in good,'duplicate responder');good[item]=value
            except Exception as e:bad.append({'source':item,'reason':str(e),'response':raw})
    for f in pending:f.cancel();bad.append({'source':futures[f],'reason':'deadline; unknown outcome','response':None})
    pool.shutdown(wait=False,cancel_futures=True)
    return {'valid':{k:good[k] for k in sorted(good)},'invalid':sorted(bad,key=lambda r:str(r['source'])),'sufficient':len(good)>=needed}
