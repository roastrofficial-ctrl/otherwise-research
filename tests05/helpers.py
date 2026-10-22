import os
import time
from pathlib import Path
from Bounded.wire import request,atomic_json
from Available.transport import UrllibTransport
from Untrusted.client import Client
W=os.environ['WITNESSES'].split(',');K=os.environ['CUSTODIANS'].split(',');TOKEN=os.environ['OTHERWISE_05_FAULT_TOKEN'];HOSTILE=os.environ['HOSTILE_TOKEN']
def trust():return {'v':5,'providers':[{'role':role,'url':u,'public':request(u+'/identity')['public']} for role,urls in [('witness',W),('custodian',K)] for u in urls]}
def mode(value):return request('http://hostile:8080/test-mode',{'mode':value},HOSTILE)
def move(kit,delta):
    base=kit['manifest']['message']['policy']['contracts'][0]['start'];now=max(base+delta,max(request(u+'/clock')['upper'] for u in W))
    for u in W:request(u+'/test-clock',{'now':now},TOKEN)
def ready():
    for u in W+K:
        end=time.monotonic()+30
        while True:
            try:request(u+'/identity');break
            except Exception:
                if time.monotonic()>end:raise
                time.sleep(.1)
def configured():
    ready();t=trust();Path('/recovery').mkdir(exist_ok=True);atomic_json('/recovery/trust.json',t);return t,Client(t)
