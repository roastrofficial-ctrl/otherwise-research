import os
import time
from pathlib import Path
from Bounded.wire import request,atomic_json
from Honest.client import Client
W=os.environ['WITNESSES'].split(',');K=os.environ['CUSTODIANS'].split(',');TOKEN=os.environ['OTHERWISE_05_FAULT_TOKEN']
def ready(urls=None):
    for u in urls or W+K:
        end=time.monotonic()+50
        while True:
            try:request(u+'/identity');break
            except Exception:
                if time.monotonic()>end:raise
                time.sleep(.2)
def configured():
    ready();trust={'v':5,'providers':[{'role':role,'url':u,'public':request(u+'/identity')['public']} for role,urls in [('witness',W),('custodian',K)] for u in urls]}
    Path('/recovery').mkdir(exist_ok=True);return trust,Client(trust)
def move(kit,delta):
    base=kit['manifest']['message']['policy']['contracts'][0]['start'];now=max(base+delta,max(request(u+'/clock')['upper'] for u in W))
    for u in W:request(u+'/test-clock',{'now':now},TOKEN)
