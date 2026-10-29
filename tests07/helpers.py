import os,time,json
from pathlib import Path
from Bounded.wire import request,atomic_json
from Missing.client import Client
W=os.environ['WITNESSES'].split(',');K=os.environ['CUSTODIANS'].split(',');A=os.environ['AUTHORITIES'].split(',');TOKEN=os.environ['OTHERWISE_05_FAULT_TOKEN']
def ready(urls=None):
    for u in urls or W+K+A:
        end=time.monotonic()+40
        while True:
            try:request(u+'/identity');break
            except Exception:
                if time.monotonic()>end:raise
                time.sleep(.1)
def configured():
    ready();trust={'v':5,'providers':[{'role':role,'url':u,'public':request(u+'/identity')['public']} for role,urls in [('witness',W),('custodian',K),('authority',A)] for u in urls]};Path('/recovery').mkdir(exist_ok=True);return trust,Client(trust)
def move(k,delta):
    base=k['manifest']['message']['policy']['contracts'][0]['start'];clocks={}
    for u in W:
        try:clocks[u]=request(u+'/clock')['upper']
        except Exception:pass
    assert len(clocks)>=3,'test-clock controller lacks a reachable quorum'
    now=max(base+delta,max(clocks.values()))
    for u in clocks:request(u+'/test-clock',{'now':now},TOKEN)
def export(k,urls):return [request(u+'/lab-export',{'capsule':k['manifest']['message']['capsule'],'all':True},TOKEN) for u in urls]
def fault(u,mode):return request(u+'/lab-fault',{'mode':mode},TOKEN)
