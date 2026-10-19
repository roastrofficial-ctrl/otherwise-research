"""python -m Available.cli --kit /recovery/solo.json create|arm|checkin|status|disarm|evaluate|simulate|repair"""
import argparse
import json
import os
from pathlib import Path
from Bounded.wire import atomic_json,strict_json
from .lifecycle import Client
from .transport import HttpClientTransport

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kit',required=True);p.add_argument('--transport',choices=['urllib','httpclient'],default='urllib');p.add_argument('action',choices=['create','arm','checkin','status','disarm','evaluate','simulate','repair']);p.add_argument('--index',type=int,default=1);p.add_argument('--challenge');p.add_argument('--seconds',type=int,default=120);p.add_argument('--rounds',type=int,default=2);a=p.parse_args()
    c=Client(HttpClientTransport() if a.transport=='httpclient' else None)
    if a.action=='create':
        kit=c.draft(os.environ['WITNESSES'].split(','),os.environ['CUSTODIANS'].split(','),a.rounds,a.seconds);out={'created':kit['manifest']['message']['capsule']}
    else:
        kit=strict_json(Path(a.kit).read_bytes())
        if a.action=='status':out=c.recover(kit)
        elif a.action=='checkin':out=c.checkin(kit,a.challenge)
        elif a.action=='repair':out=c.repair(kit,a.index)
        elif a.action=='simulate':
            decision=c.evaluate(kit);out=c.simulate(kit,decision['certificate']) if decision['authorised'] else decision
        else:out=getattr(c,a.action)(kit)
    atomic_json(a.kit,kit) # fsync before displaying successful check-in
    print(json.dumps(out,indent=2))
if __name__=='__main__':main()
