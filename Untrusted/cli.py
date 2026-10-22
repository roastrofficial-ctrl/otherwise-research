"""Independently installed local owner client; never execute software from SaaS."""
import argparse
import getpass
import json
import os
from pathlib import Path
from Bounded.wire import atomic_json,strict_json
from Available.transport import UrllibTransport,HttpClientTransport
from Available.proofs import require
from .client import Client,public,validate_public,RelayTransport
from .vault import opened,unseal

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--vault',required=True);p.add_argument('--trust',required=True);p.add_argument('--transport',choices=['urllib','httpclient'],default='urllib');p.add_argument('--relay');p.add_argument('action',choices=['create','arm','checkin','status','recover','disarm','evaluate','simulate','repair','public','publish','backup','restore','rotate']);p.add_argument('--seconds',type=int,default=120);p.add_argument('--rounds',type=int,default=2);p.add_argument('--challenge');p.add_argument('--index',type=int,default=1);p.add_argument('--out');p.add_argument('--saas');a=p.parse_args()
    trust=strict_json(Path(a.trust).read_bytes());net=HttpClientTransport() if a.transport=='httpclient' else UrllibTransport()
    if a.relay:net=RelayTransport(a.relay,[x['url'] for x in trust['providers'] if x['role']=='witness'],net)
    c=Client(trust,net);password=os.environ.get('OTHERWISE_CREATOR_PASSPHRASE') or getpass.getpass('Local recovery passphrase: ')
    if a.action=='restore':
        require(a.out is not None,'--out backup path required');restored=unseal(strict_json(Path(a.out).read_bytes()),password);c.validate(restored)
        with opened(a.vault,password,create=True) as kit:kit.update(restored)
        print(json.dumps({'restored':True,'authority':'same backed-up owner; old device is not revoked'}));return
    if a.action=='rotate':
        require(a.out is not None and not Path(a.out).exists(),'new --out vault required')
        with opened(a.vault,password) as old:result=c.run(old,'disarm')
        # Old disarm is persisted before creating a fresh policy/identity. Not atomic.
        # Persist the fresh signing capability BEFORE any new arming side effect.
        with opened(a.out,password,create=True) as new:new.update(c.draft(a.rounds,a.seconds))
        with opened(a.out,password) as new:c.run(new,'arm')
        print(json.dumps({'old':result,'new':'ARMED','rotation':'fresh Capsule; old key cannot authorise new Capsule'}));return
    with opened(a.vault,password,create=a.action=='create') as kit:
        if a.action=='create':kit.update(c.draft(a.rounds,a.seconds));out={'created':kit['manifest']['message']['capsule'],'owner':kit['manifest']['message']['policy']['owner']}
        elif a.action=='public':
            require(a.out is not None,'--out required');atomic_json(a.out,validate_public(public(kit)));out={'public_export':a.out}
        elif a.action=='publish':
            require(a.saas is not None,'--saas required');projection=validate_public(public(kit));UrllibTransport().call(a.saas+'/mirror',projection);out={'published_public_projection':True,'authoritative_status':False}
        elif a.action=='backup':out={'backup_after_commit':a.out};require(a.out is not None and not Path(a.out).exists(),'fresh --out backup path required')
        else:out=c.run(kit,a.action,challenge=a.challenge,index=a.index)
    if a.action=='backup':atomic_json(a.out,strict_json(Path(a.vault).read_bytes()))
    print(json.dumps(out,indent=2))
if __name__=='__main__':main()
