"""Standalone synthetic 0.7 creator. Local encrypted vault, independently pinned trust."""
import argparse,getpass,json,os
from pathlib import Path
from Bounded.wire import strict_json
from Untrusted.vault import opened
from .client import Client

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--vault',required=True);p.add_argument('--trust',required=True);p.add_argument('action',choices=['create','arm','checkin','status','disarm','evaluate','disclose']);p.add_argument('--rounds',type=int,default=2);p.add_argument('--seconds',type=int,default=120);p.add_argument('--challenge');a=p.parse_args()
    client=Client(strict_json(Path(a.trust).read_bytes()));password=os.environ.get('OTHERWISE_CREATOR_PASSPHRASE') or getpass.getpass('Local vault passphrase: ')
    with opened(a.vault,password,create=a.action=='create') as k:
        if a.action=='create':k.update(client.prepare(client.draft(a.rounds,a.seconds)));out={'state':'DRAFT','profile':7,'research_only':True}
        else:
            client.validate(k)
            if a.action=='status':out=client.inspect(k)
            elif a.action=='checkin':out=client.checkin(k,a.challenge)
            elif a.action=='disclose':
                d=client.evaluate(k);out={'delivery':'SIMULATED','plaintext':client.disclose(k,d['certificate']).decode()} if d['authorised'] else d
            else:out=getattr(client,a.action)(k)
        k['invalid_responses07']=json.loads(json.dumps(client.audit))
    print(json.dumps(out))
if __name__=='__main__':main()
