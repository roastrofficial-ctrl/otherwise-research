"""Synthetic-only standalone 0.6 client; encrypted local capability, never SaaS code."""
import argparse
import getpass
import json
import os
from pathlib import Path
from Bounded.wire import strict_json
from Untrusted.vault import opened
from Honest.client import Client
from Honest.crypto import dealer

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--vault',required=True);p.add_argument('--trust',required=True)
    p.add_argument('action',choices=['create','arm','checkin','status','disarm','evaluate','disclose']);p.add_argument('--rounds',type=int,default=2);p.add_argument('--seconds',type=int,default=120);p.add_argument('--challenge')
    a=p.parse_args();trust=strict_json(Path(a.trust).read_bytes());client=Client(trust)
    password=os.environ.get('OTHERWISE_CREATOR_PASSPHRASE') or getpass.getpass('Local recovery passphrase: ')
    with opened(a.vault,password,create=a.action=='create') as kit:
        if a.action=='create':
            draft=client.draft(a.rounds,a.seconds);client.prepare_custody(draft,dealer());del draft['shares'];kit.update(draft)
            out={'state':'DRAFT','custody':'unreviewed synthetic research harness'}
        else:
            client.validate(kit)
            if a.action=='status':out=client.inspect(kit)
            elif a.action=='checkin':out=client.checkin(kit,a.challenge)
            elif a.action=='disclose':
                d=client.evaluate(kit)
                out={'delivery':'SIMULATED','plaintext':client.disclose(kit,d['certificate']).decode()} if d['authorised'] else d
            else:out=getattr(client,a.action)(kit)
    print(json.dumps(out))  # Success only after local encrypted vault commit.
if __name__=='__main__':main()
