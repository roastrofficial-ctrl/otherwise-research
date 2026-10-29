"""Independent creator client; success is an authenticated terminal certificate."""
import argparse,getpass,json,os
from pathlib import Path
from Bounded.wire import strict_json
from Untrusted.vault import opened
from .client import Client
from .recipient import verify

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--vault',required=True);p.add_argument('--trust',required=True);p.add_argument('action',choices=['create','arm','checkin','policy','status','recover','disarm','commit','disclose']);p.add_argument('--rounds',type=int,default=2);p.add_argument('--seconds',type=int,default=120);p.add_argument('--challenge');a=p.parse_args();c=Client(strict_json(Path(a.trust).read_bytes()));password=os.environ.get('OTHERWISE_CREATOR_PASSPHRASE') or getpass.getpass('Local vault passphrase: ')
    with opened(a.vault,password,create=a.action=='create') as k:
        if a.action=='create':k.update(c.prepare(c.draft(a.rounds,a.seconds)));out={'state':'DRAFT','profile':8}
        elif a.action=='policy':out=c.evaluate(k)
        elif a.action=='status':out=c.statuses(k)
        elif a.action=='recover':out={'evidence':c.inspect(k),'terminal_status':c.statuses(k)}
        elif a.action=='checkin':out=c.checkin(k,a.challenge)
        elif a.action in ('commit','disclose'):
            e=c.evaluate(k)
            if not e['policy_satisfied']:out=e
            else:
                fin=c.commit_release(k,e['evidence_certificate']);out={'terminal_certificate':fin,'plaintext_disclosed':False}
                if a.action=='disclose':out=verify({'registry':k['custody08'],'ciphertext':k['ciphertext'],'recipient_seed':k['recipient_seed']},c.collect_release(k,fin))
        else:out=getattr(c,a.action)(k)
    print(json.dumps(out))
if __name__=='__main__':main()
