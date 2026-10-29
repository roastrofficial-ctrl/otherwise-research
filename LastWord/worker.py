"""Creator/SaaS-independent public relay. Receives no owner or recipient secret."""
import argparse,json
from pathlib import Path
from Bounded.wire import strict_json,atomic_json
from Available.proofs import require
from .client import Client

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--kit',required=True);p.add_argument('--out',required=True);a=p.parse_args();k=strict_json(Path(a.kit).read_bytes())
    require('owner_seed' not in k and 'recipient_seed' not in k and 'shares' not in k,'public worker must not receive private capability')
    c=Client(k['trust']);fin=c.retained_decision(k)
    if fin is None:
        e=c.evaluate(k);require(e['policy_satisfied'],'policy not satisfied');fin=c.commit_release(k,e['evidence_certificate'])
    package=c.collect_release(k,fin);atomic_json(a.out,package);print(json.dumps({'release_commitment':True,'package_written':True,'creator_secret_received':False,'plaintext_known':False}))
if __name__=='__main__':main()
