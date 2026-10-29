"""Independent recipient has no owner signing seed or committee secrets.
The expected commitment and ciphertext must be independently authenticated locally.
"""
import argparse,base64,getpass,json,os
from pathlib import Path
from Engine.protocol import digest
from Bounded.wire import strict_json
from Available.proofs import require,fence,record
from Untrusted.proofs import snapshot
from Untrusted.vault import opened
from Honest.protocol import evidence_snapshot
from .protocol import commitment
from .collect import Transport,gather
from .client import recover

def verify(config,package):
    require(set(config)=={'sidecar','ciphertext','recipient_seed','witnesses'},'recipient configuration fields')
    require(set(package)=={'certificate','contributions'},'recipient proof package; SaaS booleans are not evidence')
    c,m=commitment(config['sidecar']);nonce=os.urandom(32).hex();net=Transport(.8)
    require(len(config['witnesses'])==4,'pinned witness endpoint count')
    def valid(i,r):
        q=snapshot(c['manifest'],r,nonce,i+1)
        for item in q['records']:
            kind=item['message']['kind'];(fence if kind in ('ARM','DISARM') else record)(m,item,kind)
        return r
    got=gather(list(range(4)),lambda i:net.call(config['witnesses'][i]+'/inspect',{'capsule':m['capsule'],'nonce':nonce}),valid,3,deadline=1.2,workers=4);require(got['sufficient'],'recipient has no fresh independent evidence quorum')
    _,history,_=evidence_snapshot(c['manifest'],list(got['valid'].values()),nonce,{})
    return recover(config['sidecar'],base64.b64decode(config['ciphertext']),config['recipient_seed'],package['certificate'],package['contributions'],history)

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--vault',required=True);p.add_argument('--bundle',required=True);a=p.parse_args();password=os.environ.get('OTHERWISE_CREATOR_PASSPHRASE') or getpass.getpass('Recipient vault passphrase: ')
    with opened(a.vault,password) as cfg:plain=verify(cfg,strict_json(Path(a.bundle).read_bytes()))
    print(json.dumps({'delivery':'SIMULATED','plaintext':plain.decode(),'independently_verified':True}))
if __name__=='__main__':main()
