"""Cross-language freshness envelopes, in addition to unchanged lifecycle proofs."""
import copy
import hashlib
import json
import subprocess
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Engine.protocol import sign,canonical,digest
from scripts.conformance04 import corpus as previous
from Untrusted.proofs import snapshot

def corpus():
    sm=previous()[0]['input']['object']['manifest'];m=sm['message'];nonce='ab'*32
    key=Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'otherwise04-public-test-1').digest())
    r={'v':5,'kind':'INSPECT','capsule':m['capsule'],'manifest':digest(m),'nonce':nonce,'witness':1,'records':[],'clock':{'lower':5,'upper':5,'healthy':True,'reason':'fixture'}}
    good={'manifest':sm,'snapshot':{'message':r,'signature':sign(key,r)},'nonce':nonce,'index':1};items=[('fresh',good)]
    for kind in ['stale','scope','source','signature','clock','extension','version','boolean-time','unhealthy','missing-records','manifest-quorum','manifest-destination','manifest-epoch']:
        x=copy.deepcopy(good);r=x['snapshot']['message']
        if kind.startswith('manifest-'):
            m=x['manifest']['message']
            if kind=='manifest-quorum':m['quorum']['presence']=2
            elif kind=='manifest-destination':m['policy']['destination']['kind']='public'
            else:m['epoch']=2
            owner=Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'otherwise04-public-test-0').digest());x['manifest']['signature']=sign(owner,m);r['manifest']=digest(m)
        elif kind=='stale':x['nonce']='cd'*32
        elif kind=='scope':r['capsule']='other'
        elif kind=='source':x['index']=2
        elif kind=='signature':x['snapshot']['signature']='00'*64
        elif kind=='clock':r['clock']['upper']=0
        elif kind=='extension':r['extra']='ignored?'
        elif kind=='version':r['v']=4
        elif kind=='boolean-time':r['clock']['lower']=True
        elif kind=='unhealthy':r['clock']['healthy']=False
        else:r['records']=None
        if kind!='signature':x['snapshot']['signature']=sign(key,r)
        items.append((kind,x))
    return items

def main():
    from pathlib import Path
    items=corpus();path=Path('Protocol/vectors/generation05.json')
    if path.exists():assert json.loads(path.read_text())==[[name,x] for name,x in items],'fixed freshness corpus drift'
    p=subprocess.run(['node','Verifier/untrusted.mjs','--lines'],input=b'\n'.join(canonical(x) for _,x in items)+b'\n',capture_output=True,check=True);actual=[json.loads(s) for s in p.stdout.splitlines()]
    for (name,x),r in zip(items,actual):
        try:snapshot(x['manifest'],x['snapshot'],x['nonce'],x['index']);ok=True
        except Exception:ok=False
        assert r['ok']==ok,(name,r,ok)
    assert len(actual)==len(items)
    print(json.dumps({'freshness_vectors':len(items),'disagreements':0,'scope':'fresh signed envelopes; wire-v4 receipt/release semantics separately verified'},indent=2))
if __name__=='__main__':main()
