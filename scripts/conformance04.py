"""Reproducible signed corpus; independently evaluated by Python and Node."""
import copy
import hashlib
import itertools
import json
import subprocess
import sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Engine.protocol import digest,sign,canonical
from Available.proofs import acknowledgement,release,operation

def corpus():
    keys=[Ed25519PrivateKey.from_private_bytes(hashlib.sha256(('otherwise04-public-test-'+str(i)).encode()).digest()) for i in range(8)]
    pub=[k.public_key().public_bytes_raw().hex() for k in keys]
    p={'version':1,'owner':pub[0],'contracts':[{'id':'A','version':1,'kind':'absence','authority':pub[0],'start':0,'end':1000,'challenges':[{'id':'one','open':0,'deadline':10}]}],'expression':'A','grace':5,'max_step':60,'destination':{'kind':'simulated','verified':True,'consented':True}}
    m={'v':4,'capsule':'fixed-available','epoch':1,'policy':p,'commitment':digest(p),'payload':'ab'*32,'witnesses':{str(i):pub[i] for i in range(1,5)},'custody':{'k':2,'n':3,'keys':{str(i):pub[i+4] for i in range(1,4)}},'quorum':{'presence':3,'absence':3,'faults':1},'slots':[{'contract':'A','challenge':'one','open':0,'deadline':10}],'operation':{'attempt':'release-1','kind':'reconstruct-aes-128-gcm'}}
    sm={'message':m,'signature':sign(keys[0],m)}
    def signed(key,msg):return {'message':msg,'signature':sign(keys[key],msg)}
    pr=signed(0,{'v':4,'id':'one','capsule':m['capsule'],'manifest':digest(m),'contract':'A','contract_version':1,'challenge':'one','authority':pub[0],'valid_from':0,'valid_until':1000,'value':True})
    def rec(i,kind,proof=None):
        return signed(i,{'v':4,'kind':kind,'capsule':m['capsule'],'manifest':digest(m),'witness':i,'contract':'A','challenge':'one','operation':operation(m),'seq':1,'prev':'0'*64,'lower':5 if kind=='OBSERVATION' else 16,'upper':5 if kind=='OBSERVATION' else 16,'proof':proof,'value':'PRESENT' if proof else 'ABSENT','not_before':16})
    a={'manifest':sm,'receipts':[rec(i,'OBSERVATION',pr) for i in [1,2,3]]}
    cert={'v':4,'manifest':sm,'finals':[[rec(i,'FINAL') for i in [2,3,4]]],'operation':operation(m)};cert['authorisation']=digest(cert)
    vectors=[]
    def add(name,kind,obj,retained=None):
        inp={'kind':kind,'object':copy.deepcopy(obj),'retained':copy.deepcopy(retained or [])}
        try:r=acknowledgement(obj['manifest'],obj['receipts']) if kind=='ack' else release(obj,retained or []);expected={'ok':True,**r}
        except Exception:expected={'ok':False}
        vectors.append({'name':name,'input':inp,'expected':expected})
    add('presence','ack',a);add('absence-with-one-offline','release',cert);add('two-faults-contradictory-cert-retained-veto','release',cert,[a])
    # Raw incompatible certs above require two equivocators (2 and 3), beyond f=1.
    for q in itertools.combinations(range(1,5),3):
        for perm in itertools.permutations(q):
            add('presence-'+''.join(map(str,perm)),'ack',{'manifest':sm,'receipts':[rec(i,'OBSERVATION',pr) for i in perm]})
            c={**cert,'finals':[[rec(i,'FINAL') for i in perm]]};c['authorisation']=digest({k:v for k,v in c.items() if k!='authorisation'});add('absence-'+''.join(map(str,perm)),'release',c)
    for field in ['signature','duplicate','contract','version','expired','authority','manifest','time','extensions']:
        obj=copy.deepcopy(a);r=obj['receipts'][0]
        if field=='signature':r['signature']='00'*64
        elif field=='duplicate':obj['receipts']=[r]*3
        elif field in ['contract','version','expired','authority']:
            pr=r['message']['proof'];pr['message'][{'contract':'contract','version':'contract_version','expired':'valid_until','authority':'authority'}[field]]={'contract':'B','version':2,'expired':5,'authority':pub[7]}[field];pr['signature']=sign(keys[0],pr['message']);r['signature']=sign(keys[1],r['message'])
        elif field=='manifest':r['message']['manifest']='00'*32;r['signature']=sign(keys[1],r['message'])
        elif field=='time':r['message']['upper']=11;r['signature']=sign(keys[1],r['message'])
        else:r['message']['extension']=True;r['signature']=sign(keys[1],r['message'])
        add('reject-'+field,'ack',obj)
    for field in ['partial','early','expiry','operation','hash','version']:
        obj=copy.deepcopy(cert)
        if field=='partial':obj['finals'][0].pop()
        elif field in ['early','expiry']:
            for r in obj['finals'][0]:
                r['message']['lower']=r['message']['upper']=10 if field=='early' else 1000;r['signature']=sign(keys[r['message']['witness']],r['message'])
        elif field=='operation':obj['operation']='00'*32
        elif field=='version':obj['v']=3
        obj['authorisation']=digest({k:v for k,v in obj.items() if k!='authorisation'}) if field!='hash' else '00'*32
        add('reject-'+field,'release',obj)
    return vectors

def main():
    vectors=corpus();path=Path('Protocol/vectors/generation04.json')
    if '--write' in sys.argv:path.write_text(json.dumps(vectors,indent=2)+'\n');return
    if path.exists():assert json.loads(path.read_text())==vectors,'fixed corpus drift'
    raw=b'\n'.join(canonical(v['input']) for v in vectors)+b'\n'
    p=subprocess.run(['node','Verifier/available.mjs','--lines'],input=raw,capture_output=True,check=True)
    actual=[json.loads(s) for s in p.stdout.splitlines()];assert len(actual)==len(vectors)
    for v,r in zip(vectors,actual):
        expected=v['expected'];assert r==expected if expected['ok'] else r['ok'] is False,(v['name'],expected,r)
    print(json.dumps({'objects':len(vectors),'independent_evaluators':['Python','Node'],'disagreements':0,'negative_cases':15,'quorum_permutations':48},indent=2))
if __name__=='__main__':main()
