"""Creator-facing check_in returns a verifiable acknowledgement, never a bare OK."""
import hashlib
import os
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Engine.protocol import canonical,digest,sign,verify
from Bounded.wire import request
from .proofs import manifest,acknowledgement,release,operation,require


def aad(m):return canonical({'v':3,'capsule':m['capsule'],'commitment':m['commitment'],'epoch':m['epoch']})

def prepare(cid,policy,owner,plaintext,witness_urls,custody_urls,cutoff=10):
    m={'v':3,'capsule':cid,'epoch':1,'policy':policy,'commitment':digest(policy),
       'witnesses':{str(i+1):request(url+'/identity')['public'] for i,url in enumerate(witness_urls)},
       'custody':{'k':2,'n':3,'keys':{str(i+1):request(url+'/identity')['public'] for i,url in enumerate(custody_urls)}},
       'quorum':{'presence':2,'absence':3,'faults':1},'slots':[],
       'operation':{'attempt':'release-1','kind':'reconstruct-aes-128-gcm'}}
    for c in policy['contracts']:
        m['slots'] += [{'contract':c['id'],'challenge':ch['id'],'open':ch['open'],'deadline':ch['deadline']} for ch in c['challenges']] if c['kind']=='absence' else [{'contract':c['id'],'challenge':'attestation','open':c['start'],'deadline':cutoff}]
    key=os.urandom(16);nonce=os.urandom(12);ciphertext=nonce+AESGCM(key).encrypt(nonce,plaintext,aad(m));m['payload']=hashlib.sha256(ciphertext).hexdigest()
    signed={'message':m,'signature':sign(owner,m)};manifest(signed)
    shares=[{'index':i,'value':s.hex()} for i,s in Shamir.split(2,3,key)];return signed,ciphertext,shares


def enroll(signed,shares,witness_urls,custody_urls,tokens):
    for i,url in enumerate(witness_urls):request(url+'/enroll',{'manifest':signed},tokens[i])
    for i,url in enumerate(custody_urls):request(url+'/enroll',{'manifest':signed,'share':shares[i]},tokens[i+3])


def evidence(signed,private,contract,challenge,ident=None,value=True):
    m=manifest(signed);c=next(c for c in m['policy']['contracts'] if c['id']==contract)
    ident=ident or digest({'manifest':digest(m),'contract':contract,'challenge':challenge})
    p={'v':3,'id':ident,'capsule':m['capsule'],'manifest':digest(m),'contract':contract,'contract_version':c['version'],'challenge':challenge,'authority':c['authority'],'valid_from':c['start'],'valid_until':c['end'],'value':value}
    return {'message':p,'signature':sign(private,p)}


def check_in(signed,p,witness_urls):
    receipts=[];failures=[]
    for url in witness_urls:
        try:receipts.append(request(url+'/observe',{'proof':p}))
        except Exception as exc:failures.append(str(exc))
    acknowledgement(signed,receipts)
    return {'manifest':signed,'receipts':sorted(receipts,key=lambda r:r['message']['witness'])}


def gossip(ack,witness_urls):
    for receipt in ack['receipts']:
        for url in witness_urls:
            request(url+'/retain',{'capsule':ack['manifest']['message']['capsule'],'receipt':receipt})


def finalise(signed,witness_urls):
    m=manifest(signed);groups=[]
    for s in m['slots']:
        records=[]
        for url in witness_urls:
            try:records.append(request(url+'/finalise',{'capsule':m['capsule'],**s}))
            except Exception:pass
        groups.append(sorted(records,key=lambda r:r['message']['witness']))
    cert={'v':3,'manifest':signed,'finals':groups,'operation':operation(m)};cert['authorisation']=digest(cert);return cert


def recover(signed,ciphertext,responses,cert):
    m=manifest(signed);release(cert);require(hashlib.sha256(ciphertext).hexdigest()==m['payload'],'payload identity')
    indices=set();shares=[]
    for response in responses:
        r=response['message'];index=r['index'];require(index not in indices,'duplicate share');indices.add(index)
        verify(m['custody']['keys'][str(index)],r,response['signature'])
        require({k:v for k,v in r.items() if k not in ('index','share')}=={'v':3,'capsule':m['capsule'],'manifest':digest(m),'operation':operation(m),'authorisation':cert['authorisation'],'payload':m['payload']},'share operation binding')
        shares.append((index,bytes.fromhex(r['share'])))
    require(len(shares)>=2,'insufficient custody shares');key=Shamir.combine(shares[:2]);return AESGCM(key).decrypt(ciphertext[:12],ciphertext[12:],aad(m))


class CheckInClient:
    """Small future API/mobile boundary, including durable aggregate receipts.
    Witness receipts are authoritative; this cache preserves the user's own proof.
    """
    def __init__(self,root,witness_urls):
        from pathlib import Path
        self.root=Path(root);self.urls=witness_urls

    def check_in(self,signed,p):
        from Bounded.wire import atomic_json,strict_json
        path=self.root/(digest({'manifest':signed,'proof':p})+'.json')
        if path.exists():
            ack=strict_json(path.read_bytes());acknowledgement(ack['manifest'],ack['receipts'])
            require(ack['manifest']==signed and all(r['message']['proof']==p for r in ack['receipts']),'cache substitution')
            return ack
        ack=check_in(signed,p,self.urls)
        atomic_json(path,ack) # fsync file + directory before acknowledging the user
        return ack
