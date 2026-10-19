"""Trusted creator encryption, scoped evidence and custody response verification."""
import hashlib
import os
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Engine.protocol import canonical,digest,sign,verify
from .proofs import manifest,acknowledgement,release,operation,require


def aad(m):return canonical({'v':4,'capsule':m['capsule'],'commitment':m['commitment'],'epoch':m['epoch']})

def prepare(cid,policy,owner,plaintext,witness_urls,custody_urls,cutoff=10,*,transport):
    m={'v':4,'capsule':cid,'epoch':1,'policy':policy,'commitment':digest(policy),
       'witnesses':{str(i+1):transport(url+'/identity')['public'] for i,url in enumerate(witness_urls)},
       'custody':{'k':2,'n':3,'keys':{str(i+1):transport(url+'/identity')['public'] for i,url in enumerate(custody_urls)}},
       'quorum':{'presence':3,'absence':3,'faults':1},'slots':[],
       'operation':{'attempt':'release-1','kind':'reconstruct-aes-128-gcm'}}
    for c in policy['contracts']:
        m['slots'] += [{'contract':c['id'],'challenge':ch['id'],'open':ch['open'],'deadline':ch['deadline']} for ch in c['challenges']] if c['kind']=='absence' else [{'contract':c['id'],'challenge':'attestation','open':c['start'],'deadline':cutoff}]
    key=os.urandom(16);nonce=os.urandom(12);ciphertext=nonce+AESGCM(key).encrypt(nonce,plaintext,aad(m));m['payload']=hashlib.sha256(ciphertext).hexdigest()
    signed={'message':m,'signature':sign(owner,m)};manifest(signed)
    shares=[{'index':i,'value':s.hex()} for i,s in Shamir.split(2,3,key)];return signed,ciphertext,shares


def evidence(signed,private,contract,challenge,ident=None,value=True):
    m=manifest(signed);c=next(c for c in m['policy']['contracts'] if c['id']==contract)
    ident=ident or digest({'manifest':digest(m),'contract':contract,'challenge':challenge})
    p={'v':4,'id':ident,'capsule':m['capsule'],'manifest':digest(m),'contract':contract,'contract_version':c['version'],'challenge':challenge,'authority':c['authority'],'valid_from':c['start'],'valid_until':c['end'],'value':value}
    return {'message':p,'signature':sign(private,p)}


def recover(signed,ciphertext,responses,cert):
    m=manifest(signed);release(cert);require(hashlib.sha256(ciphertext).hexdigest()==m['payload'],'payload identity')
    indices=set();shares=[]
    for response in responses:
        r=response['message'];index=r['index'];require(index not in indices,'duplicate share');indices.add(index)
        verify(m['custody']['keys'][str(index)],r,response['signature'])
        require({k:v for k,v in r.items() if k not in ('index','share')}=={'v':4,'capsule':m['capsule'],'manifest':digest(m),'operation':operation(m),'authorisation':cert['authorisation'],'payload':m['payload']},'share operation binding')
        shares.append((index,bytes.fromhex(r['share'])))
    require(len(shares)>=2,'insufficient custody shares');key=Shamir.combine(shares[:2]);return AESGCM(key).decrypt(ciphertext[:12],ciphertext[12:],aad(m))

