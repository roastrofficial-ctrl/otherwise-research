"""Reference threshold-DH algebra and Chaum–Pedersen proofs, NOT audited crypto.
See doc/generation06/DECISION.md. Scalars are hex: wire integers stay <=2**53.
"""
import os
import re
import secrets
from Crypto.PublicKey import ECC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from Engine.protocol import canonical,digest
from Available.proofs import require

# Public NIST P-256 parameters. Library validates curve membership on import.
Q=int('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551',16)
G=ECC.construct(curve='P-256',d=1).pointQ

def scalar():return secrets.randbelow(Q-1)+1
def hx(n):return format(n,'064x')
def number(s):
    require(type(s) is str and re.fullmatch('[0-9a-f]{64}',s) is not None,'scalar encoding')
    n=int(s,16);require(n<Q,'scalar range');return n

def encode(p):
    require(not p.is_point_at_infinity(),'identity point')
    return '04'+hx(int(p.x))+hx(int(p.y))

def point(s):
    require(type(s) is str and re.fullmatch('04[0-9a-f]{128}',s) is not None,'point encoding')
    p=ECC.construct(curve='P-256',point_x=int(s[2:66],16),point_y=int(s[66:],16)).pointQ
    require(not p.is_point_at_infinity(),'identity point');return p

def derive(shared,context):return HKDF(algorithm=hashes.SHA256(),length=32,salt=None,info=canonical(context)).derive(shared)
def encrypt(key,plain,context):
    nonce=os.urandom(12);return (nonce+AESGCM(key).encrypt(nonce,plain,canonical(context))).hex()
def decrypt(key,ct,context):
    data=bytes.fromhex(ct);return AESGCM(key).decrypt(data[:12],data[12:],canonical(context))

def dealer():
    x,a=scalar(),scalar();shares={str(i):hx((x+a*i)%Q) for i in range(1,4)}
    require(all(number(s)>0 for s in shares.values()),'degenerate setup; retry')
    public={'v':6,'scheme':'reference-p256-threshold-dh','k':2,'n':3,'X':encode(x*G),'Y':{i:encode(number(s)*G) for i,s in shares.items()}}
    return public,shares  # No full x returned/persisted; dealer still knew it.

def public_key(p):
    require(set(p)=={'v','scheme','k','n','X','Y'} and type(p['v']) is int and p['v']==6 and p['scheme']=='reference-p256-threshold-dh' and type(p['k']) is int and p['k']==2 and type(p['n']) is int and p['n']==3,'key generation schema')
    require(set(p['Y'])=={'1','2','3'} and len(set(p['Y'].values()))==3 and p['X'] not in p['Y'].values(),'distinct non-degenerate verification shares')
    X=point(p['X']);ys={int(i):point(y) for i,y in p['Y'].items()}
    # All pairs must interpolate the committed X; prevents incoherent dealer shares.
    for i,j in [(1,2),(1,3),(2,3)]:
        require(ys[i]*((j*pow(j-i,-1,Q))%Q)+ys[j]*((i*pow(i-j,-1,Q))%Q)==X,'inconsistent public shares')
    return p

def wrap(public,key,context):
    public_key(public);r=scalar();R=encode(r*G)
    return {'R':R,'wrapped':encrypt(derive(bytes.fromhex(encode(r*point(public['X']))),context),key,context)}

def challenge(public,R,D,A,B,context,index):
    return int(digest({'domain':'otherwise06-cp','key':public,'R':R,'D':D,'A':A,'B':B,'context':context,'index':index}),16)%Q

def partial(public,share,index,R,context):
    public_key(public);s=number(share);require(1<=index<=3 and encode(s*G)==public['Y'][str(index)],'private/public share binding')
    rp=point(R);D=encode(s*rp);w=scalar();A=encode(w*G);B=encode(w*rp);c=challenge(public,R,D,A,B,context,index)
    return {'index':index,'D':D,'A':A,'B':B,'z':hx((w+c*s)%Q)}

def verify_partial(public,R,context,p):
    require(set(p)=={'index','D','A','B','z'} and type(p['index']) is int and p['index'] in (1,2,3),'partial schema/index')
    public_key(public);i=p['index'];D=point(p['D']);A=point(p['A']);B=point(p['B']);z=number(p['z']);c=challenge(public,R,p['D'],p['A'],p['B'],context,i)
    require(z*G==A+c*point(public['Y'][str(i)]) and z*point(R)==B+c*D,'invalid partial proof')
    return D

def combine_points(indexed):
    require(len(indexed)>=2 and len({i for i,p in indexed})==len(indexed),'insufficient or duplicate partials')
    i,A=indexed[0];j,B=indexed[1]
    return A*((j*pow(j-i,-1,Q))%Q)+B*((i*pow(i-j,-1,Q))%Q)

def unwrap(public,wrapped,context,partials,operation):
    values=[(p['index'],verify_partial(public,wrapped['R'],operation,p)) for p in partials]
    shared=combine_points(values)
    return decrypt(derive(bytes.fromhex(encode(shared)),context),wrapped['wrapped'],context)

def recipient():
    key=X25519PrivateKey.generate();return key.private_bytes_raw().hex(),key.public_key().public_bytes_raw().hex()
def seal_to(public,data,context):
    k=X25519PrivateKey.generate();ephemeral=k.public_key().public_bytes_raw().hex()
    shared=k.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(public)))
    return {'ephemeral':ephemeral,'ciphertext':encrypt(derive(shared,context),canonical(data),context)}
def open_for(private,box,context):
    from Bounded.wire import strict_json
    require(set(box)=={'ephemeral','ciphertext'},'recipient box schema')
    k=X25519PrivateKey.from_private_bytes(bytes.fromhex(private));shared=k.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(box['ephemeral'])))
    return strict_json(decrypt(derive(shared,context),box['ciphertext'],context))
