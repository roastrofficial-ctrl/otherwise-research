"""Independent Node/Python public signed DLEQ/context corpus; no release-policy shortcut."""
import copy,hashlib,json,subprocess,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Engine.protocol import canonical,digest,sign,verify
from Available.proofs import require,checked_signature
from Bounded.wire import strict_json
from Honest import crypto
from Missing.protocol import SUITE

def evaluate(x):
    try:
        require(set(x)=={'key','R','expected_context','expected_signer','contribution'},'fields');s=x['contribution'];ctx=x['expected_context'];require(ctx['v']==7 and ctx['suite']==SUITE and ctx['domain'] in ('custody','authority'),'suite')
        require(set(s)=={'message','signature'} and set(s['message'])=={'context','index','partial'} and s['message']['context']==ctx,'scope');checked_signature(x['expected_signer'],s);require(s['message']['index']==s['message']['partial']['index'],'index');crypto.verify_partial(x['key'],x['R'],ctx,s['message']['partial']);return {'ok':True,'canonical_sha256':digest(s['message'])}
    except Exception:return {'ok':False}
def corpus():
    x,a=17,29;shares={str(i):crypto.hx(x+a*i) for i in range(1,4)};key={'v':6,'scheme':'reference-p256-threshold-dh','k':2,'n':3,'X':crypto.encode(x*crypto.G),'Y':{i:crypto.encode(crypto.number(s)*crypto.G) for i,s in shares.items()}};R=crypto.encode(43*crypto.G)
    signer=Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b'otherwise07 PUBLIC TEST SIGNER').digest());pk=signer.public_key().public_bytes_raw().hex();out=[]
    def add(name,inp):out.append({'name':name,'input':inp,'expected':evaluate(inp)})
    for domain in ['custody','authority']:
        for i in [1,2,3]:
            ctx={'v':7,'suite':SUITE,'domain':domain,'capsule':'PUBLIC-FIXTURE-07','recipient':'ab'*32,'policy_version':1,'key_epoch':1,'evidence_head':'cd'*32,'release_attempt':'release-1','committee':'ef'*32};p=crypto.partial(key,shares[str(i)],i,R,ctx);msg={'context':ctx,'index':i,'partial':p};inp={'key':key,'R':R,'expected_context':ctx,'expected_signer':pk,'contribution':{'message':msg,'signature':sign(signer,msg)}};add(domain+str(i),inp)
    base=out[0]['input']
    for field in ['D','A','B','z','index','context','signature','recipient','policy_version','evidence_head','key_epoch','suite','domain','committee','R','key','extension']:
        bad=copy.deepcopy(base);msg=bad['contribution']['message']
        if field in ['D','A','B']:msg['partial'][field]=crypto.encode(101*crypto.G)
        elif field=='z':msg['partial']['z']='00'*32
        elif field=='index':msg['partial']['index']=True
        elif field=='signature':bad['contribution']['signature']='00'*64
        elif field=='R':bad['R']=crypto.encode(71*crypto.G)
        elif field=='key':bad['key']['Y']['2']=bad['key']['Y']['1']
        elif field=='extension':msg['partial']['extension']=True
        elif field=='context':msg['context']['v']=6
        else:msg['context'][field]='substituted'
        if field!='signature':bad['contribution']['signature']=sign(signer,msg)
        add('reject-'+field,bad)
    return out
p=Path('Protocol/vectors/generation07.json')
if '--write' in sys.argv:p.write_text(json.dumps(corpus(),indent=2)+'\n');sys.exit()
v=json.loads(p.read_text());require(len(v)>=20,'fixed corpus missing');actual=[evaluate(x['input']) for x in v];require(actual==[x['expected'] for x in v],'Python corpus drift')
proc=subprocess.run(['node','Missing/verifier.mjs','--lines'],input=b'\n'.join(canonical(x['input']) for x in v)+b'\n',capture_output=True,check=True);other=[json.loads(s) for s in proc.stdout.splitlines()];require(actual==other,'Python/Node proof disagreement')
for raw in [b'{"v":7,"v":7}',b'{"value":1.5}',b'{"value":9007199254740992}']:
    try:strict_json(raw);raise AssertionError('Python parser accepts invalid wire')
    except ValueError:pass
    z=subprocess.run(['node','Missing/verifier.mjs'],input=raw,capture_output=True);require(json.loads(z.stdout)=={'ok':False},'Node parser accepts invalid wire')
print(json.dumps({'signed_proof_vectors':len(v),'valid':sum(x['ok'] for x in actual),'negative':sum(not x['ok'] for x in actual),'parser_negatives':3,'Python_Node_disagreements':0,'scope':'individual signed arithmetic/context; full lifecycle policy checked separately'},indent=2))
