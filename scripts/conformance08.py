"""Fixed PUBLIC TEST finality certificates; independent Python/Node checking."""
import copy,hashlib,json,subprocess,sys
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Engine.protocol import canonical,digest,sign
from Available.proofs import operation
from Honest import crypto
from Missing.protocol import SUITE as SPLIT_SUITE,wrap_context
from LastWord.proofs import registry,scope,value,finality,vote_message,SUITE
from conformance04 import corpus

def fixtures():
    keys={i:Ed25519PrivateKey.from_private_bytes(hashlib.sha256(('otherwise04-public-test-'+str(i)).encode()).digest()) for i in range(8)}
    extra={i:Ed25519PrivateKey.from_private_bytes(hashlib.sha256(('otherwise08 PUBLIC TEST-'+str(i)).encode()).digest()) for i in range(1,4)}
    cert=next(x['input']['object'] for x in corpus() if x['name']=='absence-with-one-offline');sm=cert['manifest'];m=sm['message'];owner=keys[0]
    def pk(k):return k.public_key().public_bytes_raw().hex()
    def gen(x,a):return {'v':6,'scheme':'reference-p256-threshold-dh','k':2,'n':3,'X':crypto.encode(x*crypto.G),'Y':{str(i):crypto.encode((x+a*i)*crypto.G) for i in range(1,4)}}
    c={'v':7,'suite':SPLIT_SUITE,'epoch':1,'manifest':sm,'recipient':'ab'*32,'domains':{'custody':{'epoch':1,'key':gen(17,29),'members':m['custody']['keys']},'authority':{'epoch':1,'key':gen(31,13),'members':{str(i):pk(extra[i]) for i in extra}}},'wraps':{},'plaintext_commitment':'cd'*32}
    for d in c['domains']:c['wraps'][d]=crypto.wrap(c['domains'][d]['key'],b'\x11'*16,wrap_context(c,d))
    sc={'message':c,'signature':sign(owner,c)};r={'v':8,'suite':SUITE,'split':sc,'committee':{'epoch':1,'keys':m['witnesses']},'model':'AUTHORISATION_WINS','operation':'terminal-1'};reg={'message':r,'signature':sign(owner,r)};registry(reg)
    arms=[]
    cmd={'v':4,'capsule':m['capsule'],'manifest':digest(m),'action':'ARM','operation':operation(m)};command={'message':cmd,'signature':sign(owner,cmd)}
    for i in (1,2,3):
        msg={'v':4,'kind':'ARM','capsule':m['capsule'],'manifest':digest(m),'operation':operation(m),'witness':i,'command':command};arms.append({'message':msg,'signature':sign(keys[i],msg)})
    values=[]
    for kind in ['DISARM','RELEASE']:
        cmd={**scope(reg),'action':'DISARM'};v={'scope':scope(reg),'kind':kind,'arm':arms,'evidence':cert if kind=='RELEASE' else None,'command':None if kind=='RELEASE' else {'message':cmd,'signature':sign(owner,cmd)}};values.append(v)
    def certificate(v,n=0):
        out={'v':8,'registry':digest(reg),'view':n,'value':v}
        for phase,label in [('PREPARE','prepares'),('COMMIT','commits')]:out[label]=[{'message':vote_message(reg,phase,n,v,i),'signature':sign(keys[i],vote_message(reg,phase,n,v,i))} for i in (1,2,3)]
        return out
    out=[]
    for v in values:
        for n in [0,1,4]:out.append({'name':v['kind']+'-view'+str(n),'input':{'registry':reg,'certificate':certificate(v,n)}})
    base=out[-1]['input']
    for field in ['signature','duplicate','partial','phase','view','epoch','registry','kind','policy','recipient','extension','owner','arm','typed-epoch','typed-vote']:
        bad=copy.deepcopy(base);f=bad['certificate']
        if field=='signature':f['commits'][0]['signature']='00'*64
        elif field=='duplicate':f['commits']=[f['commits'][0]]*3
        elif field=='partial':f['commits'].pop()
        elif field=='phase':f['commits'][0]['message']['kind']='PREPARE'
        elif field=='view':f['view']+=1
        elif field=='epoch':bad['registry']['message']['committee']['epoch']=2
        elif field=='registry':f['registry']='00'*32
        elif field=='kind':f['value']['kind']='DISARM'
        elif field=='policy':f['value']['evidence']['manifest']['message']['policy']['grace']=999
        elif field=='recipient':bad['registry']['message']['split']['message']['recipient']='01'*32
        elif field=='owner':f['value']['command']={'message':{**scope(reg),'action':'DISARM'},'signature':'00'*64};f['value']['kind']='DISARM'
        elif field=='arm':f['value']['arm'].pop()
        elif field=='typed-epoch':
            bad['registry']['message']['committee']['epoch']=True;bad['registry']['signature']=sign(owner,bad['registry']['message'])
        elif field=='typed-vote':
            f['commits'][0]['message']['membership_epoch']=True;f['commits'][0]['signature']=sign(keys[1],f['commits'][0]['message'])
        else:f['extra']=True
        out.append({'name':'reject-'+field,'input':bad})
    for x in out:x['expected']=evaluate(x['input'])
    return out

def evaluate(inp):
    try:return {'ok':True,**finality(inp['registry'],inp['certificate'])}
    except Exception:return {'ok':False}
p=Path('Protocol/vectors/generation08.json')
if '--write' in sys.argv:p.write_text(json.dumps(fixtures(),indent=2)+'\n');sys.exit()
v=json.loads(p.read_text());assert len(v)>=19
actual=[evaluate(x['input']) for x in v];assert actual==[x['expected'] for x in v]
node=subprocess.run(['node','LastWord/verifier.mjs','--lines'],input=b'\n'.join(canonical(x['input']) for x in v)+b'\n',capture_output=True,check=True);other=[json.loads(s) for s in node.stdout.splitlines()];assert actual==other,(actual,other)
print(json.dumps({'terminal_vectors':len(v),'positive':sum(x['ok'] for x in actual),'negative':sum(not x['ok'] for x in actual),'Python_Node_disagreements':0,'scope':'finality signature/guard checking; not a proof of distributed safety'},indent=2))
