"""Public TEST-only deterministic identities, plus quorum-counterexample builders."""
import hashlib
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Engine.protocol import digest,sign
from .proofs import operation,acknowledgement,release


def keys():return [Ed25519PrivateKey.from_private_bytes(hashlib.sha256(('otherwise03-test-'+str(i)).encode()).digest()) for i in range(10)]

def policy(kind='absence',base=0,rounds=1,authorities=None,owner=None):
    private=keys();pub=[k.public_key().public_bytes_raw().hex() for k in private]
    authorities=authorities or ([pub[0]] if kind=='absence' else pub[1:4]);owner=owner or pub[0]
    return {'version':1,'owner':owner,'contracts':[{'id':chr(65+i),'version':1,'kind':kind,'authority':p,'start':base,'end':base+1000,'challenges':[{'id':'round-'+str(j+1),'open':base+j*11,'deadline':base+(j+1)*10} for j in range(rounds)] if kind=='absence' else []} for i,p in enumerate(authorities)],'expression':'A' if kind=='absence' else {'op':'THRESHOLD','k':2,'args':['A','B','C']},'grace':5,'max_step':60,'destination':{'kind':'simulated','verified':True,'consented':True}}


def objects(unsafe=False,accepted=(0,1),absent=(0,1,2)):
    ks=keys();pub=[k.public_key().public_bytes_raw().hex() for k in ks];p=policy()
    m={'v':3,'capsule':'fixed-retained','epoch':1,'policy':p,'commitment':digest(p),'payload':'ab'*32,
       'witnesses':{str(i+1):pub[i+4] for i in range(3)},'custody':{'k':2,'n':3,'keys':{str(i+1):pub[i+7] for i in range(3)}},
       'quorum':{'presence':2,'absence':2 if unsafe else 3,'faults':1},'slots':[{'contract':'A','challenge':'round-1','open':0,'deadline':10}],
       'operation':{'attempt':'release-1','kind':'reconstruct-aes-128-gcm'}}
    sm={'message':m,'signature':sign(ks[0],m)}
    msg={'v':3,'id':'fixed-presence','capsule':m['capsule'],'manifest':digest(m),'contract':'A','contract_version':1,'challenge':'round-1','authority':pub[0],'valid_from':0,'valid_until':1000,'value':True}
    proof={'message':msg,'signature':sign(ks[0],msg)}
    def rec(index,kind,value,proof,seq=1,prev='0'*64):
        r={'v':3,'kind':kind,'capsule':m['capsule'],'manifest':digest(m),'witness':index+1,'contract':'A','challenge':'round-1','operation':operation(m),'seq':seq,'prev':prev,'lower':5 if kind=='OBSERVATION' else 16,'upper':5 if kind=='OBSERVATION' else 16,'proof':proof,'value':value,'not_before':16}
        return {'message':r,'signature':sign(ks[index+4],r)}
    obs=[rec(i,'OBSERVATION','PRESENT',proof) for i in accepted]
    ack={'manifest':sm,'receipts':obs}
    finals=[rec(i,'FINAL','ABSENT',None) for i in absent]
    cert={'v':3,'manifest':sm,'finals':[finals],'operation':operation(m)};cert['authorisation']=digest(cert)
    return ack,cert,rec


def corpus():
    import copy
    vectors=[]
    def add(name,kind,obj,retained=None):
        inp={'kind':kind,'object':obj}
        if retained is not None:inp['retained']=retained
        try:r=acknowledgement(obj['manifest'],obj['receipts']) if kind=='ack' else release(obj,retained or ());expected={'ok':True,**r}
        except ValueError:expected={'ok':False}
        vectors.append({'name':name,'input':inp,'expected':expected})
    ack,forged,_=objects();add('accepted-presence', 'ack',ack)
    # No presence actually retained in this legitimate absence scenario.
    none,absence,_=objects(accepted=());add('closed-absence','release',absence)
    add('retained-presence-veto','release',forged,[ack])
    add('fault-budget-exceeded-two-byzantine','release',forged)
    unsafe_ack,unsafe_cert,_=objects(True,absent=(1,2));add('reject-unsafe-majority-ack','ack',unsafe_ack);add('reject-unsafe-majority-absence','release',unsafe_cert)
    for field in ('signature','identity','cross-capsule','challenge','expired','duplicate','rollback'):
        a=copy.deepcopy(ack)
        r=a['receipts'][0]
        if field=='signature':r['signature']='00'*64
        elif field=='identity':r['message']['witness']=99
        elif field=='cross-capsule':r['message']['capsule']='different'
        elif field=='challenge':r['message']['challenge']='round-2'
        elif field=='expired':r['message']['upper']=1000
        elif field=='duplicate':a['receipts']=[a['receipts'][0]]*2
        else:r['message']['seq']=0
        add('reject-'+field,'ack',a)
    for field in ('operation','authorisation','partial','early','wrong-manifest'):
        c=copy.deepcopy(absence)
        if field=='operation':c['operation']='00'*32
        elif field=='authorisation':c['authorisation']='00'*32
        elif field=='partial':c['finals'][0]=c['finals'][0][:2]
        elif field=='early':c['finals'][0][0]['message']['lower']=10
        else:c['manifest']['message']['epoch']=2
        if field!='authorisation':c['authorisation']=digest({k:v for k,v in c.items() if k!='authorisation'})
        add('reject-'+field,'release',c)
    expired=copy.deepcopy(ack);private=keys()
    for receipt in expired['receipts']:
        p=receipt['message']['proof'];p['message']['valid_until']=5
        p['signature']=sign(private[0],p['message'])
    for receipt in expired['receipts']:
        receipt['signature']=sign(private[receipt['message']['witness']+3],receipt['message'])
    add('reject-validly-signed-expired-proof','ack',expired)
    for part in ('manifest','record','proof'):
        a=copy.deepcopy(ack)
        target=a['manifest'] if part=='manifest' else a['receipts'][0] if part=='record' else a['receipts'][0]['message']['proof']
        target['unsigned_extension']=True
        add('reject-unsigned-'+part+'-extension','ack',a)
    return {'version':'otherwise-retained-0.3','test_only_seeds':[hashlib.sha256(('otherwise03-test-'+str(i)).encode()).hexdigest() for i in range(10)],'vectors':vectors,'counterexample':{'presence':unsafe_ack,'absence':unsafe_cert}}
