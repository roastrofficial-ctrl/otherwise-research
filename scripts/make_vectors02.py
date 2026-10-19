"""Fixed public TEST identities; never use these private keys outside conformance."""
import copy
import hashlib
import json
import tempfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Engine.store import Engine
from Engine.protocol import digest,sign


def identities():
    return [Ed25519PrivateKey.from_private_bytes(hashlib.sha256(('otherwise-vector-'+str(i)).encode()).digest()) for i in range(8)]

def policy(kind='attestation',base=0):
    keys=identities();pub=[k.public_key().public_bytes_raw().hex() for k in keys]
    count=1 if kind=='absence' else 3
    p={'version':1,'owner':pub[0],'contracts':[{'id':chr(65+i),'version':1,'kind':kind,'authority':pub[i+1],'start':base,'end':base+1000,'challenges':[{'id':'one','open':base,'deadline':base+10},{'id':'two','open':base+11,'deadline':base+20}] if kind=='absence' else []} for i in range(count)],'expression':'A' if count==1 else {'op':'THRESHOLD','k':2,'args':['A','B','C']},'grace':5,'max_step':60,'destination':{'kind':'simulated','verified':True,'consented':True}}
    return keys,p

def owner(e,cid,key,action):
    s=e.export(cid);m={'v':1,'capsule':cid,'commitment':s['commitment'],'action':action}
    if action=='RECOVERED':
        m={**m,'v':2,'head':s['head']}
        e.owner_command(cid,action,sign(key,m),context={'head':s['head']})
    else:e.owner_command(cid,action,sign(key,m))

def evidence(e,cid,keys,p,i=0,claim=True,challenge='one',ident=None,until=100):
    c=p['contracts'][i]
    m={'v':1,'id':ident or c['id']+'-proof','capsule':cid,'commitment':digest(p),'contract':c['id'],'contract_version':1,'authority':c['authority'],'valid_from':0,'valid_until':until}
    m.update({'claim':claim} if c['kind']=='attestation' else {'challenge':challenge})
    return m,sign(keys[i+1],m)

def build():
    vectors=[]
    def save(name,e,cid,results,eligible=False,authorised=False):
        vectors.append({'name':name,'snapshot':e.export(cid),'expected':{'ok':True,'results':results,'eligible':eligible,'authorised':authorised}})
    def result(values): return {'contracts':values,'satisfied':sum(values.values())>=2}
    for scenario in ('solo','disarm','recovery','council','gap'):
        with tempfile.TemporaryDirectory() as root:
            e=Engine(root);keys,p=policy('absence' if scenario in ('solo','disarm','recovery') else 'attestation')
            if scenario=='gap':
                p['expression']={'op':'OR','args':['A','B','C']}
                p['contracts'][1]['kind']='absence';p['contracts'][1]['challenges']=[{'id':'one','open':0,'deadline':3}]
            cid=scenario;e.import_encrypted(cid,p,b'fixed-public-vector-ciphertext')
            owner(e,cid,keys[0],'ARMED')
            if scenario=='solo':
                e.tick(10);e.submit(cid,*evidence(e,cid,keys,p))
                save('solo-inclusive-deadline',e,cid,{'contracts':{'A':False},'satisfied':False})
                e.tick(21);e.authorise(cid)
                save('solo-missed-second-grace',e,cid,{'contracts':{'A':True},'satisfied':True})
                e.tick(26);save('solo-grace-boundary',e,cid,{'contracts':{'A':True},'satisfied':True},True)
                e.authorise(cid);save('solo-authorised',e,cid,{'contracts':{'A':True},'satisfied':True},True,True)
            elif scenario=='disarm':
                owner(e,cid,keys[0],'DISARMED');e.tick(11)
                save('disarm-wins',e,cid,{'contracts':{'A':True},'satisfied':True})
            elif scenario=='recovery':
                e.tick(11,outage=True);save('outage-withholds',e,cid,{'contracts':{'A':True},'satisfied':True})
                owner(e,cid,keys[0],'RECOVERED');e.authorise(cid);e.tick(16);e.authorise(cid)
                save('owner-recovery-fresh-grace',e,cid,{'contracts':{'A':True},'satisfied':True},True,True)
            elif scenario=='council':
                rejected=[]
                for i in range(3):e.submit(cid,*evidence(e,cid,keys,p,i,claim=i<2))
                e.submit(cid,*evidence(e,cid,keys,p,2,claim=True,ident='C-opposite'))
                bad,sig=evidence(e,cid,keys,p,1,ident='bad-signature');e.submit(cid,bad,'00'*64)
                e.authorise(cid);e.tick(5);e.authorise(cid)
                save('council-contradiction-and-rejected-proof',e,cid,result({'A':True,'B':True,'C':False}),True,True)
            else:
                e.submit(cid,*evidence(e,cid,keys,p,until=2));e.authorise(cid);e.tick(5);e.authorise(cid)
                save('continuous-grace-gap',e,cid,{'contracts':{'A':False,'B':True,'C':False},'satisfied':True})
                e.tick(10);e.authorise(cid)
                save('continuous-grace-restarted',e,cid,{'contracts':{'A':False,'B':True,'C':False},'satisfied':True},True,True)
    # Rechain signature tampering to ensure validators check semantics, not only hashes.
    for mutation in ('signature','domain','late-presence','forged-authorisation'):
        original=next(v for v in vectors if v['name']=='solo-authorised')
        s=copy.deepcopy(original['snapshot'])
        accepted=next(f for f in s['events'] if f['kind']=='ACCEPTED')
        if mutation=='signature':accepted['data']['signature']='00'*64
        elif mutation=='domain':accepted['data']['message']['capsule']='another'
        elif mutation=='late-presence':accepted['time']=11
        else:
            decision=next(f for f in s['events'] if f['kind']=='AUTHORISED');decision['time']=21
        rechain(s)
        vectors.append({'name':'reject-'+mutation,'snapshot':s,'expected':{'ok':False}})
    keys=identities();pub=[k.public_key().public_bytes_raw().hex() for k in keys]
    sample=next(v['snapshot'] for v in vectors if v['name']=='solo-authorised')
    manifest={'v':2,'capsule':sample['capsule'],'epoch':1,'policy':sample['policy'],'commitment':sample['commitment'],
              'payload':sample['events'][0]['data']['payload'],'algorithm':'AES-128-GCM',
              'custody':{'scheme':'shamir-pycryptodome-128','k':2,'n':3,'keys':{str(i+1):pub[i+4] for i in range(3)}},
              'witness':pub[7],'clock':{'profile':'witness-observed-v2','outage':'withhold-and-restart-grace'}}
    receipt={'v':2,'manifest':digest(manifest),'capsule':sample['capsule'],'commitment':sample['commitment'],
             'head':sample['head'],'count':len(sample['events']),'now':sample['now'],'healthy':sample['healthy']}
    return {'protocol':'otherwise-bounded-0.2','test_only_private_seeds':[hashlib.sha256(('otherwise-vector-'+str(i)).encode()).hexdigest() for i in range(8)],
            'signed_manifest':{'manifest':manifest,'signature':sign(keys[0],manifest)},
            'witness_bundle':{'snapshot':sample,'receipt':receipt,'signature':sign(keys[7],receipt)},'vectors':vectors}

def rechain(s):
    head='0'*64
    for i,f in enumerate(s['events'],1):
        f['seq']=i;f['prev']=head
        if f['kind'] in ('CANDIDATE','AUTHORISED'):f['data']['snapshot']=head
        if f['kind']=='AUTHORISED':
            f['data']['candidate']=max((e['seq'] for e in s['events'][:i-1] if e['kind']=='CANDIDATE'),default=0)
        head=digest(f)
    s['head']=head

if __name__=='__main__':print(json.dumps(build(),sort_keys=True,indent=2))
