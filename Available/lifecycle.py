"""Standalone owner client. The recovery kit, not a SaaS account, is authority."""
import base64
import itertools
import os
import uuid
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Engine.protocol import keypair,digest,sign,canonical
from Bounded.wire import atomic_json,strict_json
from . import client
from .proofs import manifest,acknowledgement,release,operation,fence_certificate,checked_signature,require,record,fence
from .transport import UrllibTransport
from .custody import compatible,LAB_REQUIREMENTS

class Client:
    def __init__(self,transport=None):self.transport=transport or UrllibTransport()
    def call(self,url,body=None):return self.transport.call(url,body)
    def command(self,kit,action):
        m=manifest(kit['manifest']);msg={'v':4,'capsule':m['capsule'],'manifest':digest(m),'action':action,'operation':operation(m)}
        return {'message':msg,'signature':sign(self.private(kit),msg)}
    def private(self,kit):return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(kit['owner_seed']))
    def draft(self,witnesses,custodians,rounds=2,seconds=120):
        require(1<=rounds<=8 and 10<=seconds<=86400,'schedule bounds')
        owner,pub=keypair();base=max(self.call(u+'/clock')['upper'] for u in witnesses)
        p={'version':1,'owner':pub,'contracts':[{'id':'presence','version':1,'kind':'absence','authority':pub,'start':base,'end':base+(rounds+2)*seconds+3600,'challenges':[{'id':str(i+1),'open':base+i*(seconds+1),'deadline':base+(i+1)*seconds} for i in range(rounds)]}], 'expression':'presence','grace':5,'max_step':60,'destination':{'kind':'simulated','verified':True,'consented':True}}
        # Creation only: use the same independently verifiable signed wire objects.
        sm,ct,shares=client.prepare('solo-'+uuid.uuid4().hex,p,owner,b'OTHERWISE synthetic laboratory message',witnesses,custodians,transport=self.call)
        return {'v':4,'manifest':sm,'owner_seed':owner.private_bytes_raw().hex(),'ciphertext':base64.b64encode(ct).decode(),'shares':shares,'witnesses':witnesses,'custodians':custodians,'acknowledgements':[],'arm':[],'disarm':[]}
    def arm(self,kit):
        m=manifest(kit['manifest']);cmd=self.command(kit,'ARM');receipts=[]
        for i,u in enumerate(kit['custodians']):
            caps=self.call(u+'/identity')['capabilities'];compatible(caps,LAB_REQUIREMENTS)
            msg={'manifest':digest(m),'share':kit['shares'][i],'provider':self.call(u+'/identity')['public']}
            self.call(u+'/arm',{'manifest':kit['manifest'],'command':cmd,'share':kit['shares'][i],'enrollment':{'message':msg,'signature':sign(self.private(kit),msg)}})
        for i,u in enumerate(kit['witnesses'],1):
            try:
                r=self.call(u+'/arm',{'manifest':kit['manifest'],'command':cmd});info=fence(m,r,'ARM');require(info['witness']==i,'arm responder pin');receipts.append(r)
            except Exception:pass
        fence_certificate(kit['manifest'],receipts,'ARM');kit['arm']=receipts
        self.distribute(kit,receipts);return {'state':'ARMED','verified':True}
    def distribute(self,kit,receipts):
        m=manifest(kit['manifest']);holders=[]
        for r in receipts:
            retained=[]
            for i,u in enumerate(kit['witnesses']):
                try:
                    result=self.call(u+'/retain',{'capsule':m['capsule'],'receipt':r})
                    checked_signature(m['witnesses'][str(i+1)],result)
                    require(result['message']=={'v':4,'kind':'RETAINED','capsule':m['capsule'],'manifest':digest(m),'digest':digest(r),'holder':m['witnesses'][str(i+1)]},'retention binding')
                    retained.append(result)
                except Exception:pass
            require(len(retained)>=3,'insufficient durable receipt holders; outcome uncertain, retry')
            holders+=retained
            for u in kit['custodians']:
                try:self.call(u+'/retain',{'capsule':m['capsule'],'receipt':r})
                except Exception:pass
        return holders
    def checkin(self,kit,challenge=None):
        m=manifest(kit['manifest']);now=None
        if challenge is None:
            times=[]
            for u in kit['witnesses']:
                try:
                    t=self.call(u+'/clock');require(t['healthy'] and type(t['upper']) is int and type(t['lower']) is int and 0<=t['lower']<=t['upper'],'clock discovery');times.append(t['upper'])
                except Exception:pass
            require(len(times)>=3,'insufficient usable clock discovery');now=sorted(times)[len(times)//2]
        sl=next((s for s in m['slots'] if s['open']<=now<=s['deadline']),None) if challenge is None else next((s for s in m['slots'] if s['challenge']==challenge),None)
        require(sl is not None,'no open check-in window')
        p=client.evidence(kit['manifest'],self.private(kit),sl['contract'],sl['challenge']);rs=[]
        for i,u in enumerate(kit['witnesses'],1):
            try:
                r=self.call(u+'/observe',{'capsule':m['capsule'],'proof':p});info=record(m,r,'OBSERVATION');require(info['witness']==i and info['proof']==p,'observation responder/proof pin');rs.append(r)
            except Exception:pass
        a=acknowledgement(kit['manifest'],rs);ack={'manifest':kit['manifest'],'receipts':sorted(rs,key=lambda r:r['message']['witness'])}
        holders=self.distribute(kit,ack['receipts']);ack['holders']=holders
        if ack not in kit['acknowledgements']:kit['acknowledgements'].append(ack)
        return {**a,'durable_holders':len({h['message']['holder'] for h in holders})}
    def recover(self,kit):
        m=manifest(kit['manifest']);records=[];reachable=0
        for u in kit['witnesses']:
            try:
                s=self.call(u+'/status?capsule='+m['capsule']);require(s['manifest']==kit['manifest'],'status substitution');reachable+=1
                for candidate in s['records']:
                    try:
                        kind=candidate['message']['kind']
                        if kind in ('ARM','DISARM'):fence(m,candidate,kind)
                        else:record(m,candidate,kind)
                        records.append(candidate)
                    except Exception:pass
            except Exception:pass
        # Status is a discovery channel. Signatures/quorum decide acceptance.
        groups={}
        for r in records:
            if r['message']['kind']=='OBSERVATION':
                try:record(m,r,'OBSERVATION')
                except ValueError:continue
                g=groups.setdefault(digest(r['message']['proof']),{})
                g[r['message']['witness']]=r
        acks=[]
        for g in groups.values():
            if len(g)>=3:
                ack={'manifest':kit['manifest'],'receipts':sorted(g.values(),key=lambda r:r['message']['witness'])};acknowledgement(ack['manifest'],ack['receipts']);acks.append(ack)
        acks.sort(key=lambda a:next(s['deadline'] for s in m['slots'] if s['contract']==a['receipts'][0]['message']['contract'] and s['challenge']==a['receipts'][0]['message']['challenge']))
        kit['acknowledgements']=acks
        state='UNKNOWN'
        for kind in ('ARM','DISARM'):
            rs={r['message']['witness']:r for r in records if r['message']['kind']==kind}
            try:
                fence_certificate(kit['manifest'],list(rs.values()),kind);state='ARMED' if kind=='ARM' else 'DISARMED'
                kit['arm' if kind=='ARM' else 'disarm']=list(rs.values())
            except ValueError:pass
        return {'state':state,'reachable':reachable,'accepted_checkins':len(acks),'latest':acks[-1] if acks else None,'history':sorted({digest(r):r for r in records}.values(),key=lambda r:(r['message']['kind'],r['message']['witness'],r['message'].get('seq',0)))}
    def disarm(self,kit):
        m=manifest(kit['manifest']);rs=[]
        for i,u in enumerate(kit['witnesses'],1):
            try:
                r=self.call(u+'/disarm',{'capsule':m['capsule'],'command':self.command(kit,'DISARM')});info=fence(m,r,'DISARM');require(info['witness']==i,'disarm responder pin');rs.append(r)
            except Exception:pass
        fence_certificate(kit['manifest'],rs,'DISARM');self.distribute(kit,rs);kit['disarm']=rs
        return {'state':'DISARMED','verified':True}
    def evaluate(self,kit):
        m=manifest(kit['manifest']);groups=[]
        for s in m['slots']:
            rs=[]
            for i,u in enumerate(kit['witnesses'],1):
                try:
                    r=self.call(u+'/finalise',{'capsule':m['capsule'],**s});info=record(m,r,'FINAL');require(info['witness']==i and (info['contract'],info['challenge'])==(s['contract'],s['challenge']),'final responder/slot pin');rs.append(r)
                except Exception:pass
            if len(rs)<3:return {'authorised':False,'state':'WAITING','reason':'insufficient closed witnesses'}
            # For an identical slot result/proof, the earliest closed upper bound
            # dominates later ones: every committed contract has already started,
            # and increasing snapshot time can only expire evidence/contracts.
            # Avoid 4**slots repeated evaluations of equivalent honest quorums.
            candidates={}
            contract=next(c for c in m['policy']['contracts'] if c['id']==s['contract'])
            for group in itertools.combinations(sorted(rs,key=lambda r:r['message']['witness']),3):
                rows=[r['message'] for r in group]
                yes=all(r['value']=='ABSENT' for r in rows) if contract['kind']=='absence' else all(r['value']=='TRUE' for r in rows) and len({digest(r['proof']) for r in rows})==1
                key=(yes,digest(rows[0]['proof']) if yes and contract['kind']=='attestation' else None)
                if key not in candidates or max(r['upper'] for r in rows)<max(r['message']['upper'] for r in candidates[key]):candidates[key]=group
            groups.append(list(candidates.values()))
        # A Byzantine outlier must not force inclusion when a valid honest quorum exists.
        for combination in itertools.product(*groups):
            cert={'v':4,'manifest':kit['manifest'],'finals':[list(g) for g in combination],'operation':operation(m)};cert['authorisation']=digest(cert)
            try:release(cert)
            except ValueError:continue
            return {'authorised':True,'state':'AUTHORISED','certificate':cert}
        return {'authorised':False,'state':'PROTECTED','reason':'policy unsatisfied at closed snapshot'}
    def simulate(self,kit,certificate):
        m=manifest(kit['manifest']);responses=[]
        for u in kit['custodians']:
            try:responses.append(self.call(u+'/release',{'capsule':m['capsule'],'certificate':certificate,'requirements':LAB_REQUIREMENTS}))
            except Exception:pass
        text=client.recover(kit['manifest'],base64.b64decode(kit['ciphertext']),responses,certificate)
        return {'delivery':'SIMULATED','plaintext':text.decode(),'operation':operation(m)}
    def repair(self,kit,index):
        m=manifest(kit['manifest']);target=m['witnesses'][str(index)];cps=[]
        challenge=self.call(kit['witnesses'][index-1]+'/repair-challenge',{'capsule':m['capsule']});nonce=challenge['nonce'];require(challenge['target']==target,'recovery target pin')
        for i,u in enumerate(kit['witnesses'],1):
            if i!=index:cps.append(self.call(u+'/checkpoint',{'capsule':m['capsule'],'nonce':nonce,'target':target}))
        msg={'v':4,'action':'REPAIR','capsule':m['capsule'],'manifest':digest(m),'target':target,'nonce':nonce,'checkpoints':sorted(digest(c) for c in cps)}
        return self.call(kit['witnesses'][index-1]+'/repair',{'capsule':m['capsule'],'nonce':nonce,'checkpoints':cps,'command':{'message':msg,'signature':sign(self.private(kit),msg)}})
