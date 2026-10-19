"""Trusted creator provisioner and thin operator-side workflow.
Provisioning secrets exist only in the creator/orchestrator process, never Session.
"""
import hashlib
import os
from dataclasses import dataclass
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Engine.protocol import canonical, digest, sign, verify
from Engine.store import Engine
from .verify import check_manifest, validate_bundle
from .wire import request, atomic_json


def aad(manifest):
    return canonical({'v':2,'capsule':manifest['capsule'],'commitment':manifest['commitment'],'epoch':manifest['epoch']})


@dataclass
class Prepared:
    manifest: dict
    signature: str
    ciphertext: bytes
    shares: list


def prepare(cid,policy,plaintext,witness_url,custodian_urls):
    # Trusted client only. An operator-supplied or compromised client could retain
    # plaintext or the complete key; this experiment does not solve that threat.
    from .verify import check_manifest
    witness=request(witness_url+'/identity')['public']
    identities=[request(url+'/identity') for url in custodian_urls]
    key=os.urandom(16)  # library Shamir API shares one 128-bit secret
    nonce=os.urandom(12)
    minimal={'capsule':cid,'commitment':digest(policy),'epoch':1}
    ciphertext=nonce+AESGCM(key).encrypt(nonce,plaintext,aad(minimal))
    manifest={'v':2,**minimal,'policy':policy,'payload':hashlib.sha256(ciphertext).hexdigest(),
              'algorithm':'AES-128-GCM','custody':{'scheme':'shamir-pycryptodome-128','k':2,'n':3,
              'keys':{str(i+1):identity['public'] for i,identity in enumerate(identities)}},
              'witness':witness,'clock':{'profile':'witness-observed-v2','outage':'withhold-and-restart-grace'}}
    shares=[{'index':index,'value':value.hex()} for index,value in Shamir.split(2,3,key)]
    # Python cannot guarantee zeroisation of temporary objects.
    del key
    return manifest,ciphertext,shares


def provision(prepared,witness_url,custodian_urls,tokens,*,fail_after=None,fault_enrollment=None):
    m,sig=prepared.manifest,prepared.signature;check_manifest(m,sig)
    request(witness_url+'/enroll',{'manifest':m,'signature':sig},tokens[0])
    receipts=[]
    for index,url in enumerate(custodian_urls):
        body={'manifest':m,'signature':sig,'share':prepared.shares[index]}
        if fault_enrollment==index: body['fault']='after_commit'
        receipts.append(request(url+'/enroll',body,tokens[index+1]))
        if fail_after==index+1: raise RuntimeError('creator interrupted during share provisioning')
    request(witness_url+'/ready',{'capsule':m['capsule'],'receipts':receipts},tokens[0])
    return receipts


class Session:
    def __init__(self,root,witness_url):
        self.engine=Engine(root);self.witness_url=witness_url
        with self.engine.transaction() as db:
            if db.execute('SELECT count(*) FROM capsules').fetchone()[0]==0:
                observed=request(witness_url+'/clock')
                db.execute('UPDATE clock SET now=?,healthy=?',(observed['lower'],observed['healthy']))

    def install(self,prepared):
        m=prepared.manifest;check_manifest(m,prepared.signature)
        if hashlib.sha256(prepared.ciphertext).hexdigest()!=m['payload']: raise ValueError('ciphertext hash')
        self.engine.import_encrypted(m['capsule'],m['policy'],prepared.ciphertext)
        atomic_json(self.engine.root/'manifest.json',{'manifest':m,'signature':prepared.signature})
        return self.publish(m['capsule'])

    def publish(self,cid,*,lose_ack=False):
        return request(self.witness_url+'/publish',self.engine.export(cid),
                       headers={'X-Lose-Ack':'1'} if lose_ack else None)

    def command(self,cid,owner,action):
        s=self.engine.export(cid)
        msg={'v':2,'capsule':cid,'commitment':s['commitment'],'action':action,'head':s['head']}
        self.engine.owner_command(cid,action,sign(owner,msg),context={'head':s['head']})
        return self.publish(cid)

    def submit(self,cid,message,signature,*,lose_ack=False):
        receipt=self.engine.submit(cid,message,signature)
        bundle=self.publish(cid,lose_ack=lose_ack)
        # Only this externally durable checkpoint is an authoritative v2 receipt.
        return {'local':receipt,'witness':bundle['receipt'],'signature':bundle['signature']}

    def tick(self,cid,now,outage=False):
        self.engine.tick(now,outage=outage);return self.publish(cid)

    def authorise(self,cid):
        # Avoid preparing an irrevocable local decision before independently
        # observed uncertainty has allowed the complete grace to elapse.
        answer=request(self.witness_url+'/bundle?capsule='+cid+'&nonce=decision-preflight')
        status=answer['status']['message'];upper=status.get('candidate_upper')
        if upper is not None and status['clock']['lower']<upper+self.engine.export(cid)['policy']['grace']:
            return None
        decision=self.engine.authorise(cid);self.publish(cid);return decision

    def restore_projection(self,manifest):
        answer=request(self.witness_url+'/bundle?capsule='+manifest['capsule']+'&nonce=reconcile')
        bundle=answer['bundle'];validate_bundle(bundle,manifest);s=bundle['snapshot']
        # Only explicitly restore the witnessed prefix; never merge rejected local forks.
        with self.engine.transaction() as db:
            local=db.execute('SELECT commitment,payload FROM capsules WHERE id=?',(s['capsule'],)).fetchone()
            if not local or local['commitment']!=manifest['commitment'] or local['payload']!=manifest['payload']: raise ValueError('projection identity')
            db.execute('DELETE FROM events WHERE capsule=?',(s['capsule'],))
            for e in s['events']:
                db.execute('INSERT INTO events VALUES(?,?,?,?)',(s['capsule'],e['seq'],canonical(e).decode(),digest(e)))
            db.execute('UPDATE capsules SET head=?,count=? WHERE id=?',(s['head'],len(s['events']),s['capsule']))
            db.execute('UPDATE clock SET now=?,healthy=?',(s['now'],s['healthy']))
        return bundle


def release_request(manifest,decision):
    return {'capsule':manifest['capsule'],'manifest':digest(manifest),'decision':digest(decision)}


def recover(manifest,ciphertext,responses):
    if hashlib.sha256(ciphertext).hexdigest()!=manifest['payload']: raise ValueError('payload digest')
    shares=[];indices=set();binding=None
    for response in responses:
        m=response['message'];index=m['index']
        if str(index) not in manifest['custody']['keys'] or index in indices: raise ValueError('duplicate/unknown custodian')
        verify(manifest['custody']['keys'][str(index)],m,response['signature'])
        if m['capsule']!=manifest['capsule'] or m['epoch']!=manifest['epoch'] or m['manifest']!=digest(manifest) or m['commitment']!=manifest['commitment'] or m['payload']!=manifest['payload']: raise ValueError('share scope')
        current={k:v for k,v in m.items() if k not in ('index','share')}
        if binding is not None and current!=binding: raise ValueError('different release snapshots')
        binding=current;indices.add(index);shares.append((index,bytes.fromhex(m['share'])))
    if len(shares)<manifest['custody']['k']: raise ValueError('insufficient custody quorum')
    key=Shamir.combine(shares[:manifest['custody']['k']])
    return AESGCM(key).decrypt(ciphertext[:12],ciphertext[12:],aad(manifest))


def record_simulated_delivery(session,cid,decision):
    """Record a synthetic recipient acknowledgement; never claim human receipt."""
    with session.engine.transaction() as db:
        snapshot=session.engine.snapshot(db,cid)
        actual=next((e for e in snapshot['events'] if e['kind']=='AUTHORISED'),None)
        if actual!=decision: raise ValueError('delivery decision mismatch')
        if not any(e['kind']=='RELEASED' for e in snapshot['events']):
            session.engine.append(db,cid,'RELEASED',{'decision':digest(decision),'adapter':'bounded-synthetic-recipient','receipt':'synthetic acknowledgement; no human receipt'})
    return session.publish(cid)


def collect_shares(manifest,decision,custodian_urls):
    """Automatic honest-service failover; no user-selected trustee is required."""
    responses=[]
    for url in custodian_urls:
        try:responses.append(request(url+'/release',release_request(manifest,decision)))
        except Exception:continue
        if len(responses)>=manifest['custody']['k']:return responses
    raise ValueError('custody quorum unavailable')
