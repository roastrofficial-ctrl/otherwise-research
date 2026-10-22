"""Installed owner client: keys, plaintext and aggregate shares never enter SaaS."""
import copy
import os
import subprocess
from Engine.protocol import digest,canonical
from Available.lifecycle import Client as BaseClient
from Available.proofs import manifest,require,record,fence
from Available.transport import UrllibTransport
from Bounded.wire import strict_json
from .proofs import snapshot

PRIVATE={'owner_seed','shares','plaintext','passphrase','owner_vault'}

def public(kit):
    return {'v':5,'kind':'PUBLIC_CAPSULE','manifest':kit['manifest'],'ciphertext':kit['ciphertext'],'arm':kit['arm'],'disarm':kit['disarm'],'acknowledgements':kit['acknowledgements']}

def validate_public(view):
    require(set(view)=={'v','kind','manifest','ciphertext','arm','disarm','acknowledgements'} and type(view['v']) is int and view['v']==5 and view['kind']=='PUBLIC_CAPSULE','public schema')
    manifest(view['manifest'])
    def walk(x):
        if isinstance(x,dict):
            require(not(PRIVATE & set(x)),'private capability in public projection')
            for v in x.values():walk(v)
        elif isinstance(x,list):
            for v in x:walk(v)
    walk(view);return view

class RelayTransport:
    """Untrusted SaaS courier for witness messages ONLY; custody enrollment stays direct."""
    def __init__(self,relay,witnesses,transport=None):self.relay=relay;self.witnesses=witnesses;self.direct=transport or UrllibTransport()
    def call(self,url,body=None):
        if any(url.startswith(u+'/') for u in self.witnesses):return self.direct.call(self.relay+'/relay',{'url':url,'body':body})
        return self.direct.call(url,body)

class PinnedTransport:
    def __init__(self,trust,transport):self.trust=trust;self.transport=transport
    def call(self,url,body=None):
        found=next((p for p in self.trust['providers'] if url.startswith(p['url']+'/')),None)
        require(found is not None,'URL outside independently installed trust configuration')
        response=self.transport.call(url,body)
        if url==found['url']+'/identity':require(response['public']==found['public'],'provider identity substitution')
        return response

class Client(BaseClient):
    def __init__(self,trust,transport=None):
        self.trust=copy.deepcopy(trust);self.network=transport or UrllibTransport();super().__init__(PinnedTransport(trust,self.network));self.fresh={}
    def draft(self,rounds=2,seconds=120):
        w=[p['url'] for p in self.trust['providers'] if p['role']=='witness'];c=[p['url'] for p in self.trust['providers'] if p['role']=='custodian']
        require(len(w)==4 and len(c)==3,'trust committee shape')
        kit=super().draft(w,c,rounds,seconds);kit['trust']=self.trust;kit['anchors']={};return kit
    def validate(self,kit):
        m=manifest(kit['manifest']);require(kit['trust']==self.trust,'local trust configuration substitution')
        for role,urls,keys in [('witness',kit['witnesses'],m['witnesses']),('custodian',kit['custodians'],m['custody']['keys'])]:
            pins=[p for p in self.trust['providers'] if p['role']==role]
            require(urls==[p['url'] for p in pins] and [keys[str(i+1)] for i in range(len(pins))]==[p['public'] for p in pins],'manifest provider substitution')
        require(self.private(kit).public_key().public_bytes_raw().hex()==m['policy']['owner'],'local owner key substitution')
    def call(self,url,body=None):
        # Inherited lifecycle transmits signed messages, never the capability kit.
        if body is not None:
            def walk(x):
                if isinstance(x,dict):
                    require(not(PRIVATE & set(x)),'secret material in network request')
                    for v in x.values():walk(v)
                elif isinstance(x,list):
                    for v in x:walk(v)
            walk(body)
        return super().call(url,body)
    def inspect(self,kit):
        self.validate(kit);m=manifest(kit['manifest']);nonce=os.urandom(32).hex();found={};failures=[]
        for i,u in enumerate(kit['witnesses'],1):
            try:
                signed=self.call(u+'/inspect',{'capsule':m['capsule'],'nonce':nonce});r=snapshot(kit['manifest'],signed,nonce,i)
                node=subprocess.run(['node','Verifier/untrusted.mjs'],input=canonical({'manifest':kit['manifest'],'snapshot':signed,'nonce':nonce,'index':i}),capture_output=True)
                require(node.returncode==0,'independent fresh-status verification')
                hashes=set()
                for item in r['records']:
                    kind=item['message']['kind']
                    if kind in ('ARM','DISARM'):fence(m,item,kind)
                    else:record(m,item,kind)
                    hashes.add(digest(item))
                require(set(kit['anchors'].get(str(i),[]))<=hashes,'witness history rollback detected')
                found[u]={'manifest':kit['manifest'],'records':r['records']};kit['anchors'][str(i)]=sorted(hashes)
            except Exception as exc:failures.append({'witness':i,'reason':str(exc)})
        require(len(found)>=3,'no fresh authoritative status quorum; stale/withheld state is not success')
        # Reuse the existing aggregation algorithm only over fresh, verified snapshots.
        outer=self.transport
        class Discovery:
            def call(inner,url,body=None):
                for u,s in found.items():
                    if url.startswith(u+'/status?'):return s
                raise ValueError('no fresh snapshot')
        try:self.transport=Discovery();result=super().recover(kit)
        finally:self.transport=outer
        return {**result,'fresh':True,'snapshot_nonce':nonce,'sources':len(found),'failures':failures}
    def run(self,kit,action,**kw):
        self.validate(kit)
        if action in ('status','recover'):return self.inspect(kit)
        if action=='checkin':return self.checkin(kit,kw.get('challenge'))
        if action in ('arm','disarm','evaluate'):return getattr(self,action)(kit)
        if action=='repair':return self.repair(kit,kw['index'])
        if action=='simulate':
            decision=self.evaluate(kit);return self.simulate(kit,decision['certificate']) if decision['authorised'] else decision
        raise ValueError('unknown owner action')


def verify_projection(view,kit):
    """Untrusted product output cannot replace the local commitment or confirm freshness."""
    import base64,hashlib
    validate_public(view);require(view['manifest']==kit['manifest'],'operator manifest/content/destination substitution')
    require(hashlib.sha256(base64.b64decode(view['ciphertext'],validate=True)).hexdigest()==kit['manifest']['message']['payload'],'operator ciphertext substitution')
    from Available.proofs import acknowledgement,fence_certificate
    for ack in view['acknowledgements']:
        require(ack['manifest']==kit['manifest'],'operator acknowledgement scope');acknowledgement(ack['manifest'],ack['receipts'])
    if view['arm']:fence_certificate(kit['manifest'],view['arm'],'ARM')
    if view['disarm']:fence_certificate(kit['manifest'],view['disarm'],'DISARM')
    # Even valid historical receipts do not establish current state; inspect directly.
    return {'historical_projection_verified':True,'fresh':False}
