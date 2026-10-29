"""Independent creator/recipient adapter: both domains indispensable, no SaaS keys."""
import base64
import hashlib
import os
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from Engine.protocol import canonical,digest,sign
from Available.client import aad,evidence
from Available.proofs import require,manifest,release,fence,fence_certificate,record,acknowledgement,checked_signature
from Untrusted.client import Client as Creator
from Honest import crypto
from Honest.protocol import evidence_snapshot
from .protocol import DOMAINS,SUITE,CAPABILITIES,commitment,wrap_context,context,response,authorise,plain_commit
from .collect import Transport,gather

class Client(Creator):
    def __init__(self,trust,transport=None):
        super().__init__(trust,transport or Transport(4));self.audit=[]
    def parallel(self,urls,path,body,validator,needed,deadline=2.5):
        result=gather(list(range(len(urls))),lambda i:self.call(urls[i]+path,body),lambda i,r:validator(i,r),needed,deadline,workers=min(len(urls),6));self.audit+=result['invalid'];return result
    def draft(self,rounds=2,seconds=120):
        # Identity pins come from the independently installed configuration, not availability.
        urls=[p['url'] for p in self.trust['providers'] if p['role']=='witness']
        def valid(i,t):
            require(t['healthy'] is True and type(t['lower']) is int and type(t['upper']) is int and 0<=t['lower']<=t['upper'],'unusable advisory clock');return t
        got=self.parallel(urls,'/clock',None,valid,3);require(got['sufficient'],'no usable advisory clock quorum')
        clock=sorted(got['valid'].values(),key=lambda t:t['upper'])[len(got['valid'])//2];pins={p['url']:p['public'] for p in self.trust['providers']};original=self.transport
        class Discovery:
            def call(self,url,body=None):
                for u,pk in pins.items():
                    if url==u+'/identity':return {'public':pk}
                    if url==u+'/clock':return clock
                return original.call(url,body)
        try:self.transport=Discovery();return super().draft(rounds,seconds)
        finally:self.transport=original
    def prepare(self,kit,keys=None,epoch=1):
        keys=keys or {d:crypto.dealer() for d in DOMAINS};owner=self.private(kit)
        dek=Shamir.combine([(s['index'],bytes.fromhex(s['value'])) for s in kit['shares'][:2]])
        old=manifest(kit['manifest']);ct=base64.b64decode(kit['ciphertext']);text=AESGCM(dek).decrypt(ct[:12],ct[12:],aad(old));salt=os.urandom(16);nonce=os.urandom(12)
        ct=nonce+AESGCM(dek).encrypt(nonce,salt+text,aad(old));old['payload']=hashlib.sha256(ct).hexdigest();kit['manifest']={'message':old,'signature':sign(owner,old)};kit['ciphertext']=base64.b64encode(ct).decode()
        seed,pk=crypto.recipient();kit['recipient_seed']=seed;kit['authorities']=[p['url'] for p in self.trust['providers'] if p['role']=='authority'];require(len(kit['authorities'])==3,'independent authority committee required')
        domains={d:{'epoch':epoch,'key':keys[d][0],'members':{str(i+1):self.call(u+'/identity')['public'] for i,u in enumerate(kit['custodians'] if d=='custody' else kit['authorities'])}} for d in DOMAINS}
        c={'v':7,'suite':SUITE,'epoch':epoch,'manifest':kit['manifest'],'recipient':pk,'domains':domains,'wraps':{},'plaintext_commitment':plain_commit(salt,text)}
        A=os.urandom(16);parts={'custody':A,'authority':bytes(x^y for x,y in zip(A,dek))}
        for d in DOMAINS:c['wraps'][d]=crypto.wrap(keys[d][0],parts[d],wrap_context(c,d))
        sc={'message':c,'signature':sign(owner,c)};commitment(sc);kit['custody07']=sc
        for d in DOMAINS:
            urls=kit['custodians'] if d=='custody' else kit['authorities']
            for i,u in enumerate(urls,1):
                e={'v':7,'domain':d,'sidecar':digest(sc),'index':i,'share':keys[d][1][str(i)],'provider':domains[d]['members'][str(i)]}
                self.call(u+'/enroll07',{'sidecar':sc,'share':keys[d][1][str(i)],'enrollment':{'message':e,'signature':sign(owner,e)}})
        del kit['shares'];return kit
    def arm(self,kit):
        commitment(kit['custody07']);return self.fences(kit,'ARM')
    def fences(self,kit,kind):
        m=manifest(kit['manifest'])
        def valid(i,r):
            row=fence(m,r,kind);require(row['witness']==i+1,'fence responder pin');return r
        got=self.parallel(kit['witnesses'],'/'+kind.lower(),{'manifest':kit['manifest'],'capsule':m['capsule'],'command':self.command(kit,kind)},valid,3)
        require(got['sufficient'],kind+' quorum unavailable; outcome uncertain');rs=list(got['valid'].values());fence_certificate(kit['manifest'],rs,kind);self.distribute(kit,rs);kit[kind.lower()]=rs
        return {'state':'ARMED' if kind=='ARM' else 'DISARMED','verified':True}
    def disarm(self,kit):return self.fences(kit,'DISARM')
    def distribute(self,kit,receipts):
        m=manifest(kit['manifest']);holders=[]
        for receipt in receipts:
            def valid(i,r):
                checked_signature(m['witnesses'][str(i+1)],r);require(r['message']=={'v':4,'kind':'RETAINED','capsule':m['capsule'],'manifest':digest(m),'digest':digest(receipt),'holder':m['witnesses'][str(i+1)]},'retention scope');return r
            got=self.parallel(kit['witnesses'],'/retain',{'capsule':m['capsule'],'receipt':receipt},valid,3);require(got['sufficient'],'durable witness holders unavailable; outcome uncertain');holders+=list(got['valid'].values())
        return holders
    def checkin(self,kit,challenge=None):
        m=manifest(kit['manifest']);require(challenge is not None,'v7 harness requires explicit committed challenge')
        sl=next(s for s in m['slots'] if s['challenge']==challenge);p=evidence(kit['manifest'],self.private(kit),sl['contract'],sl['challenge'])
        def valid(i,r):
            row=record(m,r,'OBSERVATION');require(row['witness']==i+1 and row['proof']==p,'observation source/proof');return r
        got=self.parallel(kit['witnesses'],'/observe',{'capsule':m['capsule'],'proof':p},valid,3);require(got['sufficient'],'no authoritative presence quorum; uncertain')
        rs=list(got['valid'].values());result=acknowledgement(kit['manifest'],rs);holders=self.distribute(kit,rs);kit['acknowledgements'].append({'manifest':kit['manifest'],'receipts':rs,'holders':holders});return {**result,'durable_holders':len({x['message']['holder'] for x in holders})}
    def inspect(self,kit):
        m=manifest(kit['manifest']);nonce=os.urandom(32).hex()
        def valid(i,r):
            from Untrusted.proofs import snapshot
            s=snapshot(kit['manifest'],r,nonce,i+1)
            for item in s['records']:
                kind=item['message']['kind'];(fence if kind in ('ARM','DISARM') else record)(m,item,kind)
            require(set(kit['anchors'].get(str(i+1),[]))<=set(digest(x) for x in s['records']),'history rollback')
            return r
        got=self.parallel(kit['witnesses'],'/inspect',{'capsule':m['capsule'],'nonce':nonce},valid,3);require(got['sufficient'],'fresh witness quorum unavailable')
        _,history,anchors=evidence_snapshot(kit['manifest'],list(got['valid'].values()),nonce,kit['anchors']);kit['anchors']=anchors
        # Use original lifecycle aggregation only over fresh authenticated snapshots.
        original=self.transport;found={kit['witnesses'][i]:{'manifest':kit['manifest'],'records':s['message']['records']} for i,s in got['valid'].items()}
        class Discovery:
            def call(self,url,body=None):
                for u,state in found.items():
                    if url.startswith(u+'/status?'):return state
                raise ValueError('no fresh source')
        from Available.lifecycle import Client as Base
        try:self.transport=Discovery();state=Base.recover(self,kit)
        finally:self.transport=original
        return {**state,'fresh':True,'history':history}
    def evaluate(self,kit):
        import itertools
        m=manifest(kit['manifest']);groups=[]
        for sl in m['slots']:
            def valid(i,r):
                row=record(m,r,'FINAL');require(row['witness']==i+1 and (row['contract'],row['challenge'])==(sl['contract'],sl['challenge']),'final source/scope');return r
            got=self.parallel(kit['witnesses'],'/finalise',{'capsule':m['capsule'],**sl},valid,3)
            if not got['sufficient']:return {'authorised':False,'reason':'insufficient finality'}
            rs=list(got['valid'].values());self.distribute(kit,rs)
            # Collapse equivalent quorums by earliest upper time, preserving wire4 semantics.
            candidates={}
            for g in itertools.combinations(rs,3):
                yes=all(r['message']['value']=='ABSENT' for r in g) if next(c for c in m['policy']['contracts'] if c['id']==sl['contract'])['kind']=='absence' else all(r['message']['value']=='TRUE' for r in g) and len({digest(r['message']['proof']) for r in g})==1
                tag=(yes,digest(g[0]['message']['proof']) if yes else None)
                if tag not in candidates or max(r['message']['upper'] for r in g)<max(r['message']['upper'] for r in candidates[tag]):candidates[tag]=g
            groups.append(list(candidates.values()))
        from Available.proofs import operation
        for combo in itertools.product(*groups):
            cert={'v':4,'manifest':kit['manifest'],'finals':[list(g) for g in combo],'operation':operation(m)};cert['authorisation']=digest(cert)
            try:release(cert)
            except Exception:continue
            return {'authorised':True,'certificate':cert}
        return {'authorised':False,'reason':'policy unsatisfied'}
    def contributions(self,kit,cert):
        c,m=commitment(kit['custody07']);bundle={}
        # A single bounded six-source round; never accept one domain's surplus for another.
        items=[(d,i) for d in DOMAINS for i in range(3)]
        def fetch(item):
            d,i=item;u=(kit['custodians'] if d=='custody' else kit['authorities'])[i]
            return self.call(u+'/partial07',{'capsule':m['capsule'],'sidecar':kit['custody07'],'certificate':cert,'context':context(kit['custody07'],cert,d),'requirements':CAPABILITIES})
        def valid(item,r):
            d,i=item;part=verify_contribution(kit['custody07'],cert,kit['recipient_seed'],d,r);require(part['index']==i+1,'source substitution');return r
        got=gather(items,fetch,valid,4,deadline=3,workers=6);self.audit+=got['invalid']
        for d in DOMAINS:
            validrows=[r for (domain,i),r in got['valid'].items() if domain==d];require(len(validrows)>=2,'missing independent '+d+' capability');bundle[d]=validrows[:2]
        return bundle
    def retain_operations(self,kit,cert,bundle):
        c,m=commitment(kit['custody07'])
        for d in DOMAINS:
            for r in bundle[d]:
                b={'sidecar':kit['custody07'],'certificate':cert,'response':r}
                def valid(i,s):
                    checked_signature(m['witnesses'][str(i+1)],s);require(s['message']=={'v':7,'kind':'STORED_ENCRYPTED_CONTRIBUTION','capsule':m['capsule'],'commitment':digest(kit['custody07']),'response':digest(r),'witness':i+1},'journal ack');return s
                got=self.parallel(kit['witnesses'],'/retain07',b,valid,3);require(got['sufficient'],'partial capability may exist; journal durability uncertain')
    def journals(self,kit):
        c,m=commitment(kit['custody07']);nonce=os.urandom(32).hex()
        def valid(i,s):
            checked_signature(m['witnesses'][str(i+1)],s);r=s['message'];require(set(r)=={'v','kind','capsule','commitment','nonce','witness','bundles'} and r['v']==7 and r['kind']=='OPERATION_JOURNAL' and r['nonce']==nonce and r['capsule']==m['capsule'] and r['commitment']==digest(kit['custody07']) and r['witness']==i+1,'fresh journal scope')
            for b in r['bundles']:response(b['sidecar'],b['certificate'],b['response']['message']['context']['domain'],b['response'])
            return s
        got=self.parallel(kit['witnesses'],'/inspect07',{'sidecar':kit['custody07'],'nonce':nonce},valid,3);require(got['sufficient'],'independent journal quorum unavailable')
        return list({digest(b['response']):b for s in got['valid'].values() for b in s['message']['bundles']}.values())
    def recover_journal(self,kit,cert):
        # Witnesses attest storage of encrypted replies, not their correctness.
        found={d:{} for d in DOMAINS}
        for b in sorted(self.journals(kit),key=lambda b:digest(b['response'])):
            try:
                require(b['sidecar']==kit['custody07'] and b['certificate']==cert,'journal operation scope')
                d=b['response']['message']['context']['domain'];p=verify_contribution(kit['custody07'],cert,kit['recipient_seed'],d,b['response']);found[d].setdefault(p['index'],b['response'])
            except Exception as e:self.audit.append({'source':'journal','reason':str(e),'response':b})
        bundle={d:[rows[i] for i in sorted(rows)][:2] for d,rows in found.items()}
        require(all(len(rows)==2 for rows in bundle.values()),'journal lacks a valid independent threshold')
        return recover(kit['custody07'],base64.b64decode(kit['ciphertext']),kit['recipient_seed'],cert,bundle,self.inspect(kit)['history'])
    def disclose(self,kit,cert):
        # Recipient verifies fresh lifecycle before accepting a historical permission.
        state=self.inspect(kit);authorise(kit['custody07'],cert,state['history']);bundle=self.contributions(kit,cert);self.retain_operations(kit,cert,bundle)
        return recover(kit['custody07'],base64.b64decode(kit['ciphertext']),kit['recipient_seed'],cert,bundle,state['history'])

def verify_contribution(sc,cert,recipient_seed,domain,signed):
    c,m=commitment(sc);r=response(sc,cert,domain,signed)
    pub=X25519PrivateKey.from_private_bytes(bytes.fromhex(recipient_seed)).public_key().public_bytes_raw().hex();require(pub==c['recipient'],'wrong recipient')
    p=crypto.open_for(recipient_seed,r['box'],r['context']);require(p['index']==r['index'],'encrypted participant index');crypto.verify_partial(c['domains'][domain]['key'],c['wraps'][domain]['R'],r['context'],p);return p

def recover(sc,ciphertext,recipient_seed,cert,bundle,history):
    c,m=commitment(sc);authorise(sc,cert,history);require(set(bundle)==set(DOMAINS),'both domains mandatory');require(hashlib.sha256(ciphertext).hexdigest()==m['payload'],'ciphertext substitution')
    parts={}
    for d in DOMAINS:
        ps=[verify_contribution(sc,cert,recipient_seed,d,r) for r in bundle[d]];require(len({p['index'] for p in ps})==len(ps) and len(ps)>=2,'distinct domain threshold')
        parts[d]=crypto.unwrap(c['domains'][d]['key'],c['wraps'][d],wrap_context(c,d),ps,context(sc,cert,d))
    dek=bytes(x^y for x,y in zip(parts['custody'],parts['authority']));plain=AESGCM(dek).decrypt(ciphertext[:12],ciphertext[12:],aad(m));require(len(plain)>=16 and plain_commit(plain[:16],plain[16:])==c['plaintext_commitment'],'plaintext commitment mismatch')
    return plain[16:]
