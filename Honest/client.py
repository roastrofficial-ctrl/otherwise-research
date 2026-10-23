"""Trusted installed-client adapter. No SaaS, no custodian state mounts, no PorterNet."""
import base64
import hashlib
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Engine.protocol import canonical,digest,sign
from Available.client import aad
from Available.proofs import require,manifest,fence,fence_certificate,checked_signature
from Untrusted.client import Client as Creator
from . import crypto
from .protocol import commitment,encryption_context,operation,CAPABILITIES,compatible

class Client(Creator):
    def prepare_custody(self,kit,key):
        """Creator/dealer input shares are consumed locally, never sent to SaaS.
        The experiment keeps them for the compromised-provisioning counterexample.
        """
        public,shares=key
        secret,pub=crypto.recipient();kit['recipient_seed']=secret
        dek=Shamir.combine([(s['index'],bytes.fromhex(s['value'])) for s in kit['shares'][:2]])
        c={'v':6,'kind':'CUSTODY_RESEARCH','manifest':kit['manifest'],'key':public,'recipient':pub,
           'wrap':crypto.wrap(public,dek,encryption_context(kit['manifest'],public,pub))}
        kit['custody06']={'message':c,'signature':sign(self.private(kit),c)};commitment(kit['custody06'])
        for i,u in enumerate(kit['custodians'],1):
            caps=self.call(u+'/identity')['capabilities'];require(caps==CAPABILITIES,'provider profile pin')
            e={'v':6,'sidecar':digest(kit['custody06']),'index':i,'share':shares[str(i)],'provider':kit['manifest']['message']['custody']['keys'][str(i)]}
            self.call(u+'/enroll',{'sidecar':kit['custody06'],'share':shares[str(i)],'enrollment':{'message':e,'signature':sign(self.private(kit),e)}})
        return kit
    def arm(self,kit):
        require('custody06' in kit,'explicit v6 custody provisioning required');m=manifest(kit['manifest']);rs=[]
        for i,u in enumerate(kit['witnesses'],1):
            try:
                r=self.call(u+'/arm',{'manifest':kit['manifest'],'command':self.command(kit,'ARM')});f=fence(m,r,'ARM');require(f['witness']==i,'witness pin');rs.append(r)
            except Exception:pass
        fence_certificate(kit['manifest'],rs,'ARM');kit['arm']=rs;self.distribute(kit,rs)
        return {'state':'ARMED','verified':True}
    def context(self,kit,cert):
        # Recover an agreed set digest from independent fresh provider reads.
        m=manifest(kit['manifest']);heads={}
        for i,u in enumerate(kit['custodians'],1):
            try:
                s=self.call(u+'/head',{'capsule':m['capsule']});checked_signature(m['custody']['keys'][str(i)],s)
                r=s['message'];require(r=={'v':6,'capsule':m['capsule'],'head':r['head'],'index':i},'head domain')
                heads.setdefault(r['head'],[]).append(i)
            except Exception:pass
        head=next((h for h,ids in heads.items() if len(ids)>=2),None);require(head is not None,'no compatible fresh custody snapshot')
        return operation(kit['custody06'],cert,head)
    def request_body(self,kit,cert,ctx):
        return {'capsule':ctx['capsule'],'sidecar':kit['custody06'],'certificate':cert,'head':ctx['evidence_head'],'requirements':CAPABILITIES}
    def disclose(self,kit,cert,ctx=None):
        ctx=ctx or self.context(kit,cert);body=self.request_body(kit,cert,ctx);responses=[]
        for u in kit['custodians']:
            try:responses.append(self.call(u+'/partial',body))
            except Exception:pass
        return recover(kit['custody06'],base64.b64decode(kit['ciphertext']),kit['recipient_seed'],cert,ctx,responses)

def recover(sidecar,ciphertext,recipient_seed,cert,ctx,responses):
    from Available.proofs import release
    c,m=commitment(sidecar);release(cert);require(cert['manifest']==c['manifest'],'release scope')
    require(ctx==operation(sidecar,cert,ctx['evidence_head']),'partial context binding')
    require(hashlib.sha256(ciphertext).hexdigest()==m['payload'],'ciphertext digest')
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    pub=X25519PrivateKey.from_private_bytes(bytes.fromhex(recipient_seed)).public_key().public_bytes_raw().hex()
    require(pub==c['recipient'],'recipient substitution')
    partials=[];seen=set()
    for s in responses:
        r=s['message'];require(set(r)=={'context','index','box'} and type(r['index']) is int and r['index'] in (1,2,3) and r['index'] not in seen,'partial response schema/duplicate')
        checked_signature(m['custody']['keys'][str(r['index'])],s);require(r['context']==ctx,'partial response context');seen.add(r['index'])
        p=crypto.open_for(recipient_seed,r['box'],ctx);require(p['index']==r['index'],'inner signer index');partials.append(p)
    key=crypto.unwrap(c['key'],c['wrap'],encryption_context(c['manifest'],c['key'],c['recipient']),partials,ctx)
    return AESGCM(key).decrypt(ciphertext[:12],ciphertext[12:],aad(m))
