"""Split capability provider gated by independently verifiable terminal commitment."""
import os
from Engine.protocol import digest
from Available.proofs import require,checked_signature
from Honest import crypto
from Missing.service import Store as OldStore
from .proofs import registry,finality,contribution_context,CAPABILITIES,same

class Store(OldStore):
    def handle(self,path,b):
        require(self.available,'holder unavailable')
        if path=='/enroll08':
            r,c,m=registry(b['registry']);d=c['domains'][self.domain];require(d['members'][str(self.index)]==self.public,'domain identity')
            checked_signature(m['policy']['owner'],b['enrollment']);require(same(b['enrollment']['message'],{'v':8,'registry':digest(b['registry']),'domain':self.domain,'index':self.index,'share':b['share'],'provider':self.public}),'v8 enrollment binding')
            require(crypto.encode(crypto.number(b['share'])*crypto.G)==d['key']['Y'][str(self.index)],'share commitment')
            row=self.db.execute('SELECT body FROM capsules WHERE id=?',(m['capsule'],)).fetchone()
            if row:require(self.get(m['capsule'])['registry']==b['registry'],'immutable provider registry')
            else:self.put(m['capsule'],{'registry':b['registry'],'sidecar':r['split'],'share':b['share'],'anchors':{},'partials':{},'terminal':None})
            return {'enrolled':True,'capabilities':CAPABILITIES}
        if path in ('/retain-decision08','/decision08'):
            s=self.get(b['capsule']);r,c,m=registry(s['registry']);require(same(b['registry'],s['registry']),'decision retrieval registry')
            if path=='/retain-decision08':
                cert=b['certificate'];info=finality(s['registry'],cert)
                if s['terminal'] is not None:require(digest(s['terminal']['value'])==info['value'],'conflicting terminal record')
                s['terminal']=s['terminal'] or cert;self.put(m['capsule'],s)
            require(type(b['nonce']) is str and len(b['nonce'])==64,'decision retrieval challenge')
            return self.signed({'v':8,'kind':'RETAINED_DECISION','capsule':m['capsule'],'registry':digest(s['registry']),'nonce':b['nonce'],'domain':self.domain,'index':self.index,'certificate':s['terminal']})
        if path in ('/enroll07','/partial07'):raise ValueError('v8 requires terminal decision; no legacy downgrade')
        require(path=='/partial08','unsupported operation');s=self.get(b['capsule']);r,c,m=registry(s['registry']);require(same(b['registry'],s['registry']) and b['requirements']==CAPABILITIES,'provider profile/registry')
        decision=finality(s['registry'],b['finality']);require(decision['kind']=='RELEASE','not a release commitment');ctx=contribution_context(s['registry'],b['finality'],self.domain);require(same(ctx,b['context']),'finality/context binding')
        # Terminal finality is immutable; an online SaaS/creator or new clock decision is unnecessary.
        if s['terminal'] is not None:require(digest(s['terminal']['value'])==digest(b['finality']['value']),'conflicting committed value')
        s['terminal']=b['finality'];ident=digest(ctx)
        if self.fault=='malformed':return {'success':True}
        if ident not in s['partials']:
            p=crypto.partial(c['domains'][self.domain]['key'],s['share'],self.index,c['wraps'][self.domain]['R'],ctx)
            if self.fault=='bad-proof':p['z']='00'*32
            s['partials'][ident]=self.signed({'context':ctx,'index':self.index,'box':crypto.seal_to(c['recipient'],p,ctx)})
        if b.get('fault')=='before-commit':os._exit(71)
        self.put(m['capsule'],s)
        if b.get('fault')=='after-commit':os._exit(72)
        return s['partials'][ident]

def main():
    import Missing.service as old
    old.Store=Store;old.CAPABILITIES=CAPABILITIES;old.main()
if __name__=='__main__':main()
