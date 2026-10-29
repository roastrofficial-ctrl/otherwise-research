"""Replaceable client/relay for a single terminal decision, never protocol truth owner."""
import base64,copy,os
from Engine.protocol import digest,sign
from Available.proofs import require,checked_signature
from Missing.client import Client as OldClient
from Missing.collect import gather
from Missing.protocol import DOMAINS
from .proofs import registry,scope,value,proposal,votes,prepared,view_changes,finality,contribution_context,CAPABILITIES,checked_change,same

class Client(OldClient):
    def prepare(self,kit,keys=None,epoch=1):
        original=self.transport;pending=[]
        class EnrollmentCapture:
            def call(self,url,body=None):
                if url.endswith('/enroll07'):pending.append((url,body));return {'captured_locally':True}
                return original.call(url,body)
        try:self.transport=EnrollmentCapture();super().prepare(kit,keys,epoch)
        finally:self.transport=original
        m=kit['manifest']['message'];r={'v':8,'suite':CAPABILITIES['suite'],'split':kit['custody07'],'committee':{'epoch':1,'keys':m['witnesses']},'model':'AUTHORISATION_WINS','operation':'terminal-1'}
        reg={'message':r,'signature':sign(self.private(kit),r)};registry(reg);kit['custody08']=reg
        for url,b in pending:
            old=b['enrollment']['message'];e={'v':8,'registry':digest(reg),'domain':old['domain'],'index':old['index'],'share':b['share'],'provider':old['provider']}
            self.call(url[:-len('/enroll07')]+'/enroll08',{'registry':reg,'share':b['share'],'enrollment':{'message':e,'signature':sign(self.private(kit),e)}})
        got=self.parallel(kit['witnesses'],'/register08',{'registry':reg},lambda i,r:r if r.get('registered') else (_ for _ in ()).throw(ValueError('registration failed')),3);require(got['sufficient'],'registry quorum unavailable');return kit
    def evaluate(self,kit):
        old=super().evaluate(kit)
        return {'policy_satisfied':old['authorised'],'evidence_certificate':old.get('certificate'),'reason':old.get('reason'),'proof_authorises_release':False,'terminal_decision_checked':False,'meaning':'policy proof is not a terminal decision'}
    def make_value(self,kit,kind,certificate=None):
        reg=kit['custody08'];return {'scope':scope(reg),'kind':kind,'arm':kit['arm'],'evidence':certificate if kind=='RELEASE' else None,'command':None if kind=='RELEASE' else {'message':{**scope(reg),'action':'DISARM'},'signature':sign(self.private(kit),{**scope(reg),'action':'DISARM'})}}
    def statuses(self,kit):
        reg=kit['custody08'];_,_,m=registry(reg);nonce=os.urandom(32).hex()
        def valid(i,r):
            checked_signature(m['witnesses'][str(i+1)],r);q=r['message'];require(set(q)=={'v','kind','capsule','registry','nonce','witness','state'} and q['v']==8 and q['kind']=='DECISION_STATUS' and q['capsule']==m['capsule'] and q['registry']==digest(reg) and q['nonce']==nonce and q['witness']==i+1,'status freshness/scope')
            require(type(q['state']['view']) is int and 0<=q['state']['view']<=64,'bounded status view')
            if q['state']['terminal'] is not None:finality(reg,q['state']['terminal'])
            return q['state']
        return self.parallel(kit['witnesses'],'/status08',{'capsule':m['capsule'],'nonce':nonce},valid,3)
    def order(self,kit,wanted,rounds=5):
        reg=kit['custody08'];_,_,m=registry(reg);value(reg,wanted);cid=m['capsule']
        for attempt in range(rounds):
            statuses=self.statuses(kit);require(statuses['sufficient'],'no authoritative decision status quorum')
            finals=[s['terminal'] for s in statuses['valid'].values() if s['terminal'] is not None]
            if finals:
                require(len({digest(c['value']) for c in finals})==1,'conflicting certificates beyond fault model');return finals[0]
            views=sorted(s['view'] for s in statuses['valid'].values());n=max(views[-2],attempt)  # one Byzantine status cannot force an arbitrary high view
            changes=[]
            if n:
                for index,state in statuses['valid'].items():
                    if state['view']<n-1:
                        for step in range(state['view']+1,n):
                            try:self.call(kit['witnesses'][index]+'/view-change08',{'capsule':cid,'view':step})
                            except Exception:break
                def vc_valid(i,r):
                    q=checked_change(reg,n,r);require(q['witness']==i+1,'view-change responder pin');return r
                got=self.parallel(kit['witnesses'],'/view-change08',{'capsule':cid,'view':n},vc_valid,3)
                if not got['sufficient']:continue
                changes=list(got['valid'].values());view_changes(reg,n,changes)
            leader=n%4
            try:p=self.call(kit['witnesses'][leader]+'/propose08',{'capsule':cid,'view':n,'value':wanted,'changes':changes});q=proposal(reg,p)
            except Exception:continue
            selected=q['value']
            def vote_valid(phase):
                def check(i,r):
                    from .proofs import vote_message
                    checked_signature(m['witnesses'][str(i+1)],r);require(same(r['message'],vote_message(reg,phase,n,selected,i+1)),'vote response');return r
                return check
            got=self.parallel(kit['witnesses'],'/prepare08',{'capsule':cid,'proposal':p},vote_valid('PREPARE'),3)
            if not got['sufficient']:continue
            pc={'view':n,'value':selected,'prepares':list(got['valid'].values())};prepared(reg,pc)
            got=self.parallel(kit['witnesses'],'/commit-vote08',{'capsule':cid,'prepared':pc},vote_valid('COMMIT'),3)
            if not got['sufficient']:continue
            fin={'v':8,'registry':digest(reg),'view':n,'value':selected,'prepares':pc['prepares'],'commits':list(got['valid'].values())};finality(reg,fin)
            # Terminal certificate is valid even if notification replies are lost.
            self.parallel(kit['witnesses'],'/decide08',{'capsule':cid,'certificate':fin},lambda i,r:r if finality(reg,r) else r,3);kit['finality08']=fin;return fin
        raise ValueError('no terminal decision within bounded attempts; pending is not success; retry/recover')
    def disarm(self,kit):
        cert=self.order(kit,self.make_value(kit,'DISARM'));require(finality(kit['custody08'],cert)['kind']=='DISARM','release already committed; cannot disarm');self.retain_decision(kit,cert);return {'state':'DISARM_COMMITTED','certificate':cert}
    def commit_release(self,kit,certificate):
        fin=self.order(kit,self.make_value(kit,'RELEASE',certificate));require(finality(kit['custody08'],fin)['kind']=='RELEASE','disarm already committed; no release');self.retain_decision(kit,fin);return fin
    def retained_decision(self,kit,certificate=None):
        reg=kit['custody08'];r,c,m=registry(reg);nonce=os.urandom(32).hex();items=[(d,i) for d in DOMAINS for i in range(3)]
        def fetch(item):
            d,i=item;url=(kit['custodians'] if d=='custody' else kit['authorities'])[i];body={'capsule':m['capsule'],'registry':reg,'nonce':nonce}
            if certificate is not None:body['certificate']=certificate
            return self.call(url+('/retain-decision08' if certificate is not None else '/decision08'),body)
        def valid(item,signed):
            d,i=item;checked_signature(c['domains'][d]['members'][str(i+1)],signed);q=signed['message'];require(set(q)=={'v','kind','capsule','registry','nonce','domain','index','certificate'} and q['v']==8 and q['kind']=='RETAINED_DECISION' and q['capsule']==m['capsule'] and q['registry']==digest(reg) and q['nonce']==nonce and q['domain']==d and q['index']==i+1,'retained decision scope')
            if q['certificate'] is not None:finality(reg,q['certificate'])
            return q['certificate']
        got=gather(items,fetch,valid,1,deadline=3,workers=6);self.audit+=got['invalid'];found=[x for x in got['valid'].values() if x is not None]
        require(len({digest(x['value']) for x in found})<=1,'conflicting independently valid terminal certificates')
        return found[0] if found else None
    def retain_decision(self,kit,certificate):return self.retained_decision(kit,certificate)

    def recover_witness(self,kit,index):
        reg=kit['custody08'];_,_,m=registry(reg);cid=m['capsule'];target=m['witnesses'][str(index)];url=kit['witnesses'][index-1]
        challenge=self.call(url+'/recovery-challenge08',{'capsule':cid});require(challenge['target']==target,'recovery target')
        cps=[self.call(u+'/checkpoint08',{'capsule':cid,'nonce':challenge['nonce'],'target':target}) for i,u in enumerate(kit['witnesses'],1) if i!=index]
        return self.call(url+'/recover08',{'capsule':cid,'nonce':challenge['nonce'],'checkpoints':cps})
    def collect_release(self,kit,fin):
        reg=kit['custody08'];r,c,m=registry(reg);require(finality(reg,fin)['kind']=='RELEASE','disarm has no decryption entitlement')
        items=[(d,i) for d in DOMAINS for i in range(3)]
        def fetch(item):
            d,i=item;url=(kit['custodians'] if d=='custody' else kit['authorities'])[i];return self.call(url+'/partial08',{'capsule':m['capsule'],'registry':reg,'finality':fin,'context':contribution_context(reg,fin,d),'requirements':CAPABILITIES})
        def valid(item,s):
            d,i=item;row=s['message'];checked_signature(c['domains'][d]['members'][str(i+1)],s);require(set(row)=={'context','index','box'} and row['index']==i+1 and same(row['context'],contribution_context(reg,fin,d)),'contribution scope');return s
        got=gather(items,fetch,valid,4,deadline=3,workers=6);self.audit+=got['invalid']
        out={d:[s for (domain,i),s in got['valid'].items() if domain==d] for d in DOMAINS};require(all(len(v)>=2 for v in out.values()),'missing independent component')
        return {'v':8,'registry':reg,'ciphertext':kit['ciphertext'],'finality':fin,'contributions':out}
