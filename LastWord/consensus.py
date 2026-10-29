"""Single-instance signed prepare/commit/view-change reference state machine.
The persistence callback must durably commit BEFORE any message is returned.
"""
import copy
from Engine.protocol import digest,sign
from Available.proofs import require
from .proofs import registry,scope,value,proposal,prepared,votes,view_changes,vote_message,finality

class Replica:
    def __init__(self,reg,index,key,state=None,persist=None,guard=None):
        self.reg=reg;self.index=index;self.key=key;self.save=persist or (lambda s:None);self.guard=guard or (lambda v:True)
        self.s=copy.deepcopy(state) if state is not None else {'view':0,'proposals':{},'votes':{},'prepared':None,'changes':{},'terminal':None,'quarantine':False}
        _,_,m=registry(reg);require(key.public_key().public_bytes_raw().hex()==m['witnesses'][str(index)],'replica identity')
    def signed(self,m):return {'message':m,'signature':sign(self.key,m)}
    def put(self):self.save(copy.deepcopy(self.s))
    def ready(self):require(not self.s['quarantine'],'authenticated recovery required')
    def view_change(self,n):
        self.ready();require(self.s['terminal'] is None,'terminal decision already committed');require(type(n) is int and self.s['view']<=n<=min(64,self.s['view']+1) and n>0,'monotone bounded view')
        if str(n) not in self.s['changes']:
            self.s['view']=n;self.s['changes'][str(n)]=self.signed({**scope(self.reg),'kind':'VIEW_CHANGE','view':n,'prepared':self.s['prepared'],'witness':self.index});self.put()
        return self.s['changes'][str(n)]
    def propose(self,n,v,changes):
        self.ready();require(self.index==1+n%4 and n>=self.s['view'] and self.s['terminal'] is None,'not current leader')
        if n:
            high=view_changes(self.reg,n,changes)
            if high is not None:v=high['value']
        else:require(changes==[],'initial proposal')
        value(self.reg,v);self.guard(v)
        old=self.s['proposals'].get(str(n))
        if old:require(old['message']['value']==v,'leader cannot equivocate');return old
        out=self.signed({'scope':scope(self.reg),'kind':'PROPOSAL','view':n,'value':v,'changes':changes,'leader':self.index});proposal(self.reg,out)
        self.s['view']=n;self.s['proposals'][str(n)]=out;self.put();return out
    def prepare(self,p):
        self.ready();q=proposal(self.reg,p);n=q['view'];v=q['value'];require(self.s['terminal'] is None and n>=self.s['view'],'closed or stale view');self.guard(v)
        # A view above zero must carry the new-view proof even for lagging replicas.
        self.s['view']=n;return self.cast('PREPARE',n,v)
    def cast(self,phase,n,v):
        ident=phase+':'+str(n);old=self.s['votes'].get(ident)
        if old:require(old['message']['value']==digest(v),'no double vote');return old
        out=self.signed(vote_message(self.reg,phase,n,v,self.index));self.s['votes'][ident]=out;self.put();return out
    def commit_vote(self,pc):
        self.ready();prepared(self.reg,pc);n=pc['view'];v=pc['value'];require(self.s['terminal'] is None and n>=self.s['view'],'closed or stale prepared proof');self.guard(v)
        # Local PREPARE not required: quorum proof establishes preparation.
        prior_vote=self.s['votes'].get('COMMIT:'+str(n))
        if prior_vote:
            require(prior_vote['message']['value']==digest(v),'no conflicting commit retry');return prior_vote
        self.s['view']=n;high=self.s['prepared'];require(high is None or n>=high['view'],'prepared view regression')
        if high and n==high['view']:require(high['value']==v,'prepared conflict')
        self.s['prepared']=pc;return self.cast('COMMIT',n,v)
    def decide(self,cert):
        result=finality(self.reg,cert);old=self.s['terminal']
        require(old is None or digest(old['value'])==result['value'],'conflicting terminal certificate')
        self.s['terminal']=old or cert;self.put();return self.s['terminal']
    def quarantine(self):self.s['quarantine']=True;self.put()
    def recover(self,checkpoints):
        # Signatures and nonce freshness are verified by the service before this merge.
        require(len(checkpoints)>=3,'recovery quorum')
        for peer in checkpoints:
            if peer['terminal'] is not None:self.decide(peer['terminal'])
            if peer['prepared'] is not None:
                p=prepared(self.reg,peer['prepared']);old=self.s['prepared']
                if old is None or p['view']>old['view']:self.s['prepared']=p
                elif old['view']==p['view']:require(old['value']==p['value'],'recovery prepared fork')
        # Never re-sign a view whose local vote history may have rolled back.
        self.s['view']=max([self.s['view']]+[p['view'] for p in checkpoints])+1
        require(self.s['view']<=64,'bounded recovery view exhausted');self.s['quarantine']=False;self.put();return {'recovered':True,'view':self.s['view'],'terminal':self.s['terminal']}
