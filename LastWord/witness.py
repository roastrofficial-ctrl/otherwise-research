"""Wire4 observations + separately versioned durable v8 terminal decision log."""
import os,sqlite3,time
from Engine.protocol import canonical,digest
from Bounded.wire import strict_json,atomic_json
from Available.proofs import require,checked_signature,record,fence
from Missing.witness import Store as OldStore
from Missing.protocol import authorise
from .consensus import Replica
from .proofs import registry,scope,finality

class Store(OldStore):
    def __init__(self,root,role,index,clock=None,custody_provider=None):
        super().__init__(root,role,index,clock,custody_provider)
        self.log=sqlite3.connect(self.root/'finality08.db');self.log.execute('PRAGMA synchronous=FULL');self.log.execute('CREATE TABLE IF NOT EXISTS decisions(id TEXT PRIMARY KEY, registry TEXT NOT NULL, state TEXT NOT NULL)')
        with self.log:
            for cid,raw in self.log.execute('SELECT id,state FROM decisions').fetchall():
                s=strict_json(raw);s['quarantine']=True;self.log.execute('UPDATE decisions SET state=? WHERE id=?',(canonical(s).decode(),cid))
        self.nonces={};self.progress={}
    def save_log(self,cid,s):
        if getattr(self,'vote_fault',None)=='before-vote':os._exit(71)
        with self.log:self.log.execute('UPDATE decisions SET state=? WHERE id=?',(canonical(s).decode(),cid))
        if getattr(self,'vote_fault',None)=='after-vote':os._exit(72)
    def replica(self,cid):
        row=self.log.execute('SELECT registry,state FROM decisions WHERE id=?',(cid,)).fetchone();require(row is not None,'v8 registry unknown');reg,s=map(strict_json,row)
        def guard(v):
            if v['kind']=='RELEASE':
                state=self.get(cid);history=list(state['records'])+v['arm'];authorise(reg['message']['split'],v['evidence'],history)
            return True
        return Replica(reg,self.index,self.key,s,lambda x:self.save_log(cid,x),guard)
    def handle(self,path,b):
        if path=='/log08':
            require(os.environ.get('LAB_FAULTS')=='1' and b.get('capability')==os.environ['BOOTSTRAP_TOKEN'],'private synthetic log inspection')
            return self.replica(b['capsule']).s
        if path=='/seed08':
            require(os.environ.get('LAB_FAULTS')=='1' and b.get('capability')==os.environ['BOOTSTRAP_TOKEN'],'private synthetic extraction capability')
            return strict_json((self.root/'identity.json').read_bytes())
        if path=='/crash08':
            require(os.environ.get('LAB_FAULTS')=='1' and b.get('capability')==os.environ['BOOTSTRAP_TOKEN'],'private crash capability')
            node=self.replica(b['capsule']);node.decide(b['certificate']);os._exit(72)
        if path=='/register08':
            reg=b['registry'];r,c,m=registry(reg);require(m['witnesses'][str(self.index)]==self.public,'witness pin')
            row=self.log.execute('SELECT registry FROM decisions WHERE id=?',(m['capsule'],)).fetchone()
            if row:require(strict_json(row[0])==reg,'immutable finality membership/registry')
            else:
                s=Replica(reg,self.index,self.key).s
                with self.log:self.log.execute('INSERT INTO decisions VALUES(?,?,?)',(m['capsule'],canonical(reg).decode(),canonical(s).decode()))
            return {'registered':True,'epoch':1}
        cid=b.get('capsule')
        if path=='/arm':
            cid=b['manifest']['message']['capsule'];row=self.log.execute('SELECT state FROM decisions WHERE id=?',(cid,)).fetchone()
            if row:require(strict_json(row[0])['terminal'] is None,'cannot rearm terminal Capsule')
        if path=='/metrics08':
            node=self.replica(cid)
            return {'witness':self.index,'consensus_sqlite_row_writes':self.log.total_changes,'evidence_sqlite_row_writes':self.db.total_changes}
        if path=='/status08':
            node=self.replica(cid);nonce=b['nonce'];require(type(nonce) is str and len(nonce)==64,'fresh status challenge')
            return self.signed({'v':8,'kind':'DECISION_STATUS','capsule':cid,'registry':digest(node.reg),'nonce':nonce,'witness':self.index,'state':{k:node.s[k] for k in ('view','prepared','terminal','quarantine')}})
        if path=='/checkpoint08':
            node=self.replica(cid);node.ready();state=self.get(cid);self.ready(state)
            return self.signed({'v':8,'kind':'RECOVERY_CHECKPOINT','capsule':cid,'registry':digest(node.reg),'nonce':b['nonce'],'target':b['target'],'witness':self.index,'state':{k:node.s[k] for k in ('view','prepared','terminal','quarantine')},'records':state['records'],'clock':self.sample()})
        if path=='/recovery-challenge08':
            node=self.replica(cid);require(node.s['quarantine'] or self.get(cid)['repair'],'healthy replicas do not need recovery');nonce=os.urandom(32).hex();self.nonces[cid]=nonce;return {'nonce':nonce,'target':self.public}
        if path=='/recover08':
            node=self.replica(cid);r,c,m=registry(node.reg);require(node.s['quarantine'] or self.get(cid)['repair'],'healthy replicas do not need recovery');require(b['nonce']==self.nonces.get(cid),'stale recovery');peers=[];seen=set();merged=self.get(cid)
            for cp in b['checkpoints']:
                q=cp['message'];i=q['witness'];require(type(i) is int and i in (1,2,3,4) and i!=self.index and i not in seen,'distinct recovery peers');seen.add(i);checked_signature(m['witnesses'][str(i)],cp)
                require(set(q)=={'v','kind','capsule','registry','nonce','target','witness','state','records','clock'} and q['v']==8 and q['kind']=='RECOVERY_CHECKPOINT' and q['capsule']==cid and q['registry']==digest(node.reg) and q['nonce']==b['nonce'] and q['target']==self.public and q['state']['quarantine'] is False,'checkpoint scope/freshness')
                require(q['clock']['healthy'],'peer clock');peers.append(q['state'])
                for item in q['records']:self.import_record(merged,item)
            require(len(seen)==3,'recovery needs all three other peers')
            if not self.clock.test:
                local=self.clock.sample();lo=sorted(cp['message']['clock']['lower'] for cp in b['checkpoints'])[1];hi=sorted(cp['message']['clock']['upper'] for cp in b['checkpoints'])[1];require(local['lower']<=hi and lo<=local['upper'],'clock outside peer recovery interval');self.clock.recover()
            # Persist evidence first; keep consensus quarantined until authenticated merge succeeds.
            merged['repair']=False;self.put(cid,merged);node.recover(peers);self.boot_repair=False;self.nonces.pop(cid,None)
            return {'recovered':True,'terminal':node.s['terminal'],'view':node.s['view']}
        if path in ('/propose08','/prepare08','/commit-vote08','/view-change08','/decide08'):
            require(self.available,'witness unavailable');node=self.replica(cid);before=canonical(node.s)
            if path=='/propose08':out=node.propose(b['view'],b['value'],b['changes'])
            elif path=='/prepare08':out=node.prepare(b['proposal'])
            elif path=='/commit-vote08':
                if b.get('fault') is not None:
                    require(os.environ.get('LAB_FAULTS')=='1' and b.get('capability')==os.environ['BOOTSTRAP_TOKEN'] and b['fault'] in ('before-vote','after-vote'),'private vote crash')
                self.vote_fault=b.get('fault')
                try:out=node.commit_vote(b['prepared'])
                finally:self.vote_fault=None
            elif path=='/view-change08':
                require(str(b['view']) in node.s['changes'] or time.monotonic()-self.progress.get(cid,0)>=.25,'view timeout not reached');out=node.view_change(b['view'])
            else:out=node.decide(b['certificate'])
            if path!='/decide08' and canonical(node.s)!=before:self.progress[cid]=time.monotonic()
            return out
        # Legacy DISARM is not a terminal operation in the new profile.
        if path in ('/retain07','/inspect07'):raise ValueError('legacy journal is not v8 finality')
        if path=='/disarm':raise ValueError('use ordered v8 disarm')
        if path=='/retain' and b['receipt']['message']['kind']=='DISARM':raise ValueError('legacy disarm fence forbidden in v8')
        if cid and path in ('/observe','/finalise'):
            row=self.log.execute('SELECT state FROM decisions WHERE id=?',(cid,)).fetchone()
            if row:require(strict_json(row[0])['terminal'] is None,'terminal lifecycle closed')
        return super().handle(path,b)

def main():
    import Untrusted.service as old
    old.Store=Store;old.main()
if __name__=='__main__':main()
