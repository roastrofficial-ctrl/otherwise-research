"""Explicit message scheduler using the actual durable Replica state machine.
No sleep, thread timing or wall-clock ordering decides an execution.
"""
import copy,tempfile,sqlite3
from pathlib import Path
from Engine.protocol import canonical,digest,sign
from Bounded.wire import strict_json
from LastWord.consensus import Replica
from LastWord.proofs import scope,finality

class Lab:
    def __init__(self,reg,keys,root):
        self.reg=reg;self.keys=keys;self.root=Path(root);self.trace=[];self.nodes={};self.db={};self.savepoints={}
        for i in range(1,5):
            d=sqlite3.connect(self.root/(str(i)+'.db'));d.execute('PRAGMA synchronous=FULL');d.execute('CREATE TABLE IF NOT EXISTS state(body TEXT)');self.db[i]=d;self.nodes[i]=Replica(reg,i,keys[i],persist=lambda s,i=i:self.persist(i,s));self.persist(i,self.nodes[i].s)
    def persist(self,i,s):
        with self.db[i]:self.db[i].execute('DELETE FROM state');self.db[i].execute('INSERT INTO state VALUES(?)',(canonical(s).decode(),))
    def event(self,i,method,*args):
        before=copy.deepcopy(self.nodes[i].s)
        try:out=getattr(self.nodes[i],method)(*copy.deepcopy(args));ok=True
        except Exception as e:out={'error':str(e)};ok=False
        self.trace.append({'sequence':len(self.trace)+1,'participant':i,'event':method,'inputs':copy.deepcopy(args),'known_before':before,'accepted':ok,'output':copy.deepcopy(out),'known_after':copy.deepcopy(self.nodes[i].s)})
        return out if ok else None
    def round(self,v,view=0,participants=(1,2,3,4),changes=None):
        p=self.event(1+view%4,'propose',view,v,changes or [])
        if p is None:return None
        ps=[r for i in participants if (r:=self.event(i,'prepare',p)) is not None]
        if len(ps)<3:return None
        pc={'view':view,'value':p['message']['value'],'prepares':ps};cs=[r for i in participants if (r:=self.event(i,'commit_vote',pc)) is not None]
        if len(cs)<3:return None
        fin={'v':8,'registry':digest(self.reg),'view':view,'value':pc['value'],'prepares':ps,'commits':cs};finality(self.reg,fin)
        for i in participants:self.event(i,'decide',fin)
        return fin
    def restart(self,i):
        saved=strict_json(self.db[i].execute('SELECT body FROM state').fetchone()[0]);self.nodes[i]=Replica(self.reg,i,self.keys[i],saved,persist=lambda s:self.persist(i,s));self.event(i,'quarantine')
    def recover(self,i,peers):return self.event(i,'recover',[copy.deepcopy(self.nodes[j].s) for j in peers])
