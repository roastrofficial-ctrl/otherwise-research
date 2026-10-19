"""Isolated reference witness/custodian. No Laravel imports or product database.
Serial HTTP server + SQLite FULL commits serialize check-in/final/disarm races.
"""
import json
import os
import sqlite3
import subprocess
import uuid
from pathlib import Path
from http.server import BaseHTTPRequestHandler,HTTPServer
from urllib.parse import urlsplit,parse_qs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Engine.protocol import canonical,digest,sign
from Bounded.wire import atomic_json,strict_json
from Bounded.clock import Clock
from .proofs import manifest,proof,record,operation,require,checked_signature,owner_command,fence,acknowledgement
from .custody import StaticShareCustody,compatible,LAB_REQUIREMENTS

class Store:
    def __init__(self,root,role,index,clock=None,custody_provider=None):
        self.provider=custody_provider or StaticShareCustody()
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True)
        ident=self.root/'identity.json'
        existed=ident.exists()
        if not existed:atomic_json(ident,{'seed':os.urandom(32).hex()})
        self.key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(strict_json(ident.read_bytes())['seed']))
        self.public=self.key.public_key().public_bytes_raw().hex();self.role=role;self.index=index
        self.db=sqlite3.connect(self.root/'available.db');self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS capsules(id TEXT PRIMARY KEY, body TEXT NOT NULL)')
        cp=self.root/'clock.json'
        self.clock=clock or Clock(strict_json(cp.read_bytes()) if cp.exists() else None,test=os.environ.get('CLOCK_MODE')=='test')
        self.boot_repair=existed;self.available=True;self.recovery_nonces={}
        if existed:
            for cid,body in self.db.execute('SELECT id,body FROM capsules').fetchall():
                state=strict_json(body);state['repair']=True;self.put(cid,state)
    def signed(self,m):return {'message':m,'signature':sign(self.key,m)}
    def get(self,cid):
        row=self.db.execute('SELECT body FROM capsules WHERE id=?',(cid,)).fetchone();require(row is not None,'unknown capsule');return strict_json(row[0])
    def put(self,cid,state):
        with self.db:self.db.execute('INSERT OR REPLACE INTO capsules VALUES(?,?)',(cid,canonical(state).decode()))
    def sample(self):
        t=self.clock.sample();require(t['healthy'],'clock unhealthy');atomic_json(self.root/'clock.json',self.clock.state);return t
    def ready(self,s):require(self.available and not self.boot_repair and not s['repair'],'unavailable or recovery required')
    def import_record(self,s,r):
        m=manifest(s['manifest']);kind=r['message']['kind']
        if kind in ('ARM','DISARM'):fence(m,r,kind)
        else:record(m,r,kind)
        if r not in s['records']:s['records'].append(r)
    def conflict(self,s,slot):
        # Every authentic observation fences absence, even if aggregate acceptance was lost.
        obs=[r for r in s['records'] if r['message']['kind']=='OBSERVATION' and (r['message']['contract'],r['message']['challenge'])==slot]
        return obs
    def handle(self,path,b):
        if path=='/arm':
            sm=b['manifest'];m=manifest(sm);owner_command(m,b['command'],'ARM')
            keys=m['witnesses'] if self.role=='witness' else m['custody']['keys']
            require(keys[str(self.index)]==self.public,'identity pin')
            row=self.db.execute('SELECT body FROM capsules WHERE id=?',(m['capsule'],)).fetchone()
            if row:s=strict_json(row[0]);require(s['manifest']==sm,'immutable armed manifest')
            else:s={'manifest':sm,'records':[],'share':None,'repair':False,'released':None}
            require(not any((r['message']['kind']=='DISARM' or (r['message']['kind']=='FINAL' and r['message']['witness']==self.index)) for r in s['records']) and s['released'] is None,'cannot re-arm a closed Capsule')
            if self.role=='custodian':
                e=b['enrollment'];checked_signature(m['policy']['owner'],e)
                require(e['message']=={'manifest':digest(m),'share':b['share'],'provider':self.public},'custody enrollment binding')
                require(b['share']['index']==self.index,'share index');require(s['share'] is None or s['share']==b['share'],'immutable custody share');s['share']=b['share'];self.put(m['capsule'],s)
                return {'capabilities':self.provider.capabilities}
            self.ready(s)
            require(self.sample()['upper']<=min(x['deadline'] for x in m['slots']),'arming window expired')
            prior=next((r for r in s['records'] if r['message']['kind']=='ARM' and r['message']['witness']==self.index),None)
            r=prior or self.signed({'v':4,'kind':'ARM','capsule':m['capsule'],'manifest':digest(m),'operation':operation(m),'witness':self.index,'command':b['command']})
            self.import_record(s,r);self.put(m['capsule'],s);return r
        cid=b['capsule'];s=self.get(cid);m=manifest(s['manifest'])
        if path=='/retain':
            require(self.available,'unavailable')
            self.import_record(s,b['receipt']);self.put(cid,s)
            return self.signed({'v':4,'kind':'RETAINED','capsule':cid,'manifest':digest(m),'digest':digest(b['receipt']),'holder':self.public})
        if path=='/repair-challenge':
            require(self.role=='witness','witness recovery only')
            nonce=self.recovery_nonces.setdefault(cid,uuid.uuid4().hex)
            return {'nonce':nonce,'target':self.public}
        if path=='/checkpoint':
            require(self.role=='witness','witness checkpoints only')
            require(self.available and not self.boot_repair and not s['repair'],'checkpoint from unrepaired node')
            return self.signed({'v':4,'kind':'CHECKPOINT','capsule':cid,'manifest':digest(m),'nonce':b['nonce'],'target':b['target'],'source':self.index,'records':s['records'],'clock':self.sample()})
        if path=='/repair':
            require(self.role=='witness','witness repair only')
            require(b['nonce']==self.recovery_nonces.get(cid),'stale recovery challenge')
            cmd=b['command'];checked_signature(m['policy']['owner'],cmd)
            require(cmd['message']=={'v':4,'action':'REPAIR','capsule':cid,'manifest':digest(m),'target':self.public,'nonce':b['nonce'],'checkpoints':sorted(digest(c) for c in b['checkpoints'])},'repair command binding')
            sources=set()
            for cp in b['checkpoints']:
                q=cp['message'];require(set(q)=={'v','kind','capsule','manifest','nonce','target','source','records','clock'} and q['v']==4 and q['kind']=='CHECKPOINT' and q['capsule']==cid and q['manifest']==digest(m) and q['nonce']==b['nonce'] and q['target']==self.public,'checkpoint domain')
                require(type(q['source']) is int and q['source']!=self.index and str(q['source']) in m['witnesses'] and q['source'] not in sources,'checkpoint source')
                checked_signature(m['witnesses'][str(q['source'])],cp);sources.add(q['source'])
                t=q['clock'];require(t['healthy'] and type(t['lower']) is int and type(t['upper']) is int and 0<=t['lower']<=t['upper'],'checkpoint clock')
                for r in q['records']:self.import_record(s,r)
            require(len(sources)==3,'repair needs all three other members')
            # Union preserves every authentic lock, including contradictory/faulty records.
            # We do not erase histories or rotate identities/membership.
            if not self.clock.test:
                local=self.clock.sample();times=[cp['message']['clock'] for cp in b['checkpoints']]
                lo=sorted(t['lower'] for t in times)[1];hi=sorted(t['upper'] for t in times)[1]
                require(local['lower']<=hi and lo<=local['upper'],'local clock outside peer recovery interval')
                self.clock.recover()
            s['repair']=False;self.put(cid,s);self.boot_repair=False
            self.recovery_nonces[cid]=uuid.uuid4().hex
            return {'repaired':True,'records':len(s['records'])}
        self.ready(s)
        disarmed=any(r['message']['kind']=='DISARM' for r in s['records'])
        if path=='/disarm':
            owner_command(m,b['command'],'DISARM')
            prior=next((r for r in s['records'] if r['message']['kind']=='DISARM' and r['message']['witness']==self.index),None)
            if prior:return prior
            require(not any(r['message']['kind']=='FINAL' and r['message']['witness']==self.index for r in s['records']),'closure begun: disarm unavailable')
            r=self.signed({'v':4,'kind':'DISARM','capsule':cid,'manifest':digest(m),'operation':operation(m),'witness':self.index,'command':b['command']})
            self.import_record(s,r);self.put(cid,s);return r
        require(not disarmed,'disarmed')
        if path in ('/observe','/finalise'):
            require(self.role=='witness','witness role')
            if path=='/observe':
                c,sl=proof(m,b['proof']);slot=(sl['contract'],sl['challenge'])
                same=[r for r in self.conflict(s,slot) if r['message']['witness']==self.index]
                if same:
                    require(same[0]['message']['proof']==b['proof'],'contradictory/duplicate id proof');return same[0]
                require(not any(r['message']['kind']=='FINAL' and r['message']['witness']==self.index and (r['message']['contract'],r['message']['challenge'])==slot for r in s['records']),'slot closed')
                prior=self.conflict(s,slot);require(all(r['message']['proof']==b['proof'] for r in prior),'contradictory proof')
                p=b['proof'];kind='OBSERVATION'
            else:
                slot=(b['contract'],b['challenge']);sl=next(x for x in m['slots'] if (x['contract'],x['challenge'])==slot);c=next(c for c in m['policy']['contracts'] if c['id']==slot[0]);kind='FINAL'
                prior=next((r for r in s['records'] if r['message']['kind']=='FINAL' and (r['message']['contract'],r['message']['challenge'])==slot and r['message']['witness']==self.index),None)
                if prior:return prior
                observations=self.conflict(s,slot)
                # Contradiction is fail-closed, never choose a convenient fact.
                conflicting=len({digest(r['message']['proof']) for r in observations})>1
                p=None if conflicting and c['kind']=='attestation' else observations[0]['message']['proof'] if observations else None
            t=self.sample();own=[r for r in s['records'] if r['message'].get('witness')==self.index and r['message']['kind'] in ('OBSERVATION','FINAL')]
            value=('PRESENT' if c['kind']=='absence' else 'TRUE' if p['message']['value'] else 'FALSE') if p else ('ABSENT' if c['kind']=='absence' else 'EMPTY')
            if kind=='FINAL' and c['kind']=='attestation' and conflicting:value='CONFLICT'
            r=self.signed({'v':4,'kind':kind,'capsule':cid,'manifest':digest(m),'operation':operation(m),'witness':self.index,'contract':slot[0],'challenge':slot[1],'seq':len(own)+1,'prev':digest(own[-1]) if own else '0'*64,'lower':t['lower'],'upper':t['upper'],'proof':p,'value':value,'not_before':sl['deadline']+1+m['policy']['grace']})
            record(m,r,kind);self.import_record(s,r);self.put(cid,s);return r
        if path=='/release':
            require(self.role=='custodian','custodian role');cert=b['certificate'];require(cert['manifest']==s['manifest'],'custody manifest')
            compatible(self.provider.capabilities,b['requirements'])
            retained=[]
            # A custodian that retained any observation independently vetoes conflicting absence.
            for group in cert['finals']:
                if group and all(r['message']['value']=='ABSENT' for r in group):
                    sl=(group[0]['message']['contract'],group[0]['message']['challenge']);require(not self.conflict(s,sl),'retained presence veto')
            result=self.provider.authorise(cert,retained)
            node=subprocess.run(['node','Verifier/available.mjs'],input=canonical({'kind':'release','object':cert}),capture_output=True)
            require(node.returncode==0 and strict_json(node.stdout)=={'ok':True,**result},'independent evaluator disagreement')
            if s['released'] is None:
                s['released']=self.signed({'v':4,'capsule':cid,'manifest':digest(m),'operation':operation(m),'authorisation':cert['authorisation'],'payload':m['payload'],'index':self.index,'share':s['share']['value']});self.put(cid,s)
            return self.signed({**s['released']['message'],'authorisation':cert['authorisation']})
        raise ValueError('unknown action')


def main():
    store=Store(os.environ.get('STATE_DIR','/state'),os.environ.get('ROLE','witness'),int(os.environ.get('INDEX','1')))
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*a):pass
        def respond(self,code,value):
            data=canonical(value);self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def do_GET(self):
            try:
                u=urlsplit(self.path)
                if u.path=='/identity':out={'public':store.public,'role':store.role,'capabilities':store.provider.capabilities if store.role=='custodian' else None}
                elif u.path=='/clock':out=store.clock.sample()
                elif u.path=='/status':
                    require(store.role=='witness','private custody state')
                    out=store.get(parse_qs(u.query)['capsule'][0])
                else:raise ValueError('unknown endpoint')
                self.respond(200,out)
            except Exception as e:self.respond(400,{'error':str(e)})
        def do_POST(self):
            try:
                size=int(self.headers.get('Content-Length','0'));require(0<size<=4_000_000,'body size');b=strict_json(self.rfile.read(size))
                if self.path.startswith('/test-'):
                    require(os.environ.get('LAB_FAULTS')=='1' and self.headers.get('Authorization')=='Bearer '+os.environ['BOOTSTRAP_TOKEN'],'test capability')
                    if self.path=='/test-clock':out=store.clock.advance(b['now'],healthy=b.get('healthy',True))
                    elif self.path=='/test-availability':store.available=b['available'];out={'available':store.available}
                    elif self.path=='/test-sign':out=store.signed(b['message'])
                    elif self.path=='/test-save':store.db.backup(sqlite3.connect(store.root/'saved.db'));out={'saved':True}
                    elif self.path=='/test-restore':
                        source=sqlite3.connect(store.root/'saved.db');source.backup(store.db);source.close();store.boot_repair=True;store.recovery_nonces.clear()
                        for cid,body in store.db.execute('SELECT id,body FROM capsules').fetchall():
                            restored=strict_json(body);restored['repair']=True;store.put(cid,restored)
                        out={'repair_required':True}
                    else:raise ValueError('unknown fault')
                else:out=store.handle(self.path,b)
                self.respond(200,out)
            except Exception as e:self.respond(400,{'error':str(e)})
    class Server(HTTPServer):
        def service_actions(self):
            # Keep monotonic continuity even while no human has the page open.
            if not store.clock.test:
                store.clock.sample()
    Server(('0.0.0.0',8080),Handler).serve_forever()
if __name__=='__main__':main()
