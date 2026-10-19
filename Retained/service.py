"""One independently stored witness or custody process per container."""
import os
import secrets
import shutil
import sqlite3
import subprocess
from pathlib import Path
from http.server import HTTPServer,BaseHTTPRequestHandler
from urllib.parse import urlparse,parse_qs
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Engine.protocol import canonical,digest,verify,sign
from Bounded.clock import Clock
from Bounded.wire import atomic_json,strict_json
from .proofs import manifest,proof,record,slot,operation,release,acknowledgement,require


class Store:
    def __init__(self,root,index,role,test=True):
        root=Path(root);root.mkdir(parents=True,exist_ok=True);self.root=root;self.index=index;self.role=role
        path=root/'identity.json'
        if not path.exists():atomic_json(path,{'seed':secrets.token_hex(32)})
        self.key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(strict_json(path.read_bytes())['seed']))
        self.public=self.key.public_key().public_bytes_raw().hex()
        self.db=sqlite3.connect(root/'retained.db',isolation_level=None)
        self.db.execute('PRAGMA synchronous=FULL');self.db.execute('CREATE TABLE IF NOT EXISTS capsules(id TEXT PRIMARY KEY, body TEXT NOT NULL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS anchors(capsule TEXT, witness INTEGER, seq INTEGER, hash TEXT, body TEXT, PRIMARY KEY(capsule,witness,seq,hash))')
        cp=root/'clock.json';self.clock=Clock(strict_json(cp.read_bytes()) if cp.exists() else None,test=test);self.available=True

    def get(self,cid):
        row=self.db.execute('SELECT body FROM capsules WHERE id=?',(cid,)).fetchone();require(row is not None,'unknown capsule');return strict_json(row[0])

    def put(self,cid,data,fault=None):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('INSERT OR REPLACE INTO capsules VALUES(?,?)',(cid,canonical(data).decode()))
            if fault=='before_commit':os._exit(81)
            self.db.commit()
            if fault=='after_commit':os._exit(82)
        except BaseException:self.db.rollback();raise

    def enroll(self,body):
        m=manifest(body['manifest']);cid=m['capsule']
        require((m['witnesses'] if self.role=='witness' else m['custody']['keys'])[str(self.index)]==self.public,'wrong pinned identity')
        try:
            old=self.get(cid);require(old['manifest']==body['manifest'] and old.get('share')==body.get('share'),'immutable enrollment');return {'enrolled':True}
        except ValueError as exc:
            if str(exc)!='unknown capsule':raise
        self.put(cid,{'manifest':body['manifest'],'share':body.get('share'),'events':[],'slots':{},'retained':[],'disarmed':False,'quarantined':False,'equivocators':[]})
        return {'enrolled':True}

    def add(self,state,m,kind,s,p=None,value=None,fault=None):
        sample=self.clock.sample();require(sample['healthy'],'uncertain clock')
        atomic_json(self.root/'clock.json',sample)
        events=state['events'];r={'v':3,'kind':kind,'capsule':m['capsule'],'manifest':digest(m),'witness':self.index,
            'contract':s['contract'],'challenge':s['challenge'],'operation':operation(m),'seq':len(events)+1,
            'prev':digest(events[-1]) if events else '0'*64,'lower':sample['lower'],'upper':sample['upper'],
            'proof':p,'value':value,'not_before':s['deadline']+1+m['policy']['grace']}
        signed={'message':r,'signature':sign(self.key,r)}
        record(m,signed,kind);events.append(signed);self.put(m['capsule'],state,fault);return signed

    def observe(self,body,fault=None):
        require(self.available,'witness unavailable');p=body['proof'];cid=p['message']['capsule'];st=self.get(cid);m=manifest(st['manifest'])
        proof(m,p)
        for old in st['events']:
            if old['message']['kind']=='OBSERVATION' and old['message']['proof']['message']['id']==p['message']['id']:
                require(old['message']['proof']==p,'submission id collision');return old
        require(not st['disarmed'] and not st['quarantined'],'disarmed/quarantined')
        c,s=proof(m,p);sid=canonical([s['contract'],s['challenge']]).decode();require(sid not in st['slots'],'slot already observed or finalised')
        value='PRESENT' if c['kind']=='absence' else 'TRUE' if p['message']['value'] else 'FALSE'
        st['slots'][sid]={'proof':p,'value':value,'final':None}
        return self.add(st,m,'OBSERVATION',s,p,value,fault)

    def finalise(self,body,fault=None):
        require(self.available,'witness unavailable');st=self.get(body['capsule']);m=manifest(st['manifest'])
        require(not st['disarmed'] and not st['quarantined'],'disarmed/quarantined')
        s=slot(m,body['contract'],body['challenge']);sid=canonical([s['contract'],s['challenge']]).decode()
        if sid in st['slots'] and st['slots'][sid]['final'] is not None:return st['events'][st['slots'][sid]['final']-1]
        c=next(c for c in m['policy']['contracts'] if c['id']==s['contract'])
        entry=st['slots'].setdefault(sid,{'proof':None,'value':'ABSENT' if c['kind']=='absence' else 'EMPTY','final':None})
        entry['final']=len(st['events'])+1
        return self.add(st,m,'FINAL',s,entry['proof'],entry['value'],fault)

    def retain(self,body):
        st=self.get(body['capsule']);m=manifest(st['manifest']);r=body['receipt'];msg=record(m,r,r['message']['kind'])
        h=digest(r)
        prior=[strict_json(row[0])['message'] for row in self.db.execute('SELECT body FROM anchors WHERE capsule=? AND witness=?',(m['capsule'],msg['witness']))]
        conflict=any((p['contract'],p['challenge'])==(msg['contract'],msg['challenge']) and (
            p['kind']=='OBSERVATION' and msg['kind']=='OBSERVATION' and p['proof']!=msg['proof'] or
            p['kind']=='OBSERVATION' and msg['kind']=='FINAL' and p['proof']!=msg['proof'] or
            msg['kind']=='OBSERVATION' and p['kind']=='FINAL' and (p['proof']!=msg['proof'] or p['seq']<msg['seq'])) for p in prior)
        same=self.db.execute('SELECT hash FROM anchors WHERE capsule=? AND witness=? AND seq=?',(m['capsule'],msg['witness'],msg['seq'])).fetchall()
        self.db.execute('INSERT OR IGNORE INTO anchors VALUES(?,?,?,?,?)',(m['capsule'],msg['witness'],msg['seq'],h,canonical(r).decode()))
        if conflict or any(row[0]!=h for row in same):
            st.setdefault('equivocators',[]).append(msg['witness'])
            if msg['witness']==self.index:st['quarantined']=True
            self.put(m['capsule'],st);raise ValueError('witness equivocation retained')
        if msg['witness']==self.index:
            events=st['events'];consistent=len(events)>=msg['seq'] and digest(events[msg['seq']-1])==h
            if not consistent:st['quarantined']=True;self.put(m['capsule'],st);raise ValueError('local rollback/fork exposed by retained receipt')
        return {'retained':True}

    def custody(self,body):
        require(self.available,'custodian unavailable');cert=body['certificate'];cid=cert['manifest']['message']['capsule'];st=self.get(cid)
        require(cert['manifest']==st['manifest'],'custody manifest substitution')
        result=release(cert,st['retained'])
        js=subprocess.run(['node','Verifier/retained.mjs'],input=canonical({'kind':'release','object':cert,'retained':st['retained']}),capture_output=True,timeout=10)
        require(js.returncode==0 and strict_json(js.stdout)=={'ok':True,**result},'independent verifier disagreement')
        msg={'v':3,'capsule':cid,'manifest':digest(cert['manifest']['message']),'operation':result['operation'],
             'authorisation':cert['authorisation'],'payload':cert['manifest']['message']['payload'],'index':self.index,'share':st['share']['value']}
        return {'message':msg,'signature':sign(self.key,msg)}


def main():
    role=os.environ['ROLE'];st=Store('/state',int(os.environ['INDEX']),role,os.environ.get('CLOCK_MODE','test')=='test')
    token=os.environ['BOOTSTRAP_TOKEN'];require(token!='not-configured','run scripts/experiment03.sh')
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def reply(self,code,value):
            data=canonical(value);self.send_response(code);self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def do_GET(self):
            try:
                u=urlparse(self.path);q=parse_qs(u.query)
                if u.path=='/clock':out=st.clock.sample()
                elif u.path=='/identity':out={'public':st.public,'role':role,'index':st.index}
                elif u.path=='/status':
                    state=st.get(q['capsule'][0]);out={'events':state['events'],'quarantined':state['quarantined'],'equivocators':state.get('equivocators',[]),'bytes':os.path.getsize(st.root/'retained.db'),'logical_bytes':len(canonical(state)),'anchor_bytes':sum(len(r[0]) for r in st.db.execute('SELECT body FROM anchors WHERE capsule=?',(q['capsule'][0],)))}
                elif u.path=='/anchors':out=[strict_json(r[0]) for r in st.db.execute('SELECT body FROM anchors WHERE capsule=? AND witness=? ORDER BY seq',(q['capsule'][0],int(q['witness'][0])))]
                else:raise ValueError('route')
                self.reply(200,out)
            except Exception as exc:self.reply(409,{'error':str(exc)})
        def do_POST(self):
            try:
                n=int(self.headers.get('Content-Length',0));require(0<n<=4_000_000,'body size');b=strict_json(self.rfile.read(n));path=urlparse(self.path).path
                admin=secrets.compare_digest(self.headers.get('Authorization',''),'Bearer '+token)
                if path=='/enroll' or path.startswith('/test-') or self.headers.get('X-Crash'):require(admin,'administrative capability required')
                fault=self.headers.get('X-Crash')
                if path=='/enroll':out=st.enroll(b)
                elif path=='/observe' and role=='witness':out=st.observe(b,fault)
                elif path=='/finalise' and role=='witness':out=st.finalise(b,fault)
                elif path=='/retain' and role=='witness':out=st.retain(b)
                elif path=='/retain' and role=='custodian':
                    state=st.get(b['manifest']['message']['capsule']);require(b['manifest']==state['manifest'],'retention scope');acknowledgement(b['manifest'],b['receipts']);state['retained'].append(b);st.put(b['manifest']['message']['capsule'],state);out={'retained':True}
                elif path=='/release' and role=='custodian':out=st.custody(b)
                elif path=='/disarm':
                    state=st.get(b['message']['capsule']);m=manifest(state['manifest']);expected={'v':3,'capsule':m['capsule'],'manifest':digest(m),'action':'DISARM','operation':operation(m)}
                    require(b['message']==expected,'disarm scope');verify(m['policy']['owner'],expected,b['signature']);require(not any(e['message']['kind']=='FINAL' for e in state['events']),'finalisation already irreversible')
                    state['disarmed']=True;st.put(m['capsule'],state);out={'disarmed':True}
                elif path=='/test-clock':
                    out=st.clock.advance(b['now'],healthy=b.get('healthy',True));atomic_json(st.root/'clock.json',out)
                elif path=='/test-availability':st.available=b['available'];out={'available':st.available}
                elif path=='/test-save':
                    backup=sqlite3.connect(st.root/'saved.db');st.db.backup(backup);backup.close();out={'saved':True}
                elif path=='/test-restore':
                    st.db.close();shutil.copyfile(st.root/'saved.db',st.root/'retained.db')
                    st.db=sqlite3.connect(st.root/'retained.db',isolation_level=None);st.db.execute('PRAGMA synchronous=FULL');out={'restored':True}
                elif path=='/test-sign':out={'message':b['message'],'signature':sign(st.key,b['message'])} # explicit Byzantine control
                else:raise ValueError('route')
                self.reply(200,out)
            except Exception as exc:self.reply(409,{'error':str(exc)})
    HTTPServer(('0.0.0.0',8080),Handler).serve_forever()

if __name__=='__main__':main()
