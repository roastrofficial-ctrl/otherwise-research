"""Persistent isolated custodian research service. Actual TLS; no Laravel dependency."""
import os
import sqlite3
import ssl
from pathlib import Path
from http.server import BaseHTTPRequestHandler,HTTPServer
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Engine.protocol import canonical,digest,sign
from Bounded.wire import atomic_json,strict_json,request
from Available.proofs import require,checked_signature
from .crypto import number,G,encode,partial,seal_to
from .protocol import CAPABILITIES,compatible,commitment,evidence_snapshot,authorise,operation

class Store:
    def __init__(self,root,index):
        self.root=Path(root);self.root.mkdir(parents=True,exist_ok=True);self.index=index
        f=self.root/'identity.json'
        if not f.exists():atomic_json(f,{'seed':os.urandom(32).hex()})
        self.key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(strict_json(f.read_bytes())['seed']))
        self.public=self.key.public_key().public_bytes_raw().hex()
        self.db=sqlite3.connect(self.root/'custody06.db');self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS capsules(id TEXT PRIMARY KEY, body TEXT NOT NULL)')
        self.available=True
    def signed(self,m):return {'message':m,'signature':sign(self.key,m)}
    def get(self,cid):
        r=self.db.execute('SELECT body FROM capsules WHERE id=?',(cid,)).fetchone();require(r is not None,'unknown Capsule');return strict_json(r[0])
    def put(self,cid,s):
        with self.db:self.db.execute('INSERT OR REPLACE INTO capsules VALUES(?,?)',(cid,canonical(s).decode()))
    def inspect(self,s):
        c,m=commitment(s['sidecar']);nonce=os.urandom(32).hex();snaps=[]
        urls=os.environ['WITNESSES'].split(',');require(len(urls)==4,'configured witness committee')
        for i,u in enumerate(urls,1):
            try:
                r=request(u+'/inspect',{'capsule':m['capsule'],'nonce':nonce})
                # Wrong-signature responses must not poison an otherwise valid quorum.
                from Untrusted.proofs import snapshot
                snapshot(c['manifest'],r,nonce,i);snaps.append(r)
            except Exception:pass
        return evidence_snapshot(c['manifest'],snaps,nonce,s['anchors'])
    def handle(self,path,b):
        require(self.available,'custodian unavailable')
        if path=='/enroll':
            c,m=commitment(b['sidecar']);require(m['custody']['keys'][str(self.index)]==self.public,'custodian identity pin')
            checked_signature(m['policy']['owner'],b['enrollment'])
            require(b['enrollment']['message']=={'v':6,'sidecar':digest(b['sidecar']),'index':self.index,'share':b['share'],'provider':self.public},'share enrollment binding')
            require(encode(number(b['share'])*G)==c['key']['Y'][str(self.index)],'dealer share mismatch')
            old=self.db.execute('SELECT body FROM capsules WHERE id=?',(m['capsule'],)).fetchone()
            if old:
                s=strict_json(old[0]);require(s['sidecar']==b['sidecar'] and s['share']==b['share'],'immutable custody enrollment')
            else:self.put(m['capsule'],{'sidecar':b['sidecar'],'share':b['share'],'anchors':{},'partials':{}})
            return {'enrolled':True,'capabilities':CAPABILITIES}
        s=self.get(b['capsule']);c,m=commitment(s['sidecar'])
        if path=='/head':
            head,history,anchors=self.inspect(s);s['anchors']=anchors;self.put(m['capsule'],s)
            return self.signed({'v':6,'capsule':m['capsule'],'head':head,'index':self.index})
        if path=='/partial':
            compatible(b['requirements']);require(b['sidecar']==s['sidecar'],'immutable commitment')
            head,history,anchors=self.inspect(s)
            require(head==b['head'],'stale or inconsistent evidence head; refresh context')
            authorise(s['sidecar'],b['certificate'],history)
            ctx=operation(s['sidecar'],b['certificate'],head);ident=digest(ctx)
            s['anchors']=anchors
            if ident in s['partials']:out=s['partials'][ident]
            else:
                p=partial(c['key'],s['share'],self.index,c['wrap']['R'],ctx)
                out=self.signed({'context':ctx,'index':self.index,'box':seal_to(c['recipient'],p,ctx)})
                s['partials'][ident]=out
            if b.get('fault')=='before-commit':os._exit(71)
            self.put(m['capsule'],s)  # Durable before reply; all competing workers serialize.
            if b.get('fault')=='after-commit':os._exit(72)
            return out
        raise ValueError('unsupported custody action')

def main():
    store=Store(os.environ.get('STATE_DIR','/state'),int(os.environ['INDEX']))
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def respond(self,code,value):
            data=canonical(value);self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
        def do_GET(self):
            if self.path=='/identity':self.respond(200,{'public':store.public,'role':'custodian','capabilities':CAPABILITIES})
            else:self.respond(404,{'error':'unknown endpoint'})
        def do_POST(self):
            try:
                size=int(self.headers.get('Content-Length','0'));require(0<size<=4_000_000,'body size');b=strict_json(self.rfile.read(size))
                if self.path.startswith('/lab-') or 'fault' in b:
                    require(os.environ.get('LAB_FAULTS')=='1' and self.headers.get('Authorization')=='Bearer '+os.environ['BOOTSTRAP_TOKEN'],'private fault capability')
                if self.path=='/lab-export':out=store.get(b['capsule']) # Deliberate custodian compromise.
                elif self.path=='/lab-available':store.available=b['available'];out={'available':store.available}
                elif self.path=='/lab-save':
                    db=sqlite3.connect(store.root/'saved06.db');store.db.backup(db);db.close();out={'saved':True}
                elif self.path=='/lab-restore':
                    db=sqlite3.connect(store.root/'saved06.db');db.backup(store.db);db.close();out={'restored':True}
                else:out=store.handle(self.path,b)
                self.respond(200,out)
            except Exception as e:self.respond(400,{'error':str(e)})
    server=HTTPServer(('0.0.0.0',8080),Handler);ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(os.environ['TLS_CERT'],os.environ['TLS_KEY']);server.socket=ctx.wrap_socket(server.socket,server_side=True);server.serve_forever()
if __name__=='__main__':main()
