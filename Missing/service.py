"""One isolated capability holder. Each process mounts only its own domain share."""
import os
import time
import ssl
import sqlite3
from http.server import BaseHTTPRequestHandler,HTTPServer
from Engine.protocol import canonical,digest
from Bounded.wire import strict_json
from Available.proofs import require,checked_signature,record,fence
from Untrusted.proofs import snapshot
from Honest.service import Store as OldStore
from Honest import crypto
from .collect import Transport,gather
from .protocol import CAPABILITIES,commitment,compatible,authorise,context,evidence_snapshot

class Store(OldStore):
    def __init__(self,root,index,domain):
        super().__init__(root,index);self.domain=domain;self.fault='honest';self.net=Transport(.8)
    def inspect(self,s):
        c,m=commitment(s['sidecar']);nonce=os.urandom(32).hex();urls=os.environ['WITNESSES'].split(',')
        def validate(i,signed):
            r=snapshot(c['manifest'],signed,nonce,i+1)
            # Reject an invalid source before quorum aggregation.
            for item in r['records']:
                kind=item['message']['kind'];(fence if kind in ('ARM','DISARM') else record)(m,item,kind)
            require(set(s['anchors'].get(str(i+1),[]))<=set(digest(x) for x in r['records']),'source history rollback')
            return signed
        found=gather(list(range(4)),lambda i:self.net.call(urls[i]+'/inspect',{'capsule':m['capsule'],'nonce':nonce}),validate,3,deadline=1.1,workers=4)
        require(found['sufficient'],'no fresh witness quorum; timeout is uncertainty')
        head,history,anchors=evidence_snapshot(c['manifest'],list(found['valid'].values()),nonce,s['anchors'])
        return head,history,anchors,found['invalid']
    def handle(self,path,b):
        require(self.available,'capability holder unavailable')
        if path=='/enroll07':
            c,m=commitment(b['sidecar']);require(c['domains'][self.domain]['members'][str(self.index)]==self.public,'domain identity pin')
            e=b['enrollment'];checked_signature(m['policy']['owner'],e)
            require(e['message']=={'v':7,'domain':self.domain,'sidecar':digest(b['sidecar']),'index':self.index,'share':b['share'],'provider':self.public},'enrollment scope')
            require(crypto.encode(crypto.number(b['share'])*crypto.G)==c['domains'][self.domain]['key']['Y'][str(self.index)],'share commitment mismatch')
            row=self.db.execute('SELECT body FROM capsules WHERE id=?',(m['capsule'],)).fetchone()
            if row:
                old=strict_json(row[0]);require(old['sidecar']==b['sidecar'] and old['share']==b['share'],'immutable armed capability')
            else:self.put(m['capsule'],{'sidecar':b['sidecar'],'share':b['share'],'anchors':{},'partials':{},'invalid':[]})
            return {'enrolled':True,'capabilities':CAPABILITIES}
        if path!='/partial07':raise ValueError('unsupported action')
        s=self.get(b['capsule']);c,m=commitment(s['sidecar']);compatible(b['requirements']);require(b['sidecar']==s['sidecar'],'immutable sidecar')
        _,history,anchors,invalid=self.inspect(s);authorise(s['sidecar'],b['certificate'],history);ctx=context(s['sidecar'],b['certificate'],self.domain)
        require(b['context']==ctx,'stale or substituted operation context');ident=digest(ctx);s['anchors']=anchors;s['invalid']=invalid
        if self.fault=='delay':time.sleep(6)
        if self.fault=='oversize':return {'padding':'x'*1_000_100}
        if self.fault=='malformed':return {'ok':True,'claimed_success':True,'domain':self.domain}
        if ident not in s['partials']:
            part=crypto.partial(c['domains'][self.domain]['key'],s['share'],self.index,c['wraps'][self.domain]['R'],ctx)
            if self.fault=='bad-proof':part['z']='00'*32
            s['partials'][ident]=self.signed({'context':ctx,'index':self.index,'box':crypto.seal_to(c['recipient'],part,ctx)})
        if b.get('fault')=='before-commit':os._exit(71)
        self.put(m['capsule'],s)
        if b.get('fault')=='after-commit':os._exit(72)
        return s['partials'][ident]

def main():
    store=Store(os.environ.get('STATE_DIR','/state'),int(os.environ['INDEX']),os.environ['DOMAIN'])
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*a):pass
        def respond(self,code,value):
            raw=canonical(value);self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def do_GET(self):self.respond(200,{'public':store.public,'role':store.domain,'capabilities':CAPABILITIES})
        def do_POST(self):
            try:
                size=int(self.headers.get('Content-Length','0'));require(0<size<=4_000_000,'body size');b=strict_json(self.rfile.read(size))
                if self.path.startswith('/lab-') or 'fault' in b:require(os.environ.get('LAB_FAULTS')=='1' and self.headers.get('Authorization')=='Bearer '+os.environ['BOOTSTRAP_TOKEN'],'fault capability')
                if self.path=='/lab-export':
                    out=store.get(b['capsule'])
                    if b.get('all'):out={**out,'identity_seed':strict_json((store.root/'identity.json').read_bytes())['seed'],'tls_private_key':open(os.environ['TLS_KEY']).read()}
                elif self.path=='/lab-fault':store.fault=b['mode'];out={'mode':store.fault}
                elif self.path=='/lab-available':store.available=b['available'];out={'available':store.available}
                elif self.path=='/lab-save':
                    d=sqlite3.connect(store.root/'saved07.db');store.db.backup(d);d.close();out={'saved':True}
                elif self.path=='/lab-restore':
                    d=sqlite3.connect(store.root/'saved07.db');d.backup(store.db);d.close();out={'restored':True}
                else:out=store.handle(self.path,b)
                self.respond(200,out)
            except Exception as e:
                try:self.respond(400,{'error':str(e)})
                except (BrokenPipeError,ssl.SSLError):pass
    server=HTTPServer(('0.0.0.0',8080),Handler);ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.minimum_version=ssl.TLSVersion.TLSv1_2;ctx.load_cert_chain(os.environ['TLS_CERT'],os.environ['TLS_KEY']);server.socket=ctx.wrap_socket(server.socket,server_side=True);server.serve_forever()
if __name__=='__main__':main()
