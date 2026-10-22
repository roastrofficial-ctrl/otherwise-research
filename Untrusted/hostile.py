"""Deliberately adversarial SaaS backend. No protocol state or creator capability."""
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler,HTTPServer
from Engine.protocol import canonical
from Bounded.wire import strict_json,atomic_json
from Available.transport import UrllibTransport
from .client import validate_public

def main():
    root=Path('/saas');root.mkdir(exist_ok=True);mode='honest';cache={};public_path=root/'public.json'
    class H(BaseHTTPRequestHandler):
        def log_message(self,*a):pass
        def send(self,code,value,js=False):
            raw=value.encode() if js else canonical(value);self.send_response(code);self.send_header('Content-Type','application/javascript' if js else 'application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def do_GET(self):
            if self.path=='/client.js':self.send(200,"// hostile operator-delivered code\nglobalThis.stolen = localStorage.getItem('otherwise-kit');\nglobalThis.falseSuccess = true;",True)
            elif self.path=='/mirror':self.send(200,strict_json(public_path.read_bytes()) if public_path.exists() else {'operator_view':'empty, unauthoritative'})
            else:self.send(404,{'error':'unknown'})
        def do_POST(self):
            nonlocal mode
            try:
                size=int(self.headers.get('Content-Length',0))
                if not 0<size<=4_000_000:raise ValueError('body size')
                b=strict_json(self.rfile.read(size))
                if self.path=='/test-mode':
                    if self.headers.get('Authorization')!='Bearer '+os.environ['HOSTILE_TOKEN']:raise ValueError('test capability')
                    mode=b['mode'];self.send(200,{'mode':mode});return
                if self.path=='/mirror':validate_public(b);atomic_json(public_path,b);self.send(200,{'stored_public_projection':True});return
                if self.path!='/relay':raise ValueError('unknown action')
                url=b['url'];allowed=os.environ['WITNESSES'].split(',')
                if not any(url.startswith(u+'/') for u in allowed):raise ValueError('witness-only relay')
                key=url
                if mode=='censor-arm' and url.endswith('/arm'):raise ValueError('operator suppresses new arming')
                if mode=='censor':raise ValueError('operator censorship')
                if mode=='false-success':self.send(200,{'accepted':True,'state':'DISARMED','receipts':[]});return
                if mode=='stale' and key in cache:self.send(200,cache[key]);return
                if mode=='identity-substitution' and url.endswith('/identity'):self.send(200,{'public':'00'*32});return
                body=b['body']
                if mode=='alter' and body is not None:
                    if 'proof' in body:body['proof']['message']['challenge']='operator-substitution'
                    elif 'command' in body:body['command']['message']['capsule']='operator-substitution'
                result=UrllibTransport().call(url,body);cache[key]=result;self.send(200,result)
            except Exception as exc:self.send(422,{'error':str(exc)})
    HTTPServer(('0.0.0.0',8080),H).serve_forever()
if __name__=='__main__':main()
