"""Stateless product adapter. Owner capability supplied by client, never stored here."""
import os
from http.server import BaseHTTPRequestHandler,HTTPServer
from Engine.protocol import canonical
from Bounded.wire import strict_json
from .lifecycle import Client

def main():
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            try:
                size=int(self.headers.get('Content-Length',0))
                if not 0<size<4_000_000:raise ValueError('body size')
                b=strict_json(self.rfile.read(size));action=self.path[1:];c=Client()
                if action=='create':kit=c.draft(os.environ['WITNESSES'].split(','),os.environ['CUSTODIANS'].split(','),b.get('rounds',2),b.get('seconds',120));result={'state':'DRAFT'}
                else:
                    kit=b['kit']
                    if action=='status':result=c.recover(kit)
                    elif action=='checkin':result=c.checkin(kit,b.get('challenge'))
                    elif action=='simulate':result=c.simulate(kit,b['certificate'])
                    elif action in ('arm','disarm','evaluate'):result=getattr(c,action)(kit)
                    else:raise ValueError('unsupported action')
                out={'kit':kit,'result':result};code=200
            except Exception as e:out={'error':str(e),'uncertain':True};code=422
            raw=canonical(out);self.send_response(code);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    HTTPServer(('0.0.0.0',8080),Handler).serve_forever()
if __name__=='__main__':main()
