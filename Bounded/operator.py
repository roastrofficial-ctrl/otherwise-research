"""Adversarial app process: full access to its own filesystem, no custody mounts.
The integration harness supplies only public manifests, ciphertext and attack inputs.
"""
import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .client import aad
from .wire import strict_json,request
from Engine.protocol import canonical

ROOT=Path('/operator')
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def respond(self,status,body):
        raw=canonical(body);self.send_response(status);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
    def do_GET(self):
        self.respond(200,{'files':[str(p.relative_to(ROOT)) for p in ROOT.rglob('*') if p.is_file()],
                          'has_bootstrap':any('TOKEN' in k for k in os.environ),
                          'has_state_mount':Path('/state/identity.json').exists(),
                          'has_docker_socket':Path('/var/run/docker.sock').exists()})
    def do_POST(self):
        try:
            b=strict_json(self.rfile.read(int(self.headers['Content-Length'])))
            if self.path=='/store':
                # Full app data is available to the compromised operator.
                (ROOT/'public-capsule.json').write_bytes(canonical(b))
                for name,contents in b.get('files',{}).items():
                    target=ROOT/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(bytes.fromhex(contents))
                self.respond(200,{'stored':True});return
            if self.path=='/attack':
                ciphertext=bytes.fromhex(b['ciphertext']);m=b['manifest'];decrypt=False
                # A concrete failed attempt, not a proof by exhaustive key search.
                for key in (bytes(16),bytes.fromhex(m['payload'])[:16]):
                    try: AESGCM(key).decrypt(ciphertext[:12],ciphertext[12:],aad(m));decrypt=True
                    except Exception: pass
                refused=[]
                for url in b['custodians']:
                    try: request(url+'/release',b['claim']);refused.append(False)
                    except Exception: refused.append(True)
                self.respond(200,{'plaintext_recovered':decrypt,'custodians_refused':refused});return
            raise ValueError('route')
        except Exception as exc:self.respond(409,{'error':str(exc)})

if __name__=='__main__':
    ROOT.mkdir(exist_ok=True);HTTPServer(('0.0.0.0',8080),Handler).serve_forever()
