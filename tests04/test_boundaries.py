import ast
import copy
import datetime
import os
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from Engine.protocol import canonical
from Available.transport import UrllibTransport,HttpClientTransport
from Available.proofs import release
from scripts.conformance04 import corpus

class Separability(unittest.TestCase):
    def test_protocol_image_and_import_graph_exclude_saas(self):
        self.assertFalse(Path('Consumer').exists())
        self.assertIsNone(shutil.which('php'));self.assertIsNone(shutil.which('composer'))
        for p in Path('Available').glob('*.py'):
            for node in ast.walk(ast.parse(p.read_text())):
                names=[node.module or ''] if isinstance(node,ast.ImportFrom) else [a.name for a in node.names] if isinstance(node,ast.Import) else []
                self.assertFalse(any(n.split('.')[0] in ['Consumer','App','Retained','porternet','laravel'] for n in names),str(p))
        self.assertTrue(release(corpus()[1]['input']['object'])['authorised'])
    def test_two_actual_https_transports_keep_signed_message_and_decision(self):
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'otherwise-local-test')]);now=datetime.datetime.now(datetime.timezone.utc)
        cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost')]),False).sign(key,hashes.SHA256()))
        received=[]
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def do_POST(self):
                raw=self.rfile.read(int(self.headers['Content-Length']));received.append(raw)
                self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        with tempfile.TemporaryDirectory() as d:
            cp=Path(d)/'ca.pem';kp=Path(d)/'key.pem';cp.write_bytes(cert.public_bytes(serialization.Encoding.PEM));kp.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));kp.chmod(0o600)
            ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain(cp,kp)
            server=HTTPServer(('127.0.0.1',0),Handler);server.socket=ctx.wrap_socket(server.socket,server_side=True)
            thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
            old=os.environ.get('SSL_CERT_FILE');url='https://localhost:'+str(server.server_port)+'/message';message=corpus()[1]['input']['object']
            try:
                for t in [UrllibTransport(),HttpClientTransport()]:
                    with self.assertRaises(Exception):t.call(url,message)
                for t in [UrllibTransport(cafile=str(cp)),HttpClientTransport(cafile=str(cp))]:
                    reply=t.call(url,message);self.assertEqual(reply,message);self.assertEqual(release(reply),release(message))
                    p=subprocess.run(['node','Verifier/available.mjs'],input=canonical({'kind':'release','object':reply}),capture_output=True);self.assertEqual(p.returncode,0,p.stdout)
                self.assertEqual(received,[canonical(message),canonical(message)])
            finally:
                if old is None:os.environ.pop('SSL_CERT_FILE',None)
                else:os.environ['SSL_CERT_FILE']=old
                server.shutdown();server.server_close();thread.join()

    def test_custody_gate_substitution_obeys_same_requirements(self):
        from Available.custody import CustodyProvider,StaticShareCustody,NodeCheckedStaticShareCustody,compatible,LAB_REQUIREMENTS
        cert=corpus()[1]['input']['object']
        for provider in [StaticShareCustody(),NodeCheckedStaticShareCustody()]:
            self.assertIsInstance(provider,CustodyProvider)
            self.assertTrue(compatible(provider.capabilities,LAB_REQUIREMENTS))
            self.assertEqual(provider.authorise(cert,[]),release(cert))
            with self.assertRaises(ValueError):compatible(provider.capabilities,{**LAB_REQUIREMENTS,'cryptographic_policy_enforcement':True})
