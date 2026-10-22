"""Reference protocol service extension, independent of any consumer application."""
import re
from Engine.protocol import digest
from Available.proofs import manifest,require
import Available.service as reference

class Store(reference.Store):
    def handle(self,path,b):
        if path=='/lab-collude':
            import os
            require(os.environ.get('LAB_FAULTS')=='1' and b.get('capability')==os.environ.get('BOOTSTRAP_TOKEN') and self.role=='custodian','malicious custody experiment only')
            return self.get(b['capsule'])['share']
        if path!='/inspect':return super().handle(path,b)
        require(set(b)=={'capsule','nonce'} and type(b['nonce']) is str and re.fullmatch('[0-9a-f]{64}',b['nonce']),'inspection request')
        require(self.role=='witness','witness status only');s=self.get(b['capsule']);self.ready(s);m=manifest(s['manifest'])
        return self.signed({'v':5,'kind':'INSPECT','capsule':m['capsule'],'manifest':digest(m),'nonce':b['nonce'],'witness':self.index,'records':s['records'],'clock':self.sample()})

def main():
    import os,ssl
    require(os.environ.get('TLS_CERT') and os.environ.get('TLS_KEY'),'0.5 providers require independent TLS credentials')
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(os.environ['TLS_CERT'],os.environ['TLS_KEY'])
    class SecureServer(reference.HTTPServer):
        def __init__(self,*args,**kwargs):
            super().__init__(*args,**kwargs);self.socket=context.wrap_socket(self.socket,server_side=True)
    reference.HTTPServer=SecureServer
    reference.Store=Store
    reference.main()
if __name__=='__main__':main()
