"""Preserved wire4 witness plus a separate v7 durable encrypted-contribution journal.
Retention attests storage, not mathematical validity of encrypted content.
"""
import os
from Engine.protocol import digest
from Available.proofs import require,checked_signature,release
from Untrusted.service import Store as OldStore
from .protocol import commitment,response

class Store(OldStore):
    def check_bundle(self,b):
        c,m=commitment(b['sidecar']);release(b['certificate']);require(set(b)=={'sidecar','certificate','response'},'journal bundle')
        domain=b['response']['message']['context']['domain'];response(b['sidecar'],b['certificate'],domain,b['response'])
        return c,m
    def handle(self,path,b):
        if path=='/retain07':
            c,m=self.check_bundle(b);s=self.get(m['capsule']);self.ready(s);require(s['manifest']==c['manifest'],'journal Capsule scope')
            journal=s.setdefault('operations07',{});journal[digest(b['response'])]=b;self.put(m['capsule'],s)
            return self.signed({'v':7,'kind':'STORED_ENCRYPTED_CONTRIBUTION','capsule':m['capsule'],'commitment':digest(b['sidecar']),'response':digest(b['response']),'witness':self.index})
        if path=='/inspect07':
            c,m=commitment(b['sidecar']);s=self.get(m['capsule']);self.ready(s);require(s['manifest']==c['manifest'] and type(b['nonce']) is str and len(b['nonce'])==64,'journal request')
            return self.signed({'v':7,'kind':'OPERATION_JOURNAL','capsule':m['capsule'],'commitment':digest(b['sidecar']),'nonce':b['nonce'],'witness':self.index,'bundles':list(s.get('operations07',{}).values())})
        return super().handle(path,b)

def main():
    import Untrusted.service as old
    old.Store=Store;old.main()
if __name__=='__main__':main()
