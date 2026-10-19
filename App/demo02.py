"""Trusted creator/recipient CLI. Runs only against the disposable bounded cluster."""
import os
import tempfile
import uuid
from Engine.protocol import keypair,sign,digest
from Bounded.client import Prepared,Session,prepare,provision,recover,release_request,record_simulated_delivery,collect_shares
from Bounded.wire import request

W='http://witness:8080';C=['http://custodian'+str(i)+':8080' for i in range(1,4)]
TOKENS=[os.environ['OTHERWISE_'+name+'_TOKEN'] for name in ('WITNESS','C1','C2','C3')]


def run(kind):
    base=request(W+'/clock')['lower'];owner,pub=keypair();authorities=[keypair() for _ in range(1 if kind=='absence' else 3)]
    p={'version':1,'owner':pub,'contracts':[{'id':chr(65+i),'version':1,'kind':kind,'authority':a[1],'start':base,'end':base+1000,'challenges':[{'id':'one','open':base,'deadline':base+10},{'id':'two','open':base+11,'deadline':base+20}] if kind=='absence' else []} for i,a in enumerate(authorities)],'expression':'A' if kind=='absence' else {'op':'THRESHOLD','k':2,'args':['A','B','C']},'grace':5,'max_step':60,'destination':{'kind':'simulated','verified':True,'consented':True}}
    cid='demo-'+uuid.uuid4().hex;plaintext=b'synthetic demonstration '+os.urandom(16)
    manifest,ciphertext,shares=prepare(cid,p,plaintext,W,C);prepared=Prepared(manifest,sign(owner,manifest),ciphertext,shares)
    provision(prepared,W,C,TOKENS);prepared.shares=[]
    with tempfile.TemporaryDirectory() as root:
        session=Session(root,W);session.install(prepared);session.command(cid,owner,'ARMED')
        def tick(delta):
            request(W+'/test-clock',{'now':base+delta},TOKENS[0]);session.tick(cid,base+delta)
        if kind=='absence':tick(10)
        for i,a in enumerate(authorities):
            msg={'v':1,'id':'proof-'+str(i),'capsule':cid,'commitment':manifest['commitment'],'contract':chr(65+i),'contract_version':1,'authority':a[1],'valid_from':base,'valid_until':base+100}
            msg.update({'challenge':'one'} if kind=='absence' else {'claim':i<2})
            session.submit(cid,msg,sign(a[0],msg))
        if kind=='absence':tick(21)
        assert session.authorise(cid) is None
        tick(26 if kind=='absence' else 5);decision=session.authorise(cid);assert decision
        responses=collect_shares(manifest,decision,C)
        assert recover(manifest,ciphertext,responses)==plaintext
        record_simulated_delivery(session,cid,decision)
        audit=session.engine.export(cid)
        print(('Solo Witness' if kind=='absence' else 'Council')+': AUTHORISED -> two independent custody responses -> synthetic recipient -> RELEASED')
        print('Policy contract count:',len(p['contracts']),'Custody threshold: 2 of 3','Audit facts:',len(audit['events']))
        print('Witnessed decision:',digest(decision))
        print('Operator key files:',len(list(session.engine.root.rglob('*.key'))))

if __name__=='__main__':run('absence');run('attestation')
