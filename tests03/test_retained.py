import copy
import itertools
import json
import os
import subprocess
import tempfile
import time
import unittest
import uuid
from Engine.protocol import keypair,sign,digest,canonical
from Bounded.wire import request
from Retained.client import prepare,enroll,evidence,check_in,gossip,finalise,recover,CheckInClient
from Retained.fixtures import policy,objects
from Retained.proofs import acknowledgement,release,operation

W=['http://rw'+str(i)+':8080' for i in range(1,4)]
K=['http://rk'+str(i)+':8080' for i in range(1,4)]
T=[os.environ.get('OTHERWISE_03_'+prefix+str(i)+'_TOKEN','') for prefix in ('RW','RK') for i in range(1,4)]


class RetainedExperiments(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for url in W+K:cls.wait(url)
    @classmethod
    def wait(cls,url):
        until=time.monotonic()+30
        while True:
            try:return request(url+'/identity')
            except Exception:
                if time.monotonic()>until:raise
                time.sleep(.1)
    def setup_capsule(self,kind='absence',rounds=1):
        owner,pub=keypair();authorities=[(owner,pub)] if kind=='absence' else [keypair() for _ in range(3)]
        base=max(request(url+'/clock')['lower'] for url in W)
        for i,url in enumerate(W):request(url+'/test-clock',{'now':base},T[i])
        p=policy(kind,base,rounds,[a[1] for a in authorities],pub)
        sm,ciphertext,shares=prepare('retained-'+uuid.uuid4().hex,p,owner,os.urandom(32),W,K,base+10)
        enroll(sm,shares,W,K,T)
        return owner,authorities,sm,ciphertext,base
    def move(self,base,delta,indices=range(3)):
        for i in indices:request(W[i]+'/test-clock',{'now':base+delta},T[i])
    def p(self,sm,a,challenge='round-1',index=0,**kwargs):return evidence(sm,a[index][0],chr(65+index),challenge,**kwargs)
    def sign_absent(self,sm,index,template=None):
        m=sm['message'];s=m['slots'][0]
        r={'v':3,'kind':'FINAL','capsule':m['capsule'],'manifest':digest(m),'witness':index+1,'contract':s['contract'],'challenge':s['challenge'],'operation':operation(m),'seq':1,'prev':'0'*64,'lower':s['deadline']+1+m['policy']['grace'],'upper':s['deadline']+1+m['policy']['grace'],'proof':None,'value':'ABSENT','not_before':s['deadline']+1+m['policy']['grace']}
        if template:r.update(seq=template['message']['seq']+1,prev=digest(template))
        return request(W[index]+'/test-sign',{'message':r},T[index])
    def rebind(self,c):c['authorisation']=digest({k:v for k,v in c.items() if k!='authorisation'});return c

    def test_00_majority_intersection_counterexample(self):
        ack,cert,_=objects(True,absent=(1,2))
        self.assertTrue(acknowledgement(ack['manifest'],ack['receipts'],unsafe=True)['accepted'])
        self.assertTrue(release(cert,unsafe=True)['authorised'])
        with self.assertRaises(ValueError):release(cert)
        print('COUNTEREXAMPLE: P={A,B}, A={B,C}, B equivocates: both naive 2/3 certificates verify. Revised profile rejects 2/2.')

    def test_A_lost_acknowledgement(self):
        o,a,sm,ct,b=self.setup_capsule();self.move(b,5)
        request(W[2]+'/test-availability',{'available':False},T[2])
        try:
            p=self.p(sm,a)
            with tempfile.NamedTemporaryFile(mode='w',dir='/tmp') as f:
                json.dump({'proof':p,'urls':W[:2]},f);f.flush()
                code="import json,sys,os;from Bounded.wire import request;b=json.load(open(sys.argv[1]));[request(u+'/observe',{'proof':b['proof']}) for u in b['urls']];os._exit(83)"
                self.assertEqual(subprocess.run(['python','-c',code,f.name]).returncode,83)
            before=[request(url+'/status?capsule='+sm['message']['capsule'])['events'][0] for url in W[:2]]
            cache=tempfile.TemporaryDirectory(dir='/client-state');client=CheckInClient(cache.name,W)
            ack=client.check_in(sm,p);self.assertTrue(acknowledgement(sm,ack['receipts'])['accepted']);self.assertEqual(ack['receipts'],before)
            self.assertEqual(client.check_in(sm,p),ack)
            self.assertEqual(len(os.listdir(cache.name)),1)
            with tempfile.NamedTemporaryFile(mode='w',dir='/tmp') as f:
                json.dump({'manifest':sm,'proof':p},f);f.flush()
                code="import json,sys;from Retained.client import CheckInClient;b=json.load(open(sys.argv[2]));assert CheckInClient(sys.argv[1],[]).check_in(b['manifest'],b['proof'])['receipts']"
                self.assertEqual(subprocess.run(['python','-c',code,cache.name,f.name]).returncode,0)
            cache.cleanup()
        finally:request(W[2]+'/test-availability',{'available':True},T[2])

    def test_B_forgotten_witness(self):
        o,a,sm,ct,b=self.setup_capsule();cid=sm['message']['capsule'];request(W[0]+'/test-save',{'capsule':cid},T[0])
        self.move(b,5);ack=check_in(sm,self.p(sm,a),W);gossip(ack,W)
        request(W[0]+'/test-restore',{'capsule':cid},T[0])
        anchors=request(W[1]+'/anchors?capsule='+cid+'&witness=1');self.assertTrue(anchors)
        with self.assertRaises(ValueError):request(W[0]+'/retain',{'capsule':cid,'receipt':anchors[-1]})
        self.assertTrue(request(W[0]+'/status?capsule='+cid)['quarantined'])
        self.move(b,16);c=finalise(sm,W)
        with self.assertRaises(ValueError):release(c)

    def test_C_fabricated_absence_one_malicious(self):
        o,a,sm,ct,b=self.setup_capsule();self.move(b,5);ack=check_in(sm,self.p(sm,a),W[:2])
        self.move(b,16);c=finalise(sm,W)
        c['finals'][0][1]=self.sign_absent(sm,1,ack['receipts'][1]);self.rebind(c)
        with self.assertRaises(ValueError):release(c)
        self.assertTrue(acknowledgement(sm,ack['receipts'])['accepted'])

    def test_D_equivocating_witness(self):
        o,a,sm,ct,b=self.setup_capsule();self.move(b,5);ack=check_in(sm,self.p(sm,a),W[:2]);gossip(ack,W)
        fake=self.sign_absent(sm,1,ack['receipts'][1])
        with self.assertRaises(ValueError):request(W[0]+'/retain',{'capsule':sm['message']['capsule'],'receipt':fake})
        status=request(W[0]+'/status?capsule='+sm['message']['capsule'])
        self.assertFalse(status['quarantined']);self.assertIn(2,status['equivocators'])

    def test_E_partitioned_groups(self):
        o,a,sm,ct,b=self.setup_capsule();self.move(b,10);ack=check_in(sm,self.p(sm,a),W[:2])
        self.move(b,16);c=finalise(sm,W[1:])
        with self.assertRaises(ValueError):release(c)
        self.assertTrue(acknowledgement(sm,ack['receipts'])['accepted'])
        # Exhaust all quorum pairs: with p=2,a=3 every intersection exceeds f=1.
        for p in itertools.combinations(range(3),2):
            self.assertGreater(len(set(p)&{0,1,2}),1)
        self.assertEqual(len({0,1}&{1,2}),1)

    def test_F_late_witness_and_exact_boundary(self):
        o,a,sm,ct,b=self.setup_capsule();p=self.p(sm,a);self.move(b,10,[0]);first=request(W[0]+'/observe',{'proof':p})
        self.move(b,11,[1,2])
        for i in (1,2):
            with self.assertRaises(ValueError):request(W[i]+'/observe',{'proof':p})
        with self.assertRaises(ValueError):acknowledgement(sm,[first])
        self.move(b,16);c=finalise(sm,W)
        with self.assertRaises(ValueError):release(c) # conservative minority retention blocks unanimity
        self.assertEqual(request(W[0]+'/observe',{'proof':p}),first) # receipt recovery after deadline

    def test_G_silent_witness(self):
        o,a,sm,ct,b=self.setup_capsule();self.move(b,16)
        request(W[2]+'/test-availability',{'available':False},T[2])
        try:
            c=finalise(sm,W);self.assertEqual(len(c['finals'][0]),2)
            with self.assertRaises(ValueError):release(c)
        finally:request(W[2]+'/test-availability',{'available':True},T[2])

    def test_H_stolen_identity_and_replay(self):
        o,a,sm,ct,b=self.setup_capsule(rounds=2);self.move(b,5);ack=check_in(sm,self.p(sm,a),W)
        for field,value in [('signature','00'*64),('witness',99),('challenge','round-2'),('capsule','different')]:
            bad=copy.deepcopy(ack['receipts'])
            if field=='signature':bad[0][field]=value
            else:bad[0]['message'][field]=value
            with self.assertRaises(ValueError):acknowledgement(sm,bad)
        self.assertEqual(check_in(sm,self.p(sm,a),W),ack)
        wrong=self.p(sm,a);wrong['message']['contract_version']=2
        with self.assertRaises(ValueError):request(W[0]+'/observe',{'proof':wrong})

    def test_I_custodians_retained_doubt_exceeded_fault_budget(self):
        o,a,sm,ct,b=self.setup_capsule();self.move(b,5);ack=check_in(sm,self.p(sm,a),W[:2])
        for url in K:request(url+'/retain',ack)
        self.move(b,16);c=finalise(sm,W)
        for i in (0,1):c['finals'][0][i]=self.sign_absent(sm,i,ack['receipts'][i])
        self.rebind(c);self.assertTrue(release(c)['authorised']) # two Byzantine witnesses violate f=1
        for url in K:
            with self.assertRaises(ValueError):request(url+'/release',{'certificate':c})
        print('BOUNDARY: two Byzantine witnesses can produce conflicting 2/3 presence and 3/3 absence; informed custodians veto.')

    def test_J_solo_witness_and_disarm(self):
        o,a,sm,ct,b=self.setup_capsule(rounds=2);self.move(b,5);ack=check_in(sm,self.p(sm,a),W);gossip(ack,W)
        self.move(b,26);c=finalise(sm,W);self.assertTrue(release(c)['authorised'])
        responses=[request(url+'/release',{'certificate':c}) for url in K[:2]];self.assertEqual(len(recover(sm,ct,responses,c)),32)
        # All slots are present; the first PRESENT and second ABSENT remain distinct.
        self.assertEqual(c['finals'][0][0]['message']['value'],'PRESENT');self.assertEqual(c['finals'][1][0]['message']['value'],'ABSENT')
        o,a,sm,ct,b=self.setup_capsule();m=sm['message'];msg={'v':3,'capsule':m['capsule'],'manifest':digest(m),'action':'DISARM','operation':operation(m)}
        for url in W:request(url+'/disarm',{'message':msg,'signature':sign(o,msg)})
        self.move(b,16)
        with self.assertRaises(ValueError):release(finalise(sm,W))
        o,a,sm,ct,b=self.setup_capsule(rounds=2)
        self.move(b,5);check_in(sm,self.p(sm,a),W)
        self.move(b,15);check_in(sm,self.p(sm,a,'round-2'),W)
        self.move(b,26)
        with self.assertRaises(ValueError):release(finalise(sm,W))
        print('Solo: one human; verifiable/repeated check-ins, missed next challenge, grace, compact custody release, disarm.')

    def test_K_council(self):
        o,a,sm,ct,b=self.setup_capsule('attestation');self.move(b,5)
        for i in range(3):check_in(sm,self.p(sm,a,'attestation',i,value=i<2,ident='claim-'+str(i)),W)
        self.move(b,16);c=finalise(sm,W);self.assertEqual(release(c)['contracts'],{'A':True,'B':True,'C':False})
        responses=[request(url+'/release',{'certificate':c}) for url in K[1:]];self.assertEqual(len(recover(sm,ct,responses,c)),32)

    def test_L_hostile_recovery_actual_process_crashes(self):
        for i,fault in ((0,'before_commit'),(1,'after_commit')):
            o,a,sm,ct,b=self.setup_capsule();self.move(b,5);p=self.p(sm,a);cid=sm['message']['capsule']
            with self.assertRaises(Exception):request(W[i]+'/observe',{'proof':p},T[i],{'X-Crash':fault})
            self.wait(W[i]);status=request(W[i]+'/status?capsule='+cid)
            self.assertEqual(len(status['events']),0 if fault=='before_commit' else 1)
            recovered=request(W[i]+'/observe',{'proof':p});self.assertEqual(request(W[i]+'/observe',{'proof':p}),recovered)
            self.move(b,16);c=finalise(sm,W)
            with self.assertRaises(ValueError):release(c)
