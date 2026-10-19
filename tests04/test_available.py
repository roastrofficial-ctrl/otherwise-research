import copy
import itertools
import json
import os
import subprocess
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from Engine.protocol import digest,sign,canonical,keypair
from Bounded.wire import request,atomic_json,strict_json
from Available.lifecycle import Client
from Available.proofs import acknowledgement,release,manifest,operation,fence_certificate
from Available.transport import HttpClientTransport,UrllibTransport
from Available.custody import compatible,LAB_REQUIREMENTS,StaticShareCustody
from Available import client as wireclient

W=['http://aw'+str(i)+':8080' for i in range(1,5)]
K=['http://ak'+str(i)+':8080' for i in range(1,4)]
TOKEN=os.environ['OTHERWISE_04_FAULT_TOKEN']

class AvailableExperiments(unittest.TestCase):
    def setUp(self):self.c=Client();self.vectors=[]
    def draft(self,rounds=1):return self.c.draft(W,K,rounds,10)
    def arm(self,rounds=1):
        k=self.draft(rounds);self.c.arm(k);return k
    def fault(self,i,path,body):return request(W[i]+path,body,TOKEN)
    def move(self,k,delta):
        base=k['manifest']['message']['policy']['contracts'][0]['start']
        now=max(base+delta,max(request(u+'/clock')['upper'] for u in W))
        for i in range(4):self.fault(i,'/test-clock',{'now':now})
    def node(self,kind,obj,retained=None):
        inp={'kind':kind,'object':obj,'retained':retained or []}
        p=subprocess.run(['node','Verifier/available.mjs'],input=canonical(inp),capture_output=True)
        return strict_json(p.stdout)
    def test_01_solo_cli_full_lifecycle_without_saas(self):
        with tempfile.TemporaryDirectory(dir='/recovery') as d:
            path=d+'/owner.json'
            def cli(action,*args):
                p=subprocess.run(['python','-m','Available.cli','--kit',path,action,*args],capture_output=True,text=True)
                self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout)
            cli('create','--rounds','2','--seconds','10');cli('arm')
            self.assertTrue(cli('checkin','--challenge','1')['accepted'])
            self.assertEqual(cli('status')['accepted_checkins'],1)
            self.assertEqual(cli('disarm')['state'],'DISARMED')
            self.assertFalse(cli('evaluate')['authorised'])
    def test_02_one_withholder_presence_and_absence_live(self):
        for missing in range(4):
            k=self.arm();self.fault(missing,'/test-availability',{'available':False})
            try:self.assertTrue(self.c.checkin(k,'1')['accepted'])
            finally:self.fault(missing,'/test-availability',{'available':True})
            k=self.arm();self.move(k,16);self.fault(missing,'/test-availability',{'available':False})
            try:
                d=self.c.evaluate(k);self.assertTrue(d['authorised']);self.assertTrue(self.node('release',d['certificate'])['ok'])
                self.assertEqual(self.c.simulate(k,d['certificate'])['delivery'],'SIMULATED')
            finally:self.fault(missing,'/test-availability',{'available':True})
    def test_03_two_faults_fail_closed(self):
        k=self.arm()
        for i in [0,1]:self.fault(i,'/test-availability',{'available':False})
        try:
            with self.assertRaises(ValueError):self.c.checkin(k,'1')
            self.move(k,16);self.assertEqual(self.c.evaluate(k)['state'],'WAITING')
        finally:
            for i in [0,1]:self.fault(i,'/test-availability',{'available':True})
    def test_04_retained_checkin_lost_reply_expiry_and_repair(self):
        k=self.arm();cid=k['manifest']['message']['capsule'];self.fault(0,'/test-save',{})
        self.c.checkin(k,'1');original=k['acknowledgements'][0];self.assertTrue(self.node('ack',original)['ok'])
        # Forget local client history and restore an entire witness DB to before presence.
        k['acknowledgements']=[];self.fault(0,'/test-restore',{})
        with self.assertRaises(ValueError):self.c.call(W[0]+'/observe',{'capsule':cid,'proof':original['receipts'][0]['message']['proof']})
        self.assertEqual(self.c.recover(k)['accepted_checkins'],1)
        self.assertTrue(self.c.repair(k,1)['repaired']);self.move(k,16)
        self.assertFalse(self.c.evaluate(k)['authorised'])
        # Expiration of a presence claim does not erase the historical accepted check-in.
        self.assertEqual(acknowledgement(original['manifest'],original['receipts'])['accepted'],True)
        with self.assertRaises(ValueError):self.c.call(W[0]+'/repair',{'capsule':cid,'nonce':'forged','checkpoints':[],'command':self.c.command(k,'DISARM')})
    def test_05_equivocation_quorum_intersection(self):
        quorums=list(itertools.combinations(range(4),3))
        for p,a in itertools.product(quorums,repeat=2):
            for faulty in range(4):self.assertTrue((set(p)&set(a))-{faulty})
        k=self.arm();self.c.checkin(k,'1');self.move(k,16);m=k['manifest']['message'];s=m['slots'][0]
        # One actual witness key lies about absence; two honest witnesses retain presence.
        finals=[]
        for i in range(3):
            r=self.c.call(W[i]+'/finalise',{'capsule':m['capsule'],**s})
            if i==0:
                r['message']['proof']=None;r['message']['value']='ABSENT';r=self.fault(i,'/test-sign',{'message':r['message']})
            finals.append(r)
        cert={'v':4,'manifest':k['manifest'],'finals':[finals],'operation':operation(m)};cert['authorisation']=digest(cert)
        with self.assertRaises(ValueError):release(cert)
        self.assertFalse(self.node('release',cert)['ok'])
    def test_06_duplicate_reordered_and_scope(self):
        k=self.arm();self.c.checkin(k,'1');a=k['acknowledgements'][0]
        for perm in itertools.permutations(a['receipts']):
            obj={'manifest':a['manifest'],'receipts':list(perm)}
            self.assertTrue(acknowledgement(obj['manifest'],obj['receipts'])['accepted']);self.assertTrue(self.node('ack',obj)['ok'])
        p=a['receipts'][0]['message']['proof'];before=self.c.recover(k)['history']
        self.c.checkin(k,'1');self.assertEqual(before,self.c.recover(k)['history'])
        for bad in ['duplicate','capsule','contract','version','expired']:
            obj=copy.deepcopy(a)
            if bad=='duplicate':obj['receipts']=[obj['receipts'][0]]*3
            else:
                q=obj['receipts'][0]['message']['proof']['message']
                if bad=='capsule':q['capsule']='other'
                if bad=='contract':q['contract']='other'
                if bad=='version':q['contract_version']=2
                if bad=='expired':q['valid_until']=q['valid_from']
            with self.assertRaises(ValueError):acknowledgement(obj['manifest'],obj['receipts'])
            self.assertFalse(self.node('ack',obj)['ok'])
    def test_07_disarm_release_race_and_workers(self):
        k=self.arm();self.move(k,16)
        with ThreadPoolExecutor(max_workers=3) as pool:
            fs=[pool.submit(self.c.disarm,k),pool.submit(self.c.evaluate,k),pool.submit(self.c.evaluate,k)]
            outcomes=[]
            for f in fs:
                try:outcomes.append(f.result())
                except ValueError:pass
        disarmed=any(r.get('state')=='DISARMED' for r in outcomes)
        authorised=[r for r in outcomes if r.get('authorised')]
        self.assertFalse(disarmed and authorised)
        if authorised:
            cert=authorised[0]['certificate']
            with ThreadPoolExecutor(max_workers=2) as pool:
                deliveries=list(pool.map(lambda _:self.c.simulate(k,cert),range(2)))
            self.assertEqual(deliveries[0],deliveries[1])
            # Certificate permutations bind a different proof hash, same fixed custody operation.
            alt=copy.deepcopy(cert);alt['finals'][0].reverse();alt['authorisation']=digest({x:y for x,y in alt.items() if x!='authorisation'})
            self.assertEqual(self.c.simulate(k,alt),deliveries[0])
    def test_08_transports_same_protocol_bytes_and_authorisation(self):
        k=self.arm();a=Client(UrllibTransport());b=Client(HttpClientTransport())
        p=wireclient.evidence(k['manifest'],self.c.private(k),'presence','1')
        body={'capsule':k['manifest']['message']['capsule'],'proof':p}
        first=a.call(W[0]+'/observe',body);second=b.call(W[0]+'/observe',body);self.assertEqual(canonical(first),canonical(second))
        a.checkin(k,'1');self.assertEqual(a.recover(k),b.recover(k));self.move(k,16)
        self.assertEqual(a.evaluate(k),b.evaluate(k))
        missing=self.arm();self.move(missing,16);self.assertEqual(a.evaluate(missing),b.evaluate(missing))
    def test_09_custody_capability_compatibility(self):
        self.assertTrue(compatible(StaticShareCustody.capabilities,LAB_REQUIREMENTS))
        for key,value in [('cryptographic_policy_enforcement',True),('owner_disarm',False),('operation','timelock')]:
            req={**LAB_REQUIREMENTS,key:value}
            with self.assertRaises(ValueError):compatible(StaticShareCustody.capabilities,req)
        k=self.arm();self.move(k,16);cert=self.c.evaluate(k)['certificate'];m=k['manifest']['message']
        with self.assertRaises(ValueError):self.c.call(K[0]+'/release',{'capsule':m['capsule'],'certificate':cert,'requirements':{**LAB_REQUIREMENTS,'cryptographic_policy_enforcement':True}})
    def test_10_immutable_policy_owner_and_authority_revocation(self):
        k=self.arm();altered=copy.deepcopy(k);altered['manifest']['message']['policy']['grace']=1
        with self.assertRaises(ValueError):self.c.arm(altered)
        # Static membership profile: authority revocation is explicit owner disarm,
        # then a fresh Capsule/manifest, never a hidden authority-list edit.
        self.c.disarm(k)
        with self.assertRaises(ValueError):self.c.arm(k)
        with self.assertRaises(ValueError):self.c.checkin(k,'1')
        self.move(k,16);self.assertFalse(self.c.evaluate(k)['authorised'])
    def test_11_council_independent_facts_and_two_evaluators(self):
        k=self.draft();m=k['manifest']['message'];base=m['policy']['contracts'][0]['start'];auth=[keypair() for _ in range(3)]
        m['policy']['contracts']=[{'id':chr(65+i),'version':1,'kind':'attestation','authority':pair[1],'start':base,'end':base+1000,'challenges':[]} for i,pair in enumerate(auth)]
        m['policy']['expression']={'op':'THRESHOLD','k':2,'args':['A','B','C']};m['slots']=[{'contract':c['id'],'challenge':'attestation','open':base,'deadline':base+10} for c in m['policy']['contracts']]
        m['commitment']=digest(m['policy']);k['manifest']['signature']=sign(self.c.private(k),m);self.c.arm(k)
        for order in [(0,1,2),(2,1,0)]:
            for i in order:
                p=wireclient.evidence(k['manifest'],auth[i][0],chr(65+i),'attestation',value=i!=2)
                for u in W:self.c.call(u+'/observe',{'capsule':m['capsule'],'proof':p})
        self.move(k,16);d=self.c.evaluate(k);self.assertTrue(d['authorised']);py=release(d['certificate']);js=self.node('release',d['certificate']);self.assertEqual(js,{'ok':True,**py});self.assertEqual(py['contracts'],{'A':True,'B':True,'C':False})
    def test_12_clock_uncertainty_stale_submission_and_partial_close(self):
        k=self.arm();m=k['manifest']['message'];self.move(k,11)
        with self.assertRaises(ValueError):self.c.checkin(k,'1')
        self.assertFalse(self.c.evaluate(k)['authorised']);self.move(k,16)
        self.fault(3,'/test-clock',{'now':max(request(u+'/clock')['upper'] for u in W),'healthy':False})
        try:self.assertTrue(self.c.evaluate(k)['authorised'])
        finally:self.fault(3,'/test-clock',{'now':max(request(u+'/clock')['upper'] for u in W),'healthy':True})
    def test_13_repair_freshness_and_partial_state_transfer(self):
        k=self.arm();m=k['manifest']['message'];cid=m['capsule'];self.c.checkin(k,'1')
        nonce=self.c.call(W[0]+'/repair-challenge',{'capsule':cid})['nonce'];target=m['witnesses']['1']
        cps=[self.c.call(u+'/checkpoint',{'capsule':cid,'nonce':nonce,'target':target}) for u in W[1:]]
        def body(checkpoints):
            msg={'v':4,'action':'REPAIR','capsule':cid,'manifest':digest(m),'target':target,'nonce':nonce,'checkpoints':sorted(digest(c) for c in checkpoints)}
            return {'capsule':cid,'nonce':nonce,'checkpoints':checkpoints,'command':{'message':msg,'signature':sign(self.c.private(k),msg)}}
        with self.assertRaises(ValueError):self.c.call(W[0]+'/repair',body(cps[:2]))
        valid=body(cps);self.assertTrue(self.c.call(W[0]+'/repair',valid)['repaired'])
        with self.assertRaises(ValueError):self.c.call(W[0]+'/repair',valid)
        self.assertEqual(self.c.recover(k)['accepted_checkins'],1)
    def test_14_attestation_expiry_changes_snapshot_result(self):
        k=self.draft();m=k['manifest']['message'];base=m['policy']['contracts'][0]['start'];owner=self.c.private(k)
        m['policy']['contracts']=[{'id':'A','version':1,'kind':'attestation','authority':m['policy']['owner'],'start':base,'end':base+1000,'challenges':[]}]
        m['policy']['expression']='A';m['slots']=[{'contract':'A','challenge':'attestation','open':base,'deadline':base+10}];m['commitment']=digest(m['policy']);k['manifest']['signature']=sign(owner,m);self.c.arm(k)
        p=wireclient.evidence(k['manifest'],owner,'A','attestation');p['message']['valid_until']=base+11;p['signature']=sign(owner,p['message'])
        rs=[self.c.call(u+'/observe',{'capsule':m['capsule'],'proof':p}) for u in W]
        self.assertTrue(acknowledgement(k['manifest'],rs)['accepted']);self.move(k,16)
        self.assertFalse(self.c.evaluate(k)['authorised'])
    def test_15_deadline_inclusive_with_one_late_witness(self):
        k=self.arm();m=k['manifest']['message'];deadline=m['slots'][0]['deadline']
        for i in range(4):self.fault(i,'/test-clock',{'now':deadline+(1 if i==3 else 0)})
        self.assertTrue(self.c.checkin(k,'1')['accepted']);self.assertEqual(len(k['acknowledgements'][-1]['receipts']),3)
        self.move(k,16);self.assertFalse(self.c.evaluate(k)['authorised'])
    def test_16_untrusted_status_is_discovery_not_authority(self):
        k=self.arm();self.c.checkin(k,'1');expected=self.c.recover(k)
        class CorruptDiscovery:
            def call(self,url,body=None):
                result=UrllibTransport().call(url,body)
                if '/status?' in url:
                    fake=copy.deepcopy(result['records'][0]);fake['signature']='00'*64
                    result['records'] += [fake,{'message':{'kind':'FINAL'}}]
                return result
        actual=Client(CorruptDiscovery()).recover(k)
        self.assertEqual(actual,expected)
    def test_17_byzantine_future_final_cannot_close_honest_nodes_early(self):
        k=self.arm();m=k['manifest']['message'];s=m['slots'][0];t=s['deadline']+1+m['policy']['grace']
        r={'v':4,'kind':'FINAL','capsule':m['capsule'],'manifest':digest(m),'operation':operation(m),'witness':4,'contract':s['contract'],'challenge':s['challenge'],'seq':1,'prev':'0'*64,'lower':t,'upper':t,'proof':None,'value':'ABSENT','not_before':t}
        early=self.fault(3,'/test-sign',{'message':r})
        for u in W:self.c.call(u+'/retain',{'capsule':m['capsule'],'receipt':early})
        # Only the equivocator's own final closes its slot; three honest nodes stay open.
        self.assertTrue(self.c.checkin(k,'1')['accepted']);self.assertEqual(len(k['acknowledgements'][-1]['receipts']),3)
        self.assertEqual(self.c.disarm(k)['state'],'DISARMED')
        self.move(k,16);self.assertFalse(self.c.evaluate(k)['authorised'])
    def test_18_contradictory_c_does_not_own_a_threshold_policy(self):
        k=self.draft();m=k['manifest']['message'];base=m['policy']['contracts'][0]['start'];auth=[keypair() for _ in range(3)]
        m['policy']['contracts']=[{'id':chr(65+i),'version':1,'kind':'attestation','authority':pair[1],'start':base,'end':base+1000,'challenges':[]} for i,pair in enumerate(auth)]
        m['policy']['expression']={'op':'THRESHOLD','k':2,'args':['A','B','C']};m['slots']=[{'contract':c['id'],'challenge':'attestation','open':base,'deadline':base+10} for c in m['policy']['contracts']];m['commitment']=digest(m['policy']);k['manifest']['signature']=sign(self.c.private(k),m);self.c.arm(k)
        for i in range(3):
            p=wireclient.evidence(k['manifest'],auth[i][0],chr(65+i),'attestation',value=True)
            receipts=[self.c.call(u+'/observe',{'capsule':m['capsule'],'proof':p}) for u in W]
        contrary=wireclient.evidence(k['manifest'],auth[2][0],'C','attestation',ident='contrary',value=False)
        liar=copy.deepcopy(receipts[-1]['message']);liar['proof']=contrary;liar['value']='FALSE';liar['seq']+=1;liar['prev']=digest(receipts[-1]);signed=self.fault(3,'/test-sign',{'message':liar})
        for u in W:self.c.call(u+'/retain',{'capsule':m['capsule'],'receipt':signed})
        self.move(k,16);d=self.c.evaluate(k);self.assertTrue(d['authorised']);py=release(d['certificate']);self.assertEqual(py['contracts'],{'A':True,'B':True,'C':False});self.assertEqual(self.node('release',d['certificate']),{'ok':True,**py})
    def test_19_malformed_peer_replies_cannot_poison_honest_quorum(self):
        class BadPeer:
            def call(self,url,body=None):
                if url.startswith(W[3]) and any(path in url for path in ['/clock','/arm','/observe','/retain','/disarm','/finalise']):return {'garbage':True}
                return UrllibTransport().call(url,body)
        c=Client(BadPeer());k=self.draft();self.assertEqual(c.arm(k)['state'],'ARMED');self.assertTrue(c.checkin(k)['accepted']);self.assertEqual(c.disarm(k)['state'],'DISARMED')
        k=self.draft();c.arm(k);self.move(k,16);d=c.evaluate(k);self.assertTrue(d['authorised']);self.assertEqual(c.simulate(k,d['certificate'])['delivery'],'SIMULATED')
    def test_20_eight_present_slots_do_not_expand_equivalent_quorums(self):
        k=self.arm(8);m=k['manifest']['message'];base=m['policy']['contracts'][0]['start']
        for s in m['slots']:
            self.move(k,s['open']-base);self.c.checkin(k,s['challenge'])
        self.move(k,m['slots'][-1]['deadline']+6-base)
        import time
        started=time.monotonic();self.assertFalse(self.c.evaluate(k)['authorised']);self.assertLess(time.monotonic()-started,10,'equivalent quorums must not trigger exponential signature revalidation')
