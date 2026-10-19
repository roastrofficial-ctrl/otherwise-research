import copy
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Engine.protocol import keypair,sign,digest,canonical
from Bounded.client import Prepared,Session,prepare,provision,recover,release_request,aad,collect_shares
from Bounded.clock import Clock
from Bounded.service import State
from Bounded.verify import validate_snapshot
from Bounded.wire import request

WITNESS='http://witness:8080'
CUSTODIANS=['http://custodian'+str(i)+':8080' for i in range(1,4)]
OPERATOR='http://operator:8080'
TOKENS=[os.environ.get('OTHERWISE_'+suffix+'_TOKEN','') for suffix in ('WITNESS','C1','C2','C3')]


class CustodyExperiments(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        for url in [WITNESS,*CUSTODIANS,OPERATOR]:
            deadline=time.monotonic()+25
            while True:
                try:request(url+('/' if url==OPERATOR else '/identity'));break
                except Exception:
                    if time.monotonic()>deadline:raise
                    time.sleep(.1)
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.base=request(WITNESS+'/clock')['lower'];self.plaintexts={}
    def tearDown(self):self.tmp.cleanup()
    def setup_capsule(self,kind='attestation',*,ready=True):
        owner,pub=keypair();authorities=[keypair() for _ in range(1 if kind=='absence' else 3)]
        b=self.base
        policy={'version':1,'owner':pub,'contracts':[{'id':chr(65+i),'version':1,'kind':kind,'authority':a[1],'start':b,'end':b+1000,'challenges':[{'id':'one','open':b,'deadline':b+10},{'id':'two','open':b+11,'deadline':b+20}] if kind=='absence' else []} for i,a in enumerate(authorities)],'expression':'A' if kind=='absence' else {'op':'THRESHOLD','k':2,'args':['A','B','C']},'grace':5,'max_step':60,'destination':{'kind':'simulated','verified':True,'consented':True}}
        cid='capsule-'+uuid.uuid4().hex
        plaintext=b'synthetic payload '+os.urandom(32);self.plaintexts[cid]=plaintext
        manifest,ciphertext,shares=prepare(cid,policy,plaintext,WITNESS,CUSTODIANS)
        prepared=Prepared(manifest,sign(owner,manifest),ciphertext,shares)
        if ready:provision(prepared,WITNESS,CUSTODIANS,TOKENS)
        session=Session(self.tmp.name+'/'+cid,WITNESS)
        if ready:session.install(prepared);session.command(cid,owner,'ARMED')
        return owner,authorities,prepared,session
    def move(self,s,p,delta,outage=False):
        now=self.base+delta
        request(WITNESS+'/test-clock',{'now':now,'healthy':not outage},TOKENS[0])
        return s.tick(p.manifest['capsule'],now,outage=outage)
    def evidence(self,p,a,index=0,claim=True,challenge='one',ident=None):
        m=p.manifest;c=m['policy']['contracts'][index]
        msg={'v':1,'id':ident or c['id']+'-proof','capsule':m['capsule'],'commitment':m['commitment'],'contract':c['id'],'contract_version':1,'authority':c['authority'],'valid_from':self.base,'valid_until':self.base+100}
        msg.update({'claim':claim} if c['kind']=='attestation' else {'challenge':challenge})
        return msg,sign(a[index][0],msg)
    def council(self):
        o,a,p,s=self.setup_capsule()
        for i in range(3):s.submit(p.manifest['capsule'],*self.evidence(p,a,i,claim=i<2))
        return o,a,p,s
    def authorise(self,p,s,delta=5):
        cid=p.manifest['capsule'];self.assertIsNone(s.authorise(cid));self.move(s,p,delta)
        decision=s.authorise(cid);self.assertIsNotNone(decision);return decision
    def get_shares(self,p,d,urls=None):
        return [request(url+'/release',release_request(p.manifest,d)) for url in (urls or CUSTODIANS[:2])]
    def refuse(self,p,d=None):
        for url in CUSTODIANS:
            with self.assertRaises(ValueError):request(url+'/release',release_request(p.manifest,d or {'fake':True}))

    def test_A_compromised_operator(self):
        o,a,p,s=self.setup_capsule()
        request(OPERATOR+'/store',{'manifest':p.manifest,'ciphertext':p.ciphertext.hex(),'projection':s.engine.export(p.manifest['capsule']),'files':{str(f.relative_to(s.engine.root)):f.read_bytes().hex() for f in s.engine.root.rglob('*') if f.is_file()}})
        attack=request(OPERATOR+'/attack',{'manifest':p.manifest,'ciphertext':p.ciphertext.hex(),'custodians':CUSTODIANS,'claim':release_request(p.manifest,{'fake':True})})
        self.assertFalse(attack['plaintext_recovered']);self.assertEqual(attack['custodians_refused'],[True]*3)
        inspection=request(OPERATOR+'/');self.assertFalse(inspection['has_bootstrap']);self.assertFalse(inspection['has_state_mount']);self.assertFalse(inspection['has_docker_socket'])
        self.assertFalse((s.engine.root/'keys').exists())

    def test_B_forged_release(self):
        o,a,p,s=self.setup_capsule();cid=p.manifest['capsule']
        forged=s.engine.export(cid)
        event={'v':1,'capsule':cid,'seq':len(forged['events'])+1,'time':self.base,'kind':'AUTHORISED','data':{'commitment':forged['commitment'],'snapshot':forged['head'],'results':{'satisfied':True},'candidate':1,'payload':p.manifest['payload']},'prev':forged['head']}
        forged['events'].append(event);forged['head']=digest(event)
        with self.assertRaises(ValueError):request(WITNESS+'/publish',forged)
        self.refuse(p,event)

    def test_C_replayed_authorisation(self):
        o,a,p,s=self.council();d=self.authorise(p,s)
        responses=self.get_shares(p,d)
        self.assertEqual(recover(p.manifest,p.ciphertext,responses),self.plaintexts[p.manifest['capsule']])
        other_o,other_a,q,t=self.setup_capsule()
        self.refuse(q,d)
        with self.assertRaises(ValueError):recover(q.manifest,q.ciphertext,responses)
        for field,value in (('commitment','0'*64),('epoch',2),('payload','0'*64)):
            changed=copy.deepcopy(p.manifest);changed[field]=value
            with self.assertRaises(ValueError):recover(changed,p.ciphertext,responses)
        changed=copy.deepcopy(responses);changed[0]['message']['history']='0'*64
        with self.assertRaises(ValueError):recover(p.manifest,p.ciphertext,changed)

    def test_D_missing_custodian(self):
        o,a,p,s=self.council();d=self.authorise(p,s)
        # Inject an actual protocol-service failure, then automatically skip it.
        request(CUSTODIANS[1]+'/test-availability',{'available':False},TOKENS[2])
        try:
            with self.assertRaises(ValueError):request(CUSTODIANS[1]+'/release',release_request(p.manifest,d))
            responses=collect_shares(p.manifest,d,CUSTODIANS)
            self.assertEqual([r['message']['index'] for r in responses],[1,3])
        finally:request(CUSTODIANS[1]+'/test-availability',{'available':True},TOKENS[2])
        self.assertEqual(recover(p.manifest,p.ciphertext,responses),self.plaintexts[p.manifest['capsule']])
        with self.assertRaises(ValueError):recover(p.manifest,p.ciphertext,responses[:1])
        with self.assertRaises(ValueError):recover(p.manifest,p.ciphertext,[responses[0],responses[0]])

    def test_E_colluding_custodians_bypass_policy(self):
        o,a,p,s=self.setup_capsule();self.refuse(p)
        # Test admin capabilities model compromise of two independent services.
        shares=[request(CUSTODIANS[i]+'/test-export-share',{'capsule':p.manifest['capsule']},TOKENS[i+1]) for i in range(2)]
        key=Shamir.combine([(r['index'],bytes.fromhex(r['value'])) for r in shares])
        plaintext=AESGCM(key).decrypt(p.ciphertext[:12],p.ciphertext[12:],aad(p.manifest))
        self.assertEqual(plaintext,self.plaintexts[p.manifest['capsule']])
        print('OBSERVED LIMIT: two compromised custodians decrypt before authorisation.')

    def test_F_rewritten_history(self):
        o,a,p,s=self.setup_capsule('absence');cid=p.manifest['capsule']
        backup=Path(self.tmp.name)/'before-presence.db';shutil.copy2(s.engine.path,backup)
        self.move(s,p,5);receipt=s.submit(cid,*self.evidence(p,a));self.assertTrue(receipt['local']['accepted'])
        shutil.copy2(backup,s.engine.path)
        self.move_clock_only(11);s.engine.tick(self.base+11);s.engine.authorise(cid)
        self.move_clock_only(16);s.engine.tick(self.base+16);decision=s.engine.authorise(cid)
        self.assertIsNotNone(decision);validate_snapshot(s.engine.export(cid))
        with self.assertRaises(ValueError):s.publish(cid)
        self.refuse(p,decision)
        restored=s.restore_projection(p.manifest)
        self.assertTrue(any(f['kind']=='ACCEPTED' for f in restored['snapshot']['events']))

    def move_clock_only(self,delta,healthy=True):
        request(WITNESS+'/test-clock',{'now':self.base+delta,'healthy':healthy},TOKENS[0])

    def test_G_solo_witness_lifecycle(self):
        o,a,p,s=self.setup_capsule('absence');cid=p.manifest['capsule']
        self.move(s,p,10);receipt=s.submit(cid,*self.evidence(p,a));self.assertTrue(receipt['local']['accepted'])
        self.move(s,p,11);self.assertIsNone(s.authorise(cid));self.refuse(p)
        self.move(s,p,21);self.assertIsNone(s.authorise(cid));self.move(s,p,26)
        d=s.authorise(cid);self.assertIsNotNone(d)
        self.assertEqual(recover(p.manifest,p.ciphertext,self.get_shares(p,d)),self.plaintexts[p.manifest['capsule']])
        # Same sole owner can disarm another Capsule, no trustee approval.
        self.base=request(WITNESS+'/clock')['lower'];o,a,p,s=self.setup_capsule('absence')
        s.command(p.manifest['capsule'],o,'DISARMED');self.move(s,p,11)
        self.assertIsNone(s.authorise(p.manifest['capsule']));self.refuse(p)
        self.base=request(WITNESS+'/clock')['lower'];o,a,p,s=self.setup_capsule('absence');cid=p.manifest['capsule']
        self.move(s,p,11,outage=True);self.assertIsNone(s.authorise(cid));self.refuse(p)
        self.move_clock_only(11,healthy=True);s.command(cid,o,'RECOVERED');self.assertIsNone(s.authorise(cid))
        self.move(s,p,16);d=s.authorise(cid)
        self.assertEqual(recover(p.manifest,p.ciphertext,self.get_shares(p,d)),self.plaintexts[p.manifest['capsule']])
        print('Solo: check-in, missed obligation, grace, release, disarm and owner recovery completed; no second human.')

    def test_H_council_policy_and_custody_are_distinct(self):
        o,a,p,s=self.setup_capsule();cid=p.manifest['capsule']
        s.submit(cid,*self.evidence(p,a,0));self.assertIsNone(s.authorise(cid));self.refuse(p)
        s.submit(cid,*self.evidence(p,a,1));s.submit(cid,*self.evidence(p,a,2,claim=False))
        s.submit(cid,*self.evidence(p,a,2,claim=True,ident='C-opposite'))
        d=self.authorise(p,s);responses=self.get_shares(p,d,[CUSTODIANS[1],CUSTODIANS[2]])
        # A/B policy authorities differ from the 2/3 custody services actually used.
        self.assertEqual(recover(p.manifest,p.ciphertext,responses),self.plaintexts[p.manifest['capsule']])
        self.assertNotEqual({c['authority'] for c in p.manifest['policy']['contracts']},set(p.manifest['custody']['keys'].values()))

    def test_I_emergency_disarm_and_irrevocability(self):
        o,a,p,s=self.council();cid=p.manifest['capsule'];s.authorise(cid);self.move(s,p,5)
        def disarm():
            try:s.command(cid,o,'DISARMED');return True
            except ValueError:return False
        def participate():
            deadline=time.monotonic()+1
            while time.monotonic()<deadline:
                history=s.engine.export(cid)['events']
                decision=next((f for f in history if f['kind']=='AUTHORISED'),None)
                if decision:
                    try:return request(CUSTODIANS[0]+'/release',release_request(p.manifest,decision))
                    except ValueError:return None
                if any(f['kind']=='DISARMED' for f in history):return None
                time.sleep(.001)
            return None
        with ThreadPoolExecutor(max_workers=3) as pool:
            d=pool.submit(disarm);r=pool.submit(s.authorise,cid);c=pool.submit(participate)
            disarmed=d.result();decision=r.result();capability=c.result()
        if disarmed:self.assertIsNone(capability)
        names={e['kind'] for e in s.engine.export(cid)['events']}
        self.assertNotEqual('DISARMED' in names,'AUTHORISED' in names)
        if disarmed:self.refuse(p)
        else:self.assertEqual(recover(p.manifest,p.ciphertext,self.get_shares(p,decision)),self.plaintexts[p.manifest['capsule']])
        self.base=request(WITNESS+'/clock')['lower'];o,a,p,s=self.council();cid=p.manifest['capsule'];decision=self.authorise(p,s)
        first=request(CUSTODIANS[0]+'/release',release_request(p.manifest,decision))
        with self.assertRaises(ValueError):s.command(cid,o,'DISARMED')
        second=request(CUSTODIANS[1]+'/release',release_request(p.manifest,decision))
        self.assertEqual(recover(p.manifest,p.ciphertext,[first,second]),self.plaintexts[p.manifest['capsule']])

    def test_J_broken_authority_and_compromised_witness(self):
        o,a,p,s=self.council();d=self.authorise(p,s)
        request(WITNESS+'/test-availability',{'available':False},TOKENS[0])
        try:self.refuse(p,d)
        finally:request(WITNESS+'/test-availability',{'available':True},TOKENS[0])
        self.base=request(WITNESS+'/clock')['lower'];o,a,p,s=self.setup_capsule('absence');cid=p.manifest['capsule']
        backup=Path(self.tmp.name)/'before-witness.db';shutil.copy2(s.engine.path,backup)
        self.move(s,p,5);s.submit(cid,*self.evidence(p,a))
        shutil.copy2(backup,s.engine.path)
        self.move_clock_only(11);s.engine.tick(self.base+11);s.engine.authorise(cid)
        self.move_clock_only(16);s.engine.tick(self.base+16);decision=s.engine.authorise(cid)
        with self.assertRaises(ValueError):s.publish(cid)
        # Compromise BOTH operator and independent observation/witness authority.
        request(WITNESS+'/test-rewrite',{'snapshot':s.engine.export(cid)},TOKENS[0])
        responses=self.get_shares(p,decision)
        self.assertEqual(recover(p.manifest,p.ciphertext,responses),self.plaintexts[p.manifest['capsule']])
        print('OBSERVED LIMIT: compromised operator + previously trusted witness can fabricate a complete absence history unseen by custodians.')

    def test_O_custodians_retain_pre_release_history(self):
        o,a,p,s=self.setup_capsule('absence');cid=p.manifest['capsule']
        backup=Path(self.tmp.name)/'prior.db';shutil.copy2(s.engine.path,backup)
        self.move(s,p,5);s.submit(cid,*self.evidence(p,a))
        for url in CUSTODIANS[:2]:
            with self.assertRaises(ValueError):request(url+'/release',release_request(p.manifest,{'fake':True}))
        shutil.copy2(backup,s.engine.path)
        self.move_clock_only(11);s.engine.tick(self.base+11);s.engine.authorise(cid)
        self.move_clock_only(16);s.engine.tick(self.base+16);decision=s.engine.authorise(cid)
        request(WITNESS+'/test-rewrite',{'snapshot':s.engine.export(cid)},TOKENS[0])
        for url in CUSTODIANS[:2]:
            with self.assertRaises(ValueError):request(url+'/release',release_request(p.manifest,decision))
        # The uninformed third service trusts the compromised witness but cannot
        # supply a sufficient quorum by itself.
        one=request(CUSTODIANS[2]+'/release',release_request(p.manifest,decision))
        with self.assertRaises(ValueError):recover(p.manifest,p.ciphertext,[one])

    def test_P_grace_starts_at_latest_possible_observation(self):
        o,a,p,s=self.council();cid=p.manifest['capsule']
        request(WITNESS+'/test-clock',{'now':self.base,'upper':self.base+2},TOKENS[0])
        self.assertIsNone(s.authorise(cid))
        self.move(s,p,5)
        # Endpoint-based grace would release here; full observation uncertainty
        # requires lower >= observed_upper + grace, hence at least t=7.
        self.assertIsNone(s.authorise(cid));self.refuse(p)
        self.move(s,p,7);decision=s.authorise(cid);self.assertIsNotNone(decision)
        self.assertEqual(recover(p.manifest,p.ciphertext,self.get_shares(p,decision)),self.plaintexts[cid])

    def test_K_lost_witness_ack_and_incomplete_provisioning(self):
        o,a,p,s=self.setup_capsule();cid=p.manifest['capsule']
        msg,sig=self.evidence(p,a)
        with self.assertRaises(Exception):s.submit(cid,msg,sig,lose_ack=True)
        retry=s.submit(cid,msg,sig);self.assertTrue(retry['local']['duplicate'])
        self.assertEqual(sum(f['kind']=='ACCEPTED' for f in s.engine.export(cid)['events']),1)
        o,a,p,s=self.setup_capsule(ready=False);cid=p.manifest['capsule']
        with self.assertRaises(RuntimeError):provision(p,WITNESS,CUSTODIANS,TOKENS,fail_after=1)
        with self.assertRaises(ValueError):s.install(p)
        # Idempotent retry resumes the same share enrollment, not a new key.
        provision(p,WITNESS,CUSTODIANS,TOKENS)
        s.publish(cid);s.command(cid,o,'ARMED')
        self.refuse(p)

    def test_L_enrollment_ack_loss(self):
        o,a,p,s=self.setup_capsule(ready=False)
        with self.assertRaises(ValueError):provision(p,WITNESS,CUSTODIANS,TOKENS,fault_enrollment=0)
        provision(p,WITNESS,CUSTODIANS,TOKENS);s.install(p);s.command(p.manifest['capsule'],o,'ARMED')
        self.refuse(p)


    def test_M_recovery_isolation_at_witness(self):
        o,a,p,s=self.setup_capsule('absence')
        other,b,q,t=self.setup_capsule('absence')
        self.move(s,p,11,outage=True)
        self.move_clock_only(11,healthy=True);s.command(p.manifest['capsule'],o,'RECOVERED')
        t.engine.tick(self.base+11)
        with self.assertRaises(ValueError):t.publish(q.manifest['capsule'])
        status=request(WITNESS+'/bundle?capsule='+q.manifest['capsule']+'&nonce=isolation')['status']['message']
        self.assertTrue(status['blocked'])
        t.command(q.manifest['capsule'],other,'RECOVERED')
        status=request(WITNESS+'/bundle?capsule='+q.manifest['capsule']+'&nonce=recovered')['status']['message']
        self.assertFalse(status['blocked'])

    def test_N_prepared_authorisation_is_not_external_permission(self):
        o,a,p,s=self.council();cid=p.manifest['capsule']
        s.authorise(cid);self.move(s,p,5)
        local=s.engine.authorise(cid);self.assertIsNotNone(local)
        # Simulate crash before witness publication. Custody refuses the local claim.
        self.refuse(p,local)
        s.restore_projection(p.manifest);s.command(cid,o,'DISARMED')
        with self.assertRaises(ValueError):request(WITNESS+'/publish',self._append_local_claim(s.engine.export(cid),local))
        self.refuse(p,local)

    def _append_local_claim(self,snapshot,decision):
        snapshot=copy.deepcopy(snapshot);decision=copy.deepcopy(decision)
        decision['seq']=len(snapshot['events'])+1;decision['prev']=snapshot['head'];decision['data']['snapshot']=snapshot['head']
        snapshot['events'].append(decision);snapshot['head']=digest(decision)
        return snapshot


class ClockAndDurability(unittest.TestCase):
    def test_M_real_clock_and_faults(self):
        actual=Clock();sample=actual.sample();self.assertLessEqual(sample['lower'],time.time_ns()//1_000_000_000);self.assertTrue(sample['healthy'])
        for wall_delta,mono_delta in ((-2000,1000),(5000,1000),(31000,31000),(1000,-1000)):
            values=[100_000_000_000,50_000_000_000]
            c=Clock(wall=lambda:values[0],mono=lambda:values[1]);c.sample()
            values[0]+=wall_delta*1_000_000;values[1]+=mono_delta*1_000_000
            self.assertFalse(c.sample()['healthy'])
        c=Clock(sample);self.assertFalse(c.sample()['healthy']);c.recover();self.assertTrue(c.sample()['healthy'])
        values=[100_000_000_000,50_000_000_000];c=Clock(wall=lambda:values[0],mono=lambda:values[1]);c.sample()
        for _ in range(6):values[0]+=1_200_000_000;values[1]+=1_000_000_000;c.sample()
        self.assertFalse(c.sample()['healthy']) # cumulative, not merely per-sample drift

    def test_N_process_crashes_at_payload_and_database_boundaries(self):
        # Actual child exits during the transaction, then reopen the SQLite database.
        for stage,exists in (('payload',False),('before_commit',False),('after_commit',True)):
            root=Path(tempfile.mkdtemp(dir='/tmp',prefix='otherwise-crash-'))
            try:
                program="""import sys
sys.path.insert(0,'scripts')
from make_vectors02 import policy
from Engine.store import Engine
_,p=policy();Engine(sys.argv[1]).import_encrypted('crash',p,b'crash fixture',crash_at=sys.argv[2])
"""
                proc=subprocess.run(['python','-c',program,str(root),stage]);self.assertIn(proc.returncode,(71,72,73))
                from Engine.store import Engine
                e=Engine(root)
                with e.connect() as db:self.assertEqual(bool(db.execute('SELECT count(*) FROM capsules').fetchone()[0]),exists)
                self.assertEqual(len(list((root/'payloads').glob('*.aes'))),1)
                self.assertFalse((root/'keys').exists())
                if exists:self.assertEqual(e.export('crash')['events'][0]['kind'],'CREATED')
            finally:shutil.rmtree(root)

    def test_O_real_observation_pause_and_recovery(self):
        import sys
        sys.path.insert(0,'scripts')
        from make_vectors02 import identities,policy,owner
        from Engine.store import Engine
        with tempfile.TemporaryDirectory() as root:
            state=State(Path(root)/'witness','witness')
            values=[100_000_000_000,50_000_000_000]
            state.clock=Clock(wall=lambda:values[0],mono=lambda:values[1],radius_ms=0)
            state.elapsed=lambda:values[1]/1e9
            keys,p=policy('absence',100);cid='real-observation'
            ciphertext=b'real-clock synthetic ciphertext';ref=hashlib.sha256(ciphertext).hexdigest()
            pub=[k.public_key().public_bytes_raw().hex() for k in keys]
            manifest={'v':2,'capsule':cid,'epoch':1,'policy':p,'commitment':digest(p),'payload':ref,'algorithm':'AES-128-GCM','custody':{'scheme':'shamir-pycryptodome-128','k':2,'n':3,'keys':{str(i+1):pub[i+4] for i in range(3)}},'witness':state.public,'clock':{'profile':'witness-observed-v2','outage':'withhold-and-restart-grace'}}
            state.register({'manifest':manifest,'signature':sign(keys[0],manifest)})
            receipts=[]
            for i in range(3):
                msg={'v':2,'action':'ENROLLED','manifest':digest(manifest),'index':i+1,'public':pub[i+4]}
                receipts.append({'message':msg,'signature':sign(keys[i+4],msg)})
            state.ready({'capsule':cid,'receipts':receipts})
            e=Engine(Path(root)/'operator')
            with e.transaction() as db:db.execute('UPDATE clock SET now=100')
            e.import_encrypted(cid,p,ciphertext);state.publish(e.export(cid));owner(e,cid,keys[0],'ARMED');state.publish(e.export(cid))
            # The witness clock runs normally while app heartbeats disappear for
            # entire check-in windows. This is distinct from a stopped clock.
            for _ in range(22):
                values[0]+=1_000_000_000;values[1]+=1_000_000_000;state.sample()
            e.tick(122)
            with self.assertRaises(ValueError):state.publish(e.export(cid))
            self.assertTrue(state.bundle(cid,'pause')['status']['message']['blocked'])
            owner(e,cid,keys[0],'RECOVERED')
            # Reconcile prepared local CLOCK + RECOVERED together at current time.
            state.publish(e.export(cid))
            self.assertFalse(state.bundle(cid,'recover')['status']['message']['blocked'])
            e.authorise(cid);state.publish(e.export(cid))
            values[0]+=5_000_000_000;values[1]+=5_000_000_000
            e.tick(127);e.authorise(cid);state.publish(e.export(cid))
            self.assertTrue(validate_snapshot(e.export(cid))['authorised'])

    def test_P_clock_interval_and_restored_state(self):
        values=[110_000_000_000,50_000_000_000]
        c=Clock(wall=lambda:values[0],mono=lambda:values[1],radius_ms=1000)
        sample=c.sample()
        self.assertEqual((sample['lower'],sample['upper']),(109,111))
        # No claim of an exact t=110 deadline is justified by this interval.
        self.assertGreater(sample['upper'],110)
        saved=dict(sample);values[0]=100_000_000_000
        restored=Clock(saved,wall=lambda:values[0],mono=lambda:values[1])
        self.assertFalse(restored.sample()['healthy'])
        with tempfile.TemporaryDirectory() as root:
            state=State(root,'witness');public=state.public;state.sample();state.db.close()
            reopened=State(root,'witness');self.assertEqual(reopened.public,public)
            self.assertFalse(reopened.sample()['healthy'])

    def test_Q_recovery_signatures_bind_current_head(self):
        import sys
        sys.path.insert(0,'scripts')
        from make_vectors02 import policy,owner
        from Engine.store import Engine
        with tempfile.TemporaryDirectory() as root:
            keys,p=policy('absence');e=Engine(root);cid='recovery-replay'
            e.import_encrypted(cid,p,b'recovery fixture');owner(e,cid,keys[0],'ARMED');e.tick(11,outage=True)
            snapshot=e.export(cid)
            msg={'v':2,'capsule':cid,'commitment':snapshot['commitment'],'action':'RECOVERED','head':snapshot['head']}
            signature=sign(keys[0],msg);e.owner_command(cid,'RECOVERED',signature,context={'head':snapshot['head']})
            e.tick(12,outage=True)
            with self.assertRaises(ValueError):e.owner_command(cid,'RECOVERED',signature,context={'head':snapshot['head']})
            self.assertFalse(e.export(cid)['healthy'])
