import base64,copy,json,os,tempfile,unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Engine.protocol import digest,sign
from Bounded.wire import atomic_json,request
from Available.proofs import operation
from LastWord.proofs import registry,scope,value,proposal,prepared,finality,vote_message,contribution_context,CAPABILITIES
from LastWord.recipient import verify
from LastWord.client import Client
from Honest import crypto
from helpers import W,K,A,TOKEN,configured,ready,move
from scheduler import Lab
LEDGER=[]
def record_case(name,classification,initial,schedule,output):
    LEDGER.append({'scenario':name,'classification':classification,'initial_state':initial,'participant_configuration':'four fixed witnesses, f<=1, prepare3/commit3; independent custody2/3 AND authority2/3','schedule':schedule,'observed':output})
    atomic_json('/recovery/finality08.json',json.loads(json.dumps(LEDGER)))

class FinalityLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.trust,cls.c=configured();cls.keys={d:crypto.dealer() for d in ('custody','authority')}
    def new(self,rounds=1):
        k=self.c.draft(rounds,10);self.c.prepare(k,self.keys);self.c.arm(k);return k
    def release_candidate(self):
        k=self.new();move(k,16);e=self.c.evaluate(k);self.assertTrue(e['policy_satisfied']);self.assertFalse(e['proof_authorises_release']);return k,e['evidence_certificate']
    def lab(self,k,d):
        # Private test extraction signs only for the deterministic synthetic scheduler.
        keys={i:Ed25519PrivateKey.from_private_bytes(bytes.fromhex(request(W[i-1]+'/seed08',{'capability':TOKEN})['seed'])) for i in range(1,5)}
        return Lab(k['custody08'],keys,d)
    def config(self,k):return {'registry':k['custody08'],'ciphertext':k['ciphertext'],'recipient_seed':k['recipient_seed']}
    def test_A_historical_window_final_disarm_succeeds(self):
        k=self.new(2);self.c.checkin(k,'1');move(k,16);m=k['manifest']['message']
        for u in W:request(u+'/finalise',{'capsule':m['capsule'],**m['slots'][0]})
        self.assertFalse(self.c.evaluate(k)['policy_satisfied']);result=self.c.disarm(k);self.assertEqual(result['state'],'DISARM_COMMITTED')
        with self.assertRaises(Exception):self.c.arm(k)
        record_case('A: Attack V corrected','Prevented',{'registry':k['custody08'],'first_window':'PRESENT_FINAL','later_window':'OPEN','policy_satisfied':False},[{'event':'owner disarm'}],result)
    def test_B_before_commitment(self):
        k,ev=self.release_candidate();r=self.c.make_value(k,'RELEASE',ev);d=self.c.make_value(k,'DISARM')
        with tempfile.TemporaryDirectory() as td:
            lab=self.lab(k,td);fin=lab.round(d);self.assertEqual(finality(k['custody08'],fin)['kind'],'DISARM');self.assertIsNone(lab.round(r));record_case('B: disarm ordered before release','Prevented',{'release_policy_proof':ev,'terminal':None},lab.trace,{'finality':fin,'release_allowed':False})
    def test_C_after_commitment(self):
        k,ev=self.release_candidate();fin=self.c.commit_release(k,ev);self.assertEqual(finality(k['custody08'],fin)['kind'],'RELEASE')
        with self.assertRaises(Exception):self.c.disarm(k)
        package=self.c.collect_release(k,fin);self.assertIn('synthetic',verify(self.config(k),package)['plaintext'])
        record_case('C: disarm after release commitment','Successful',{'registry':k['custody08']},[{'event':'release consensus'},{'event':'late owner disarm rejected'},{'event':'cryptographic disclosure'}],{'finality':fin,'package':package})
    def test_D_opposite_delivery_orders(self):
        k,ev=self.release_candidate();r=self.c.make_value(k,'RELEASE',ev);d=self.c.make_value(k,'DISARM')
        with tempfile.TemporaryDirectory() as td:
            lab=self.lab(k,td)
            # One Byzantine leader equivocates; honest voters never double-prepare.
            def p(v):return {'message':{'scope':scope(k['custody08']),'kind':'PROPOSAL','view':0,'value':v,'changes':[],'leader':1},'signature':sign(lab.keys[1],{'scope':scope(k['custody08']),'kind':'PROPOSAL','view':0,'value':v,'changes':[],'leader':1})}
            pr,pd=p(r),p(d);ra=[lab.event(i,'prepare',pr) for i in (2,3)];da=[lab.event(i,'prepare',pd) for i in (4,)];self.assertIsNone(lab.event(2,'prepare',pd));self.assertIsNone(lab.event(4,'prepare',pr))
            rb={'message':vote_message(k['custody08'],'PREPARE',0,r,1),'signature':sign(lab.keys[1],vote_message(k['custody08'],'PREPARE',0,r,1))};pc={'view':0,'value':r,'prepares':[rb,*ra]};cs=[lab.event(i,'commit_vote',pc) for i in (2,3,4)];fin={'v':8,'registry':digest(k['custody08']),'view':0,'value':r,'prepares':pc['prepares'],'commits':cs};finality(k['custody08'],fin)
            changes=[lab.event(i,'view_change',1) for i in (2,3,4)];pnext=lab.event(2,'propose',1,d,changes);self.assertEqual(pnext['message']['value'],r)
            record_case('D: opposite delivery / equivocation','Prevented',{'registry':k['custody08'],'byzantine':1},lab.trace,{'only_compatible_finality':fin,'new_view_preserves':digest(r)})
    def test_E_partition_then_view_change(self):
        k,ev=self.release_candidate();r=self.c.make_value(k,'RELEASE',ev);d=self.c.make_value(k,'DISARM')
        with tempfile.TemporaryDirectory() as td:
            lab=self.lab(k,td);pr=lab.event(1,'propose',0,r,[]);self.assertIsNotNone(lab.event(1,'prepare',pr));self.assertIsNotNone(lab.event(2,'prepare',pr))
            # The other partition cannot gather3; no terminal state exists in either partition.
            self.assertTrue(all(x.s['terminal'] is None for x in lab.nodes.values()));changes=[lab.event(i,'view_change',1) for i in (1,2,3,4)];fin=lab.round(d,1,changes=changes);self.assertEqual(finality(k['custody08'],fin)['kind'],'DISARM')
            self.assertIsNone(lab.event(3,'prepare',pr));record_case('E: 2/2 partition and healing','Recoverable',{'partition':[[1,2],[3,4]],'registry':k['custody08']},lab.trace,{'during_partition':'NO_DECISION','after_heal':fin})
    def test_F_pending_lock_not_a_cancellation_ack(self):
        k,ev=self.release_candidate();r=self.c.make_value(k,'RELEASE',ev);d=self.c.make_value(k,'DISARM')
        with tempfile.TemporaryDirectory() as td:
            lab=self.lab(k,td);p=lab.event(1,'propose',0,r,[]);ps=[lab.event(i,'prepare',p) for i in (1,2,3)];pc={'view':0,'value':r,'prepares':ps}
            for i in (1,2):lab.event(i,'commit_vote',pc)
            self.assertTrue(all(n.s['terminal'] is None for n in lab.nodes.values()));changes=[lab.event(i,'view_change',1) for i in (1,2,3)];fin=lab.round(d,1,changes=changes)
            self.assertEqual(finality(k['custody08'],fin)['kind'],'RELEASE');record_case('F: pending prepared locks constrain cancellation','Detected',{'registry':k['custody08'],'certificate_known_to_creator':False},lab.trace,{'outcome':fin,'meaning':'a submitted disarm before certificate delivery is not guaranteed to win; Model A, not last-packet priority'})
    def test_G_delayed_presence(self):
        k=self.new();m=k['manifest']['message'];from Available.client import evidence
        proof=evidence(k['manifest'],self.c.private(k),'presence','1');receipts=[request(u+'/observe',{'capsule':m['capsule'],'proof':proof}) for u in W[:3]]
        move(k,16);request(W[3]+'/finalise',{'capsule':m['capsule'],**m['slots'][0]});self.c.distribute(k,receipts);self.assertFalse(self.c.evaluate(k)['policy_satisfied'])
        never=self.new();local=evidence(never['manifest'],self.c.private(never),'presence','1');move(never,16);self.assertTrue(self.c.evaluate(never)['policy_satisfied'])
        record_case('G: delayed accepted vs locally created presence','Recoverable',{'accepted_manifest':k['manifest'],'local_only_manifest':never['manifest']},[{'event':'three durable observations before cutoff, copied later','receipts':receipts},{'event':'separate proof never submitted','proof':local}],{'accepted_prevents_policy':True,'never_submitted_does_not':True})
    def test_H_forged_saas_and_direct_path(self):
        k=self.new();bad=self.c.make_value(k,'DISARM');bad['command']['signature']='00'*64
        with self.assertRaises(Exception):value(k['custody08'],bad)
        result=self.c.disarm(k);stale={'success':True,'state':'DISARM_COMMITTED'}
        with self.assertRaises(Exception):finality(k['custody08'],stale)
        record_case('H: SaaS censorship / false acknowledgement','Recoverable',{'registry':k['custody08'],'operator_has':'public data only'},[{'event':'drop signed disarm; fabricate success','reply':stale},{'event':'independent direct submission'}],{'direct_result':result,'censorship':'not prevented; direct path required','stale_nonce':'fresh signed status challenge required'})
    def test_I_J_actual_restart_and_membership(self):
        k,ev=self.release_candidate();fin=self.c.commit_release(k,ev);cid=k['manifest']['message']['capsule']
        with self.assertRaises(Exception):request(W[0]+'/recovery-challenge08',{'capsule':cid})
        # Service instrumentation kills the process after a durable terminal write.
        with self.assertRaises(Exception):request(W[0]+'/crash08',{'capsule':cid,'certificate':fin,'capability':TOKEN},TOKEN)
        ready(W[:1]);repaired=self.c.recover_witness(k,1);self.assertTrue(repaired['recovered']);self.assertEqual(finality(k['custody08'],repaired['terminal'])['kind'],'RELEASE')
        self.assertIn('synthetic',verify(self.config(k),self.c.collect_release(k,fin))['plaintext'])
        altered=copy.deepcopy(k['custody08']);altered['message']['committee']['epoch']=2;altered['signature']=sign(self.c.private(k),altered['message'])
        with self.assertRaises(Exception):registry(altered)
        record_case('I/J: durable crash recovery and frozen membership','Recoverable',{'registry':k['custody08'],'fin':fin},[{'event':'actual process exit after terminal commit'},{'event':'fresh three-peer recovery without owner signature'},{'event':'attempt epoch2 during pending/committed instance'}],{'recovered':repaired,'replacement':'rejected; no unsafe hot-swap'})
    def test_K_L_split_and_combined(self):
        k=self.new();c=k['custody07']['message'];states={d:[request(u+'/lab-export',{'capsule':k['manifest']['message']['capsule'],'all':True},TOKEN) for u in urls] for d,urls in [('custody',K),('authority',A)]}
        from Missing.protocol import wrap_context
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from Available.client import aad
        def component(d,owned):
            shared=crypto.combine_points([(i,crypto.number(s['share'])*crypto.point(c['wraps'][d]['R'])) for i,s in enumerate(owned[:2],1)]);return crypto.decrypt(crypto.derive(bytes.fromhex(crypto.encode(shared)),wrap_context(c,d)),c['wraps'][d]['wrapped'],wrap_context(c,d))
        x=component('custody',states['custody']);ct=base64.b64decode(k['ciphertext'])
        with self.assertRaises(Exception):AESGCM(x).decrypt(ct[:12],ct[12:],aad(k['manifest']['message']))
        with self.assertRaises(Exception):component('authority',states['custody'])
        y=component('authority',states['authority']);plain=AESGCM(bytes(a^b for a,b in zip(x,y))).decrypt(ct[:12],ct[12:],aad(k['manifest']['message']));self.assertIn(b'synthetic',plain)
        record_case('K/L: custody-only vs combined collusion','Successful',{'registry':k['custody08'],'policy_satisfied':False},[{'event':'extract all custody secrets: recover A only'},{'event':'extract authority threshold: recover B and bypass ordering'}],{'custody_alone':'insufficient','combined_plaintext':plain.hex(),'finality_certificate':None})
    def test_M_N_creator_gone_offline_recipient(self):
        k=self.new();config=self.config(k);worker=copy.deepcopy(k);worker.pop('owner_seed');worker.pop('recipient_seed');self.assertNotIn('owner_seed',worker)
        move(k,16)  # Logical test clock advances after the creator capability is removed from worker input.
        import subprocess
        with tempfile.TemporaryDirectory(dir='/recovery') as td:
            atomic_json(td+'/public.json',worker)
            child=subprocess.run(['python','-m','LastWord.worker','--kit',td+'/public.json','--out',td+'/package.json'],capture_output=True,text=True);self.assertEqual(child.returncode,0,child.stderr)
            package=json.loads(Path(td+'/package.json').read_text())
        fin=package['finality'];out=verify(config,package);self.assertTrue(out['verified_offline'])
        from Untrusted.vault import seal
        atomic_json('/recovery/recipient08.ovault',seal(config,os.environ['OTHERWISE_CREATOR_PASSPHRASE']));atomic_json('/recovery/portable08.json',package)
        late=self.c.make_value(k,'DISARM');self.assertEqual(finality(k['custody08'],self.c.order(k,late))['kind'],'RELEASE')
        typed=copy.deepcopy(package);typed['registry']['message']['committee']['epoch']=True
        with self.assertRaisesRegex(Exception,'pinned portable release scope'):verify(config,typed)
        bad=copy.deepcopy(package);bad['finality']['commits'][0]['signature']='00'*64
        with self.assertRaises(Exception):verify(config,bad)
        record_case('M/N: creator absent and returns after disclosure','Recoverable',{'registry':k['custody08'],'worker_secrets':'no creator or recipient secret'},[{'event':'policy evidence and terminal consensus relayed by independent worker'},{'event':'recipient verifies portable package offline'},{'event':'late disarm cannot undo plaintext'}],{'finality':fin,'package':package,'plaintext':out['plaintext'],'revocation':'cannot erase knowledge'})
    def test_O_rollback_and_conflicting_proofs(self):
        k,ev=self.release_candidate();r=self.c.make_value(k,'RELEASE',ev);d=self.c.make_value(k,'DISARM')
        with tempfile.TemporaryDirectory() as td:
            lab=self.lab(k,td);saved=copy.deepcopy(lab.nodes[4].s);fin=lab.round(r);lab.nodes[4].s=saved;lab.persist(4,saved);lab.restart(4);self.assertIsNone(lab.event(4,'prepare',lab.nodes[1].s['proposals']['0']))
            self.assertIsNotNone(lab.recover(4,[1,2,3]));self.assertEqual(lab.nodes[4].s['terminal']['value'],r);self.assertIsNone(lab.round(d,1,changes=[]))
            record_case('O: old snapshot / authenticated recovery','Recoverable',{'registry':k['custody08'],'restored_replica':4},lab.trace,{'terminal':fin,'history_rewrite':False})
    def test_P_malformed_crypto_quorums(self):
        k,ev=self.release_candidate();fin=self.c.commit_release(k,ev)
        for u in (K[0],A[0]):request(u+'/lab-fault',{'mode':'bad-proof'},TOKEN)
        try:
            package=self.c.collect_release(k,fin);out=verify(self.config(k),package);self.assertIn('synthetic',out['plaintext']);self.assertEqual(len(out['invalid_contributions']),2)
        finally:
            for u in (K[0],A[0]):request(u+'/lab-fault',{'mode':'honest'},TOKEN)
        record_case('P: correctly signed invalid partial minority','Recoverable',{'registry':k['custody08']},[{'event':'one holder in each domain signs an encrypted invalid proof'}],out)
    def test_Q_provisioning_related_entropy_and_commitments(self):
        from Missing.protocol import wrap_context
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from Available.client import aad
        key,shares=crypto.dealer();linked={'v':6,'scheme':key['scheme'],'k':2,'n':3,'X':crypto.encode(2*crypto.point(key['X'])),'Y':{i:crypto.encode(2*crypto.point(y)) for i,y in key['Y'].items()}};other={i:crypto.hx(2*crypto.number(s)%crypto.Q) for i,s in shares.items()}
        k=self.c.draft(1,10);self.c.prepare(k,{'custody':(key,shares),'authority':(linked,other)});self.c.arm(k);c=k['custody07']['message']
        owned=[request(u+'/lab-export',{'capsule':k['manifest']['message']['capsule']},TOKEN) for u in K[:2]];parts={}
        for d in ('custody','authority'):
            pts=[(i,(crypto.number(s['share'])*(2 if d=='authority' else 1)%crypto.Q)*crypto.point(c['wraps'][d]['R'])) for i,s in enumerate(owned,1)];shared=crypto.combine_points(pts);parts[d]=crypto.decrypt(crypto.derive(bytes.fromhex(crypto.encode(shared)),wrap_context(c,d)),c['wraps'][d]['wrapped'],wrap_context(c,d))
        ct=base64.b64decode(k['ciphertext']);plain=AESGCM(bytes(x^y for x,y in zip(parts['custody'],parts['authority']))).decrypt(ct[:12],ct[12:],aad(k['manifest']['message']));self.assertIn(b'synthetic',plain)
        # Reusing the exact same random generation / cross-domain key is rejected.
        with self.assertRaises(Exception):self.c.prepare(self.c.draft(1,10),{'custody':(key,shares),'authority':(key,shares)})
        bad=copy.deepcopy(k['custody08']);bad['message']['split']['message']['domains']['authority']['key']['X']='04'+'00'*64
        with self.assertRaises(Exception):registry(bad)
        reg=k['custody08'];e={'v':8,'registry':digest(reg),'domain':'custody','index':1,'share':'01'*32,'provider':k['manifest']['message']['custody']['keys']['1']}
        with self.assertRaises(Exception):request(K[0]+'/enroll08',{'registry':reg,'share':'01'*32,'enrollment':{'message':e,'signature':sign(self.c.private(k),e)}})
        record_case('Q: Attack U and provisioning boundary','Successful',{'registry':reg,'known_private_relation':2},[{'event':'malicious dealer / repeated entropy'},{'event':'cross-domain identical keys rejected'},{'event':'substituted public key and incorrect share rejected'},{'event':'custody shares derive related authority shares'}],{'premature_plaintext':plain.hex(),'fix':'independent secret generation and administration still required; DKG not claimed','shared_backup':'both indispensable capabilities exposed equals combined-domain compromise'})
    def test_R_vote_fsync_crashes(self):
        outcomes=[]
        for phase in ('before-vote','after-vote'):
            k,ev=self.release_candidate();cid=k['manifest']['message']['capsule'];v=self.c.make_value(k,'RELEASE',ev);p=request(W[0]+'/propose08',{'capsule':cid,'view':0,'value':v,'changes':[]});ps=[request(u+'/prepare08',{'capsule':cid,'proposal':p}) for u in W];pc={'view':0,'value':v,'prepares':ps}
            with self.assertRaises(Exception):request(W[0]+'/commit-vote08',{'capsule':cid,'prepared':pc,'fault':phase,'capability':TOKEN})
            ready(W[:1]);raw=request(W[0]+'/log08',{'capsule':cid,'capability':TOKEN});self.assertEqual('COMMIT:0' in raw['votes'],phase=='after-vote');self.assertTrue(raw['quarantine']);self.c.recover_witness(k,1)
            fin=self.c.commit_release(k,ev);self.assertEqual(finality(k['custody08'],fin)['kind'],'RELEASE');outcomes.append({'phase':phase,'durable_before_recovery':raw,'eventual_finality':fin})
        record_case('R: actual before/after durable commit vote crashes','Recoverable',{'timing':'explicit crash hooks, no sleeps'},[{'event':'exit71 before SQL vote commit'},{'event':'exit72 after SQL FULL commit before response'},{'event':'fresh three-peer recovery'}],outcomes)
    def test_S_stale_status_and_creator_cli(self):
        k=self.new();reg=k['custody08'];cid=k['manifest']['message']['capsule'];key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(request(W[0]+'/seed08',{'capability':TOKEN})['seed']));original=self.c.transport
        class Stale:
            def call(inner,url,body=None):
                if url==W[0]+'/status08':
                    q={'v':8,'kind':'DECISION_STATUS','capsule':cid,'registry':digest(reg),'nonce':'00'*32,'witness':1,'state':{'view':0,'prepared':None,'terminal':None,'quarantine':False}}
                    return {'message':q,'signature':sign(key,q)}
                return original.call(url,body)
        try:
            self.c.transport=Stale();statuses=self.c.statuses(k);self.assertTrue(statuses['sufficient']);self.assertEqual(len(statuses['invalid']),1)
        finally:self.c.transport=original
        import subprocess
        with tempfile.TemporaryDirectory(dir='/recovery') as td:
            atomic_json(td+'/trust.json',self.trust)
            def cli(action,*extra):
                p=subprocess.run(['python','-m','LastWord.cli','--vault',td+'/creator.ovault','--trust',td+'/trust.json',action,*extra],capture_output=True,text=True);self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout)
            cli('create','--rounds','2','--seconds','10');cli('arm');self.assertTrue(cli('checkin','--challenge','1')['accepted']);self.assertFalse(cli('policy')['proof_authorises_release']);self.assertEqual(cli('disarm')['state'],'DISARM_COMMITTED')
        record_case('S: stale head / standalone creator','Recoverable',{'registry':reg},[{'event':'one witness signs an old status challenge'},{'event':'remaining fresh quorum accepted'},{'event':'actual child-process Solo lifecycle CLI'}],{'fresh_sources':3,'private_seed_in_SaaS':False,'cancellation':'terminal certificate verified'})
    def test_T_byzantine_view_change_does_not_poison_quorum(self):
        k=self.new();reg=k['custody08'];cid=k['manifest']['message']['capsule'];key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(request(W[0]+'/seed08',{'capability':TOKEN})['seed']));original=self.c.transport
        class Byzantine:
            def call(inner,url,body=None):
                if url==W[0]+'/status08':
                    q={'v':8,'kind':'DECISION_STATUS','capsule':cid,'registry':digest(reg),'nonce':body['nonce'],'witness':1,'state':{'view':64,'prepared':None,'terminal':None,'quarantine':False}};return {'message':q,'signature':sign(key,q)}
                if url==W[0]+'/propose08':return {'claimed_success':True}
                if url==W[0]+'/view-change08':
                    q={**scope(reg),'kind':'VIEW_CHANGE','view':body['view'],'prepared':None,'witness':1};q['registry']='00'*32;return {'message':q,'signature':sign(key,q)}
                return original.call(url,body)
        try:
            self.c.transport=Byzantine();result=self.c.disarm(k);self.assertEqual(result['state'],'DISARM_COMMITTED');self.assertGreater(result['certificate']['view'],0)
        finally:self.c.transport=original
        record_case('T: Byzantine leader / high head / invalid view-change minority','Prevented',{'registry':reg,'Byzantine':1},[{'event':'lie about view64'},{'event':'bad proposal'},{'event':'correctly signed wrong-scope view change'},{'event':'three valid peers and next leader progress'}],result)
    def test_U_committed_release_survives_all_witness_routes_lost(self):
        k,ev=self.release_candidate();fin=self.c.commit_release(k,ev);original=self.c.transport
        class NoWitness:
            def call(inner,url,body=None):
                if any(url.startswith(w+'/') for w in W):raise ValueError('every witness route unavailable')
                return original.call(url,body)
        try:
            self.c.transport=NoWitness();retained=self.c.retained_decision(k);self.assertEqual(finality(k['custody08'],retained)['kind'],'RELEASE');out=verify(self.config(k),self.c.collect_release(k,retained));self.assertTrue(out['verified_offline'])
        finally:self.c.transport=original
        record_case('U: retained commitment survives absent witness/creator/SaaS routes','Recoverable',{'registry':k['custody08'],'committed':True},[{'event':'valid terminal certificate retained at independent key holders'},{'event':'deny every witness route'},{'event':'retrieve and independently verify certificate, collect ciphertext-specific capabilities'}],out)
    def test_V_no_policy_only_or_cross_commitment_release(self):
        k,ev=self.release_candidate();fake={'v':8,'registry':digest(k['custody08']),'view':0,'value':self.c.make_value(k,'RELEASE',ev),'prepares':[],'commits':[]}
        for u in K+A:
            with self.assertRaises(Exception):request(u+'/partial08',{'capsule':k['manifest']['message']['capsule'],'registry':k['custody08'],'finality':fake,'context':{},'requirements':CAPABILITIES})
            with self.assertRaises(Exception):request(u+'/partial07',{'capsule':k['manifest']['message']['capsule']})
        d=self.c.disarm(k)
        with self.assertRaises(Exception):self.c.commit_release(k,ev)
        record_case('V: policy proof cannot bypass terminal commitment','Prevented',{'registry':k['custody08'],'policy_evidence':ev,'release_authorised':False},[{'event':'request capability with no commit votes'},{'event':'attempt legacy partial downgrade'},{'event':'commit disarm then replay policy proof'}],{'disarm':d,'capability_issued':False})
