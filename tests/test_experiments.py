import copy
import itertools
import json
import random
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from Engine.store import Engine
from Engine.protocol import sign, digest, validate_policy
from Engine.evaluator import evaluate
from Engine.independent import interpret, release_eligible
from helpers import fixture, command, proof


class Experiments(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.e=Engine(self.tmp.name)
    def tearDown(self): self.tmp.cleanup()
    def setup_capsule(self,kind='attestation',count=3,expression=None,cid='capsule'):
        owner,auth,p=fixture(kind,count,expression)
        self.e.create(cid,p); command(self.e,cid,owner,'ARMED')
        return owner,auth,p
    def compare(self,cid='capsule'):
        s=self.e.export(cid); reference=evaluate(s['policy'],s['events'],s['now'])
        self.assertEqual(reference,interpret(json.loads(json.dumps(s))))
        return reference
    def decide(self,cid):
        expected=release_eligible(self.e.export(cid))
        actual=self.e.authorise(cid)
        self.assertEqual(actual is not None,expected)
        return actual
    def satisfy(self,p,a,cid='capsule'):
        for i in range(2): self.assertTrue(self.e.submit(cid,*proof(p,cid,a[i],i))['accepted'])
    def release(self,cid='capsule'):
        self.assertIsNone(self.decide(cid)); now=self.e.export(cid)['now']
        self.e.tick(now+5); self.assertIsNotNone(self.decide(cid))

    def test_A_last_second_witness(self):
        owner,a,p=self.setup_capsule('absence',1)
        self.e.tick(10)
        self.assertIsNone(self.decide('capsule'))
        m,s=proof(p,'capsule',a[0])
        self.assertTrue(self.e.submit('capsule',m,s)['accepted'])
        self.e.tick(11); self.assertFalse(self.compare()['satisfied'])
        self.e.tick(20)
        self.assertTrue(self.e.submit('capsule',*proof(p,'capsule',a[0],ident='second',challenge='round-2'))['accepted'])
        self.e.tick(21); self.assertFalse(self.compare()['satisfied'])
        self.assertIsNone(self.decide('capsule'))
        # Received at the edge but only presented to authority after boundary.
        owner,a,p=self.setup_capsule('absence',1,cid='late')
        self.assertFalse(self.e.submit('late',*proof(p,'late',a[0]))['accepted'])
        self.release('late')

    def test_B_competing_executors(self):
        o,a,p=self.setup_capsule(); self.satisfy(p,a); self.decide('capsule'); self.e.tick(5)
        with ThreadPoolExecutor(max_workers=8) as pool:
            decisions=list(pool.map(lambda _:Engine(self.tmp.name).authorise('capsule'),range(24)))
        self.assertEqual(len({digest(d) for d in decisions}),1)
        self.assertEqual(sum(e['kind']=='AUTHORISED' for e in self.e.export('capsule')['events']),1)

    def test_C_forgotten_receipt(self):
        o,a,p=self.setup_capsule(); msg,sig=proof(p,'capsule',a[0])
        first=self.e.submit('capsule',msg,sig); retry=self.e.submit('capsule',msg,sig)
        self.assertEqual(first['receipt'],retry['receipt']); self.assertTrue(retry['duplicate'])
        changed=copy.deepcopy(msg); changed['claim']=False
        with self.assertRaises(ValueError): self.e.submit('capsule',changed,sign(a[0][0],changed))
        self.assertEqual(sum(e['kind']=='ACCEPTED' for e in self.e.export('capsule')['events']),1)

    def test_D_dead_scheduler(self):
        o,a,p=self.setup_capsule('absence',1)
        self.e.tick(30,outage=True)
        self.e=Engine(self.tmp.name)
        self.assertIsNone(self.decide('capsule'))
        command(self.e,'capsule',o,'RECOVERED')
        self.assertIsNone(self.decide('capsule')); self.e.tick(34)
        self.assertIsNone(self.decide('capsule')); self.e.tick(35)
        self.assertIsNotNone(self.decide('capsule'))

    def test_E_double_release(self):
        o,a,p=self.setup_capsule(); self.satisfy(p,a); self.release()
        with self.assertRaises(RuntimeError): self.e.deliver('capsule',crash=True)
        self.e=Engine(self.tmp.name)
        self.assertEqual(self.e.deliver('capsule'),b'Otherwise test message')
        self.e.deliver('capsule')
        with self.e.connect() as db: self.assertEqual(db.execute('SELECT count(*) FROM inbox').fetchone()[0],1)
        self.assertEqual(sum(e['kind']=='RELEASED' for e in self.e.export('capsule')['events']),1)

    def test_F_emergency_disarm(self):
        # Both serial orders, then actual concurrent workers with transaction ordering.
        for first in ('disarm','release','race'):
            cid=first; o,a,p=self.setup_capsule(cid=cid); self.satisfy(p,a,cid)
            self.decide(cid); self.e.tick(self.e.export(cid)['now']+5)
            def disarm():
                try: command(self.e,cid,o,'DISARMED'); return True
                except ValueError: return False
            if first=='disarm': self.assertTrue(disarm()); self.assertIsNone(self.decide(cid))
            elif first=='release': self.decide(cid); self.assertFalse(disarm())
            else:
                with ThreadPoolExecutor(max_workers=2) as pool:
                    f=pool.submit(disarm); g=pool.submit(self.e.authorise,cid); f.result(); g.result()
            kinds={e['kind'] for e in self.e.export(cid)['events']}
            self.assertNotEqual('DISARMED' in kinds,'AUTHORISED' in kinds)

    def test_G_broken_clock(self):
        o,a,p=self.setup_capsule(); self.satisfy(p,a); self.decide('capsule')
        with self.assertRaises(ValueError): self.e.tick(-1)
        self.e.tick(80); self.assertFalse(self.e.export('capsule')['healthy'])
        self.assertIsNone(self.decide('capsule'))
        command(self.e,'capsule',o,'RECOVERED'); self.decide('capsule'); self.e.tick(85)
        self.assertIsNotNone(self.decide('capsule'))
        with self.assertRaises(ValueError): self.e.tick(84)

    def test_H_corrupted_history(self):
        for mutation in ('remove','alter','reorder','tail','policy'):
            cid=mutation; o,a,p=self.setup_capsule(cid=cid); self.satisfy(p,a,cid)
            with self.e.connect() as db:
                if mutation=='remove': db.execute('DELETE FROM events WHERE capsule=? AND seq=2',(cid,))
                elif mutation=='tail': db.execute('DELETE FROM events WHERE capsule=? AND seq=(SELECT max(seq) FROM events WHERE capsule=?)',(cid,cid))
                elif mutation=='policy': db.execute("UPDATE capsules SET policy=replace(policy,'THRESHOLD','OR') WHERE id=?",(cid,))
                elif mutation=='alter': db.execute("UPDATE events SET body=replace(body,'ARMED','DISARMED') WHERE capsule=? AND seq=2",(cid,))
                else: db.execute('UPDATE events SET seq=999 WHERE capsule=? AND seq=2',(cid,))
            with self.assertRaises(ValueError): self.decide(cid)

    def test_I_unreachable_creator(self):
        o,a,p=self.setup_capsule('absence',1)
        self.e.notify('capsule',False); self.assertFalse(self.compare()['satisfied'])
        self.e.tick(11); self.assertTrue(self.compare()['satisfied'])
        self.release() # This is permission under policy, not evidence of incapacity.
        self.assertEqual(self.e.deliver('capsule'),b'Otherwise test message')

    def test_J_independent_interpretation(self):
        rng=random.Random(701)
        for i in range(40):
            expr=rng.choice([{'op':'AND','args':['A',{'op':'OR','args':['B','C']}]},{'op':'THRESHOLD','k':2,'args':['A','B','C']},{'op':'OR','args':['A','B','C']}])
            cid='random-'+str(i); o,a,p=self.setup_capsule(expression=expr,cid=cid)
            for j in range(3):
                self.e.submit(cid,*proof(p,cid,a[j],j,claim=bool(rng.randrange(2)),until=900))
            for delta in (0,1,5,20):
                self.e.tick(self.e.export(cid)['now']+delta); self.compare(cid)

    def test_K_two_of_three_reordered_duplicates_contradictions(self):
        for permutation in itertools.permutations(range(3)):
            cid='order-'+''.join(map(str,permutation)); o,a,p=self.setup_capsule(cid=cid)
            for index in permutation:
                pair=proof(p,cid,a[index],index,claim=index!=2,until=900)
                self.e.submit(cid,*pair); self.e.submit(cid,*pair)
            self.assertTrue(self.compare(cid)['satisfied'])
            # C's contradictory evidence is scoped to C and does not veto A/B.
            self.e.submit(cid,*proof(p,cid,a[2],2,claim=True,until=900,ident='C-contradiction'))
            self.assertFalse(self.compare(cid)['contracts']['C'])
            self.release(cid)

    def test_L_revocation_expiry_stale_and_scope(self):
        o,a,p=self.setup_capsule(); self.satisfy(p,a)
        self.assertTrue(self.compare()['satisfied'])
        # Valid signature by A cannot satisfy B.
        m,s=proof(p,'capsule',a[0],index=1,ident='wrong-authority')
        self.assertFalse(self.e.submit('capsule',m,s)['accepted'])
        m={'v':1,'capsule':'capsule','commitment':digest(p),'action':'REVOKED','authority':a[0][1]}
        self.e.revoke('capsule',a[0][1],sign(o,m))
        self.assertFalse(self.compare()['satisfied']); self.assertIsNone(self.decide('capsule'))
        self.e.tick(60); self.e.tick(100)
        self.assertFalse(self.e.submit('capsule',*proof(p,'capsule',a[2],2))['accepted'])
        self.assertFalse(self.compare()['satisfied'])
        for t in range(160,1000,60): self.e.tick(t)
        self.e.tick(1000); self.assertFalse(self.compare()['satisfied'])

    def test_M_policy_immutability_and_expression_validation(self):
        o,a,p=self.setup_capsule()
        changed=copy.deepcopy(p); changed['expression']['k']=1
        with self.assertRaises(Exception): self.e.create('capsule',changed)
        for expression in ({'op':'THRESHOLD','k':0,'args':['A','B','C']},{'op':'OR','args':['A','A','B','C']}):
            changed=copy.deepcopy(p); changed['expression']=expression
            with self.assertRaises(ValueError): validate_policy(changed)
        with self.assertRaises(ValueError): self.e.owner_command('capsule','DISARMED','00'*64)

    def test_N_authenticated_encryption(self):
        o,a,p=self.setup_capsule(); self.satisfy(p,a); self.release()
        payload=next((self.e.root/'payloads').iterdir()); ciphertext=bytearray(payload.read_bytes()); ciphertext[-1]^=1; payload.write_bytes(ciphertext)
        with self.assertRaises(Exception): self.e.deliver('capsule')
        with self.e.connect() as db: self.assertEqual(db.execute('SELECT count(*) FROM inbox').fetchone()[0],0)

    def test_O_grace_cannot_bridge_truth_gap(self):
        o,a,p=fixture(expression={'op':'OR','args':['A','B','C']})
        p['contracts'][1]['kind']='absence'
        p['contracts'][1]['challenges']=[{'id':'round-1','open':0,'deadline':3}]
        self.e.create('capsule',p); command(self.e,'capsule',o,'ARMED')
        self.e.submit('capsule',*proof(p,'capsule',a[0],until=2))
        self.decide('capsule'); self.e.tick(5)
        self.assertTrue(self.compare()['satisfied'])
        self.assertIsNone(self.decide('capsule')) # A expires at 2; B starts at 4.
        self.e.tick(10); self.assertIsNotNone(self.decide('capsule'))

    def test_P_deadline_concurrent_presence(self):
        for i in range(12):
            cid='deadline-'+str(i); o,a,p=self.setup_capsule('absence',1,cid=cid)
            self.e.tick(10)
            with ThreadPoolExecutor(max_workers=2) as pool:
                f=pool.submit(self.e.submit,cid,*proof(p,cid,a[0]))
                g=pool.submit(self.e.authorise,cid)
                self.assertTrue(f.result()['accepted']); self.assertIsNone(g.result())
            self.e.tick(11); self.assertFalse(self.compare(cid)['satisfied'])
            self.assertIsNone(self.decide(cid))
            # Create next fixture at zero with its own authoritative database.
            if i<11:
                self.tmp.cleanup(); self.tmp=tempfile.TemporaryDirectory(); self.e=Engine(self.tmp.name)

    def test_Q_same_authority_scoped_to_multiple_contracts(self):
        o,a,p=fixture()
        p['contracts'][1]['authority']=a[0][1]
        self.e.create('capsule',p); command(self.e,'capsule',o,'ARMED')
        self.e.submit('capsule',*proof(p,'capsule',a[0]))
        self.assertEqual(self.compare()['contracts'],{'A':True,'B':False,'C':False})
        self.e.submit('capsule',*proof(p,'capsule',a[0],index=1))
        self.assertTrue(self.compare()['satisfied'])
        # Threshold counts contracts, not unique principals; independence is a policy requirement.

    def test_R_recovery_does_not_clear_other_owners_latch(self):
        first,a,p=self.setup_capsule('absence',1,cid='first')
        second,b,q=self.setup_capsule('absence',1,cid='second')
        self.e.tick(30,outage=True)
        command(self.e,'first',first,'RECOVERED')
        self.assertTrue(self.e.export('first')['healthy'])
        self.assertFalse(self.e.export('second')['healthy'])
        self.assertIsNone(self.decide('second'))
        self.e.tick(31)
        self.assertFalse(self.e.export('second')['healthy'])
        command(self.e,'second',second,'RECOVERED')
        self.assertTrue(self.e.export('second')['healthy'])
        self.release('second')

    def test_S_composed_contract_adversarial_matrix(self):
        for variant in ('stale-C','contradictory-C','revoked-C','revoked-B','expired-C','expired-B'):
            for order in itertools.permutations(range(3)):
                cid=variant+''.join(map(str,order)); self.e=Engine(self.tmp.name+'/'+cid)
                o,a,p=self.setup_capsule(cid=cid)
                for i in order:
                    until=0 if variant=='stale-C' and i==2 else 2 if variant=='expired-C' and i==2 or variant=='expired-B' and i==1 else 100
                    claim=i<2 or variant in ('contradictory-C','expired-C','revoked-C')
                    result=self.e.submit(cid,*proof(p,cid,a[i],i,until=until,claim=claim))
                    self.assertEqual(result['accepted'],not(variant=='stale-C' and i==2))
                    if result['accepted']: self.assertTrue(self.e.submit(cid,*proof(p,cid,a[i],i,until=until,claim=claim))['duplicate'])
                if variant=='contradictory-C': self.e.submit(cid,*proof(p,cid,a[2],2,claim=False,ident='negative-C'))
                if variant.startswith('revoked'):
                    i=2 if variant=='revoked-C' else 1
                    m={'v':1,'capsule':cid,'commitment':digest(p),'action':'REVOKED','authority':a[i][1]}
                    self.e.revoke(cid,a[i][1],sign(o,m))
                self.decide(cid); self.e.tick(5); self.compare(cid)
                expected=release_eligible(self.e.export(cid))
                self.assertEqual(expected,variant not in ('revoked-B','expired-B'))
                with ThreadPoolExecutor(max_workers=4) as pool:
                    results=list(pool.map(lambda _:Engine(self.e.root).authorise(cid),range(8)))
                self.assertTrue(all((r is not None)==expected for r in results))
                self.assertLessEqual(sum(e['kind']=='AUTHORISED' for e in self.e.export(cid)['events']),1)

    def test_T_evidence_domain_and_schema_separation(self):
        o,a,p=self.setup_capsule()
        baseline,_=proof(p,'capsule',a[0])
        for field,value in (('capsule','other'),('commitment','0'*64),('contract_version',2),('authority',a[1][1]),('valid_from',1),('valid_until',0),('claim',1),('v',True)):
            changed=dict(baseline); changed[field]=value
            self.assertFalse(self.e.submit('capsule',changed,sign(a[0][0],changed))['accepted'])
        changed=dict(baseline); changed['challenge']='round-1'
        self.assertFalse(self.e.submit('capsule',changed,sign(a[0][0],changed))['accepted'])
        self.assertFalse(self.e.submit('capsule',baseline,'00'*64)['accepted'])
        self.assertTrue(self.e.submit('capsule',*proof(p,'capsule',a[0]))['accepted'])
        self.assertEqual(self.compare()['contracts'],{'A':True,'B':False,'C':False})
