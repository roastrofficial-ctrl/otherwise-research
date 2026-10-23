import base64
import copy
import concurrent.futures
import os
import subprocess
import unittest
from pathlib import Path
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Engine.protocol import digest,canonical,sign
from Bounded.wire import request,atomic_json
from Available.client import aad
from Available.proofs import operation as witness_operation,release
from Honest import crypto
from Honest.client import Client,recover
from Honest.protocol import CAPABILITIES,compatible,encryption_context,evidence_snapshot
from Untrusted.vault import seal,unseal
from helpers import W,K,TOKEN,ready,configured,move

RESULTS=[]
def result(name,capabilities,action,outcome,classification,evidence):
    RESULTS.append({'experiment':name,'attacker_capabilities':capabilities,'attempted_action':action,'actual_result':outcome,'classification':classification,'preserved_evidence':evidence})
    atomic_json('/recovery/attacks06.json',RESULTS)

class Custody(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.trust,cls.c=configured();cls.key=crypto.dealer()
    def new(self,rounds=1,arm=True):
        k=self.c.draft(rounds,10);self.c.prepare_custody(k,self.key)
        # Recovery never needs aggregate static shares or dealer shares.
        del k['shares']
        if arm:self.c.arm(k)
        return k
    def closed(self):
        k=self.new();move(k,16);cert=self.c.evaluate(k)['certificate'];return k,cert,self.c.context(k,cert)
    def responses(self,k,cert,ctx,urls=K):
        b=self.c.request_body(k,cert,ctx);return [request(u+'/partial',b) for u in urls]
    def test_01_single_compromise(self):
        k=self.new();s=request(K[0]+'/lab-export',{'capsule':k['manifest']['message']['capsule']},TOKEN);c=k['custody06']['message']
        D=crypto.number(s['share'])*crypto.point(c['wrap']['R']);context=encryption_context(c['manifest'],c['key'],c['recipient'])
        with self.assertRaises(Exception):crypto.decrypt(crypto.derive(bytes.fromhex(crypto.encode(D)),context),c['wrap']['wrapped'],context)
        with self.assertRaises(Exception):crypto.combine_points([(1,D)])
        self.assertFalse(self.c.evaluate(k)['authorised'])
        result('one extracted custodian','own identity, share, complete DB and public ciphertext','derive wrapping key with one partial','no plaintext recovered','Prevented','test_01; threshold algebra and AES tag failure, computational assumption rather than exhaustive impossibility test')
    def test_02_threshold_collusion_early(self):
        k=self.new();c=k['custody06']['message'];states=[request(u+'/lab-export',{'capsule':k['manifest']['message']['capsule']},TOKEN) for u in K[:2]]
        # Bypass honest policy entirely. No private scalar reconstruction needed.
        Ds=[(i,crypto.number(s['share'])*crypto.point(c['wrap']['R'])) for i,s in enumerate(states,1)]
        shared=crypto.combine_points(Ds);context=encryption_context(c['manifest'],c['key'],c['recipient'])
        dek=crypto.decrypt(crypto.derive(bytes.fromhex(crypto.encode(shared)),context),c['wrap']['wrapped'],context)
        ct=base64.b64decode(k['ciphertext']);plain=AESGCM(dek).decrypt(ct[:12],ct[12:],aad(k['manifest']['message']))
        self.assertIn(b'synthetic',plain);self.assertFalse(self.c.evaluate(k)['authorised'])
        result('threshold premature disclosure','two custodians extracted; no creator, recipient, SaaS or witness key','compute raw partial points outside server and interpolate','synthetic plaintext disclosed before authorisation','Successful','test_02; valid AES tag and independent engine authorised=false; no long-lived key reconstruction')
    def test_03_honest_release_recipient_only(self):
        k,cert,ctx=self.closed();rs=self.responses(k,cert,ctx)
        text=recover(k['custody06'],base64.b64decode(k['ciphertext']),k['recipient_seed'],cert,ctx,rs)
        self.assertIn(b'synthetic',text)
        for r in rs:self.assertNotIn('D',r['message']);self.assertNotIn('share',r['message'])
        with self.assertRaises(Exception):recover(k['custody06'],base64.b64decode(k['ciphertext']),crypto.recipient()[0],cert,ctx,rs)
        self.assertEqual(rs[0],self.responses(k,cert,ctx,K[:1])[0])
        result('honest release','honest custodians; untrusted courier; committed recipient key','release after signed witness closure','recipient decrypts; courier receives encrypted partials; scalar x never combined','Recoverable','test_03; complete authenticated plaintext, repeated operation byte-identical, wrong recipient rejected')
    def test_04_forged_saas_decision(self):
        k=self.new();m=k['manifest']['message'];fake={'v':4,'manifest':k['manifest'],'finals':[[]],'operation':witness_operation(m)};fake['authorisation']=digest(fake)
        ctx=self.c.context(k,fake);body=self.c.request_body(k,fake,ctx)
        for u in K:
            with self.assertRaises(Exception):request(u+'/partial',body)
        result('forged SaaS success','public metadata and arbitrary request bodies','submit incomplete certificate with self-computed decision hash','all honest custodians refuse','Prevented','test_04; no authoritative witness finals, no partial record issued')
    def test_05_stale_head_and_replay(self):
        k=self.new(2);m=k['manifest']['message'];fake={'authorisation':'00'*32};ctx=self.c.context(k,fake)
        self.c.checkin(k,'1');move(k,27);cert=self.c.evaluate(k)['certificate'];b=self.c.request_body(k,cert,ctx)
        for u in K:
            with self.assertRaisesRegex(Exception,'stale'):request(u+'/partial',b)
        fresh=self.c.context(k,cert);self.assertNotEqual(fresh['evidence_head'],ctx['evidence_head']);self.assertIn(b'synthetic',self.c.disclose(k,cert,fresh))
        nonce='11'*32;s=request(W[0]+'/inspect',{'capsule':m['capsule'],'nonce':nonce})
        with self.assertRaises(Exception):evidence_snapshot(k['manifest'],[s,s,s],'22'*32,{})
        result('stale evidence head','replay authentic historical set digest and signed snapshot','reuse context after accepted presence and later closure','head mismatch and nonce replay refused; fresh release succeeds','Detected','test_05; previous and fresh set digests differ, fresh snapshots read directly by each custodian')
    def test_06_changed_capsule_and_proof(self):
        k,cert,ctx=self.closed();rs=self.responses(k,cert,ctx);ct=base64.b64decode(k['ciphertext'])
        with self.assertRaises(Exception):recover(k['custody06'],ct+b'x',k['recipient_seed'],cert,ctx,rs)
        for field in ['recipient','commitment','manifest','ciphertext','manifest_version','authorisation','evidence_head']:
            bad=copy.deepcopy(ctx);bad[field]='substitution' if field!='manifest_version' else 99
            with self.assertRaises(Exception):recover(k['custody06'],ct,k['recipient_seed'],cert,bad,rs)
        other,oc,ox=self.closed()
        with self.assertRaises(Exception):recover(other['custody06'],base64.b64decode(other['ciphertext']),other['recipient_seed'],oc,ox,rs)
        c=k['custody06']['message'];p=crypto.open_for(k['recipient_seed'],rs[0]['message']['box'],ctx);p['z']='00'*32
        with self.assertRaises(Exception):crypto.verify_partial(c['key'],c['wrap']['R'],ctx,p)
        b=self.c.request_body(k,cert,ctx);b['sidecar']=copy.deepcopy(b['sidecar']);b['sidecar']['message']['recipient']=crypto.recipient()[1]
        with self.assertRaises(Exception):request(K[0]+'/partial',b)
        result('substitution and cross-Capsule reuse','genuine recipient-encrypted partials and certificate','change ciphertext, recipient, manifest version, commitment, authorisation or head','all verifying paths reject','Prevented','test_06; signature, context, proof and AES checks; distinct Capsules share same long-lived public key')
    def test_07_disarm_boundary(self):
        k=self.new();move(k,16);m=k['manifest']['message'];sl=m['slots'][0]
        request(W[0]+'/finalise',{'capsule':m['capsule'],**sl})
        self.assertEqual(self.c.disarm(k)['state'],'DISARMED');self.assertFalse(self.c.evaluate(k)['authorised'])
        k,cert,ctx=self.closed();m=k['manifest']['message']
        for u in W:
            with self.assertRaises(Exception):request(u+'/disarm',{'capsule':m['capsule'],'command':self.c.command(k,'DISARM')})
        self.assertIn(b'synthetic',self.c.disclose(k,cert,ctx))
        result('disarm before quorum closure','owner has valid disarm signing capability','one witness finalises, remaining three disarm','disarm quorum blocks release','Prevented','test_07 first branch; each honest witness serialises its first local FINAL/DISARM')
        result('disarm after closure','owner retains signing capability after all four finals','submit late disarm, then obtain partials','late disarm rejected; authorised disclosure succeeds','Successful','test_07 second branch; no clawback after irreversible witness closure or emitted partials')
    def test_08_unavailable_restore(self):
        k,cert,ctx=self.closed();request(K[2]+'/lab-available',{'available':False},TOKEN)
        try:self.assertIn(b'synthetic',self.c.disclose(k,cert,ctx))
        finally:request(K[2]+'/lab-available',{'available':True},TOKEN)
        self.assertEqual(len(self.responses(k,cert,ctx)),3)
        for u in K[1:]:request(u+'/lab-available',{'available':False},TOKEN)
        try:
            with self.assertRaises(Exception):self.c.disclose(k,cert,ctx)
        finally:
            for u in K[1:]:request(u+'/lab-available',{'available':True},TOKEN)
        result('custodian unavailable and restored','suppress one service, then two','release under outage and retry after restore','2/3 live; 1/3 fails closed; restored identity participates','Recoverable','test_08; actual endpoint refusal with independently persistent identities; process crashes separately in test_09')
    def test_09_actual_process_crashes_and_rollback(self):
        for fault in ['before-commit','after-commit']:
            k,cert,ctx=self.closed();cid=k['manifest']['message']['capsule'];body=self.c.request_body(k,cert,ctx)
            with self.assertRaises(Exception):request(K[0]+'/partial',{**body,'fault':fault},TOKEN)
            ready(K[:1]);s=request(K[0]+'/lab-export',{'capsule':cid},TOKEN)
            self.assertEqual(len(s['partials']),0 if fault=='before-commit' else 1)
            rs=self.responses(k,cert,ctx);self.assertIn(b'synthetic',recover(k['custody06'],base64.b64decode(k['ciphertext']),k['recipient_seed'],cert,ctx,rs))
            if fault=='after-commit':self.assertEqual(rs[0],next(iter(s['partials'].values())))
        k,cert,ctx=self.closed();cid=k['manifest']['message']['capsule'];request(K[0]+'/lab-save',{},TOKEN)
        first=self.responses(k,cert,ctx,K[:1])[0];request(K[0]+'/lab-restore',{},TOKEN);second=self.responses(k,cert,ctx,K[:1])[0]
        self.assertNotEqual(first,second) # Recipient can see that its retained receipt changed.
        p1=crypto.open_for(k['recipient_seed'],first['message']['box'],ctx);p2=crypto.open_for(k['recipient_seed'],second['message']['box'],ctx);self.assertEqual(p1['D'],p2['D'])
        result('actual service crash around durable commit','fault capability kills one process before/after SQLite FULL commit','retry after Compose restarts same persistent identity','pre-commit no record; post-commit exact response retained','Recoverable','test_09; exit codes 71/72; DB inspection and byte-identical post-commit retry')
        result('custody DB rollback','restore complete local DB before issued response; recipient retains original receipt','repeat same authorised operation','new receipt detectable by recipient; same partial point, no extra decryption power','Detected','test_09; no universal rollback detection without external anchors; fresh witness checks remain mandatory')
    def test_10_compromised_provisioning(self):
        k=self.c.draft(1,10);stolen=copy.deepcopy(k['shares']);self.c.prepare_custody(k,self.key);self.c.arm(k)
        key=Shamir.combine([(s['index'],bytes.fromhex(s['value'])) for s in stolen[:2]]);ct=base64.b64decode(k['ciphertext'])
        self.assertIn(b'synthetic',AESGCM(key).decrypt(ct[:12],ct[12:],aad(k['manifest']['message'])))
        self.assertFalse(self.c.evaluate(k)['authorised'])
        result('malicious creator/provisioning','creator process sees plaintext, AES key and all enrollment material','copy material before local deletion','undetectable early plaintext disclosure','Successful','test_10; valid decrypt while unauthorised; no claim of Python secure erasure or trusted-dealer resistance')
    def test_11_independent_recovery_and_compatibility(self):
        k=self.new(2);self.c.checkin(k,'1');backup=seal(k,'independent test recovery phrase');restored=unseal(backup,'independent test recovery phrase');other=Client(self.trust)
        self.assertEqual(other.inspect(restored)['accepted_checkins'],1);move(k,11);self.assertTrue(other.checkin(restored,'2')['accepted']);self.assertEqual(other.disarm(restored)['state'],'DISARMED')
        self.assertFalse(Path('Consumer').exists());self.assertFalse(Path('Consumer05').exists())
        self.assertTrue(compatible({'long_lived_key_reconstruction':False,'cryptographic_policy_enforcement':False}))
        with self.assertRaises(Exception):compatible({'cryptographic_policy_enforcement':True})
        with self.assertRaises(Exception):compatible({'reviewed':True})
        result('SaaS absent and creator replaced','no Laravel/database containers; encrypted backup and independent trust file','restore latest receipt, check in and disarm directly','complete independent lifecycle succeeds','Recoverable','test_11; original aggregate static shares absent from backup; no SaaS or provider private volume in client')
    def test_12_competing_workers(self):
        k,cert,ctx=self.closed();body=self.c.request_body(k,cert,ctx)
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:rs=list(pool.map(lambda _:request(K[0]+'/partial',body),range(6)))
        self.assertTrue(all(r==rs[0] for r in rs));self.assertIn(b'synthetic',self.c.disclose(k,cert,ctx))
        result('competing release workers','six concurrent authenticated public release requests','obtain same partial operation concurrently','one durable response, identical retries; plaintext remains recipient-only','Prevented','test_12; serial service and operation digest idempotency; no real external delivery exactly-once claim')
    def test_13_lost_anchors_boundary(self):
        # Explicitly records untested stronger adversary rather than disguising it.
        result('all infrastructure and anchors compromised','Docker host/admin can inspect every volume, replace software and restore all state','erase every independent history and secret boundary','no resistance claimed or experimentally established','Outside the threat model','threat model; local containers share one host, not independent organisations')
    def test_14_reference_algebra_and_invalid_encodings(self):
        from cryptography.hazmat.primitives.asymmetric import ec
        x,a,r=5,7,11;shares={str(i):crypto.hx(x+a*i) for i in range(1,4)}
        p={'v':6,'scheme':'reference-p256-threshold-dh','k':2,'n':3,'X':crypto.encode(x*crypto.G),'Y':{i:crypto.encode(crypto.number(s)*crypto.G) for i,s in shares.items()}}
        R=crypto.encode(r*crypto.G);ctx={'v':6,'fixed':'public-reference-vector'}
        ps=[crypto.partial(p,shares[str(i)],i,R,ctx) for i in range(1,4)]
        independent=ec.derive_private_key(x*r,ec.SECP256R1()).public_key().public_numbers()
        import itertools
        for pair in itertools.permutations(ps,2):
            D=crypto.combine_points([(v['index'],crypto.verify_partial(p,R,ctx,v)) for v in pair])
            self.assertEqual((int(D.x),int(D.y)),(independent.x,independent.y))
        for bad in ['', '00', '04'+'00'*64, '04'+'ff'*64]:
            with self.assertRaises(Exception):crypto.point(bad)
        with self.assertRaises(Exception):crypto.combine_points([(1,crypto.G),(1,crypto.G)])
        for value in [True,0,4,'1']:
            bad=copy.deepcopy(ps[0]);bad['index']=value
            with self.assertRaises(Exception):crypto.verify_partial(p,R,ctx,bad)
        degenerate=copy.deepcopy(p);degenerate['Y']={str(i):p['X'] for i in range(1,4)}
        with self.assertRaises(Exception):crypto.public_key(degenerate)
        bad=copy.deepcopy(p);bad['Y']['3']=crypto.encode(99*crypto.G)
        with self.assertRaises(Exception):crypto.public_key(bad)
        for field in ['D','A','B']:
            bad=copy.deepcopy(ps[0]);bad[field]=crypto.encode(101*crypto.G)
            with self.assertRaises(Exception):crypto.verify_partial(p,R,ctx,bad)
        with self.assertRaises(Exception):crypto.verify_partial(p,R,{'v':7},ps[0])
        # Fixed independent oracle is public test material, not secret provisioning.
        atomic_json('/recovery/reference06.json',{'x':x,'a':a,'r':r,'public':p,'R':R,'expected_shared':crypto.encode(x*r*crypto.G),'independent_oracle':'cryptography/OpenSSL SECP256R1 scalar multiplication','pairs':6})
    def test_15_snapshot_rollback_and_contradiction(self):
        k=self.new();self.c.checkin(k,'1');m=k['manifest']['message'];nonce='ab'*32
        snaps=[request(u+'/inspect',{'capsule':m['capsule'],'nonce':nonce}) for u in W[:3]]
        head,history,anchors=evidence_snapshot(k['manifest'],snaps,nonce,{})
        bad=copy.deepcopy(snaps);bad[0]['message']['records']=[]
        bad[0]=request(W[0]+'/test-sign',{'message':bad[0]['message']},TOKEN)
        with self.assertRaisesRegex(Exception,'rollback'):evidence_snapshot(k['manifest'],bad,nonce,anchors)
        bad=copy.deepcopy(snaps);original=next(r for r in history if r['message']['kind']=='OBSERVATION' and r['message']['witness']==1)
        fork=copy.deepcopy(original);fork['message']['upper']=fork['message']['lower']+1
        fork=request(W[0]+'/test-sign',{'message':fork['message']},TOKEN);bad[0]['message']['records'].append(fork);bad[0]=request(W[0]+'/test-sign',{'message':bad[0]['message']},TOKEN)
        with self.assertRaisesRegex(Exception,'contradictory'):evidence_snapshot(k['manifest'],bad,nonce,anchors)
        result('signed witness rollback/fork','one extracted witness signing key, previous provider anchors retained','sign fresh nonce over omitted history or two same-sequence records','provider snapshot validator refuses','Detected','test_15; correctly signed malicious snapshots; conservative fork veto may sacrifice availability')
    def test_16_standalone_cli_lifecycle(self):
        import json,tempfile
        with tempfile.TemporaryDirectory(dir='/recovery') as d:
            trust=d+'/trust.json';atomic_json(trust,self.trust);vault=d+'/owner.ovault'
            def cli(action,*args):
                p=subprocess.run(['python','-m','Honest.cli','--vault',vault,'--trust',trust,action,*args],capture_output=True,text=True)
                self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout)
            cli('create','--rounds','1','--seconds','10');cli('arm');self.assertTrue(cli('checkin','--challenge','1')['accepted']);self.assertEqual(cli('status')['accepted_checkins'],1);self.assertEqual(cli('disarm')['state'],'DISARMED')
            vault=d+'/missed.ovault';cli('create','--rounds','1','--seconds','10');cli('arm')
            kit=unseal(__import__('Bounded.wire',fromlist=['strict_json']).strict_json(Path(vault).read_bytes()),os.environ['OTHERWISE_CREATOR_PASSPHRASE']);self.assertNotIn('shares',kit);move(kit,16)
            self.assertTrue(cli('evaluate')['authorised']);self.assertEqual(cli('disclose')['delivery'],'SIMULATED')
        result('standalone CLI with alternate custody','trusted installed client, local encrypted vault, independent provider pins; SaaS absent','create, arm, durable checkin, fresh status, disarm, and separate missed-window disclose','full Solo lifecycle with new provider succeeds','Recoverable','test_16; actual child-process CLI commands over provider TLS, no Laravel')
