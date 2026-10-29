import base64,copy,concurrent.futures,hashlib,json,os,subprocess,tempfile,time,unittest
from pathlib import Path
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Engine.protocol import canonical,digest,sign
from Bounded.wire import request,atomic_json
from Available.client import aad
from Available.proofs import operation,release
from Honest import crypto
from Missing.collect import gather
from Missing.protocol import DOMAINS,context,wrap_context,commitment,CAPABILITIES,compatible
from Missing.client import Client,recover,verify_contribution
from Untrusted.vault import seal,unseal
from helpers import W,K,A,TOKEN,configured,ready,move,export,fault

LOG=[]
def record_case(name,capability,action,outcome,classification,inputs=None):
    LOG.append({'experiment':name,'attacker_capabilities':capability,'action':action,'observed_output':outcome,'classification':classification,'inputs':inputs or {},'transcript_test':name.split(':')[0]})
    atomic_json('/recovery/attacks07.json',json.loads(json.dumps(LOG)))
def offline_component(k,d,states):
    c=k['custody07']['message'];shared=crypto.combine_points([(i,crypto.number(s['share'])*crypto.point(c['wraps'][d]['R'])) for i,s in enumerate(states[:2],1)])
    return crypto.decrypt(crypto.derive(bytes.fromhex(crypto.encode(shared)),wrap_context(c,d)),c['wraps'][d]['wrapped'],wrap_context(c,d))
def raw_decrypt(k,a,b):
    ct=base64.b64decode(k['ciphertext']);return AESGCM(bytes(x^y for x,y in zip(a,b))).decrypt(ct[:12],ct[12:],aad(k['manifest']['message']))

class MissingPiece(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.trust,cls.c=configured();cls.keys={d:crypto.dealer() for d in DOMAINS}
    def new(self,rounds=1,epoch=1):
        k=self.c.draft(rounds,10);self.c.prepare(k,self.keys,epoch);self.c.arm(k);return k
    def closed(self):
        k=self.new();move(k,16);d=self.c.evaluate(k);self.assertTrue(d['authorised']);return k,d['certificate']
    def test_A_entire_custody_domain(self):
        k=self.new();states=export(k,K);a=offline_component(k,'custody',states)
        self.assertEqual(len(states),3);self.assertTrue(all('identity_seed' in s and 'PRIVATE KEY' in s['tls_private_key'] for s in states))
        with self.assertRaises(Exception):raw_decrypt(k,a,b'\0'*16)
        # Derive only from owned material, bypassing every honest API.
        with self.assertRaises(Exception):offline_component(k,'authority',states)
        self.assertFalse(self.c.evaluate(k)['authorised'])
        record_case('A: full custody extraction','all three shares, signing keys, TLS keys, DBs; no authority secret','raw interpolate custody points; substitute those secrets into authority wrapping','one component recovered; other wrap/AES authentication fails','Prevented',{'sidecar':k['custody07'],'ciphertext':k['ciphertext'],'owned_scalar_shares':[s['share'] for s in states],'scope':'synthetic test secrets only; finite attacks plus stated hardness assumptions'})
    def test_B_entire_authority_domain(self):
        k=self.new();states=export(k,A);b=offline_component(k,'authority',states)
        with self.assertRaises(Exception):raw_decrypt(k,b'\0'*16,b)
        with self.assertRaises(Exception):offline_component(k,'custody',states)
        record_case('B: full authority extraction','all authority-local secret capabilities, no custody secret','recover B then attempt DEK and custody unwrap','B alone insufficient; valid AES/custody authentication not obtained','Prevented',{'sidecar':k['custody07'],'ciphertext':k['ciphertext'],'owned_scalar_shares':[s['share'] for s in states]})
    def test_C_combined_collusion(self):
        k=self.new();cs=export(k,K);aa=export(k,A);a=offline_component(k,'custody',cs);b=offline_component(k,'authority',aa);plain=raw_decrypt(k,a,b)
        self.assertIn(b'synthetic',plain);self.assertFalse(self.c.evaluate(k)['authorised'])
        record_case('C: combined domains','two or more extracted members in each domain; no valid evidence','raw point operations, unwrap A/B, XOR and AES decrypt','premature plaintext and random encrypted commitment salt recovered','Successful',{'sidecar':k['custody07'],'ciphertext':k['ciphertext'],'custody_shares':[s['share'] for s in cs[:2]],'authority_shares':[s['share'] for s in aa[:2]],'plaintext_hex':plain.hex(),'authorised':False})
    def test_D_honest_release(self):
        k,cert=self.closed();plain=self.c.disclose(k,cert);self.assertIn(b'synthetic',plain);journals=self.c.journals(k);self.assertGreaterEqual(len(journals),4)
        record_case('D: legitimate release','honest committees and pinned recipient; no SaaS','verify policy and 2 correct contributions per independent domain','synthetic plaintext returned; only points combined; encrypted operations retained by witness quorum','Recoverable',{'sidecar':k['custody07'],'certificate':cert,'plaintext':plain.decode(),'journal_responses':len(journals)})
    def test_E_forged_decision(self):
        k=self.new();m=k['manifest']['message'];cert={'v':4,'manifest':k['manifest'],'finals':[[]],'operation':operation(m)};cert['authorisation']=digest(cert)
        for d,urls in [('custody',K),('authority',A)]:
            for u in urls:
                with self.assertRaises(Exception):request(u+'/partial07',{'capsule':m['capsule'],'sidecar':k['custody07'],'certificate':cert,'context':context(k['custody07'],cert,d),'requirements':CAPABILITIES})
        record_case('E: forged SaaS decision','public metadata and arbitrary success claims; no witness keys','submit self-hashed incomplete release certificate','all six holders refuse; no partial record issued','Prevented',{'certificate':cert})
    def test_F_valid_arithmetic_invalid_authority(self):
        k=self.new();m=k['manifest']['message'];fake={'v':4,'manifest':k['manifest'],'finals':[[]],'operation':operation(m)};fake['authorisation']=digest(fake);bundle={}
        for d,urls in [('custody',K),('authority',A)]:
            bundle[d]=[];states=export(k,urls)
            for i,s in enumerate(states[:2],1):
                ctx=context(k['custody07'],fake,d);p=crypto.partial(self.keys[d][0],s['share'],i,k['custody07']['message']['wraps'][d]['R'],ctx)
                crypto.verify_partial(self.keys[d][0],k['custody07']['message']['wraps'][d]['R'],ctx,p)
                key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(s['identity_seed']));msg={'context':ctx,'index':i,'box':crypto.seal_to(k['custody07']['message']['recipient'],p,ctx)};bundle[d].append({'message':msg,'signature':sign(key,msg)})
                verify_contribution(k['custody07'],fake,k['recipient_seed'],d,bundle[d][-1])
        with self.assertRaises(Exception):recover(k['custody07'],base64.b64decode(k['ciphertext']),k['recipient_seed'],fake,bundle,self.c.inspect(k)['history'])
        record_case('F: correct arithmetic invalid authority','combined extracted secrets generate valid signed DLEQ partials','present genuine arithmetic under an unauthorised certificate to recipient','individual math passes; collective policy verification rejects; C still bypasses privately','Detected',{'certificate':fake,'responses':bundle,'warning':'valid arithmetic is not policy authority'})
    def test_G_substitution(self):
        k,cert=self.closed();bundle=self.c.contributions(k,cert);history=self.c.inspect(k)['history'];ct=base64.b64decode(k['ciphertext'])
        with self.assertRaises(Exception):recover(k['custody07'],ct+b'x',k['recipient_seed'],cert,bundle,history)
        for field in ['capsule','recipient','policy_version','evidence_head','participant_set','key_epoch','release_attempt','suite','commitment']:
            bad=copy.deepcopy(bundle);bad['custody'][0]['message']['context'][field]='swapped'
            with self.assertRaises(Exception):recover(k['custody07'],ct,k['recipient_seed'],cert,bad,history)
        other,oc=self.closed()
        with self.assertRaises(Exception):recover(other['custody07'],base64.b64decode(other['ciphertext']),other['recipient_seed'],oc,bundle,self.c.inspect(other)['history'])
        bad=copy.deepcopy(bundle);bad['custody']=[bundle['custody'][0]]*2
        with self.assertRaises(Exception):recover(k['custody07'],ct,k['recipient_seed'],cert,bad,history)
        record_case('G: substitution and duplicates','genuine replies and public commitments','change ciphertext, capsule, recipient, version, certificate/head, committee, epoch or release attempt','signature/context/AEAD/threshold checks reject','Prevented',{'sidecar':k['custody07'],'certificate':cert,'responses':bundle})
    def test_H_disarm_finality(self):
        k=self.new();move(k,16);m=k['manifest']['message'];request(W[0]+'/finalise',{'capsule':m['capsule'],**m['slots'][0]})
        self.assertEqual(self.c.disarm(k)['state'],'DISARMED');self.assertFalse(self.c.evaluate(k)['authorised'])
        protected=self.c.inspect(k);self.assertEqual(protected['state'],'DISARMED')
        late,cert=self.closed()
        with self.assertRaises(Exception):self.c.disarm(late)
        self.assertIn(b'synthetic',self.c.disclose(late,cert))
        record_case('H: disarm race','owner capability racing independent durable witness writes','one FINAL then three DISARMs; separate Capsule all FINALs then late disarm','early disarm quorum blocks release; late disarm unavailable and release succeeds','Recoverable',{'disarm_receipts':k['disarm'],'late_certificate':cert,'boundary':'per-witness first durable FINAL or DISARM; 3-signature certificates intersect honestly for f<=1'})
    def test_I_provisioning_exposure(self):
        raw=self.c.draft(1,10);stolen=copy.deepcopy(raw);self.c.prepare(raw,self.keys);self.c.arm(raw)
        # A compromised creation process can retain the AES key before distribution.
        dek=Shamir.combine([(x['index'],bytes.fromhex(x['value'])) for x in stolen['shares'][:2]]);ct=base64.b64decode(raw['ciphertext']);plain=AESGCM(dek).decrypt(ct[:12],ct[12:],aad(raw['manifest']['message']));self.assertIn(b'synthetic',plain)
        bad=copy.deepcopy(raw['custody07']);bad['message']['domains']['authority']['members']=bad['message']['domains']['custody']['members'];bad['signature']=sign(self.c.private(raw),bad['message'])
        with self.assertRaises(Exception):commitment(bad)
        record_case('I: creator/dealer compromise','creation process copies DEK, plaintext and both domain setup shares','retain key before distribution; additionally try explicitly aliased committee identities','retained DEK decrypts undetectably; identical public identities detected but common admin is not','Successful',{'sidecar':raw['custody07'],'ciphertext':raw['ciphertext'],'stolen_dek':dek.hex(),'scope':'synthetic creator-compromise fixture'})
    def test_J_rotation_and_replacement(self):
        old=self.new();cs=export(old,K);aa=export(old,A);self.c.disarm(old)
        prior=self.keys
        try:
            self.keys={d:crypto.dealer() for d in DOMAINS};new=self.new(epoch=2);self.c.checkin(new,'1')
            with self.assertRaises(Exception):offline_component(new,'custody',cs)
            with self.assertRaises(Exception):offline_component(new,'authority',aa)
            self.assertIn(b'synthetic',raw_decrypt(old,offline_component(old,'custody',cs),offline_component(old,'authority',aa)))
        finally:self.keys=prior
        record_case('J: rotation/replacement limit','attacker retains historical secrets and ciphertext; new Capsule gets fresh domain keys/epoch','retire old Capsule, create epoch2; reuse old shares against new wraps','new Capsule protected; copied old Capsule remains decryptable','Successful',{'old':old['custody07'],'new':new['custody07'],'limit':'no proactive resharing/in-place committee replacement; one lost member tolerated by surviving 2, replacing all requires reviewed migration or authorised re-encryption'})
    def test_K_correlated_compromise(self):
        k=self.new();owned={d:export(k,urls) for d,urls in [('custody',K),('authority',A)]};self.assertIn(b'synthetic',raw_decrypt(k,offline_component(k,'custody',owned['custody']),offline_component(k,'authority',owned['authority'])))
        record_case('K: shared administrator compromise','one Docker host/backup administrator reads all six nominal domains','aggregate extracted secret material across the two committees','same successful early decrypt as C; effective host-admin trust boundary count is one','Successful',{'sidecar':k['custody07'],'nominal_committees':2,'effective_shared_host_boundary':1})
    def test_L_independent_recipient(self):
        k,cert=self.closed();bundle=self.c.contributions(k,cert);history=self.c.inspect(k)['history'];self.assertIn(b'synthetic',recover(k['custody07'],base64.b64decode(k['ciphertext']),k['recipient_seed'],cert,bundle,history))
        bad=copy.deepcopy(bundle);bad['authority']=bundle['custody']
        with self.assertRaises(Exception):recover(k['custody07'],base64.b64decode(k['ciphertext']),k['recipient_seed'],cert,bad,history)
        with self.assertRaises(Exception):recover(k['custody07'],base64.b64decode(k['ciphertext']),crypto.recipient()[0],cert,bundle,history)
        record_case('L: dishonest combiner','public SaaS success, genuine partials, swapped domain bundle, wrong recipient secret','independent recipient verifies authority, all arithmetic, 2+2 thresholds and salted plaintext commitment','valid bundle opens; forged status, mixed domains and wrong recipient fail','Prevented',{'sidecar':k['custody07'],'certificate':cert,'responses':bundle})
    def test_M_byzantine_collection(self):
        for mode in ['malformed','bad-proof','oversize','delay']:
            k,cert=self.closed();fault(K[0],mode);fault(A[0],mode);before=time.monotonic()
            try:
                self.assertIn(b'synthetic',self.c.disclose(k,cert));self.assertLess(time.monotonic()-before,8)
            finally:
                # A delayed serial holder may finish after the caller's deadline.
                ready([K[0],A[0]]);fault(K[0],'honest');fault(A[0],'honest')
        self.assertTrue(self.c.audit)
        record_case('M: malicious minority','one holder per domain returns junk, signed invalid proofs or delayed responses','collect all six concurrently and validate each source independently','two valid members per domain selected; invalid replies audited; no threshold downgrade','Recoverable',{'invalid_responses':json.loads(json.dumps(self.c.audit[-12:])),'timing':'provider witness reads <=1.1s; recipient six-source deadline3s, sockets4s; bounded callbacks may finish after return'})
    def test_N_reorder_duplicate_and_deadline(self):
        def run(order):
            def fetch(i):time.sleep((3-i)*.01);return {'id':i}
            return gather(order,fetch,lambda i,r:r if r['id']==i else (_ for _ in ()).throw(ValueError()),2,.3,3)
        self.assertEqual(list(run([0,1,2])['valid']),list(run([2,0,1])['valid']))
        got=gather([0,1,2],lambda i:({'id':0} if i==2 else {'id':i}),lambda i,r:r if r['id']==i else (_ for _ in ()).throw(ValueError('duplicate source')),2,.3,3);self.assertTrue(got['sufficient']);self.assertEqual(len(got['invalid']),1)
        got=gather([0,1,2],lambda i:(time.sleep(.3) if i==2 else i),lambda i,r:r,2,.05,3);self.assertTrue(got['sufficient']);self.assertEqual(len(got['invalid']),1)
    def test_O_independent_journal_after_device_and_db_rollback(self):
        k,cert=self.closed();backup=seal(k,'otherwise07 independent backup password');cid=k['manifest']['message']['capsule'];request(K[0]+'/lab-save',{},TOKEN)
        self.c.disclose(k,cert);request(K[0]+'/lab-restore',{},TOKEN)
        restored=unseal(backup,'otherwise07 independent backup password');other=Client(self.trust);entries=other.journals(restored);self.assertGreaterEqual(len(entries),4);self.assertIn(b'synthetic',other.recover_journal(restored,cert))
        bundle={d:[b['response'] for b in entries if b['response']['message']['context']['domain']==d][:2] for d in DOMAINS};self.assertIn(b'synthetic',recover(restored['custody07'],base64.b64decode(restored['ciphertext']),restored['recipient_seed'],cert,bundle,other.inspect(restored)['history']))
        old=[b['response'] for b in entries if b['response']['message']['context']['domain']=='custody' and b['response']['message']['index']==1][0]
        fresh=request(K[0]+'/partial07',{'capsule':cid,'sidecar':k['custody07'],'certificate':cert,'context':context(k['custody07'],cert,'custody'),'requirements':CAPABILITIES});self.assertNotEqual(old,fresh)
        record_case('O: independent rollback evidence','creator loses current device, restores old vault; custodian rolls back full DB; SaaS absent','recover later encrypted contributions from 3/4 fresh witness journals','recipient discloses from retained evidence; changed custodian retry independently detectable','Recoverable',{'certificate':cert,'old_response':old,'new_response':fresh,'journal_responses':len(entries),'limit':'global loss/rollback of every anchor and keys remains outside prevention'})
    def test_P_two_losses_and_recovery(self):
        k,cert=self.closed()
        for u in [K[2],A[2]]:request(u+'/lab-available',{'available':False},TOKEN)
        try:self.assertIn(b'synthetic',self.c.disclose(k,cert))
        finally:
            for u in [K[2],A[2]]:request(u+'/lab-available',{'available':True},TOKEN)
        for u in K[1:]:request(u+'/lab-available',{'available':False},TOKEN)
        try:
            with self.assertRaises(Exception):self.c.disclose(k,cert)
        finally:
            for u in K[1:]:request(u+'/lab-available',{'available':True},TOKEN)
        record_case('P: participant loss','one member in each domain unavailable, then two custody members unavailable','attempt valid release and restore participants','one/domain loss tolerated; threshold loss blocks disclosure without leaking missing key','Recoverable',{'certificate':cert,'permanent_loss':'same surviving 2 can release; no safe in-place resharing implemented'})
    def test_Q_holder_actual_crash(self):
        for phase in ['before-commit','after-commit']:
            k,cert=self.closed();cid=k['manifest']['message']['capsule'];body={'capsule':cid,'sidecar':k['custody07'],'certificate':cert,'context':context(k['custody07'],cert,'authority'),'requirements':CAPABILITIES}
            with self.assertRaises(Exception):request(A[0]+'/partial07',{**body,'fault':phase},TOKEN)
            ready(A[:1]);s=export(k,A[:1])[0];self.assertEqual(len(s['partials']),0 if phase=='before-commit' else 1)
            self.assertIn(b'synthetic',self.c.disclose(k,cert))
        record_case('Q: actual capability process crash','fault injection exits before/after SQLite FULL commit','retry after automatic process restart with same own volume','no precommit record; durable postcommit response retained; normal release recovers','Recoverable')
    def test_R_capability_negotiation_and_separation(self):
        self.assertTrue(compatible({'independent_missing_capability':True}))
        with self.assertRaises(Exception):compatible({'cryptographic_policy_enforcement_against_combined_quorum':True})
        self.assertFalse(Path('Consumer').exists());self.assertFalse(Path('Consumer05').exists());self.assertIsNone(__import__('shutil').which('php'))
        record_case('R: global compromise boundary','all domains, creator, recipient or every independent history compromised','assume all indispensable capabilities or anchors are lost','no software-only prevention or automatic recovery claimed','Outside the threat model')
    def test_S_actual_standalone_creator_cli(self):
        with tempfile.TemporaryDirectory(dir='/recovery') as d:
            trust=d+'/trust.json';atomic_json(trust,self.trust);vault=d+'/owner.ovault'
            def cli(action,*args):
                p=subprocess.run(['python','-m','Missing.cli','--vault',vault,'--trust',trust,action,*args],capture_output=True,text=True);self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout)
            cli('create','--rounds','1','--seconds','10');cli('arm');self.assertTrue(cli('checkin','--challenge','1')['accepted']);self.assertEqual(cli('status')['accepted_checkins'],1);self.assertEqual(cli('disarm')['state'],'DISARMED')
        record_case('S: independent creator CLI','no Laravel or SaaS database, encrypted local capability and public pins','create, provision both domains, arm, checkin, status and disarm in child processes','complete Solo lifecycle succeeded','Recoverable')
    def test_T_actual_independent_recipient_cli(self):
        k,cert=self.closed();bundle=self.c.contributions(k,cert)
        cfg={'sidecar':k['custody07'],'ciphertext':k['ciphertext'],'recipient_seed':k['recipient_seed'],'witnesses':k['witnesses']};self.assertNotIn('owner_seed',cfg)
        from Missing.recipient import verify as recipient_verify
        package={'certificate':cert,'contributions':bundle};self.assertIn(b'synthetic',recipient_verify(cfg,package))
        fake=copy.deepcopy(package);fake['certificate']['authorisation']='00'*32
        with self.assertRaises(Exception):recipient_verify(cfg,fake)
        with tempfile.TemporaryDirectory(dir='/recovery') as d:
            vault=d+'/recipient.ovault';proof=d+'/proof.json';atomic_json(vault,seal(cfg,os.environ['OTHERWISE_CREATOR_PASSPHRASE']));atomic_json(proof,package)
            p=subprocess.run(['python','-m','Missing.recipient','--vault',vault,'--bundle',proof],capture_output=True,text=True);self.assertEqual(p.returncode,0,p.stderr);self.assertTrue(json.loads(p.stdout)['independently_verified'])
        record_case('T: separate recipient client','recipient has only expected commitment, ciphertext, recipient secret and pinned witness endpoints','verify fresh independent snapshots, signatures, every DLEQ proof, two domain thresholds and salted plaintext commitment','correct plaintext recovered with no owner signing seed or SaaS trust','Recoverable',{'sidecar':k['custody07'],'certificate':cert,'contributions':bundle})
    def test_U_correlated_dealer_keys(self):
        # Distinct public keys do not establish independently unknown private keys.
        key,shares=crypto.dealer();factor=2
        linked={'v':6,'scheme':key['scheme'],'k':2,'n':3,'X':crypto.encode(factor*crypto.point(key['X'])),'Y':{i:crypto.encode(factor*crypto.point(y)) for i,y in key['Y'].items()}}
        linked_shares={i:crypto.hx((factor*crypto.number(s))%crypto.Q) for i,s in shares.items()}
        k=self.c.draft(1,10);self.c.prepare(k,{'custody':(key,shares),'authority':(linked,linked_shares)});self.c.arm(k)
        owned=export(k,K);derived=[{**s,'share':crypto.hx((factor*crypto.number(s['share']))%crypto.Q)} for s in owned]
        self.assertIn(b'synthetic',raw_decrypt(k,offline_component(k,'custody',owned),offline_component(k,'authority',derived)));self.assertFalse(self.c.evaluate(k)['authorised'])
        record_case('U: deliberately correlated dealer keys','malicious creator/dealer chooses distinct committee keys with known private relation; attacker extracts custody only','derive all authority shares as twice the owned custody shares','both components recoverable; early disclosure succeeds despite distinct public keys','Successful',{'sidecar':k['custody07'],'ciphertext':k['ciphertext'],'known_relation_multiplier':factor,'owned_shares':[s['share'] for s in owned],'limit':'outside securely independent creation assumption; setup independence is not proven by key inequality'})
    def test_V_early_slot_closure_can_block_disarm(self):
        k=self.new(2);self.c.checkin(k,'1');move(k,16);m=k['manifest']['message']
        for u in W:request(u+'/finalise',{'capsule':m['capsule'],**m['slots'][0]})
        self.assertFalse(self.c.evaluate(k)['authorised'])
        with self.assertRaises(Exception):self.c.disarm(k)
        record_case('V: inherited early-finalisation cancellation limit','public worker can request closure of an expired first window; first checkin was accepted','finalise the satisfied first presence slot before later window closes, then attempt owner disarm','release not yet authorised, but all four local FINAL fences make disarm unavailable','Successful',{'sidecar':k['custody07'],'policy_authorised':False,'limit':'wire4 disarm rejects any own FINAL, not only a complete release decision; requires a versioned lifecycle redesign, not a hidden bypass'})
