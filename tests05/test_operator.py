import base64
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Engine.protocol import sign,digest,canonical,keypair
from Bounded.wire import request,atomic_json,strict_json
from Available.client import aad,evidence
from Available.proofs import release,operation
from Available.transport import UrllibTransport,HttpClientTransport
from Untrusted.client import Client,public,validate_public,verify_projection,RelayTransport
from Untrusted.vault import seal,unseal,opened
from helpers import configured,W,K,TOKEN,HOSTILE,mode,move

OUT=Path('/recovery/attack-results.json')
RESULTS=[]
def result(name,classification,reason):RESULTS.append({'attack':name,'classification':classification,'evidence':reason});atomic_json(OUT,RESULTS)

class HostileOperator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.trust,cls.direct=configured()
    def setUp(self):mode('honest');self.c=Client(self.trust)
    def arm(self,rounds=2):
        k=self.c.draft(rounds,10);self.c.run(k,'arm');return k
    def relayed(self):return Client(self.trust,RelayTransport('http://laravel:8000',W))
    def test_01_cli_complete_lifecycle_secrets_stay_local(self):
        with tempfile.TemporaryDirectory(dir='/recovery') as d:
            vault=d+'/owner.ovault';pub=d+'/public.json';backup=d+'/backup.ovault';tp='/recovery/trust.json'
            def cli(action,*args):
                p=subprocess.run(['python','-m','Untrusted.cli','--vault',vault,'--trust',tp,action,*args],capture_output=True,text=True);self.assertEqual(p.returncode,0,p.stderr);return json.loads(p.stdout)
            cli('create','--seconds','10');cli('backup','--out',backup);cli('arm');self.assertTrue(cli('checkin','--challenge','1')['accepted']);self.assertEqual(cli('status')['accepted_checkins'],1);cli('public','--out',pub);cli('publish','--saas','http://laravel:8000');self.assertEqual(cli('disarm')['state'],'DISARMED')
            blob=strict_json(Path(vault).read_bytes());kit=unseal(blob,os.environ['OTHERWISE_CREATOR_PASSPHRASE']);projection=request('http://laravel:8000/operator-view')
            self.assertNotIn(kit['owner_seed'],canonical(projection).decode());self.assertNotIn('owner_seed',canonical(projection).decode());self.assertNotIn('shares',projection);self.assertEqual(Path(vault).stat().st_mode&0o777,0o600)
            with self.assertRaises(Exception):unseal(blob,'wrong independent passphrase')
            self.assertNotIn(kit['owner_seed'],Path(vault).read_text())
        result('steal authority through SaaS account/API','prevented','independent local vault; public-only Laravel mirror has no signing seed or aggregate shares')
    def test_02_substitution_ciphertext_contract_recipient(self):
        k=self.arm();v=public(k)
        for field in ['ciphertext','owner','destination','contract']:
            bad=copy.deepcopy(v)
            if field=='ciphertext':bad['ciphertext']=base64.b64encode(b'operator payload').decode()
            elif field=='owner':bad['manifest']['message']['policy']['owner']=keypair()[1]
            elif field=='destination':bad['manifest']['message']['policy']['destination']={'kind':'email','address':'synthetic@example.invalid'}
            else:bad['manifest']['message']['policy']['grace']=0
            with self.assertRaises(Exception):verify_projection(bad,k)
        mode('identity-substitution')
        with self.assertRaises(Exception):self.relayed().draft(2,10)
        mode('honest');result('substitute keys/content/contracts/destinations','detectable','local owner commitment, independent provider pins, ciphertext digest and signatures reject substitution')
    def test_03_forge_checkin_disarm_and_false_success(self):
        k=self.arm();attacker,_=keypair();m=k['manifest']['message'];p=evidence(k['manifest'],attacker,'presence','1');cmd=self.c.command(k,'DISARM');cmd['signature']=sign(attacker,cmd['message'])
        for u in W:
            with self.assertRaises(Exception):request(u+'/observe',{'capsule':m['capsule'],'proof':p})
            with self.assertRaises(Exception):request(u+'/disarm',{'capsule':m['capsule'],'command':cmd})
        mode('false-success')
        with self.assertRaises(Exception):self.relayed().run(k,'checkin',challenge='1')
        self.assertEqual(self.c.inspect(k)['accepted_checkins'],0);mode('honest')
        result('forge creator check-in/disarm','prevented','honest witnesses reject attacker signatures')
        result('false successful acknowledgement / misleading accepted witnesses','detectable','SaaS success booleans do not satisfy distinct pinned witness signatures and retention requirements')
    def test_04_censorship_and_alternative_path(self):
        k=self.arm();mode('censor')
        with self.assertRaises(Exception):self.relayed().run(k,'checkin',challenge='1')
        self.assertTrue(self.c.run(k,'checkin',challenge='1')['accepted']);self.assertEqual(self.c.inspect(k)['accepted_checkins'],1)
        mode('honest');result('suppress valid check-in through SaaS','recoverable','courier censorship succeeds; independently reachable direct witness path accepts the same scoped proof')
        class NoPath:
            def call(self,*a,**kw):raise ValueError('all independent paths unavailable')
        with self.assertRaises(Exception):Client(self.trust,NoPath()).run(k,'checkin',challenge='2')
        result('censorship when every independent path is unavailable','successful','no network-delivery guarantee; trusted client reports uncertainty, cannot manufacture receipt quorum')
    def test_05_replay_authorisation_and_stale_state(self):
        k=self.arm();relay=self.relayed();before=relay.inspect(k);self.c.run(k,'checkin',challenge='1');mode('stale')
        with self.assertRaises(Exception):relay.inspect(k)
        self.assertEqual(self.c.inspect(k)['accepted_checkins'],1);mode('honest')
        self.c.run(k,'disarm');self.assertEqual(self.c.inspect(k)['state'],'DISARMED')
        with self.assertRaises(Exception):self.c.run(k,'arm')
        other=self.arm();old=self.c.command(k,'DISARM')
        for u in W:
            with self.assertRaises(Exception):request(u+'/disarm',{'capsule':other['manifest']['message']['capsule'],'command':old})
        result('substitute stale signed protocol state','detectable','old inspect envelopes fail the new random challenge; direct recovery reveals accepted presence')
        result('replay old authorisation into another Capsule or re-arm disarmed state','prevented','manifest/operation/challenge domain binding and immutable witness fences; identical safe retries remain idempotent')
    def test_06_premature_and_withheld_legitimate_release(self):
        k=self.arm(1);m=k['manifest']['message'];cert={'v':4,'manifest':k['manifest'],'finals':[[]],'operation':operation(m)};cert['authorisation']=digest(cert)
        for u in K:
            with self.assertRaises(Exception):request(u+'/release',{'capsule':m['capsule'],'certificate':cert,'requirements':{'operation':'reconstruct-aes-128-gcm','owner_disarm':True,'verified_certificate':True,'simulated_delivery':True,'cryptographic_policy_enforcement':False}})
        self.assertFalse(self.c.run(k,'evaluate')['authorised']);move(k,16);mode('censor')
        self.assertFalse(self.relayed().run(k,'evaluate')['authorised']);d=self.c.run(k,'evaluate');self.assertTrue(d['authorised']);self.assertEqual(self.c.simulate(k,d['certificate'])['delivery'],'SIMULATED');mode('honest')
        result('trigger premature release without custody compromise','prevented','honest closure timing and independent custody certificate checks reject incomplete permission')
        result('prevent legitimate release by withholding SaaS worker','recoverable','SaaS worker can stop, but independent worker obtains closure certificate and simulated delivery')
    def test_07_malicious_client_delivery_success_is_retained(self):
        k=self.arm();js=__import__('urllib.request',fromlist=['urlopen']).urlopen('http://laravel:8000/delivered-client.js').read().decode()
        source=Path('Untrusted/client.py').read_bytes()
        self.assertTrue(self.c.run(k,'checkin',challenge='1')['accepted']);self.assertEqual(source,Path('Untrusted/client.py').read_bytes())
        runner="const vm=require('vm'),fs=require('fs');const b=JSON.parse(fs.readFileSync(0,'utf8'));let ctx={localStorage:{getItem:()=>JSON.stringify(b.kit)}};vm.createContext(ctx);vm.runInContext(b.js,ctx);process.stdout.write(ctx.stolen);"
        p=subprocess.run(['node','-e',runner],input=json.dumps({'kit':k,'js':js}),text=True,capture_output=True,check=True);stolen=json.loads(p.stdout)
        # This intentionally models running an untrusted client while its key is accessible.
        cmd=Client(self.trust).command(stolen,'DISARM');rs=[request(u+'/disarm',{'capsule':k['manifest']['message']['capsule'],'command':cmd}) for u in W]
        self.assertGreaterEqual(len(rs),3)
        result('malicious SaaS JavaScript against independently installed client','prevented','CLI never fetches or executes delivered-client.js; independently pinned installation is an assumption')
        result('malicious client code when executed with accessible creator capability','successful','executed hostile JavaScript steals a synthetic capability; attacker disarm is accepted by honest witnesses')
        result('previously exposed owner material from a 0.4-style client','successful','already known signing seeds remain usable for the old Capsule; upgrading software cannot unlearn exposed keys or plaintext')
    def test_08_device_loss_backup_replacement_and_rotation(self):
        k=self.arm();password=os.environ['OTHERWISE_CREATOR_PASSPHRASE'];backup=seal(k,password);replaced=unseal(backup,password);self.assertTrue(self.c.run(replaced,'checkin',challenge='1')['accepted']);self.assertEqual(self.c.inspect(replaced)['accepted_checkins'],1)
        # Old unlocked device still has the old signing authority until disarm.
        move(k,11);self.assertTrue(self.c.run(k,'checkin',challenge='2')['accepted']);self.assertEqual(self.c.inspect(replaced)['accepted_checkins'],2)
        result('stolen unlocked device before explicit retirement','successful','restoring a backup clones authority; old device signs a new second check-in until the old Capsule is disarmed')
        self.c.run(replaced,'disarm');new=self.arm();oldproof=evidence(k['manifest'],self.c.private(k),'presence','1');oldproof['message']['capsule']=new['manifest']['message']['capsule']
        for u in W:
            with self.assertRaises(Exception):request(u+'/observe',{'capsule':new['manifest']['message']['capsule'],'proof':oldproof})
        with self.assertRaises(Exception):unseal(backup,'lost passphrase too')
        result('device loss with independently retained encrypted backup','recoverable','replacement device decrypts same capability; fresh direct inspection, check-in and disarm succeed')
        result('device loss without backup/passphrase','successful','owner capability unavailable; no account-reset or administrative signing bypass')
        result('old device authority after fresh-Capsule rotation','prevented','old Capsule disarmed; new owner key, payload and policy commitment reject old signatures')
    def test_09_custody_quorum_early_decryption_stays_successful(self):
        k=self.arm();m=k['manifest']['message'];shares=[request(u+'/lab-collude',{'capsule':m['capsule'],'capability':TOKEN}) for u in K[:2]]
        key=Shamir.combine([(s['index'],bytes.fromhex(s['value'])) for s in shares]);ct=base64.b64decode(k['ciphertext']);plaintext=AESGCM(key).decrypt(ct[:12],ct[12:],aad(m));self.assertIn(b'synthetic',plaintext);self.assertFalse(self.c.run(k,'evaluate')['authorised'])
        result('colluding static-share custody quorum','successful','two malicious providers export their own shares and decrypt before any release certificate; stronger witness quorums do not fix this')
    def test_10_transports_projection_and_runtime_separability(self):
        k=self.arm();self.c.run(k,'checkin',challenge='1');other=Client(self.trust,HttpClientTransport());self.assertEqual(other.inspect(k)['accepted_checkins'],1)
        self.assertFalse(Path('Consumer').exists());self.assertFalse(Path('Consumer05').exists());self.assertIsNone(shutil.which('php'))
        bad=public(k);bad['owner_seed']=k['owner_seed']
        with self.assertRaises(Exception):request('http://laravel:8000/mirror',bad)
        self.assertFalse(verify_projection(public(k),k)['fresh'])
    def test_11_one_unavailable_witness_with_trusted_client(self):
        k=self.arm();request(W[3]+'/test-availability',{'available':False},TOKEN)
        try:
            self.assertTrue(self.c.run(k,'checkin',challenge='1')['accepted']);self.assertEqual(self.c.inspect(k)['sources'],3);self.assertEqual(self.c.run(k,'disarm')['state'],'DISARMED')
        finally:request(W[3]+'/test-availability',{'available':True},TOKEN)
    def test_12_rotation_failure_keeps_new_owner_capability(self):
        with tempfile.TemporaryDirectory(dir='/recovery') as d:
            old=d+'/old.ovault';new=d+'/new.ovault';password=os.environ['OTHERWISE_CREATOR_PASSPHRASE']
            with opened(old,password,create=True) as k:k.update(self.c.draft(2,10));self.c.run(k,'arm')
            mode('censor-arm')
            p=subprocess.run(['python','-m','Untrusted.cli','--trust','/recovery/trust.json','--vault',old,'--relay','http://laravel:8000','rotate','--out',new,'--seconds','10'],capture_output=True,text=True)
            self.assertNotEqual(p.returncode,0);self.assertTrue(Path(new).exists(),'persist new signing capability before attempting arm')
            prior=unseal(strict_json(Path(old).read_bytes()),password);created=unseal(strict_json(Path(new).read_bytes()),password);self.assertGreaterEqual(len(prior['disarm']),3)
            mode('honest');self.assertEqual(self.c.run(created,'arm')['state'],'ARMED')
        result('interrupt rotation between retirement and replacement arming','recoverable','old disarm persisted; new encrypted capability persisted before attempted arm; direct retry arms replacement')
    def test_13_tampered_vault_never_yields_creator_authority(self):
        k=self.c.draft(2,10);password=os.environ['OTHERWISE_CREATOR_PASSPHRASE'];encrypted=seal(k,password)
        for field in ['ciphertext','salt','kdf']:
            x=copy.deepcopy(encrypted)
            if field=='kdf':x[field]['n']=2**30
            else:x[field]=('00' if x[field][:2]!='00' else 'ff')+x[field][2:]
            with self.assertRaises(Exception):unseal(x,password)
    def test_14_censored_presence_can_cause_policy_authorised_disclosure(self):
        k=self.arm(1);mode('censor')
        with self.assertRaises(Exception):self.relayed().run(k,'checkin',challenge='1')
        # No timely independent path is used in this deliberately successful attack.
        move(k,16);decision=self.c.run(k,'evaluate');self.assertTrue(decision['authorised']);self.assertEqual(self.c.simulate(k,decision['certificate'])['delivery'],'SIMULATED');mode('honest')
        result('censor genuine presence until deadline with no timely alternative submission','successful','creator tried to check in, but no authoritative receipt quorum formed; honest protocol authorises simulated disclosure after the missed window')
    def test_15_installed_build_manifest_and_independent_hash(self):
        from Untrusted.install_check import files
        bundle=strict_json(Path('Protocol/client05-build.json').read_bytes());expected=digest(bundle);self.assertEqual(bundle,{'v':5,'files':files()})
        p=subprocess.run(['python','-m','Untrusted.install_check','--expected',expected],capture_output=True,text=True);self.assertEqual(p.returncode,0,p.stderr)
        p=subprocess.run(['python','-m','Untrusted.install_check','--expected','00'*32],capture_output=True,text=True);self.assertNotEqual(p.returncode,0)
    def test_16_provider_tls_verification_is_required(self):
        self.assertTrue(all(p['url'].startswith('https://') for p in self.trust['providers']))
        import ssl,urllib.request
        with self.assertRaises(Exception):urllib.request.urlopen(W[0]+'/identity',context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT),timeout=3)
        self.assertEqual(UrllibTransport().call(W[0]+'/identity')['public'],self.trust['providers'][0]['public'])
