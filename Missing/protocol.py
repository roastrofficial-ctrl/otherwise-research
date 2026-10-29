"""Versioned two-domain key access structure; evidence stays wire4, not reinterpreted."""
import hashlib
import re
import subprocess
from Engine.protocol import digest,canonical
from Available.proofs import manifest,checked_signature,require,release,fence_certificate,record,fence
from Honest.crypto import public_key,point
from Honest.protocol import evidence_snapshot
from Bounded.wire import strict_json

DOMAINS=('custody','authority')
SUITE='otherwise07-xor2-threshold-dh-p256-hkdf-sha256-aesgcm-x25519'
CAPABILITIES={'v':7,'suite':SUITE,'threshold_per_domain':2,'members_per_domain':3,'required_domains':list(DOMAINS),'independent_missing_capability':True,'cryptographic_policy_enforcement_against_combined_quorum':False,'long_lived_key_reconstruction':False,'provisioning':'trusted-creator-dealer','reviewed':False,'simulated_delivery':True}
def compatible(required):
    require(type(required) is dict and set(required)<=set(CAPABILITIES) and all(CAPABILITIES[k]==v for k,v in required.items()),'custody security capability mismatch')
    return True

def commitment(sc):
    c=sc['message'];require(set(c)=={'v','suite','epoch','manifest','recipient','domains','wraps','plaintext_commitment'},'v7 commitment fields')
    require(type(c['v']) is int and c['v']==7 and c['suite']==SUITE and type(c['epoch']) is int and c['epoch']>=1,'v7 suite/epoch')
    m=manifest(c['manifest']);checked_signature(m['policy']['owner'],sc)
    require(set(c['domains'])==set(DOMAINS) and set(c['wraps'])==set(DOMAINS),'independent domains required')
    allkeys=[];generations=[]
    for domain in DOMAINS:
        d=c['domains'][domain];require(set(d)=={'epoch','key','members'} and type(d['epoch']) is int and d['epoch']>=1,'key epoch')
        public_key(d['key']);generations.append(d['key']['X']);require(set(d['members'])=={'1','2','3'},'committee shape')
        for pk in d['members'].values():require(type(pk) is str and re.fullmatch('[0-9a-f]{64}',pk),'member encoding');allkeys.append(pk)
        w=c['wraps'][domain];require(set(w)=={'R','wrapped'} and type(w['wrapped']) is str and re.fullmatch('[0-9a-f]{88}',w['wrapped']),'wrapped component');point(w['R'])
    require(len(set(allkeys))==6 and len(set(generations))==2,'cryptographically distinct committees')
    require(c['domains']['custody']['members']==m['custody']['keys'],'legacy custody identities remain pinned')
    require(type(c['recipient']) is str and re.fullmatch('[0-9a-f]{64}',c['recipient']) and type(c['plaintext_commitment']) is str and re.fullmatch('[0-9a-f]{64}',c['plaintext_commitment']),'recipient/plaintext commitment')
    return c,m

def wrap_context(c,domain):
    m=manifest(c['manifest']);return {'v':7,'suite':SUITE,'kind':'KEY_COMPONENT_WRAP','capsule':m['capsule'],'manifest':digest(m),'ciphertext':m['payload'],'recipient':c['recipient'],'policy_version':m['policy']['version'],'capsule_epoch':c['epoch'],'domain':domain,'key_epoch':c['domains'][domain]['epoch'],'committees':digest(c['domains']),'plaintext_commitment':c['plaintext_commitment']}

def context(sc,cert,domain):
    c,m=commitment(sc);require(domain in DOMAINS,'wrong capability domain');require(cert['manifest']==c['manifest'],'certificate scope')
    return {**wrap_context(c,domain),'kind':'PARTIAL_DECRYPT','commitment':digest(sc),'release_attempt':m['operation']['attempt'],'authorisation':cert['authorisation'],'evidence_head':digest({'finality_certificate':cert}),'participant_set':digest(c['domains'][domain]['members'])}

def authorise(sc,cert,history):
    c,m=commitment(sc);require(cert['manifest']==c['manifest'],'certificate scope');decision=release(cert)
    arms={r['message']['witness']:r for r in history if r['message']['kind']=='ARM'};fence_certificate(c['manifest'],list(arms.values()),'ARM')
    require(not any(r['message']['kind']=='DISARM' for r in history),'retained disarm veto')
    # The signed finality certificate supplies immutable finals; snapshots supply current vetoes.
    # Finals need not all be copied into every sampled witness before a signer goes offline.
    for group in cert['finals']:
        if all(r['message']['value']=='ABSENT' for r in group):
            slot=(group[0]['message']['contract'],group[0]['message']['challenge'])
            require(not any(r['message']['kind']=='OBSERVATION' and (r['message']['contract'],r['message']['challenge'])==slot for r in history),'retained presence veto')
    p=subprocess.run(['node','Verifier/available.mjs'],input=canonical({'kind':'release','object':cert}),capture_output=True,timeout=2)
    require(p.returncode==0 and strict_json(p.stdout)=={'ok':True,**decision},'independent evaluator disagreement')
    return decision

def response(sc,cert,domain,signed):
    c,m=commitment(sc);r=signed['message'];require(set(r)=={'context','index','box'},'contribution schema')
    i=r['index'];require(type(i) is int and i in (1,2,3),'participant index');checked_signature(c['domains'][domain]['members'][str(i)],signed)
    require(r['context']==context(sc,cert,domain),'contribution domain binding')
    require(set(r['box'])=={'ephemeral','ciphertext'},'encrypted partial schema')
    return r

def plain_commit(salt,text):return hashlib.sha256(b'otherwise07-plaintext\x00'+salt+text).hexdigest()
