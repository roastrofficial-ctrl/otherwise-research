"""Same workload, sequential local Docker TLS runs; only medians and observed maxima."""
import base64
import json
import os
import statistics
import sys
import tempfile
import time
from pathlib import Path
from Crypto.Protocol.SecretSharing import Shamir
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Engine.protocol import canonical
from Available.client import recover as static_recover
from Available.custody import LAB_REQUIREMENTS
from Untrusted.client import Client as StaticClient
from Untrusted.vault import seal,unseal
from Honest.client import recover
from Honest import crypto
from Honest.protocol import encryption_context
from helpers import configured,move,K,TOKEN
from Bounded.wire import request
trust,new=configured();baseline='--baseline' in sys.argv;c=StaticClient(trust) if baseline else new
report={'provider':'0.5 static Shamir' if baseline else '0.6 reference threshold DH','scope':'same Docker host, sequential TLS, synthetic 38-byte payload, 2 check-in windows, one accepted check-in then one missed; no WAN extrapolation','samples_per_lifecycle':8,'measurements':{}}
samples={};wire={};storage=[]
def timed(name,fn):
    t=time.perf_counter();value=fn();samples.setdefault(name,[]).append((time.perf_counter()-t)*1000);return value
key=crypto.dealer()
for _ in range(8):
    start=time.perf_counter();kit=timed('draft_discovery_and_aes_encrypt',lambda:c.draft(2,10))
    if not baseline:
        timed('custody_provision_wrap_enroll',lambda:c.prepare_custody(kit,key));del kit['shares']
    timed('arm_with_retention',lambda:c.arm(kit));samples.setdefault('total_create_provision_arm',[]).append((time.perf_counter()-start)*1000)
    timed('checkin_with_retention',lambda:c.checkin(kit,'1'))
    timed('fresh_owner_inspection',lambda:c.inspect(kit));blob=seal(kit,'benchmark recovery secret phrase')
    restored=timed('encrypted_backup_open',lambda:unseal(blob,'benchmark recovery secret phrase'))
    timed('recover_fresh_state',lambda:c.inspect(restored));move(kit,27)
    cert=timed('authorisation_with_witness_finalisation',lambda:c.evaluate(kit))['certificate']
    ct=base64.b64decode(kit['ciphertext']);cid=kit['manifest']['message']['capsule']
    if baseline:
        body={'capsule':cid,'certificate':cert,'requirements':LAB_REQUIREMENTS}
        rs=timed('two_partial_requests',lambda:[request(u+'/release',body) for u in K[:2]])
        timed('recipient_verify_combine_disclose',lambda:static_recover(kit['manifest'],ct,rs,cert))
        saved=[request(u+'/lab-collude',{'capsule':cid,'capability':TOKEN}) for u in K]
        storage.append({'private_material_logical_bytes':sum(len(canonical(x)) for x in saved),'complete_service_db_bytes':None})
    else:
        ctx=timed('fresh_custody_snapshot_agreement',lambda:c.context(kit,cert));body=c.request_body(kit,cert,ctx)
        rs=timed('two_partial_requests',lambda:[request(u+'/partial',body) for u in K[:2]])
        timed('recipient_verify_combine_disclose',lambda:recover(kit['custody06'],ct,kit['recipient_seed'],cert,ctx,rs))
        states=[request(u+'/lab-export',{'capsule':cid},TOKEN) for u in K]
        storage.append({'private_material_logical_bytes':sum(len(x['share']) for x in states),'complete_capsule_rows_logical_bytes':sum(len(canonical(x)) for x in states),'complete_service_db_bytes':None})
    witness_reads=[{'capsule':cid,'nonce':'ab'*32} for _ in range(4)]
    witness_responses=[request(u+'/inspect',b) for u,b in zip(os.environ['WITNESSES'].split(','),witness_reads)]
    scan_bytes=sum(len(canonical(b))+len(canonical(r)) for b,r in zip(witness_reads,witness_responses))
    wire={'one_four_witness_scan_json_bytes':scan_bytes,'new_release_scan_count':0 if baseline else 5,'two_requests_json_bytes':2*len(canonical(body)),'two_responses_json_bytes':sum(len(canonical(r)) for r in rs),'ciphertext_bytes':len(ct),'encrypted_backup_bytes':len(canonical(blob)),'note':'JSON bytes exclude HTTP/TLS framing; new partial requests additionally perform 8 fresh witness inspection round trips, plus head agreement queries'}
    request(K[2]+('/test-availability' if baseline else '/lab-available'),{'available':False},TOKEN)
    try:
        if baseline:timed('one_unavailable_release',lambda:c.simulate(kit,cert))
        else:timed('one_unavailable_release',lambda:c.disclose(kit,cert,ctx))
    finally:request(K[2]+('/test-availability' if baseline else '/lab-available'),{'available':True},TOKEN)
# Pure crypto costs use equivalent plaintext and exclude TLS/storage.
ctx={'domain':'otherwise06-benchmark'};plaintext=b'OTHERWISE synthetic laboratory message'
for _ in range(40):
    timed('pure_dealer_setup' if not baseline else 'pure_static_share_setup',lambda:crypto.dealer() if not baseline else Shamir.split(2,3,os.urandom(16)))
    def encrypt():
        dek=os.urandom(16);nonce=os.urandom(12);ct=AESGCM(dek).encrypt(nonce,plaintext,canonical(ctx))
        if not baseline:crypto.wrap(key[0],dek,ctx)
        return ct
    timed('pure_payload_encrypt_and_custody_wrap',encrypt)
for name,values in samples.items():report['measurements'][name]={'n':len(values),'median_ms':round(statistics.median(values),3),'observed_max_ms':round(max(values),3)}
report['wire_last_sample']=wire;report['storage_last_sample']=storage[-1];report['storage_note']='Logical JSON/scalar bytes only; allocated DB/WAL bytes are not measured or equated with logical content. v6 public key is reusable; each row currently duplicates it.'
report['failure_note']='one unavailable custodian measured; crash, rollback and 2-down semantics are conformance experiments, not latency distributions'
print(json.dumps(report,indent=2))
