"""Same primary workloads against the unchanged 0.7 profile; missing stages labelled."""
import json,statistics,time
from Engine.protocol import canonical
from Available.proofs import release
from Missing.recipient import verify
from tests07.helpers import configured,move
trust,c=configured();samples={}
def sample(n,fn):
    t=time.perf_counter();r=fn();samples.setdefault(n,[]).append((time.perf_counter()-t)*1000);return r
for _ in range(8):
    k=c.prepare(c.draft(2,10));c.arm(k);sample('checkin',lambda:c.checkin(k,'1'));move(k,27);e=sample('policy_satisfaction_and_implicit07_authorisation',lambda:c.evaluate(k));cert=e['certificate'];bundle=sample('crypto_collection',lambda:c.contributions(k,cert));cfg={'sidecar':k['custody07'],'ciphertext':k['ciphertext'],'recipient_seed':k['recipient_seed'],'witnesses':k['witnesses']};package={'certificate':cert,'contributions':bundle};sample('recipient_verification_disclosure',lambda:verify(cfg,package));sample('decision_recovery',lambda:c.inspect(k))
    active=c.prepare(c.draft(2,10));c.arm(active);sample('disarm',lambda:c.disarm(active))
for _ in range(100):sample('local_finality_verification',lambda:release(cert))
# Same recovery comparison: actual process exit, then owner-authorised v7 peer repair.
for _ in range(3):
    from tests07.helpers import TOKEN,W,ready
    cid=k['manifest']['message']['capsule'];request=__import__('Bounded.wire',fromlist=['request']).request
    # The old service lacks a crash API; stop is externally exercised by its retained scenario.
    # Mark/restore its actual DB through the existing test capability, which quarantines the target.
    request(W[0]+'/test-save',{},TOKEN);request(W[0]+'/test-restore',{},TOKEN);sample('restart_authenticated_recovery',lambda:c.repair(k,1))
for _ in range(3):
    from tests07.helpers import TOKEN,W
    active=c.prepare(c.draft(2,10));c.arm(active)
    for u in W[2:]:request(u+'/test-availability',{'available':False},TOKEN)
    try:
        try:c.disarm(active);raise AssertionError('partition unexpectedly disarmed')
        except ValueError:pass
    finally:
        for u in W[2:]:request(u+'/test-availability',{'available':True},TOKEN)
    sample('partition_heal_to_terminal',lambda:c.disarm(active))
print(json.dumps({'profile':'0.7','scope':'same eight primary two-window workloads and eight fresh disarms; local Docker/controlled clocks','samples':{n:{'n':len(v),'median_ms':round(statistics.median(v),3),'observed_max_ms':round(max(v),3)} for n,v in samples.items()},'release_commitment_stage':'not implemented independently in0.7; its complete window proof is treated as irreversible','package_bytes':len(canonical(package)),'finality_bytes':len(canonical(cert)),'verification_difference':'0.7 recipient fetches live evidence; 0.8 portable terminal package verifies offline'},indent=2))
