"""Equivalent public lifecycle workload; sample maxima, not inferred tail guarantees."""
import json,statistics,time,resource,os
from Bounded.wire import request
from Engine.protocol import canonical
from LastWord.client import Client
from LastWord.proofs import finality
from LastWord.recipient import verify
from helpers import configured,move,W,K,A,TOKEN
trust,c=configured();data={};network={};writes=[]
def sample(name,fn):
    before=time.perf_counter();v=fn();data.setdefault(name,[]).append((time.perf_counter()-before)*1000);return v
def metrics(k):
    return sum(request(u+'/metrics08',{'capsule':k['manifest']['message']['capsule']})['consensus_sqlite_row_writes'] for u in W)
for _ in range(8):
    k=c.prepare(c.draft(2,10));c.arm(k);sample('checkin',lambda:c.checkin(k,'1'));move(k,27);e=sample('policy_satisfaction',lambda:c.evaluate(k));before_writes=metrics(k);fin=sample('release_authorisation_and_commitment',lambda:c.commit_release(k,e['evidence_certificate']));writes.append(metrics(k)-before_writes);package=sample('crypto_collection',lambda:c.collect_release(k,fin));cfg={'registry':k['custody08'],'ciphertext':k['ciphertext'],'recipient_seed':k['recipient_seed']};sample('recipient_verification_disclosure',lambda:verify(cfg,package));sample('decision_recovery',lambda:c.statuses(k))
    active=c.prepare(c.draft(2,10));c.arm(active);sample('disarm',lambda:c.disarm(active))
    network={'registry_bytes':len(canonical(k['custody08'])),'terminal_certificate_bytes':len(canonical(fin)),'portable_package_bytes':len(canonical(package)),'note':'JSON only; excludes HTTP/TLS framing; healthy coordination sends4 proposal/status peers, prepare4, commit4, notify4 plus view-change messages when required'}
for _ in range(100):sample('local_finality_verification',lambda:finality(k['custody08'],fin))
# Recovery timing excludes process boot: actual exit/restart is verified, then peer repair timed.
for _ in range(3):
    cid=k['manifest']['message']['capsule']
    try:request(W[0]+'/crash08',{'capsule':cid,'certificate':fin,'capability':TOKEN})
    except Exception:pass
    from helpers import ready
    ready(W[:1]);sample('restart_authenticated_recovery',lambda:c.recover_witness(k,1))
for _ in range(3):
    pending=c.prepare(c.draft(2,10));c.arm(pending);v=c.make_value(pending,'DISARM')
    for u in W[2:]:request(u+'/test-availability',{'available':False},TOKEN)
    try:
        try:c.order(pending,v,rounds=2);raise AssertionError('partition unexpectedly decided')
        except ValueError:pass
    finally:
        for u in W[2:]:request(u+'/test-availability',{'available':True},TOKEN)
    sample('partition_heal_to_terminal',lambda:c.order(pending,v,rounds=8))

print(json.dumps({'profile':'0.8','scope':'single Docker host, real TLS/SQLite operations, controlled witness clocks; n8 lifecycle and n100 local finality verification','samples':{name:{'n':len(v),'median_ms':round(statistics.median(v),3),'observed_max_ms':round(max(v),3)} for name,v in data.items()},'consensus_sqlite_row_writes_per_release':writes,'durability_scope':'row updates measured across four witness log connections; normal path expected13, not an OS fsync count; each holder separately persists retained decision and partial response','network':network,'client_maxrss_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'cpu_seconds':resource.getrusage(resource.RUSAGE_SELF).ru_utime+resource.getrusage(resource.RUSAGE_SELF).ru_stime},indent=2))
