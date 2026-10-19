"""Modest reproducible workload. Reports measurements, never invented estimates."""
import json
import math
import os
import statistics
import tempfile
import subprocess
import time
import uuid
from Engine.protocol import keypair,sign,canonical
from Bounded.wire import request,strict_json
from Bounded.verify import validate_snapshot
from Retained.client import prepare,enroll,evidence,check_in,finalise,CheckInClient,gossip
from Retained.proofs import release
from Retained.fixtures import policy

W=['http://rw'+str(i)+':8080' for i in range(1,4)];K=['http://rk'+str(i)+':8080' for i in range(1,4)]
T=[os.environ['OTHERWISE_03_'+prefix+str(i)+'_TOKEN'] for prefix in ('RW','RK') for i in range(1,4)]

def setup():
    base=max(request(u+'/clock')['lower'] for u in W)
    for i,u in enumerate(W):request(u+'/test-clock',{'now':base},T[i])
    owner,pub=keypair();p=policy('absence',base,authorities=[pub],owner=pub)
    sm,ct,shares=prepare('bench-'+uuid.uuid4().hex,p,owner,os.urandom(32),W,K,base+10);enroll(sm,shares,W,K,T)
    return sm,evidence(sm,owner,'A','round-1'),base

def summary(samples):
    ordered=sorted(samples);return {'samples':len(samples),'median_ms':round(statistics.median(samples)*1000,3),'p95_ms':round(ordered[max(0,math.ceil(.95*len(ordered))-1)]*1000,3)}

def main():
    out={'environment':'Docker internal HTTP network; SQLite synchronous=FULL; controlled integer service clocks; sequential synthetic workload'}
    for mode,count in [('all_three_available',20),('one_unavailable',10)]:
        timings=[];receipt_sizes=[];ack_sizes=[];growth=[];commits=[];gossip_times=[];anchor_sizes=[]
        for _ in range(count):
            sm,p,b=setup();cid=sm['message']['capsule'];before=[request(u+'/status?capsule='+cid) for u in W]
            if mode=='one_unavailable':request(W[2]+'/test-availability',{'available':False},T[2])
            try:
                with tempfile.TemporaryDirectory(dir='/client-state') as root:
                    client=CheckInClient(root,W)
                    start=time.perf_counter();ack=client.check_in(sm,p);timings.append(time.perf_counter()-start)
            finally:
                if mode=='one_unavailable':request(W[2]+'/test-availability',{'available':True},T[2])
            after=[request(u+'/status?capsule='+cid) for u in W]
            receipt_sizes.extend(len(canonical(r)) for r in ack['receipts']);ack_sizes.append(len(canonical(ack)))
            growth.append(sum(a['logical_bytes']-z['logical_bytes'] for a,z in zip(after,before)))
            commits.append(sum(len(a['events'])-len(z['events']) for a,z in zip(after,before)))
            start=time.perf_counter();gossip(ack,W);gossip_times.append(time.perf_counter()-start)
            anchor_sizes.append(sum(request(u+'/status?capsule='+cid)['anchor_bytes'] for u in W))
        out[mode]={'acceptance_latency':summary(timings),'optional_post_acceptance_gossip_latency':summary(gossip_times),'aggregate_retained_anchor_bytes_mean':round(statistics.mean(anchor_sizes)),'receipt_bytes_mean':round(statistics.mean(receipt_sizes)),
            'acknowledgement_bytes_mean':round(statistics.mean(ack_sizes)),'logical_observation_commits_per_checkin':statistics.mean(commits),
            'client_certificate_cache_commits_per_checkin':1,'clock_file_checkpoints_per_checkin':statistics.mean(commits),'aggregate_logical_storage_growth_per_capsule_bytes':round(statistics.mean(growth))}
    sm,p,b=setup();cid=sm['message']['capsule'];start=time.perf_counter()
    try:request(W[0]+'/observe',{'proof':p},T[0],{'X-Crash':'after_commit'})
    except Exception:pass
    while True:
        try:request(W[0]+'/observe',{'proof':p});break
        except Exception:
            if time.perf_counter()-start>30:raise
            time.sleep(.05)
    out['restart_and_receipt_recovery_ms']=round((time.perf_counter()-start)*1000,3)
    sm,p,b=setup()
    for i,u in enumerate(W):request(u+'/test-clock',{'now':b+16},T[i])
    cert=finalise(sm,W);out['compact_release_certificate_bytes']=len(canonical(cert))
    samples=[]
    for _ in range(100):
        start=time.perf_counter();release(cert);samples.append(time.perf_counter()-start)
    out['python_compact_release_verification']=summary(samples)
    samples=[]
    for _ in range(10):
        start=time.perf_counter();request(K[0]+'/release',{'certificate':cert});samples.append(time.perf_counter()-start)
    out['custody_http_python_plus_node_process_verification']=summary(samples)
    corpus=strict_json(open('Protocol/vectors/generation02.json','rb').read());snapshot=corpus['witness_bundle']['snapshot']
    samples=[]
    for _ in range(100):
        start=time.perf_counter();validate_snapshot(snapshot);samples.append(time.perf_counter()-start)
    out['generation02_fixed_history_python_verification']=summary(samples)
    out['generation02_fixed_history_bytes']=len(canonical(snapshot))
    out['comparison_limit']='Different proof shapes and workload histories; CPU and encoded bytes only. No Gen0.2 network-latency comparison claimed; no physical fsync count inferred.'
    print(json.dumps(out,indent=2,sort_keys=True))

if __name__=='__main__':main()
