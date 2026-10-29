"""Equivalent healthy/fault workloads on isolated local Docker; no WAN inference."""
import base64,json,os,statistics,time,resource,tracemalloc
from pathlib import Path
from Bounded.wire import request
from Engine.protocol import canonical
from Honest import crypto
from Honest.client import Client as OldClient,recover as old_recover
from Missing.client import Client,recover,verify_contribution
from Missing.protocol import DOMAINS,context
from Untrusted.vault import seal,unseal
baseline='--baseline06' in __import__('sys').argv
W=os.environ['WITNESSES'].split(',');K=os.environ['CUSTODIANS'].split(',');A=[] if baseline else os.environ['AUTHORITIES'].split(',');token=os.environ['OTHERWISE_05_FAULT_TOKEN']
for u in W+K+A:
    end=time.monotonic()+30
    while True:
        try:request(u+'/identity');break
        except Exception:
            if time.monotonic()>end:raise
            time.sleep(.1)
trust={'v':5,'providers':[{'role':role,'url':u,'public':request(u+'/identity')['public']} for role,urls in [('witness',W),('custodian',K),('authority',A)] for u in urls]};c=OldClient(trust) if baseline else Client(trust)
keys=crypto.dealer() if baseline else {d:crypto.dealer() for d in DOMAINS};measure={};wire={};cpu=time.process_time()
def timed(name,fn):
    t=time.perf_counter();v=fn();measure.setdefault(name,[]).append((time.perf_counter()-t)*1000);return v
for j in range(8):
    t=time.perf_counter();k=timed('draft_discovery_encrypt',lambda:c.draft(2,10));timed('wrap_and_distribute',lambda:c.prepare_custody(k,keys) if baseline else c.prepare(k,keys))
    if baseline:del k['shares']
    timed('arm',lambda:c.arm(k));measure.setdefault('total_create_arm',[]).append((time.perf_counter()-t)*1000)
    timed('checkin',lambda:c.checkin(k,'1'));timed('fresh_inspection',lambda:c.inspect(k));blob=seal(k,'otherwise07 benchmark backup phrase');replacement=timed('backup_open',lambda:unseal(blob,'otherwise07 benchmark backup phrase'));timed('fresh_recovery',lambda:c.inspect(replacement))
    base=k['manifest']['message']['policy']['contracts'][0]['start'];now=max(base+27,max(request(u+'/clock')['upper'] for u in W))
    for u in W:request(u+'/test-clock',{'now':now},token)
    cert=timed('authorise',lambda:c.evaluate(k))['certificate'];ct=base64.b64decode(k['ciphertext'])
    if baseline:
        ctx=timed('head_agreement',lambda:c.context(k,cert));body=c.request_body(k,cert,ctx);bundle=timed('contribution_collection',lambda:[request(u+'/partial',body) for u in K[:2]])
        timed('recipient_verification_disclose',lambda:old_recover(k['custody06'],ct,k['recipient_seed'],cert,ctx,bundle))
        timed('full_honest_disclose',lambda:c.disclose(k,cert));wire={'contribution_request_json':2*len(canonical(body)),'contribution_response_json':sum(len(canonical(x)) for x in bundle),'payload_ciphertext_bytes':len(ct),'backup_bytes':len(canonical(blob))}
    else:
        bundle=timed('contribution_collection',lambda:c.contributions(k,cert));history=c.inspect(k)['history'];timed('recipient_verification_disclose',lambda:recover(k['custody07'],ct,k['recipient_seed'],cert,bundle,history));timed('journal_retention',lambda:c.retain_operations(k,cert,bundle));timed('journal_recovery',lambda:c.journals(k));timed('full_honest_disclose',lambda:c.disclose(k,cert))
        for d in DOMAINS:timed('single_contribution_verify',lambda d=d:verify_contribution(k['custody07'],cert,k['recipient_seed'],d,bundle[d][0]))
        wire={'contribution_response_json':sum(len(canonical(x)) for rows in bundle.values() for x in rows),'sidecar_json':len(canonical(k['custody07'])),'payload_ciphertext_bytes':len(ct),'backup_bytes':len(canonical(blob)),'journal_bundle_json':sum(len(canonical({'sidecar':k['custody07'],'certificate':cert,'response':x})) for rows in bundle.values() for x in rows),'note':'four selected replies of six requested; fresh snapshots and replication additional; TLS/HTTP framing excluded'}
    path='/lab-available'
    for u in ([K[2]] if baseline else [K[2],A[2]]):request(u+path,{'available':False},token)
    try:timed('one_unavailable_per_domain_disclose',lambda:c.disclose(k,cert))
    finally:
        for u in ([K[2]] if baseline else [K[2],A[2]]):request(u+path,{'available':True},token)
    if not baseline:
        for u in [K[2],A[2]]:request(u+'/lab-fault',{'mode':'malformed'},token)
        try:timed('one_malicious_per_domain_disclose',lambda:c.disclose(k,cert))
        finally:
            for u in [K[2],A[2]]:request(u+'/lab-fault',{'mode':'honest'},token)
# Rotation is explicit retirement + fresh Capsule/keys; not in-place resharing.
for _ in range(8):
    active=c.draft(1,10)
    if baseline:c.prepare_custody(active,keys);del active['shares']
    else:c.prepare(active,keys)
    c.arm(active);start=time.perf_counter();c.disarm(active);replacement=c.draft(1,10)
    newkeys=crypto.dealer() if baseline else {d:crypto.dealer() for d in DOMAINS}
    if baseline:c.prepare_custody(replacement,newkeys);del replacement['shares']
    else:c.prepare(replacement,newkeys,epoch=2)
    c.arm(replacement);measure.setdefault('retire_and_fresh_capsule_rotation',[]).append((time.perf_counter()-start)*1000)
# Pure computation, n=40; no network or durable write in these samples.
for _ in range(40):
    timed('pure_key_generation',lambda:crypto.dealer() if baseline else [crypto.dealer(),crypto.dealer()])
    d='custody';public=keys[0] if baseline else keys[d][0];share=keys[1]['1'] if baseline else keys[d][1]['1'];R=crypto.encode(43*crypto.G);ctx={'v':7,'benchmark':'pure'}
    p=timed('pure_partial_generation',lambda:crypto.partial(public,share,1,R,ctx));timed('pure_partial_verification',lambda:crypto.verify_partial(public,R,ctx,p))
    timed('pure_wrap',lambda:crypto.wrap(public,os.urandom(16),ctx) if baseline else [crypto.wrap(keys[x][0],os.urandom(16),{**ctx,'domain':x}) for x in DOMAINS])
cpu_elapsed=time.process_time()-cpu
# Memory tracing is isolated from latency samples; maxrss covers the entire client.
tracemalloc.start();crypto.partial(public,share,1,R,ctx);current,peak=tracemalloc.get_traced_memory();tracemalloc.stop();out={'provider':'0.6' if baseline else '0.7','environment':'one local Docker host; TLS; sequential independent fresh clusters; eight Capsules, two windows, one checkin then one miss','samples':{n:{'n':len(v),'median_ms':round(statistics.median(v),3),'observed_max_ms':round(max(v),3)} for n,v in measure.items()},'wire_last_sample':wire,'client_cpu_seconds':round(cpu_elapsed,3),'separate_single_partial_tracemalloc_peak_bytes':peak,'client_maxrss_linux_kib':resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,'resource_scope':'CPU/maxrss cover client process only; Python heap probe is one separate partial, outside latency measurements; cgroup holder stats captured by orchestrator; no p95/p99 from n=8','rotation':'eight measured retirement + fresh Capsule/key operations; total24 Capsule rows per provider; no in-place refresh because unsupported'}
print(json.dumps(out,indent=2))
