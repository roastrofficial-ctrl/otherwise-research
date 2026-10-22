import json
import os
import statistics
import tempfile
import time
from pathlib import Path
from Engine.protocol import canonical,sign,verify
from Untrusted.client import public
from Untrusted.vault import seal,unseal,opened
from helpers import configured
trust,c=configured();kit=c.draft(2,10);c.run(kit,'arm')
def sample(fn,n):
    out=[]
    for _ in range(n):
        t=time.perf_counter();fn();out.append((time.perf_counter()-t)*1000)
    return {'samples':n,'median_ms':round(statistics.median(out),3),'max_sample_ms':round(max(out),3)}
password=os.environ['OTHERWISE_CREATOR_PASSPHRASE'];blob=seal(kit,password);private=c.private(kit);msg=c.command(kit,'ARM')['message'];sig=sign(private,msg)
report={'scope':'one Docker host; synthetic data; not WAN or production latency','scrypt_parameters':{'n':32768,'r':8,'p':1,'memory_bytes_approx':128*32768*8},'vault_seal':sample(lambda:seal(kit,password),10),'vault_open':sample(lambda:unseal(blob,password),10),'ed25519_sign':sample(lambda:sign(private,msg),200),'ed25519_verify':sample(lambda:verify(kit['manifest']['message']['policy']['owner'],msg,sig),200)}
report['checkin_with_direct_retention']=sample(lambda:c.run(kit,'checkin',challenge='1'),5);report['fresh_status_with_node_verification']=sample(lambda:c.inspect(kit),5)
report['encrypted_vault_bytes']=len(canonical(seal(kit,password)));report['public_projection_bytes']=len(canonical(public(kit)));report['creator_local_plaintext_capability_bytes']=len(canonical(kit));report['witness_logical_state_bytes']={p['url']:len(canonical(c.call(p['url']+'/status?capsule='+kit['manifest']['message']['capsule']))) for p in trust['providers'] if p['role']=='witness'}
print(json.dumps(report,indent=2))
