import json
import math
import os
import statistics
import time
from Available.lifecycle import Client
from Engine.protocol import canonical
from Bounded.wire import request
c=Client();w=os.environ['WITNESSES'].split(',');cust=os.environ['CUSTODIANS'].split(',');token=os.environ['OTHERWISE_04_FAULT_TOKEN']
def batch(missing,n):
    values=[];sizes=[]
    if missing:request(w[-1]+'/test-availability',{'available':False},token)
    try:
        for _ in range(n):
            k=c.draft(w,cust,1,10);c.arm(k);start=time.perf_counter();c.checkin(k,'1');values.append((time.perf_counter()-start)*1000);sizes.append(len(canonical(k['acknowledgements'][0])))
    finally:
        if missing:request(w[-1]+'/test-availability',{'available':True},token)
    return {'samples':n,'median_ms':round(statistics.median(values),3),'p95_nearest_rank_ms':round(sorted(values)[math.ceil(.95*n)-1],3),'ack_with_holder_proofs_bytes_mean':round(statistics.mean(sizes))}
print(json.dumps({'scope':'single Docker host; sequential fsync + direct witness/custody receipt distribution; no WAN estimate','all_four':batch(False,10),'one_fast_refusal':batch(True,5)},indent=2))
