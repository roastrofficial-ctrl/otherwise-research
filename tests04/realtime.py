"""Real wall/monotonic clock Solo demonstration; no clock fault endpoint."""
import json
import os
import time
from Available.lifecycle import Client
from Available.transport import HttpClientTransport
c=Client(HttpClientTransport());k=c.draft(os.environ['WITNESSES'].split(','),os.environ['CUSTODIANS'].split(','),2,10);c.arm(k)
end=time.monotonic()+8
while True:
    try:c.checkin(k,'1');break
    except ValueError:
        if time.monotonic()>end:raise
        time.sleep(.5)
while time.time()<=k['manifest']['message']['slots'][-1]['deadline']+8:time.sleep(.5)
d=c.evaluate(k);assert d['authorised'],d
assert c.simulate(k,d['certificate'])['delivery']=='SIMULATED'
print(json.dumps({'clock':'real UTC + monotonic continuity','clock_injection':False,'accepted_first_checkin':True,'missed_second_checkin_authorised':True,'simulated_delivery':True,'elapsed_seconds':round(time.time()-k['manifest']['message']['policy']['contracts'][0]['start'],1)},indent=2))
