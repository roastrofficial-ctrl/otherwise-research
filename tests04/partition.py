import os
import sys
from pathlib import Path
from Available.lifecycle import Client
from Bounded.wire import atomic_json,strict_json,request
p=Path('/recovery/partition.json');c=Client();w=os.environ['WITNESSES'].split(',');k=os.environ['CUSTODIANS'].split(',')
if sys.argv[1]=='before':
    kits=[c.draft(w,k,1,10) for _ in range(2)]
    for kit in kits:c.arm(kit)
    atomic_json(p,kits);print('Two Capsules armed before actual Docker network isolation.')
else:
    kits=strict_json(p.read_bytes());assert c.checkin(kits[0],'1')['accepted']
    assert len(kits[0]['acknowledgements'][0]['receipts'])==3
    now=max(x['manifest']['message']['slots'][0]['deadline'] for x in kits)+6
    for u in w[:3]:request(u+'/test-clock',{'now':now},os.environ['OTHERWISE_04_FAULT_TOKEN'])
    assert not c.evaluate(kits[0])['authorised'];d=c.evaluate(kits[1]);assert d['authorised'];assert c.simulate(kits[1],d['certificate'])['delivery']=='SIMULATED'
    print('Live but network-disconnected fourth witness: three retained check-in receipts protect presence; independent absent Capsule reaches simulated release with three reachable members.')
