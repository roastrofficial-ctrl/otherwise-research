"""Executed around a real Docker witness process stop/start."""
import json
import os
import sys
from pathlib import Path
from Available.lifecycle import Client
from Bounded.wire import atomic_json,strict_json,request
p=Path('/recovery/process.json');c=Client();w=os.environ['WITNESSES'].split(',');k=os.environ['CUSTODIANS'].split(',')
if sys.argv[1]=='before':
    kit=c.draft(w,k,1,10);c.arm(kit);atomic_json(p,kit);print('Capsule armed before witness process stop.')
elif sys.argv[1]=='during':
    kit=strict_json(p.read_bytes());assert c.checkin(kit,'1')['accepted'];atomic_json(p,kit);print('Check-in accepted with one Docker witness process stopped.')
else:
    kit=strict_json(p.read_bytes());result=c.repair(kit,4);assert result['repaired'];assert c.recover(kit)['accepted_checkins']==1
    end=kit['manifest']['message']['slots'][-1]['deadline']+6;now=max(end,max(request(u+'/clock')['upper'] for u in w))
    for u in w:request(u+'/test-clock',{'now':now},os.environ['OTHERWISE_04_FAULT_TOKEN'])
    assert not c.evaluate(kit)['authorised'];print('Restarted witness required owner-authenticated three-peer repair; accepted presence survived and vetoed absence.')
