import base64,json,os,sys
from pathlib import Path
from Bounded.wire import request,atomic_json,strict_json
from Missing.client import Client,recover
from Untrusted.vault import seal,unseal
from helpers import configured,move,W,K,A,TOKEN
password=os.environ['OTHERWISE_CREATOR_PASSPHRASE'];stage=sys.argv[1]
if stage=='before':
    trust,c=configured();atomic_json('/recovery/public-trust07.json',trust)
else:
    trust=strict_json(Path('/recovery/public-trust07.json').read_bytes());c=Client(trust)
if stage=='before':
    k=c.draft(2,10);c.prepare(k);c.arm(k);atomic_json('/recovery/old07.ovault',seal(k,password));c.checkin(k,'1');atomic_json('/recovery/current07.ovault',seal(k,password));Path('/recovery/current07.ovault').unlink();print('Encrypted backup precedes accepted presence; current creator vault deleted. No SaaS or database exists in this deployment.')
elif stage=='stopped':
    k=unseal(strict_json(Path('/recovery/old07.ovault').read_bytes()),password);s=c.inspect(k);assert s['accepted_checkins']==1;move(k,11);assert c.checkin(k,'2')['accepted'];assert c.disarm(k)['state']=='DISARMED';atomic_json('/recovery/restored07.ovault',seal(k,password));print('With aw4 process stopped: old backup recovered later accepted presence, new checkin accepted, durable disarm verified.')
    missed=c.draft(1,10);c.prepare(missed);c.arm(missed);move(missed,16);cert=c.evaluate(missed)['certificate'];assert b'synthetic' in c.disclose(missed,cert);atomic_json('/recovery/missed07.ovault',seal(missed,password));print('With one witness permanently absent for this operation, valid 3/4 evidence and 2/3 in each capability domain completed disclosure.')
elif stage=='repaired':
    k=unseal(strict_json(Path('/recovery/restored07.ovault').read_bytes()),password);c.repair(k,4);assert c.inspect(k)['state']=='DISARMED';print('Actual witness restart: existing owner-authorised peer repair preserved disarm and presence. Journal repair is separately limited: original wire4 checkpoint does not transfer v7 operation journals; three surviving holders retain them.')
