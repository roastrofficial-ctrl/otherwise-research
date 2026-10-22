"""The Hostile SaaS: persistent independent vault across outage/loss/restart."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from Bounded.wire import strict_json
from Untrusted.vault import unseal
from helpers import configured,mode,move
root=Path('/recovery/hostile-lifecycle');root.mkdir(exist_ok=True);owner=root/'owner.ovault';backup=root/'offline-backup.ovault';replacement=root/'replacement.ovault';rotated=root/'rotated.ovault';password=os.environ['OTHERWISE_CREATOR_PASSPHRASE']
def cli(path,action,*args,relay=False,allow_failure=False):
    cmd=['python','-m','Untrusted.cli','--trust','/recovery/trust.json','--vault',str(path)]
    if relay:cmd+=['--relay','http://laravel:8000']
    p=subprocess.run(cmd+[action,*args],capture_output=True,text=True)
    if allow_failure:assert p.returncode!=0;return
    assert p.returncode==0,p.stderr
    return json.loads(p.stdout)
def kit(path):return unseal(strict_json(path.read_bytes()),password)
def main():
    phase=sys.argv[1]
    if phase=='before':
        configured();mode('false-success');cli(owner,'create','--seconds','10');cli(owner,'backup','--out',str(backup));cli(owner,'arm');cli(owner,'publish','--saas','http://laravel:8000')
        cli(owner,'checkin','--challenge','1',relay=True,allow_failure=True)
        assert cli(owner,'checkin','--challenge','1')['accepted'];assert cli(owner,'status')['accepted_checkins']==1
        print('Hostile SaaS false-success rejected; independent create/encrypt/commit/arm/check-in/fresh verification passed. Offline encrypted backup predates presence acknowledgement.')
    elif phase=='after':
        for host,port in [('laravel',8000),('hostile',8080),('product-db',5432)]:
            try:s=socket.create_connection((host,port),2)
            except OSError:print(host+': unavailable (verified)')
            else:s.close();raise AssertionError('SaaS still available')
        owner.unlink();cli(replacement,'restore','--out',str(backup));assert cli(replacement,'recover')['accepted_checkins']==1
        move(kit(replacement),11);assert cli(replacement,'checkin','--challenge','2')['accepted'];assert cli(replacement,'disarm')['state']=='DISARMED'
        cli(replacement,'rotate','--out',str(rotated),'--seconds','10')
        assert kit(rotated)['manifest']['message']['policy']['owner']!=kit(replacement)['manifest']['message']['policy']['owner']
        print('After SaaS/database/backend loss + device vault deletion: offline restore, fresh presence recovery, new check-in, disarm and fresh-Capsule/key rotation passed; no operator recovery capability used.')
    elif phase=='during-restart':
        assert cli(rotated,'checkin','--challenge','1')['accepted'];assert cli(rotated,'status')['sources']==3
        print('Replacement client accepted and verified presence with one actual witness process stopped.')
    elif phase=='after-restart':
        assert cli(rotated,'repair','--index','4')['repaired'];assert cli(rotated,'status')['accepted_checkins']==1
        print('After actual witness restart: owner-authorised peer repair + fresh signed status retained presence.')
        # Legitimate release continues without a SaaS worker, using a different missed Capsule.
        missed=root/'missed.ovault';cli(missed,'create','--seconds','10','--rounds','1');cli(missed,'arm');move(kit(missed),16);assert cli(missed,'simulate')['delivery']=='SIMULATED'
        print('Independent missed-window evaluation and synthetic disclosure passed with SaaS still stopped.')
if __name__=='__main__':main()
