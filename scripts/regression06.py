"""Rerun original generation scripts without rewriting their retained results.
Temporary script copies only redirect artifacts and add explicit disposable subnets.
"""
import os
import sys
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
root=Path(__file__).resolve().parent.parent
out=root/'doc/results06/regression';out.mkdir(parents=True,exist_ok=True)
for gen in ['02','03','04','05']:(out/('generation'+gen)).mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='otherwise06-regression-') as td:
    tmp=Path(td)
    for name,network,subnet in [('old','custody','10.206.7.0/24'),('04','protocol','10.206.8.0/24'),('05','protocol','10.206.9.0/24')]:
        # 0.5 consumer adds two networks; give each an unused explicit range.
        text=f'networks:\n  {network}:\n    ipam:\n      config: [{{subnet: {subnet}}}]\n'
        if name=='05':text+='  product:\n    ipam:\n      config: [{subnet: 10.206.10.0/24}]\n  browser:\n    ipam:\n      config: [{subnet: 10.206.11.0/24}]\n'
        if name=='05':text+='services:\n  laravel:\n    ports: !reset []\n'
        (tmp/f'network{name}.yaml').write_text(text)
    names=['experiment02.sh','experiment03.sh','regression04-for05.sh','experiment05.sh','lab04.sh','lab05.sh']
    for name in names:
        text=(root/'scripts'/name).read_text()
        text=text.replace('cd "$(dirname "$0")/.."','cd '+shlex.quote(str(root)))
        # Longest replacements first; keep every pre-existing raw artifact untouched.
        for gen in ['05','04','03','02']:
            text=text.replace('doc/results'+gen,str(out/('generation'+gen)))
        text=text.replace('docker compose --profile','docker compose -f compose.yaml -f '+shlex.quote(str(tmp/'networkold.yaml'))+' --profile')
        # Plain non-profile commands in old scripts.
        text=text.replace('docker compose run','docker compose -f compose.yaml -f '+shlex.quote(str(tmp/'networkold.yaml'))+' run')
        if name=='lab04.sh':text=text.replace('-f compose04.yaml','-f compose04.yaml -f '+shlex.quote(str(tmp/'network04.yaml')))
        if name=='lab05.sh':text=text.replace('-f compose05.yaml','-f compose05.yaml -f '+shlex.quote(str(tmp/'network05.yaml')))
        for ref in names:text=text.replace('./scripts/'+ref,shlex.quote(str(tmp/ref)))
        path=tmp/name;path.write_text(text);path.chmod(0o700)
    sequence=['regression04-for05.sh','experiment05.sh'] if '--remaining' in sys.argv else ['experiment03.sh','regression04-for05.sh','experiment05.sh']
    if '--05-only' in sys.argv:sequence=['experiment05.sh']
    for name in sequence:
        with (out/(name+'.log')).open('w') as log:
            subprocess.run([str(tmp/name)],cwd=root,stdout=log,stderr=subprocess.STDOUT,check=True)
    print('All original generation scripts completed; artifacts:',out)
