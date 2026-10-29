"""Preserve and rerun Generations0.1–0.7 without changing historical artifacts."""
from pathlib import Path
import subprocess,tempfile,shlex
root=Path(__file__).resolve().parent.parent;out=root/'doc/results08';(out/'history').mkdir(parents=True,exist_ok=True);(out/'history07').mkdir(exist_ok=True)
with tempfile.TemporaryDirectory(prefix='otherwise08-history-') as td:
    p=Path(td)
    src=(root/'scripts/regression07.py').read_text().replace('root=Path(__file__).resolve().parent.parent','root=Path('+repr(str(root))+')',1).replace('doc/results07','doc/results08/history')
    (p/'older.py').write_text(src)
    with (out/'history-01-06.txt').open('w') as log:subprocess.run(['python3',str(p/'older.py')],cwd=root,stdout=log,stderr=subprocess.STDOUT,check=True)
    s=(root/'scripts/experiment07.sh').read_text().replace('cd "$(dirname "$0")/.."','cd '+shlex.quote(str(root))).replace('doc/results07','doc/results08/history07')
    (p/'generation07.sh').write_text(s)
    with (out/'history07-run.txt').open('w') as log:subprocess.run(['sh',str(p/'generation07.sh')],cwd=root,stdout=log,stderr=subprocess.STDOUT,check=True)
print('All preserved 0.1–0.7 suites and successful attacks rerun; original evidence unchanged.')
