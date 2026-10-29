"""Run every preserved generation without overwriting historical evidence."""
from pathlib import Path
import os,subprocess,tempfile,shlex
root=Path(__file__).resolve().parent.parent;out=root/'doc/results07';(out/'regression06').mkdir(parents=True,exist_ok=True)
with tempfile.TemporaryDirectory(prefix='otherwise07-regression-') as td:
    temp=Path(td)
    # This existing driver already isolates 0.1–0.5 projects and internal Laravel ports.
    src=(root/'scripts/regression06.py').read_text().replace("root=Path(__file__).resolve().parent.parent",'root=Path('+repr(str(root))+')').replace('doc/results06/regression','doc/results07/regression')
    driver=temp/'older.py';driver.write_text(src)
    if '--06-only' not in __import__('sys').argv:
        with (out/'older-regression.txt').open('w') as log:subprocess.run(['python3',str(driver)]+(['--05-only'] if '--05-and-06' in __import__('sys').argv else []),cwd=root,stdout=log,stderr=subprocess.STDOUT,check=True)
    s=(root/'scripts/experiment06.sh').read_text().replace('cd "$(dirname "$0")/.."','cd '+shlex.quote(str(root))).replace('doc/results06','doc/results07/regression06')
    p=temp/'generation06.sh';p.write_text(s);p.chmod(0o700)
    with (out/'generation06-regression.txt').open('w') as log:subprocess.run([str(p)],cwd=root,stdout=log,stderr=subprocess.STDOUT,check=True)
print('Preserved 0.1–0.6 tests and attacks complete; originals unchanged.')
