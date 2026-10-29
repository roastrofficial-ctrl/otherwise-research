"""Review fingerprint only; authenticate release/digest independently."""
import hashlib,json
from pathlib import Path
root=Path(__file__).resolve().parent.parent;paths=[]
for name in ['Engine','Bounded','Available','Untrusted','Honest','Missing','LastWord','Verifier','tests08']:
    paths += [p for p in (root/name).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc']
paths += [root/n for n in ['requirements.txt','Dockerfile.protocol08','compose08.yaml','scripts/conformance08.py','Protocol/vectors/generation08.json']]
files={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)};raw=json.dumps(files,sort_keys=True,separators=(',',':')).encode();v={'v':8,'scope':'source review fingerprint; not a signature, update channel or reproducible toolchain proof','files':files,'sha256':hashlib.sha256(raw).hexdigest()};(root/'Protocol/client08-build.json').write_text(json.dumps(v,indent=2)+'\n');print(v['sha256'])
