"""Source review fingerprint, not authentication of itself or a secure update service."""
import hashlib,json
from pathlib import Path
root=Path(__file__).resolve().parent.parent;paths=[]
for name in ['Engine','Bounded','Available','Untrusted','Honest','Missing','Verifier','tests07']:
    paths += [p for p in (root/name).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc']
paths += [root/n for n in ['requirements.txt','Dockerfile.protocol07','compose07.yaml','scripts/conformance07.py','Protocol/vectors/generation07.json']]
files={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)};raw=json.dumps(files,sort_keys=True,separators=(',',':')).encode();result={'v':7,'scope':'source review only; authenticate digest independently','files':files,'sha256':hashlib.sha256(raw).hexdigest()};(root/'Protocol/client07-build.json').write_text(json.dumps(result,indent=2)+'\n');print(result['sha256'])
