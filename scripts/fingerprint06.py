"""Local review fingerprint, NOT self-authentication or a signed update channel."""
import hashlib,json
from pathlib import Path
root=Path(__file__).resolve().parent.parent
paths=[]
for name in ['Engine','Bounded','Available','Untrusted','Honest','Verifier','tests06']:
    paths += [p for p in (root/name).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix!='.pyc']
paths += [root/'requirements.txt',root/'Dockerfile.protocol06',root/'compose06.yaml',root/'compose05.yaml']
files={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
raw=json.dumps(files,sort_keys=True,separators=(',',':')).encode();out={'v':6,'scope':'source review fingerprint; authenticate digest independently','files':files,'sha256':hashlib.sha256(raw).hexdigest()}
(root/'Protocol/client06-build.json').write_text(json.dumps(out,indent=2)+'\n');print(out['sha256'])
