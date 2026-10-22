"""Check a source manifest against an independently authenticated expected hash.
This helper is not secure boot; run verification from an already trusted toolchain.
"""
import argparse
import hashlib
import json
from pathlib import Path
from Engine.protocol import canonical,digest

def files():
    paths=[]
    for root in ['Engine','Bounded','Available','Untrusted','Verifier','tests05']:
        paths += [p for p in Path(root).rglob('*') if p.is_file() and '__pycache__' not in p.parts]
    paths += [Path(p) for p in ['requirements.txt','Dockerfile.protocol05','scripts/conformance04.py','scripts/conformance05.py','Protocol/vectors/generation04.json','Protocol/vectors/generation05.json']]
    return {str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--write',action='store_true');p.add_argument('--manifest',default='Protocol/client05-build.json');p.add_argument('--expected');a=p.parse_args();path=Path(a.manifest)
    if a.write:path.write_text(json.dumps({'v':5,'files':files()},indent=2)+'\n');return
    blob=json.loads(path.read_text());assert a.expected and digest(blob)==a.expected,'source manifest differs from independent expected hash';assert blob=={'v':5,'files':files()},'installed client source/dependency manifest differs';print(json.dumps({'verified':True,'source_manifest_sha256':digest(blob),'trust_requirement':'expected digest and verification toolchain must be obtained independently of SaaS'}))
if __name__=='__main__':main()
