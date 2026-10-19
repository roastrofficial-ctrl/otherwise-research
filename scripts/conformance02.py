"""Check fixed vectors and generated nested histories against Python and JavaScript.
On disagreement, greedily shrink the event list and print the permanent counterexample.
"""
import copy
import json
import random
import subprocess
import sys
import tempfile
from pathlib import Path
from Engine.protocol import canonical, digest, sign
from Engine.store import Engine
from Bounded.verify import validate_snapshot, check_manifest, validate_bundle
from Bounded.wire import strict_json
from make_vectors02 import policy, owner, evidence, rechain


def python_result(s):
    try:return {'ok':True,**validate_snapshot(s)}
    except Exception:return {'ok':False}

def js_results(snapshots):
    proc=subprocess.run(['node','Verifier/verify.mjs','--lines'],input=b'\n'.join(canonical(s) for s in snapshots)+b'\n',capture_output=True,check=True)
    return [{k:v for k,v in strict_json(line).items() if k!='error'} for line in proc.stdout.splitlines()]

def differs(s):return python_result(s)!=js_results([s])[0]

def shrink(s):
    current=copy.deepcopy(s);changed=True
    while changed:
        changed=False
        for i in range(len(current['events'])):
            candidate=copy.deepcopy(current);del candidate['events'][i];rechain(candidate)
            if differs(candidate):current=candidate;changed=True;break
    return current

def generated():
    rng=random.Random(20261015);cases=[]
    for i in range(90):
        with tempfile.TemporaryDirectory() as root:
            e=Engine(root);keys,p=policy()
            p['expression']=rng.choice([{'op':'AND','args':['A',{'op':'OR','args':['B','C']}]},
                {'op':'OR','args':['A',{'op':'AND','args':['B','C']}]},
                {'op':'THRESHOLD','k':2,'args':['A',{'op':'THRESHOLD','k':1,'args':['B','C']}]}])
            cid='generated-'+str(i);e.import_encrypted(cid,p,b'generated-ciphertext');owner(e,cid,keys[0],'ARMED')
            order=list(range(3));rng.shuffle(order)
            for index in order:
                pair=evidence(e,cid,keys,p,index,claim=bool(rng.randrange(2)),until=rng.choice([2,100]))
                e.submit(cid,*pair);e.submit(cid,*pair)
            if i%5==0:e.submit(cid,*evidence(e,cid,keys,p,0,claim=False,ident='contradiction'))
            if i%7==0:owner(e,cid,keys[0],'DISARMED')
            e.authorise(cid);cases.append(e.export(cid));e.tick(5);e.authorise(cid);cases.append(e.export(cid))
    return cases

def main():
    corpus=strict_json(Path('Protocol/vectors/generation02.json').read_bytes())
    check_manifest(**corpus['signed_manifest'])
    validate_bundle(corpus['witness_bundle'],corpus['signed_manifest']['manifest'])
    snapshots=[v['snapshot'] for v in corpus['vectors']];expected=[v['expected'] for v in corpus['vectors']]
    snapshots.extend(generated());answers=js_results(snapshots)
    if len(answers)!=len(snapshots):raise AssertionError('missing JavaScript results')
    for i,(s,js) in enumerate(zip(snapshots,answers)):
        py=python_result(s)
        if py!=js:
            print('DISAGREEMENT',i,json.dumps(shrink(s),sort_keys=True));raise AssertionError('portable disagreement')
        if i<len(expected) and py!=expected[i]:
            print('VECTOR FAILURE',corpus['vectors'][i]['name'],py,expected[i]);raise AssertionError('fixed expectation')
    # Parser cases are raw to preserve duplicate names.
    raw='{"capsule":"first","capsule":"second"}'
    proc=subprocess.run(['node','Verifier/verify.mjs','--lines'],input=raw.encode()+b'\n',capture_output=True,check=True)
    assert not strict_json(proc.stdout)['ok']
    try:strict_json(raw)
    except ValueError:pass
    else:raise AssertionError('Python discarded duplicate key')
    print('Fixed signed vectors:',len(expected))
    print('Generated nested/adversarial snapshots:',len(snapshots)-len(expected))
    print('Python / JavaScript disagreements: 0')
    print('Duplicate-key parser rejection: both implementations')
    print('Conformance OK')

if __name__=='__main__':main()
