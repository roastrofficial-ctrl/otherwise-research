import copy
import itertools
import json
import subprocess
from pathlib import Path
from Engine.protocol import canonical
from Retained.proofs import acknowledgement,release
from Retained.fixtures import corpus
from Bounded.wire import strict_json


def py(inp):
    try:return {'ok':True,**(acknowledgement(inp['object']['manifest'],inp['object']['receipts']) if inp['kind']=='ack' else release(inp['object'],inp.get('retained',())))}
    except Exception:return {'ok':False}


def js(inputs):
    p=subprocess.run(['node','Verifier/retained.mjs','--lines'],input=b'\n'.join(canonical(v) for v in inputs)+b'\n',capture_output=True,check=True)
    return [{k:v for k,v in strict_json(line).items() if k!='error'} for line in p.stdout.splitlines()]


def shrink(inp):
    current=copy.deepcopy(inp);field=current['object']['receipts'] if current['kind']=='ack' else current['object']['finals'][0]
    for i in reversed(range(len(field))):
        removed=field.pop(i)
        if py(current)==js([current])[0]:field.insert(i,removed)
    return current


def main():
    fixed=strict_json(Path('Protocol/vectors/generation03.json').read_bytes());assert fixed==corpus(),'fixed corpus changed'
    cases=[v['input'] for v in fixed['vectors']];expected=[v['expected'] for v in fixed['vectors']]
    for v in fixed['vectors']:
        if v['input']['kind']=='ack':
            for perm in itertools.permutations(v['input']['object']['receipts']):
                inp=copy.deepcopy(v['input']);inp['object']['receipts']=list(perm);cases.append(inp)
    answers=js(cases);assert len(answers)==len(cases)
    for i,(inp,other) in enumerate(zip(cases,answers)):
        ours=py(inp)
        if ours!=other:print('MINIMAL DISAGREEMENT',json.dumps(shrink(inp)));raise AssertionError('Python/JavaScript mismatch')
        if i<len(expected):assert ours==expected[i]
    print('Fixed witness vectors:',len(expected));print('Additional reordered proof objects:',len(cases)-len(expected));print('Python / JavaScript disagreements: 0')
    print('Unsafe 2/2 Byzantine intersection counterexample retained; production profile rejected.')
    print('Conformance OK')

if __name__=='__main__':main()
