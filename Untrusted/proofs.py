"""Fresh signed status extension; old lifecycle messages retain wire version 4."""
import re
from Engine.protocol import digest
from Available.proofs import manifest,checked_signature,require

def snapshot(sm,signed,nonce,index):
    m=manifest(sm);r=signed['message']
    require(set(r)=={'v','kind','capsule','manifest','nonce','witness','records','clock'},'snapshot fields')
    require(type(r['v']) is int and r['v']==5 and r['kind']=='INSPECT' and r['capsule']==m['capsule'] and r['manifest']==digest(m),'snapshot domain')
    require(type(nonce) is str and re.fullmatch('[0-9a-f]{64}',nonce) and r['nonce']==nonce,'fresh inspection challenge')
    require(type(r['witness']) is int and r['witness']==index and str(index) in m['witnesses'],'snapshot source')
    checked_signature(m['witnesses'][str(index)],signed)
    t=r['clock'];require(set(t)=={'lower','upper','healthy','reason'} and t['healthy'] is True and type(t['lower']) is int and type(t['upper']) is int and 0<=t['lower']<=t['upper'],'snapshot clock')
    require(type(r['records']) is list,'snapshot records')
    return r
