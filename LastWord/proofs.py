"""Portable finality verification; no timestamps decide terminal order."""
import copy
from functools import lru_cache
from Bounded.wire import strict_json
from Engine.protocol import canonical,digest,sign
from Available.proofs import require,checked_signature,manifest,fence_certificate,release
from Missing.protocol import commitment as split_commitment,context as old_context,DOMAINS

def same(a,b):return canonical(a)==canonical(b)

SUITE='otherwise08-pbft-single-terminal-split-dh'
CAPABILITIES={'v':8,'suite':SUITE,'faults':1,'committee':4,'prepare':3,'commit':3,'model':'AUTHORISATION_WINS','missing_domain_required':True,'combined_quorum_enforcement':False,'reviewed':False}

def _registry_uncached(signed):
    r=signed['message'];require(set(r)=={'v','suite','split','committee','model','operation'},'registry fields')
    c,m=split_commitment(r['split']);require(r['v']==8 and type(r['v']) is int and r['suite']==SUITE and r['model']=='AUTHORISATION_WINS' and r['operation']=='terminal-1','registry version/model')
    require(type(r['committee'].get('epoch')) is int and same(r['committee'],{'epoch':1,'keys':m['witnesses']}),'immutable finality membership; no hot replacement')
    checked_signature(m['policy']['owner'],signed);return r,c,m

@lru_cache(maxsize=128)
def _registry_cache(raw):return _registry_uncached(strict_json(raw))
def registry(signed):
    # Immutable canonical bytes key the cache; return fresh objects to prevent cache poisoning.
    return copy.deepcopy(_registry_cache(canonical(signed)))

def scope(reg):
    r,c,m=registry(reg);return {'v':8,'suite':SUITE,'capsule':m['capsule'],'registry':digest(reg),'membership_epoch':1,'operation':'terminal-1'}

def value(reg,v):
    r,c,m=registry(reg);require(set(v)=={'scope','kind','arm','evidence','command'} and same(v['scope'],scope(reg)) and v['kind'] in ('RELEASE','DISARM'),'terminal value scope')
    fence_certificate(c['manifest'],v['arm'],'ARM')
    if v['kind']=='RELEASE':
        require(v['command'] is None and v['evidence']['manifest']==c['manifest'],'release value');release(v['evidence'])
    else:
        require(v['evidence'] is None,'disarm evidence field');checked_signature(m['policy']['owner'],v['command']);require(same(v['command']['message'],{**scope(reg),'action':'DISARM'}),'owner disarm scope')
    return v

def vote_message(reg,phase,view,v,index):
    require(type(view) is int and 0<=view<=64 and phase in ('PREPARE','COMMIT'),'bounded view/phase')
    return {**scope(reg),'kind':phase,'view':view,'value':digest(v),'witness':index}

def votes(reg,phase,view,v,items):
    r,c,m=registry(reg);require(type(items) is list and 3<=len(items)<=4,'vote quorum');seen=set()
    for item in items:
        i=item['message']['witness'];require(type(i) is int and i in (1,2,3,4) and i not in seen,'distinct voters');seen.add(i);checked_signature(m['witnesses'][str(i)],item)
        require(same(item['message'],vote_message(reg,phase,view,v,i)),'vote domain/phase')
    return True

def prepared(reg,pc):
    require(set(pc)=={'view','value','prepares'},'prepared certificate');value(reg,pc['value']);votes(reg,'PREPARE',pc['view'],pc['value'],pc['prepares']);return pc

def checked_change(reg,view,item):
    r,c,m=registry(reg);q=item['message'];require(set(q)==set(scope(reg))|{'kind','view','prepared','witness'},'view-change fields');i=q['witness'];require(type(i) is int and i in (1,2,3,4),'view-change source');checked_signature(m['witnesses'][str(i)],item)
    require(same({k:q[k] for k in scope(reg)},scope(reg)) and q['kind']=='VIEW_CHANGE' and type(q['view']) is int and q['view']==view,'view-change scope')
    if q['prepared'] is not None:
        p=prepared(reg,q['prepared']);require(p['view']<view,'prepared must predate view change')
    return q

def view_changes(reg,view,changes):
    require(type(view) is int and 1<=view<=64 and 3<=len(changes)<=4,'view-change quorum');seen=set();proofs=[]
    for item in changes:
        q=checked_change(reg,view,item);i=q['witness'];require(i not in seen,'duplicate view-change source');seen.add(i)
        if q['prepared'] is not None:proofs.append(q['prepared'])
    if not proofs:return None
    top=max(p['view'] for p in proofs);latest=[p for p in proofs if p['view']==top];require(len({digest(p['value']) for p in latest})==1,'conflicting highest prepared certificates')
    return latest[0]

def proposal(reg,signed):
    r,c,m=registry(reg);q=signed['message'];require(set(q)=={'scope','kind','view','value','changes','leader'} and same(q['scope'],scope(reg)) and q['kind']=='PROPOSAL','proposal scope')
    n=q['view'];require(type(n) is int and 0<=n<=64 and q['leader']==1+n%4,'rotating leader');checked_signature(m['witnesses'][str(q['leader'])],signed);value(reg,q['value'])
    if n==0:require(q['changes']==[],'initial view changes')
    else:
        highest=view_changes(reg,n,q['changes']);require(highest is None or highest['value']==q['value'],'new view abandons prepared value')
    return q

def finality(reg,cert):
    require(set(cert)=={'v','registry','view','value','prepares','commits'} and cert['v']==8 and type(cert['v']) is int and cert['registry']==digest(reg),'finality certificate scope')
    value(reg,cert['value']);votes(reg,'PREPARE',cert['view'],cert['value'],cert['prepares']);votes(reg,'COMMIT',cert['view'],cert['value'],cert['commits']);return {'kind':cert['value']['kind'],'value':digest(cert['value']),'view':cert['view']}

def contribution_context(reg,fin,domain):
    r,c,m=registry(reg);result=finality(reg,fin);require(result['kind']=='RELEASE' and domain in DOMAINS,'no release commitment')
    return {**old_context(r['split'],fin['value']['evidence'],domain),'v':8,'suite':SUITE,'registry':digest(reg),'final_decision':digest(fin['value']),'finality_certificate':digest(fin),'membership_epoch':1,'release_operation':'terminal-1'}
