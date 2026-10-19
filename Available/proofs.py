"""Immutable per-challenge observations and finalisations, not total-order consensus."""
import re
from Engine.protocol import canonical,digest,verify,validate_policy


def require(condition,reason):
    if not condition: raise ValueError(reason)


def checked_signature(public,signed):
    require(set(signed)=={'message','signature'} and type(signed['signature']) is str and re.fullmatch('[0-9a-f]{128}',signed['signature']) is not None,'signed object encoding')
    verify(public,signed['message'],signed['signature'])


def manifest(signed):
    m=signed['message'];canonical(m)
    require(set(m)=={'v','capsule','epoch','policy','commitment','payload','witnesses','custody','quorum','slots','operation'},'manifest fields')
    require(type(m['v']) is int and m['v']==4 and type(m['epoch']) is int and type(m['epoch']) is int and m['epoch']==1,'version')
    require(1<=len(m['slots'])<=8 and 1<=len(m['policy']['contracts'])<=8,'bounded profile size')
    validate_policy(m['policy']);require(digest(m['policy'])==m['commitment'],'commitment')
    require(type(m['capsule']) is str and m['capsule'] and type(m['payload']) is str and re.fullmatch('[0-9a-f]{64}',m['payload']) is not None,'identity')
    require(set(m['witnesses'])=={'1','2','3','4'} and len(set(m['witnesses'].values()))==4,'witness identities')
    for key in [m['policy']['owner'],*[c['authority'] for c in m['policy']['contracts']],*m['witnesses'].values(),*m['custody']['keys'].values()]: require(type(key) is str and re.fullmatch('[0-9a-f]{64}',key) is not None,'canonical public key')
    q=m['quorum'];require(all(type(v) is int for v in q.values()),'quorum integer');require(q=={'presence':3,'absence':3,'faults':1},'unsafe quorum')
    require(set(m['custody'])=={'k','n','keys'} and m['custody']['k']==2 and m['custody']['n']==3 and set(m['custody']['keys'])=={'1','2','3'} and len(set(m['custody']['keys'].values()))==3,'custody configuration')
    require(m['operation']=={'attempt':'release-1','kind':'reconstruct-aes-128-gcm'},'operation')
    expected=[]
    for c in m['policy']['contracts']:
        if c['kind']=='absence':
            expected += [{'contract':c['id'],'challenge':ch['id'],'open':ch['open'],'deadline':ch['deadline']} for ch in c['challenges']]
        else:
            matches=[s for s in m['slots'] if s['contract']==c['id']]
            require(len(matches)==1 and matches[0]['challenge']=='attestation','attestation slot')
            s=matches[0];require(c['start']<=s['open']<=s['deadline'] and s['deadline']+1+m['policy']['grace']<c['end'],'attestation cutoff')
            expected.append(s)
    require(m['slots']==expected and all(set(s)=={'contract','challenge','open','deadline'} and type(s['open']) is int and type(s['deadline']) is int and s['open']>=0 for s in expected),'slot commitment/order')
    checked_signature(m['policy']['owner'],signed);return m


def slot(m,contract,challenge):
    found=next((s for s in m['slots'] if s['contract']==contract and s['challenge']==challenge),None)
    require(found is not None,'uncommitted slot');return found


def operation(m):
    return digest({'v':4,'capsule':m['capsule'],'epoch':m['epoch'],'manifest':digest(m),'commitment':m['commitment'],'payload':m['payload'],**m['operation']})


def proof(m,signed):
    p=signed['message']
    require(set(p)=={'v','id','capsule','manifest','contract','contract_version','challenge','authority','valid_from','valid_until','value'},'evidence schema')
    require(type(p['v']) is int and p['v']==4 and type(p['id']) is str and p['id'] and p['capsule']==m['capsule'] and p['manifest']==digest(m),'evidence domain')
    c=next((c for c in m['policy']['contracts'] if c['id']==p['contract']),None)
    require(c is not None and type(p['contract_version']) is int and p['contract_version']==c['version'] and p['authority']==c['authority'],'authority/version')
    s=slot(m,p['contract'],p['challenge'])
    require(type(p['value']) is bool and (c['kind']!='absence' or p['value'] is True),'claim value')
    require(type(p['valid_from']) is int and type(p['valid_until']) is int and c['start']<=p['valid_from']<p['valid_until']<=c['end'],'proof interval')
    checked_signature(c['authority'],signed);return c,s


def record(m,signed,kind):
    require(kind in ('OBSERVATION','FINAL'),'record kind');r=signed['message'];require(set(r)=={'v','kind','capsule','manifest','witness','contract','challenge','operation','seq','prev','lower','upper','proof','value','not_before'},'record fields')
    require(type(r['v']) is int and r['v']==4 and r['kind']==kind and r['capsule']==m['capsule'] and r['manifest']==digest(m) and r['operation']==operation(m),'record domain')
    require(str(r['witness']) in m['witnesses'] and type(r['witness']) is int,'witness identity')
    require(type(r['seq']) is int and r['seq']>=1 and type(r['prev']) is str and re.fullmatch('[0-9a-f]{64}',r['prev']) is not None,'lineage')
    require(type(r['lower']) is int and type(r['upper']) is int and 0<=r['lower']<=r['upper'],'clock interval')
    s=slot(m,r['contract'],r['challenge']);c=next(c for c in m['policy']['contracts'] if c['id']==s['contract'])
    require(r['not_before']==s['deadline']+1+m['policy']['grace'],'deadline/grace binding')
    checked_signature(m['witnesses'][str(r['witness'])],signed)
    if r['proof'] is not None:
        pc,ps=proof(m,r['proof']);require(pc==c and ps==s,'proof slot substitution')
    if kind=='OBSERVATION':
        require(r['proof'] is not None,'missing proof')
        p=r['proof']['message']
        require(s['open']<=r['lower'] and r['upper']<=s['deadline'] and p['valid_from']<=r['lower']<=r['upper']<p['valid_until'],'late/expired observation')
        require(r['value']==('PRESENT' if c['kind']=='absence' else 'TRUE' if p['value'] else 'FALSE'),'observation value')
    else:
        require(r['lower']>=r['not_before'],'unclosed window/grace')
        if r['proof'] is None: require(r['value'] in (['ABSENT'] if c['kind']=='absence' else ['EMPTY','CONFLICT']),'unsupported final value')
        else: require(r['value']==('PRESENT' if c['kind']=='absence' else 'TRUE' if r['proof']['message']['value'] else 'FALSE'),'final value')
    return r


def acknowledgement(signed_manifest,receipts):
    m=manifest(signed_manifest);require(len(receipts)>=m['quorum']['presence'],'insufficient observations')
    records=[record(m,r,'OBSERVATION') for r in receipts]
    require(len({r['witness'] for r in records})==len(records),'duplicate witness')
    first=records[0];require(all((r['contract'],r['challenge'],r['proof'])==(first['contract'],first['challenge'],first['proof']) for r in records),'mixed observations')
    return {'accepted':True,'evidence':digest(first['proof']),'contract':first['contract'],'challenge':first['challenge']}


def release(certificate,retained=()):
    require(set(certificate)=={'v','manifest','finals','operation','authorisation'},'release fields')
    m=manifest(certificate['manifest'])
    require(type(certificate['v']) is int and certificate['v']==4 and certificate['operation']==operation(m),'custody operation')
    require(certificate['authorisation']==digest({k:v for k,v in certificate.items() if k!='authorisation'}),'authorisation binding')
    groups=certificate['finals'];require(len(groups)==len(m['slots']),'incomplete snapshot')
    values={};latest=0;allrecords=[]
    for s,group in zip(m['slots'],groups):
        require(len(group)>=m['quorum']['absence'],'insufficient finalisations')
        records=[record(m,r,'FINAL') for r in group]
        require(len({r['witness'] for r in records})==len(records) and all((r['contract'],r['challenge'])==(s['contract'],s['challenge']) for r in records),'finalisation identities/order')
        latest=max(latest,max(r['upper'] for r in records));allrecords+=records
        c=next(c for c in m['policy']['contracts'] if c['id']==s['contract'])
        if c['kind']=='absence': value=all(r['value']=='ABSENT' for r in records)
        else: value=all(r['value']=='TRUE' for r in records) and len({digest(r['proof']) for r in records})==1
        values[(s['contract'],s['challenge'])]=value
    for ack in retained:
        require(ack['manifest']==certificate['manifest'],'retained certificate scope')
        a=acknowledgement(ack['manifest'],ack['receipts'])
        c=next(c for c in m['policy']['contracts'] if c['id']==a['contract'])
        require(not(c['kind']=='absence' and values[(a['contract'],a['challenge'])]),'contradictory retained presence')
    contracts={}
    for c in m['policy']['contracts']:
        active=c['start']<=latest<c['end']
        if c['kind']=='absence': contracts[c['id']]=active and any(values[(c['id'],s['challenge'])] for s in m['slots'] if s['contract']==c['id'])
        else:
            valid=all(r['proof']['message']['valid_until']>latest for r in allrecords if r['contract']==c['id'] and r['value']=='TRUE')
            contracts[c['id']]=active and valid and values[(c['id'],'attestation')]
    def eval_node(e):
        if isinstance(e,str): return contracts[e]
        votes=sum(eval_node(a) for a in e['args']);return votes>=(len(e['args']) if e['op']=='AND' else 1 if e['op']=='OR' else e['k'])
    require(eval_node(m['policy']['expression']),'policy unsatisfied')
    return {'authorised':True,'contracts':contracts,'time':latest,'operation':operation(m)}


def owner_command(m,signed,action):
    r=signed['message']
    require(set(r)=={'v','capsule','manifest','action','operation'} and r=={'v':4,'capsule':m['capsule'],'manifest':digest(m),'action':action,'operation':operation(m)},'owner command domain')
    checked_signature(m['policy']['owner'],signed)
    return r


def fence(m,signed,kind):
    r=signed['message']
    require(set(r)=={'v','kind','capsule','manifest','operation','witness','command'},'fence fields')
    require(r['v']==4 and type(r['v']) is int and r['kind']==kind and r['capsule']==m['capsule'] and r['manifest']==digest(m) and r['operation']==operation(m),'fence domain')
    require(type(r['witness']) is int and str(r['witness']) in m['witnesses'],'fence signer')
    owner_command(m,r['command'],kind)
    checked_signature(m['witnesses'][str(r['witness'])],signed)
    return r


def fence_certificate(sm,receipts,kind):
    m=manifest(sm);rs=[fence(m,r,kind) for r in receipts]
    require(len(rs)>=3 and len({r['witness'] for r in rs})==len(rs),'fence quorum')
    return {'verified':True,'kind':kind,'operation':operation(m)}
