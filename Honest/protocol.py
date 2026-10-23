"""Authenticated custody sidecar, unchanged wire4 policy evaluator, explicit capabilities."""
import re
from Engine.protocol import digest,canonical
from Available.proofs import manifest,checked_signature,require,release,record,fence,fence_certificate
from Untrusted.proofs import snapshot
from .crypto import public_key,point

CAPABILITIES={'v':6,'operation':'reconstruct-aes-128-gcm','method':'reference-p256-threshold-dh',
 'threshold':2,'participants':3,'long_lived_key_reconstruction':False,
 'cryptographic_policy_enforcement':False,'recipient_encryption':True,'synthetic_only':True,
 'provisioning':'trusted-dealer','reviewed':False}

def compatible(required):
    require(set(required)<=set(CAPABILITIES) and all(CAPABILITIES[k]==v for k,v in required.items()),'custody capability mismatch')
    return True

def commitment(sidecar):
    c=sidecar['message'];require(set(c)=={'v','kind','manifest','key','recipient','wrap'},'custody commitment schema')
    require(type(c['v']) is int and c['v']==6 and c['kind']=='CUSTODY_RESEARCH','custody profile')
    m=manifest(c['manifest']);checked_signature(m['policy']['owner'],sidecar);public_key(c['key'])
    require(type(c['recipient']) is str and re.fullmatch('[0-9a-f]{64}',c['recipient']) is not None,'recipient scope')
    require(set(c['wrap'])=={'R','wrapped'} and type(c['wrap']['wrapped']) is str and re.fullmatch('[0-9a-f]{88}',c['wrap']['wrapped']) is not None,'wrapped AES128 key');point(c['wrap']['R'])
    return c,m

def encryption_context(sm,key,recipient):
    m=manifest(sm)
    return {'v':6,'kind':'CAPSULE_KEY_WRAP','capsule':m['capsule'],'manifest':digest(m),'manifest_version':m['v'],'ciphertext':m['payload'],'recipient':recipient,'key':digest(key)}

def operation(sidecar,certificate,head):
    c,m=commitment(sidecar)
    return {'v':6,'kind':'PARTIAL_DECRYPT','capsule':m['capsule'],'manifest':digest(m),'manifest_version':m['v'],
            'ciphertext':m['payload'],'recipient':c['recipient'],'commitment':digest(sidecar),'authorisation':certificate['authorisation'],'evidence_head':head}

def evidence_snapshot(sm,signed,nonce,anchors):
    """Fresh authenticated quorum; retain all valid records, including minority vetoes.
    This is a sampled set/prefix, not a total-order consensus head or trusted UTC.
    """
    m=manifest(sm);require(type(signed) is list and 3<=len(signed)<=4,'snapshot quorum')
    sources=set();records={};nextanchors=dict(anchors)
    for s in signed:
        i=s['message']['witness'];require(i not in sources,'duplicate snapshot source');sources.add(i)
        r=snapshot(sm,s,nonce,i);hashes=[]
        for item in r['records']:
            kind=item['message']['kind']
            (fence if kind in ('ARM','DISARM') else record)(m,item,kind)
            hashes.append(digest(item));records[digest(item)]=item
        require(set(anchors.get(str(i),[]))<=set(hashes),'witness rollback')
        nextanchors[str(i)]=sorted(hashes)
    history=[records[h] for h in sorted(records)]
    lineage={}
    for item in history:
        r=item['message']
        if r['kind'] in ('OBSERVATION','FINAL'):
            ident=(r['witness'],r['seq'])
            require(ident not in lineage or lineage[ident]==digest(item),'contradictory witness lineage')
            lineage[ident]=digest(item)
    for item in history:
        r=item['message']
        if r['kind'] in ('OBSERVATION','FINAL'):
            expected='0'*64 if r['seq']==1 else lineage.get((r['witness'],r['seq']-1))
            require(expected is not None and r['prev']==expected,'incomplete or forked witness prefix')
    # Stable set digest excludes randomized freshness nonces and source response order.
    return digest(history),history,nextanchors

def authorise(sidecar,certificate,history):
    c,m=commitment(sidecar);require(certificate['manifest']==c['manifest'],'cross-Capsule certificate')
    decision=release(certificate)
    fence_certificate(c['manifest'],list({r['message']['witness']:r for r in history if r['message']['kind']=='ARM'}.values()),'ARM')
    require(not any(r['message']['kind']=='DISARM' for r in history),'retained disarm veto')
    known={digest(r) for r in history}
    require(all(digest(r) in known for group in certificate['finals'] for r in group),'release certificate outside authoritative snapshot')
    for group in certificate['finals']:
        rows=[r['message'] for r in group]
        if all(r['value']=='ABSENT' for r in rows):
            sl=(rows[0]['contract'],rows[0]['challenge'])
            require(not any(r['message']['kind']=='OBSERVATION' and (r['message']['contract'],r['message']['challenge'])==sl for r in history),'retained presence veto')
    # Independent existing evaluator confirms identical Boolean semantics.
    import subprocess
    p=subprocess.run(['node','Verifier/available.mjs'],input=canonical({'kind':'release','object':certificate}),capture_output=True)
    from Bounded.wire import strict_json
    require(p.returncode==0 and strict_json(p.stdout)=={'ok':True,**decision},'independent policy verifier disagreement')
    return True
