"""Untrusted snapshot verifier. Replay lifecycle, signatures, acceptance and decision facts.
Uses the original interpreter for semantics; JS independently verifies the same corpus.
"""
import hashlib
from Engine.protocol import canonical, digest, validate_policy, verify
from Engine.independent import interpret, release_eligible


def check_manifest(manifest, signature):
    if set(manifest)!={'v','capsule','epoch','policy','commitment','payload','algorithm','custody','witness','clock'}:
        raise ValueError('manifest schema')
    if manifest['v']!=2 or type(manifest['v']) is not int or manifest['epoch']!=1:
        raise ValueError('manifest version')
    validate_policy(manifest['policy'])
    if manifest['commitment']!=digest(manifest['policy']): raise ValueError('manifest commitment')
    if manifest['algorithm']!='AES-128-GCM' or len(bytes.fromhex(manifest['payload']))!=32:
        raise ValueError('ciphertext identity')
    custody=manifest['custody']
    if set(custody)!={'scheme','k','n','keys'} or custody['scheme']!='shamir-pycryptodome-128' or custody['k']!=2 or custody['n']!=3 or set(custody['keys'])!={'1','2','3'} or len(set(custody['keys'].values()))!=3:
        raise ValueError('custody profile')
    if manifest['clock']!={'profile':'witness-observed-v2','outage':'withhold-and-restart-grace'}:
        raise ValueError('clock profile')
    verify(manifest['policy']['owner'],manifest,signature)
    canonical(manifest)


def validate_snapshot(s):
    if set(s)!={'capsule','commitment','policy','events','head','now','healthy'}:
        raise ValueError('snapshot fields')
    validate_policy(s['policy'])
    if type(s['now']) is not int or s['now']<0 or type(s['healthy']) is not bool or digest(s['policy'])!=s['commitment']:
        raise ValueError('snapshot metadata')
    facts=[]; head='0'*64; last=-1; armed=False; terminal=None
    accepted_ids={}; revoked=set(); candidate=None; local_healthy=True; payload=None
    def view(now,healthy=None):
        return {**s,'events':list(facts),'head':head,'now':now,
                'healthy':local_healthy if healthy is None else healthy}
    for index,e in enumerate(s['events'],1):
        if set(e)!={'v','capsule','seq','time','kind','data','prev'} or type(e['v']) is not int or e['v']!=1 or type(e['seq']) is not int or e['seq']!=index or e['capsule']!=s['capsule'] or e['prev']!=head or type(e['time']) is not int or not last<=e['time']<=s['now']:
            raise ValueError('history chain/order')
        t,kind,d=e['time'],e['kind'],e['data']
        if index==1:
            if kind!='CREATED' or d.get('commitment')!=s['commitment'] or set(d)!={'commitment','payload'}: raise ValueError('genesis')
            payload=d['payload']
        elif kind=='CREATED': raise ValueError('duplicate genesis')
        if kind in ('ARMED','DISARMED','RECOVERED'):
            m={'v':1,'capsule':s['capsule'],'commitment':s['commitment'],'action':kind}
            if d.get('message',{}).get('v')==2: m={**m,'v':2,'head':head}
            if d.get('message')!=m: raise ValueError('owner command domain')
            verify(s['policy']['owner'],m,d['signature'])
            if terminal: raise ValueError('owner command after terminal')
            if kind=='ARMED':
                if armed or not local_healthy: raise ValueError('arm lifecycle')
                armed=True
            elif kind=='DISARMED': terminal='DISARMED'
            else: local_healthy=True; candidate=None
        elif kind=='CLOCK':
            if type(d.get('healthy')) is not bool: raise ValueError('clock fact')
            if not d['healthy']: local_healthy=False
        elif kind=='CHALLENGE':
            if not armed or terminal: raise ValueError('challenge lifecycle')
            c=next((c for c in s['policy']['contracts'] if c['id']==d.get('contract')),None)
            if c is None or c['kind']!='absence' or d.get('contract_version')!=c['version'] or {k:v for k,v in d.items() if k not in ('contract','contract_version')} not in c['challenges']:
                raise ValueError('uncommitted challenge')
        elif kind=='ACCEPTED':
            if not armed or terminal: raise ValueError('acceptance lifecycle')
            m=d['message']; c=next((c for c in s['policy']['contracts'] if c['id']==m.get('contract')),None)
            if c is None: raise ValueError('contract')
            required={'v','id','capsule','commitment','contract','contract_version','authority','valid_from','valid_until'}|({'claim'} if c['kind']=='attestation' else {'challenge'})
            if set(m)!=required or type(m['v']) is not int or m['v']!=1 or m['capsule']!=s['capsule'] or m['commitment']!=s['commitment'] or type(m['contract_version']) is not int or m['contract_version']!=c['version'] or m['authority']!=c['authority'] or c['authority'] in revoked or not isinstance(m['id'],str) or not m['id'] or m['id'] in accepted_ids:
                raise ValueError('evidence domain/id')
            verify(c['authority'],m,d['signature'])
            a,b=m['valid_from'],m['valid_until']
            if type(a) is not int or type(b) is not int or not c['start']<=a<=t<b<=c['end']: raise ValueError('evidence validity')
            if c['kind']=='attestation':
                if type(m['claim']) is not bool: raise ValueError('claim')
            else:
                ch=next((ch for ch in c['challenges'] if ch['id']==m['challenge']),None)
                if not ch or not ch['open']<=t<=ch['deadline']: raise ValueError('late presence')
                if not any(f['kind']=='CHALLENGE' and f['data'].get('contract')==c['id'] and f['data'].get('id')==ch['id'] for f in facts): raise ValueError('unissued challenge')
            accepted_ids[m['id']]=d
            candidate=None  # even if a hostile engine omitted CANDIDATE_RESET
        elif kind=='REVOKED':
            if terminal: raise ValueError('revocation after terminal')
            m={'v':1,'capsule':s['capsule'],'commitment':s['commitment'],'action':'REVOKED','authority':d['authority']}
            if d['message']!=m or d['authority'] not in {c['authority'] for c in s['policy']['contracts']}: raise ValueError('revocation domain')
            verify(s['policy']['owner'],m,d['signature']); revoked.add(d['authority']); candidate=None
        elif kind=='CANDIDATE_RESET': candidate=None
        elif kind=='CANDIDATE':
            current=view(t)
            if not armed or terminal or not local_healthy or not interpret(current)['satisfied'] or d['snapshot']!=head or d['results']!=interpret(current) or d['grace']!=s['policy']['grace']:
                raise ValueError('unsupported candidate')
            candidate=index
        elif kind=='AUTHORISED':
            current=view(t)
            # Projection resets cannot be omitted to preserve an old grace.
            if candidate is None or terminal or not release_eligible(current) or d.get('commitment')!=s['commitment'] or d.get('snapshot')!=head or d.get('candidate')!=candidate or d.get('payload')!=payload or d.get('results')!=interpret(current):
                raise ValueError('unsupported authorisation')
            terminal='AUTHORISED'
        elif kind=='RELEASED':
            decision=next((f for f in facts if f['kind']=='AUTHORISED'),None)
            if not decision or d.get('decision')!=digest(decision): raise ValueError('unsupported delivery')
        elif kind not in ('CREATED','SUBMITTED','REJECTED','NOTIFICATION'):
            raise ValueError('unknown event')
        facts.append(e); last=t; head=digest(e)
    if not facts or head!=s['head']: raise ValueError('head mismatch')
    # A projection may be more conservative than history, never less conservative.
    if s['healthy'] and not local_healthy: raise ValueError('false health projection')
    return {'results':interpret(s),'eligible':release_eligible(s),'authorised':terminal=='AUTHORISED'}


def validate_bundle(bundle, manifest):
    s=bundle['snapshot']; receipt=bundle['receipt']
    verify(manifest['witness'],receipt,bundle['signature'])
    if receipt!={'v':2,'manifest':digest(manifest),'capsule':manifest['capsule'],
                  'commitment':manifest['commitment'],'head':s['head'],'count':len(s['events']),
                  'now':s['now'],'healthy':s['healthy']}:
        raise ValueError('witness receipt domain')
    if s['policy']!=manifest['policy'] or s['capsule']!=manifest['capsule']: raise ValueError('manifest scope')
    result=validate_snapshot(s)
    if s['events'][0]['data']['payload']!=manifest['payload']: raise ValueError('payload binding')
    return result
