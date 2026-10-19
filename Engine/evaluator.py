"""Reference contract interpreter. Input is a validated immutable snapshot."""

def evaluate(policy, events, now):
    revoked = {e['data']['authority'] for e in events if e['kind']=='REVOKED'}
    proofs = [e['data']['message'] for e in events if e['kind']=='ACCEPTED']
    results = {}
    for c in policy['contracts']:
        if not c['start'] <= now < c['end'] or c['authority'] in revoked:
            results[c['id']] = False; continue
        scoped = [p for p in proofs if p['contract']==c['id'] and p['contract_version']==c['version']]
        if c['kind']=='attestation':
            claims = {p['claim'] for p in scoped if p['valid_from'] <= now < p['valid_until']}
            results[c['id']] = claims == {True}
        else:
            results[c['id']] = any(now > ch['deadline'] and not any(p['challenge']==ch['id'] for p in scoped) for ch in c['challenges'])
    def resolve(e):
        if isinstance(e,str): return results[e]
        values = [resolve(a) for a in e['args']]
        return all(values) if e['op']=='AND' else any(values) if e['op']=='OR' else sum(values)>=e['k']
    return {'contracts': results, 'satisfied': resolve(policy['expression'])}
