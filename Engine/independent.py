"""Second implementation: iterative policy reduction, separately derived contract rules.
Does not import the reference evaluator. It consumes exported canonical facts.
"""

def interpret(snapshot):
    p, history, t = snapshot['policy'], snapshot['events'], snapshot['now']
    disabled = set()
    by_contract = {}
    for fact in history:
        if fact['kind']=='REVOKED': disabled.add(fact['data']['authority'])
        if fact['kind']=='ACCEPTED':
            m = fact['data']['message']
            by_contract.setdefault((m['contract'],m['contract_version']), []).append(m)
    answers = {}
    for contract in p['contracts']:
        cid = contract['id']; answers[cid] = False
        if t < contract['start'] or t >= contract['end'] or contract['authority'] in disabled: continue
        evidence = by_contract.get((cid,contract['version']), [])
        if contract['kind']=='absence':
            witnessed = {m['challenge'] for m in evidence}
            for obligation in contract['challenges']:
                if obligation['deadline'] < t and obligation['id'] not in witnessed: answers[cid] = True
        else:
            yes = no = False
            for m in evidence:
                if m['valid_from'] <= t and t < m['valid_until']:
                    if m['claim']: yes = True
                    else: no = True
            answers[cid] = yes and not no
    stack = [(p['expression'],False)]; values = []
    while stack:
        node, visited = stack.pop()
        if isinstance(node,str): values.append(answers[node]); continue
        if not visited:
            stack.append((node,True))
            stack.extend((child,False) for child in reversed(node['args']))
        else:
            count = len(node['args']); children = values[-count:]; del values[-count:]
            minimum = count if node['op']=='AND' else 1 if node['op']=='OR' else node['k']
            values.append(sum(children)>=minimum)
    return {'contracts': answers, 'satisfied': values[0]}


def release_eligible(snapshot):
    """Independently replay lifecycle and continuous grace eligibility before a worker runs."""
    facts=snapshot['events']; names={f['kind'] for f in facts}
    if 'AUTHORISED' in names: return True
    if 'ARMED' not in names or 'DISARMED' in names or not snapshot['healthy']: return False
    if not interpret(snapshot)['satisfied']: return False
    since=None
    for f in facts:
        if f['kind'] in ('RECOVERED','CANDIDATE_RESET'): since=None
        elif f['kind']=='CANDIDATE': since=f['time']
    if since is None or snapshot['now']-since<snapshot['policy']['grace']: return False
    times={since,snapshot['now']}
    for c in snapshot['policy']['contracts']:
        times |= {c['start'],c['end']}
        for ch in c['challenges']: times.add(ch['deadline']+1)
    for f in facts:
        if f['kind']=='ACCEPTED':
            m=f['data']['message']; times |= {m['valid_from'],m['valid_until']}
    for t in sorted(times):
        if since<=t<=snapshot['now']:
            view=dict(snapshot); view['now']=t
            if not interpret(view)['satisfied']: return False
    return True
