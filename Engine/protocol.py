"""Restricted canonical wire format and policy validation, not full RFC 8785."""
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def canonical(value):
    def check(x):
        if x is None or type(x) in (bool, int):
            if type(x) is int and abs(x) > 2**53 - 1:
                raise ValueError('integer out of range')
        elif type(x) is str:
            if not x.isascii():
                raise ValueError('wire strings must be ASCII')
        elif type(x) is list:
            for v in x: check(v)
        elif type(x) is dict:
            for k, v in x.items():
                if type(k) is not str: raise ValueError('string keys required')
                check(k); check(v)
        else: raise ValueError('unsupported wire type')
    check(value)
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def keypair():
    private = Ed25519PrivateKey.generate()
    return private, private.public_key().public_bytes_raw().hex()


def sign(private, message):
    return private.sign(canonical(message)).hex()


def verify(public, message, signature):
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(public)).verify(bytes.fromhex(signature), canonical(message))
    except Exception as exc:
        raise ValueError('invalid signature') from exc


def validate_policy(p):
    if set(p) != {'version', 'owner', 'contracts', 'expression', 'grace', 'max_step', 'destination'}:
        raise ValueError('policy fields')
    if type(p['version']) is not int or p['version'] != 1 or type(p['grace']) is not int or p['grace'] < 1 or type(p['max_step']) is not int or p['max_step'] < 1:
        raise ValueError('policy bounds')
    if p['destination'] != {'kind': 'simulated', 'verified': True, 'consented': True} or p['destination']['verified'] is not True or p['destination']['consented'] is not True:
        raise ValueError('only consented simulated destination allowed')
    def public(k):
        if len(bytes.fromhex(k)) != 32: raise ValueError('public key')
    public(p['owner'])
    ids = set()
    for c in p['contracts']:
        if set(c) != {'id','version','kind','authority','start','end','challenges'}:
            raise ValueError('contract fields')
        if type(c['id']) is not str or c['id'] in ids or not c['id'] or type(c['version']) is not int or c['version'] != 1 or c['kind'] not in ('attestation','absence'):
            raise ValueError('contract identity')
        ids.add(c['id']); public(c['authority'])
        if type(c['start']) is not int or type(c['end']) is not int or c['start'] >= c['end']: raise ValueError('window')
        challenges = set()
        for ch in c['challenges']:
            if set(ch) != {'id','open','deadline'} or type(ch['id']) is not str or not ch['id'] or ch['id'] in challenges: raise ValueError('challenge identity')
            if type(ch['open']) is not int or type(ch['deadline']) is not int or not c['start'] <= ch['open'] <= ch['deadline'] < c['end']: raise ValueError('challenge window')
            challenges.add(ch['id'])
        if (c['kind'] == 'absence') != bool(c['challenges']): raise ValueError('challenge kind')
    if not ids: raise ValueError('empty contracts')
    used = set()
    def expression(e, depth=0):
        if depth > 32: raise ValueError('expression depth')
        if type(e) is str:
            if e not in ids or e in used: raise ValueError('unknown or repeated leaf')
            used.add(e); return
        if type(e) is not dict or e.get('op') not in ('AND','OR','THRESHOLD'): raise ValueError('operator')
        if set(e) != ({'op','args','k'} if e['op']=='THRESHOLD' else {'op','args'}): raise ValueError('expression fields')
        if not isinstance(e['args'],list) or not e['args']: raise ValueError('empty expression')
        if e['op']=='THRESHOLD' and (type(e['k']) is not int or not 1 <= e['k'] <= len(e['args'])): raise ValueError('threshold')
        for a in e['args']: expression(a,depth+1)
    expression(p['expression'])
    if used != ids: raise ValueError('unreferenced contract')
    canonical(p)
