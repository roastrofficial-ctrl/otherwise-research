"""Offline portable release verification against an independently pinned registry."""
import base64,hashlib
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Engine.protocol import digest
from Available.client import aad
from Available.proofs import require,checked_signature
from Honest import crypto
from Missing.protocol import DOMAINS,wrap_context,plain_commit
from .proofs import registry,finality,contribution_context,same

def verify(config,package):
    require(set(config)=={'registry','ciphertext','recipient_seed'},'recipient configuration; no owner seed required')
    require(set(package)=={'v','registry','ciphertext','finality','contributions'} and type(package['v']) is int and package['v']==8 and same(package['registry'],config['registry']) and package['ciphertext']==config['ciphertext'],'pinned portable release scope')
    reg=config['registry'];r,c,m=registry(reg);fin=package['finality'];require(finality(reg,fin)['kind']=='RELEASE','no release commitment')
    private=config['recipient_seed'];pub=X25519PrivateKey.from_private_bytes(bytes.fromhex(private)).public_key().public_bytes_raw().hex();require(pub==c['recipient'],'wrong recipient')
    require(set(package['contributions'])==set(DOMAINS),'two domains required');parts={};invalid=[]
    for d in DOMAINS:
        ctx=contribution_context(reg,fin,d);found={}
        for signed in package['contributions'][d]:
            try:
                q=signed['message'];i=q['index'];require(type(i) is int and i in (1,2,3) and set(q)=={'context','index','box'} and same(q['context'],ctx),'partial context');checked_signature(c['domains'][d]['members'][str(i)],signed)
                p=crypto.open_for(private,q['box'],ctx);require(p['index']==i,'inner participant');crypto.verify_partial(c['domains'][d]['key'],c['wraps'][d]['R'],ctx,p);found.setdefault(i,p)
            except Exception as e:invalid.append({'domain':d,'reason':str(e)})
        require(len(found)>=2,'insufficient mathematically valid '+d+' threshold')
        parts[d]=crypto.unwrap(c['domains'][d]['key'],c['wraps'][d],wrap_context(c,d),[found[i] for i in sorted(found)][:2],ctx)
    ct=base64.b64decode(config['ciphertext'],validate=True);require(hashlib.sha256(ct).hexdigest()==m['payload'],'ciphertext commitment')
    dek=bytes(x^y for x,y in zip(parts['custody'],parts['authority']));payload=AESGCM(dek).decrypt(ct[:12],ct[12:],aad(m));require(plain_commit(payload[:16],payload[16:])==c['plaintext_commitment'],'plaintext commitment')
    return {'plaintext':payload[16:].decode(),'delivery':'SIMULATED','decision':digest(fin['value']),'invalid_contributions':invalid,'verified_offline':True}

def main():
    import argparse,json,os,getpass
    from pathlib import Path
    from Bounded.wire import strict_json
    from Untrusted.vault import unseal
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--vault',required=True);p.add_argument('--package',required=True);a=p.parse_args();password=os.environ.get('OTHERWISE_CREATOR_PASSPHRASE') or getpass.getpass('Recipient vault passphrase: ')
    cfg=unseal(strict_json(Path(a.vault).read_bytes()),password);result=verify(cfg,strict_json(Path(a.package).read_bytes()))
    print(json.dumps(result))
if __name__=='__main__':main()
