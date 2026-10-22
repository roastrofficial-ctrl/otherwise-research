"""Local encrypted owner capability. No SaaS dependency or remote key recovery."""
import fcntl
import os
from contextlib import contextmanager
from pathlib import Path
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Engine.protocol import canonical
from Bounded.wire import atomic_json,strict_json
from Available.proofs import require

PARAMS={'n':32768,'r':8,'p':1,'length':32}

def seal(kit,password):
    require(type(password) is str and len(password)>=16,'use a separate long recovery passphrase')
    salt=os.urandom(16);nonce=os.urandom(12)
    header={'v':5,'kind':'OWNER_VAULT','kdf':PARAMS,'salt':salt.hex(),'nonce':nonce.hex()}
    key=Scrypt(salt=salt,**PARAMS).derive(password.encode())
    return {**header,'ciphertext':AESGCM(key).encrypt(nonce,canonical(kit),canonical(header)).hex()}

def unseal(blob,password):
    require(set(blob)=={'v','kind','kdf','salt','nonce','ciphertext'} and blob['v']==5 and blob['kind']=='OWNER_VAULT' and blob['kdf']==PARAMS,'vault format/KDF')
    salt=bytes.fromhex(blob['salt']);nonce=bytes.fromhex(blob['nonce']);require(len(salt)==16 and len(nonce)==12,'vault nonce/salt')
    header={k:v for k,v in blob.items() if k!='ciphertext'};key=Scrypt(salt=salt,**PARAMS).derive(password.encode())
    return strict_json(AESGCM(key).decrypt(nonce,bytes.fromhex(blob['ciphertext']),canonical(header)))

@contextmanager
def opened(path,password,create=False):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(str(path)+'.lock',os.O_CREAT|os.O_RDWR,0o600)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX)
        require(not path.is_symlink(),'vault symlink')
        require(not create or not path.exists(),'refuse to overwrite owner vault')
        kit={} if create else unseal(strict_json(path.read_bytes()),password)
        yield kit
        atomic_json(path,seal(kit,password))
        path.chmod(0o600)
    finally:os.close(fd)
