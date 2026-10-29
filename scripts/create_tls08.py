"""Local laboratory CA; provider private keys are mounted only to their provider."""
import datetime
import os
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
root=Path('/out');root.mkdir(exist_ok=True);now=datetime.datetime.now(datetime.timezone.utc)
def name(s):return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,s)])
def keyfile(path,key):path.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));path.chmod(0o600)
ca=rsa.generate_private_key(public_exponent=65537,key_size=3072)
cert=(x509.CertificateBuilder().subject_name(name('Otherwise 0.8 laboratory CA')).issuer_name(name('Otherwise 0.8 laboratory CA')).public_key(ca.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True,path_length=0),True).sign(ca,hashes.SHA256()))
keyfile(root/'ca.key',ca);(root/'ca.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
for ident in ['aw1','aw2','aw3','aw4','ak1','ak2','ak3','aa1','aa2','aa3']:
 key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
 leaf=(x509.CertificateBuilder().subject_name(name(ident)).issuer_name(cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1)).not_valid_after(now+datetime.timedelta(days=365)).add_extension(x509.SubjectAlternativeName([x509.DNSName(ident)]),False).add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),False).sign(ca,hashes.SHA256()))
 keyfile(root/(ident+'.key'),key);(root/(ident+'.pem')).write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
print('Generated local TLS CA and ten separate provider certificates; no keys printed.')
