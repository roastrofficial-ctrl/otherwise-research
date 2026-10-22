"""Inspect Compose ownership boundaries without printing credentials."""
import json
import subprocess
s=json.loads(subprocess.check_output(['./scripts/lab05.sh','config','--format','json'],text=True))['services']
for name in ['laravel','hostile','product-db']:
    env=s[name].get('environment',{})
    assert 'OTHERWISE_CREATOR_PASSPHRASE' not in env,name
    assert not any(v.get('source')=='recovery' for v in s[name].get('volumes',[])),name
    assert not any(v.get('source','').endswith('.key') for v in s[name].get('volumes',[])),name
    assert not any('docker.sock' in v.get('source','') for v in s[name].get('volumes',[])),name
assert 'OTHERWISE_CREATOR_PASSPHRASE' in s['cli']['environment']
print(json.dumps({'creator_passphrase_in_saas':False,'owner_volume_mounted_in_saas':False,'docker_socket_in_saas':False,'private_tls_keys_in_saas':False,'local_docker_host_still_trusted':True},indent=2))
