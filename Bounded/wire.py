import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from Engine.protocol import canonical


def strict_json(raw):
    def pairs(items):
        result={}
        for key,value in items:
            if key in result: raise ValueError('duplicate JSON key')
            result[key]=value
        return result
    value=json.loads(raw,object_pairs_hook=pairs)
    canonical(value)
    return value


def atomic_json(path, value):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    temp=path.with_suffix('.pending')
    fd=os.open(temp,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'wb') as f:
        f.write(canonical(value)); f.flush(); os.fsync(f.fileno())
    os.replace(temp,path)
    fd=os.open(path.parent,os.O_RDONLY)
    try: os.fsync(fd)
    finally: os.close(fd)


def request(url, body=None, token=None, headers=None):
    h={'Content-Type':'application/json',**(headers or {})}
    if token: h['Authorization']='Bearer '+token
    req=urllib.request.Request(url,data=None if body is None else canonical(body),headers=h)
    try:
        with urllib.request.urlopen(req,timeout=10) as response: return strict_json(response.read())
    except urllib.error.HTTPError as exc:
        raise ValueError(exc.read().decode()) from exc
