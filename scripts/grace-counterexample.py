"""Reproducible grace fixture. Current image must refuse t=5 and authorise t=10.
The initial image authorised at t=5; the actual observation is in doc/results.
Run: docker compose run --rm experiment python scripts/grace-counterexample.py
"""
import sys
import tempfile
sys.path.insert(0,'tests')
from helpers import fixture, command, proof
from Engine.store import Engine

with tempfile.TemporaryDirectory() as root:
    e=Engine(root)
    o,a,p=fixture(expression={'op':'OR','args':['A','B','C']})
    p['contracts'][1]['kind']='absence'
    p['contracts'][1]['challenges']=[{'id':'round-1','open':0,'deadline':3}]
    e.create('capsule',p); command(e,'capsule',o,'ARMED')
    e.submit('capsule',*proof(p,'capsule',a[0],until=2))
    e.authorise('capsule'); e.tick(5)
    result=e.authorise('capsule')
    print('A expires at 2; B becomes satisfied at 4; worker returns at 5.')
    print('Authorised at 5:',result is not None)
    assert result is None
    e.tick(10); result=e.authorise('capsule')
    print('Authorised at 10 after fresh grace:',result is not None)
    assert result is not None
