"""Local demonstration client; all recipients and data are synthetic."""
import tempfile
import json
from Engine.store import Engine
from Engine.protocol import keypair, sign, digest
from Engine.independent import interpret


def main():
    with tempfile.TemporaryDirectory(prefix='otherwise-demo-') as root:
        engine=Engine(root)
        owner,owner_pub=keypair(); pairs=[keypair() for _ in range(3)]
        policy={'version':1,'owner':owner_pub,'contracts':[{'id':name,'version':1,'kind':'attestation','authority':pairs[i][1],'start':0,'end':100,'challenges':[]} for i,name in enumerate('ABC')], 'expression':{'op':'THRESHOLD','k':2,'args':['A','B','C']},'grace':5,'max_step':60,'destination':{'kind':'simulated','verified':True,'consented':True}}
        commitment=engine.create('demo',policy,b'Your message stays yours. Otherwise...')
        m={'v':1,'capsule':'demo','commitment':commitment,'action':'ARMED'}
        engine.owner_command('demo','ARMED',sign(owner,m))
        for i,name in enumerate('ABC'):
            m={'v':1,'id':name+'-proof','capsule':'demo','commitment':commitment,'contract':name,'contract_version':1,'authority':pairs[i][1],'valid_from':0,'valid_until':90,'claim':i<2}
            print(name,engine.submit('demo',m,sign(pairs[i][0],m)))
        print('Independent interpretation:',interpret(engine.export('demo')))
        engine.authorise('demo'); engine.tick(5); decision=engine.authorise('demo')
        print('Authorised decision:',digest(decision))
        print('Simulated delivery:',engine.deliver('demo').decode())
        print('Complete audit:')
        print(json.dumps(engine.export('demo'),indent=2))

if __name__=='__main__': main()
