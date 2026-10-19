from Engine.protocol import keypair, sign, digest

def fixture(kind='attestation', count=3, expression=None):
    owner, pub=keypair(); authorities=[keypair() for _ in range(count)]
    contracts=[{'id':chr(65+i),'version':1,'kind':kind,'authority':pair[1],'start':0,'end':1000,
                'challenges':[{'id':'round-1','open':0,'deadline':10},{'id':'round-2','open':11,'deadline':20}] if kind=='absence' else []} for i,pair in enumerate(authorities)]
    policy={'version':1,'owner':pub,'contracts':contracts,'expression':expression or ({'op':'THRESHOLD','k':2,'args':['A','B','C']} if count==3 else 'A'),'grace':5,'max_step':60,'destination':{'kind':'simulated','verified':True,'consented':True}}
    return owner,authorities,policy

def command(engine,cid,owner,action):
    s=engine.export(cid); m={'v':1,'capsule':cid,'commitment':s['commitment'],'action':action}
    return engine.owner_command(cid,action,sign(owner,m))

def proof(policy,cid,authority,index=0,claim=True,until=100,ident=None,challenge='round-1'):
    c=policy['contracts'][index]
    m={'v':1,'id':ident or c['id']+'-proof','capsule':cid,'commitment':digest(policy),'contract':c['id'],'contract_version':1,'authority':c['authority'],'valid_from':0,'valid_until':until}
    m.update({'claim':claim} if c['kind']=='attestation' else {'challenge':challenge})
    return m,sign(authority[0],m)
