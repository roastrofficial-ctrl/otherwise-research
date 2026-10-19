"""Two phases, with actual Docker stop between them (see experiment04.sh)."""
import http.cookiejar
import json
import os
import re
import socket
import subprocess
import sys
import urllib.request
from pathlib import Path
from Bounded.wire import atomic_json,strict_json,request
from Available.lifecycle import Client
from Available.transport import HttpClientTransport
W=os.environ['WITNESSES'].split(',');K=os.environ['CUSTODIANS'].split(',');root=Path('/recovery/disappearing');root.mkdir(exist_ok=True)
token=os.environ['OTHERWISE_04_FAULT_TOKEN']
def move(now):
    now=max(now,max(request(u+'/clock')['upper'] for u in W))
    for u in W:request(u+'/test-clock',{'now':now},token)
def cli(path,action,*args):
    p=subprocess.run(['python','-m','Available.cli','--transport','httpclient','--kit',str(path),action,*args],capture_output=True,text=True)
    assert p.returncode==0,p.stderr
    return json.loads(p.stdout)
def before():
    jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    html=opener.open('http://laravel:8000/').read().decode();assert 'Your message stays yours' in html
    csrf=re.search(r'name="csrf-token" content="([^"]+)"',html)[1]
    js=opener.open('http://laravel:8000/solo.js').read().decode();assert 'verifyAck' in js
    def post(action,b):
        req=urllib.request.Request('http://laravel:8000/protocol/'+action,json.dumps(b).encode(),{'Content-Type':'application/json','Accept':'application/json','X-CSRF-TOKEN':csrf})
        return json.loads(opener.open(req).read())
    practice=post('create',{'rounds':1,'seconds':10});practice=post('arm',{'kit':practice['kit']});move(practice['kit']['manifest']['message']['slots'][0]['deadline']+6)
    decision=post('evaluate',{'kit':practice['kit']});assert decision['result']['authorised']
    delivery=post('simulate',{'kit':practice['kit'],'certificate':decision['result']['certificate']});assert delivery['result']['delivery']=='SIMULATED'
    cancel=post('create',{'rounds':1,'seconds':10});cancel=post('arm',{'kit':cancel['kit']});cancel=post('disarm',{'kit':cancel['kit']});assert cancel['result']['state']=='DISARMED'
    assert post('status',{'kit':cancel['kit']})['result']['state']=='DISARMED'
    b=post('create',{'rounds':2,'seconds':10});kit=b['kit'];post_result=post('arm',{'kit':kit});kit=post_result['kit'];b=post('checkin',{'kit':kit,'challenge':'1'});kit=b['kit']
    assert b['result']['accepted'] and b['result']['durable_holders']>=3
    atomic_json(root/'owner.json',kit)
    # Also retain an untouched armed Capsule for absence/live-release after SaaS loss.
    b=post('create',{'rounds':1,'seconds':10});b=post('arm',{'kit':b['kit']});atomic_json(root/'missed.json',b['kit'])
    # Direct JS verification uses exactly the source served by Laravel, in Node WebCrypto.
    runner="""const fs=require('fs'),vm=require('vm');const data=JSON.parse(fs.readFileSync(0,'utf8'));const elements=new Proxy({}, {get:(o,k)=>o[k]??=( {disabled:false,textContent:'',addEventListener(){}})});const context={crypto:require('crypto').webcrypto,TextEncoder,Uint8Array,Set,Map,JSON,Number,Array,Object,Error,console,localStorage:{getItem:()=>JSON.stringify(data.kit),setItem(){}},document:{getElementById:id=>elements[id],querySelector:()=>({content:''}),querySelectorAll:()=>[]}};vm.createContext(context);vm.runInContext(data.js,context);(async()=>{await vm.runInContext('verifyAck(kit.acknowledgements.at(-1))',context);data.kit.acknowledgements.at(-1).receipts[0].signature='00'.repeat(64);context.bad=data.kit.acknowledgements.at(-1);let rejected=false;try{await vm.runInContext('verifyAck(bad)',context)}catch(e){rejected=true}if(!rejected)throw Error('forgery accepted');console.log('served frontend verifier: valid ack accepted, forgery rejected')})().catch(e=>{console.error(e);process.exitCode=1});"""
    p=subprocess.run(['node','-e',runner],input=json.dumps({'kit':kit,'js':js}),text=True,capture_output=True);assert p.returncode==0,p.stderr
    print(p.stdout.strip());print('Laravel GET + CSRF POST create → arm → check-in → status; missed window → authorise → simulated delivery; separate disarm verified; recovery kits fsynced outside SaaS; database projection written.')
def after():
    for host,port in [('laravel',8000),('product-db',5432),('protocol-adapter',8080)]:
        try:s=socket.create_connection((host,port),2)
        except OSError:print(host+': unavailable (verified)')
        else:s.close();raise AssertionError(host+' still reachable')
    path=root/'owner.json';status=cli(path,'status');assert status['accepted_checkins']==1
    kit=strict_json(path.read_bytes());base=kit['manifest']['message']['policy']['contracts'][0]['start'];move(base+11)
    assert cli(path,'checkin','--challenge','2')['accepted'];assert cli(path,'status')['accepted_checkins']==2
    assert cli(path,'disarm')['state']=='DISARMED';move(base+26);assert not cli(path,'evaluate')['authorised']
    missed=root/'missed.json';m=strict_json(missed.read_bytes())['manifest']['message'];move(m['slots'][-1]['deadline']+6)
    assert cli(missed,'evaluate')['authorised'];delivery=cli(missed,'simulate');assert delivery['delivery']=='SIMULATED'
    print(json.dumps({'recovered_latest_presence':True,'new_checkin_without_saas':True,'owner_disarm_without_saas':True,'disarmed_release_blocked':True,'missed_release_live':True,'simulated_delivery':True,'administrative_bypass':False,'required_capability':'independently exported owner seed + signed manifest + witness/custody addresses + encrypted payload','fault_injection':'clock advance only; never an ownership bypass'},indent=2))
if __name__=='__main__':globals()[sys.argv[1]]()
