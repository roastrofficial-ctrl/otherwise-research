"""Isolated witness/custodian service. No operator filesystem is mounted here.
HTTP is limited to the private Docker laboratory network; not a production API.
"""
import hashlib
import json
import os
import secrets
import sqlite3
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from Engine.protocol import canonical, digest, sign, verify
from .clock import Clock
from .verify import check_manifest, validate_snapshot, validate_bundle
from .wire import atomic_json, strict_json, request


class State:
    def __init__(self, root, role, index=0, test=False):
        self.root=Path(root); self.root.mkdir(parents=True,exist_ok=True)
        self.role,self.index=role,index
        keyfile=self.root/'identity.json'
        if not keyfile.exists(): atomic_json(keyfile,{'private':secrets.token_hex(32)})
        self.key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(strict_json(keyfile.read_bytes())['private']))
        self.public=self.key.public_key().public_bytes_raw().hex()
        self.db=sqlite3.connect(self.root/'state.db',isolation_level=None)
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS records(id TEXT PRIMARY KEY, body TEXT NOT NULL)')
        clockfile=self.root/'clock.json'
        saved=strict_json(clockfile.read_bytes()) if clockfile.exists() else None
        self.clock=Clock(saved,test=test)
        self.clockfile=clockfile
        self.last_publish={}
        self.available=True
        self.elapsed=time.monotonic

    def get(self,cid):
        row=self.db.execute('SELECT body FROM records WHERE id=?',(cid,)).fetchone()
        if not row: raise ValueError('unknown capsule')
        return strict_json(row[0])

    def put(self,cid,value):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            self.db.execute('INSERT OR REPLACE INTO records VALUES(?,?)',(cid,canonical(value).decode()))
            self.db.commit()
        except BaseException: self.db.rollback();raise

    def sample(self):
        sample=self.clock.sample(); atomic_json(self.clockfile,sample)
        if self.role=='witness' and not sample['healthy']:
            # Clock uncertainty affects every live observation, not just the next
            # caller. Another owner's recovery cannot erase this Capsule's latch.
            for cid,body in self.db.execute('SELECT id,body FROM records').fetchall():
                record=strict_json(body)
                terminal=record.get('bundle') and any(e['kind'] in ('AUTHORISED','DISARMED') for e in record['bundle']['snapshot']['events'])
                if not terminal and not record.get('blocked'):
                    record['blocked']=True;self.put(cid,record)
        return sample

    def signed(self,message):
        return {'message':message,'signature':sign(self.key,message)}

    def register(self,body):
        m,sig=body['manifest'],body['signature'];check_manifest(m,sig);cid=m['capsule']
        if self.role=='witness' and m['witness']!=self.public: raise ValueError('wrong witness')
        if self.role=='custodian' and m['custody']['keys'][str(self.index)]!=self.public: raise ValueError('wrong custodian')
        try:
            old=self.get(cid)
            if old['manifest']!=m or old['signature']!=sig: raise ValueError('immutable enrollment')
            if self.role=='custodian' and old['share']!=body['share']: raise ValueError('share replacement')
            return old['enrollment']
        except ValueError as exc:
            if str(exc)!='unknown capsule': raise
        receipt={'v':2,'action':'ENROLLED','manifest':digest(m),'index':self.index,'public':self.public}
        enrollment=self.signed(receipt)
        record={'manifest':m,'signature':sig,'enrollment':enrollment}
        if self.role=='custodian':
            share=body['share']
            if share['index']!=self.index or len(bytes.fromhex(share['value']))!=16: raise ValueError('share schema')
            record.update(share=share,seen=None)
        else: record.update(bundle=None,ready=False,blocked=False,candidate_upper=None)
        self.put(cid,record)
        if body.get('fault')=='after_commit': raise RuntimeError('enrollment committed; acknowledgement lost')
        return enrollment

    def ready(self,body):
        cid=body['capsule'];record=self.get(cid);m=record['manifest'];receipts=body['receipts']
        if len(receipts)!=3: raise ValueError('incomplete custody provisioning')
        for index,receipt in enumerate(receipts,1):
            expected={'v':2,'action':'ENROLLED','manifest':digest(m),'index':index,'public':m['custody']['keys'][str(index)]}
            if receipt['message']!=expected: raise ValueError('provisioning receipt domain')
            verify(expected['public'],expected,receipt['signature'])
        record['ready']=True;self.put(cid,record)
        return {'ready':True}

    def allowed_gap(self, manifest):
        windows=[(ch['deadline']-ch['open']+1)*1000 for c in manifest['policy']['contracts'] for ch in c['challenges']]
        return min(self.clock.max_gap,min(windows)//2) if windows else self.clock.max_gap

    def publish(self,s):
        record=self.get(s['capsule']);m=record['manifest']
        if not record['ready']: raise ValueError('custody not fully provisioned')
        if s['policy']!=m['policy'] or s['commitment']!=m['commitment']: raise ValueError('immutable commitment')
        validate_snapshot(s)
        if s['events'][0]['data']['payload']!=m['payload']: raise ValueError('ciphertext identity')
        old=record['bundle']['snapshot'] if record['bundle'] else None
        count=len(old['events']) if old else 0
        if old and (s['events'][:count]!=old['events'] or len(s['events'])<count): raise ValueError('history rollback or fork')
        if old and s==old: return record['bundle']
        fresh=s['events'][count:];sample=self.sample()
        recovered=any(e['kind']=='RECOVERED' for e in fresh)
        if any(e['kind']=='RECOVERED' and e['data']['message']['v']!=2 for e in fresh):
            raise ValueError('recovery must bind the current history head')
        if not self.clock.test and s['capsule'] in self.last_publish and (self.elapsed()-self.last_publish[s['capsule']])*1000>self.allowed_gap(m):
            record['blocked']=True
        if not sample['healthy']: record['blocked']=True
        if recovered:
            # Observe the preceding gap first, then apply the fresh signed recovery.
            self.clock.recover();sample=self.sample();record['blocked']=False
        if not sample['lower']<=s['now']<=sample['upper']: raise ValueError('unobserved snapshot time')
        if any(not sample['lower']<=e['time']<=sample['upper'] for e in fresh): raise ValueError('backdated or future facts')
        for e in fresh:
            if e['kind'] in ('ACCEPTED','REVOKED','CANDIDATE_RESET','RECOVERED'):
                record['candidate_upper']=None
            if e['kind']=='ACCEPTED':
                msg=e['data']['message'];c=next(c for c in m['policy']['contracts'] if c['id']==msg['contract'])
                if msg['valid_from']>sample['lower'] or msg['valid_until']<=sample['upper']:
                    record['blocked']=True;self.put(s['capsule'],record);raise ValueError('uncertain proof acceptance window')
                if c['kind']=='absence':
                    ch=next(ch for ch in c['challenges'] if ch['id']==msg['challenge'])
                    if sample['lower']<ch['open'] or sample['upper']>ch['deadline']:
                        record['blocked']=True;self.put(s['capsule'],record);raise ValueError('uncertain presence deadline')
            if e['kind']=='CANDIDATE':
                if e['time']>sample['lower']: raise ValueError('candidate not independently observed yet')
                record['candidate_upper']=sample['upper']
            if e['kind']=='AUTHORISED':
                candidate=next(f for f in s['events'] if f['seq']==e['data']['candidate'])
                if record.get('candidate_upper') is None or sample['lower']<record['candidate_upper']+m['policy']['grace'] or record['blocked']:
                    raise ValueError('unwitnessed grace or observation outage')
        if record['blocked'] and s['healthy']:
            self.put(s['capsule'],record)
            raise ValueError('witness uncertainty requires recovery')
        receipt={'v':2,'manifest':digest(m),'capsule':s['capsule'],'commitment':s['commitment'],
                 'head':s['head'],'count':len(s['events']),'now':s['now'],'healthy':s['healthy']}
        bundle={'snapshot':s,'receipt':receipt,'signature':sign(self.key,receipt)}
        record['bundle']=bundle;self.put(s['capsule'],record)
        self.last_publish[s['capsule']]=self.elapsed()
        return bundle

    def bundle(self,cid,nonce):
        record=self.get(cid)
        if not record.get('bundle'): raise ValueError('no witnessed history')
        sample=self.sample()
        if not self.clock.test and cid in self.last_publish and (self.elapsed()-self.last_publish[cid])*1000>self.allowed_gap(record['manifest']):
            record['blocked']=True;self.put(cid,record)
        s=record['bundle']['snapshot']
        status={'v':2,'nonce':nonce,'manifest':digest(record['manifest']),'head':s['head'],
                'count':len(s['events']),'clock':sample,'blocked':record['blocked'],'candidate_upper':record.get('candidate_upper')}
        return {'bundle':record['bundle'],'status':self.signed(status)}

    def release(self,body,witness_url):
        if not self.available: raise ValueError('custodian unavailable')
        record=self.get(body['capsule']);m=record['manifest']
        # Caller cannot supply a witness URL, history, "approved" boolean or replacement key.
        nonce=secrets.token_hex(24)
        answer=request(witness_url+'/bundle?capsule='+m['capsule']+'&nonce='+nonce)
        status=answer['status']['message'];verify(m['witness'],status,answer['status']['signature'])
        bundle=answer['bundle'];s=bundle['snapshot']
        if status['nonce']!=nonce or status['manifest']!=digest(m) or status['head']!=s['head'] or status['count']!=len(s['events']) or status['blocked'] or not status['clock']['healthy']:
            raise ValueError('witness freshness/health')
        result=validate_bundle(bundle,m)
        node=subprocess.run(['node','Verifier/verify.mjs'],input=canonical(s),capture_output=True,timeout=10)
        independent=strict_json(node.stdout)
        if not independent.get('ok') or {k:v for k,v in independent.items() if k!='ok'}!=result:
            raise ValueError('independent verifier disagreement')
        seen=record['seen']
        if seen and (len(s['events'])<seen['count'] or digest(s['events'][seen['count']-1])!=seen['head']):
            raise ValueError('custodian history rollback')
        # Retain valid history even when there is no permission to release yet.
        record['seen']={'count':len(s['events']),'head':s['head']};self.put(m['capsule'],record)
        if not result['authorised']: raise ValueError('policy has not authorised release')
        decision=next(e for e in s['events'] if e['kind']=='AUTHORISED')
        if status.get('candidate_upper') is None or decision['time']<status['candidate_upper']+m['policy']['grace']:
            raise ValueError('insufficient independently observed grace')
        context={'v':2,'capsule':m['capsule'],'epoch':m['epoch'],'manifest':digest(m),
                 'commitment':m['commitment'],'payload':m['payload'],'decision':digest(decision),
                 'history':s['head'],'index':self.index,'share':record['share']['value']}
        if body.get('decision')!=context['decision'] or body.get('manifest')!=context['manifest']:
            raise ValueError('release request context')
        return self.signed(context)


def main():
    role=os.environ['ROLE'];state=State(os.environ.get('STATE_DIR','/state'),role,int(os.environ.get('INDEX','0')),os.environ.get('CLOCK_MODE')=='test')
    bootstrap=os.environ['BOOTSTRAP_TOKEN']
    if bootstrap=='not-configured': raise ValueError('use scripts/experiment02.sh to provision random capabilities')
    witness=os.environ.get('WITNESS_URL','http://witness:8080')
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass  # Do not log secrets, shares or evidence bodies.
        def respond(self,status,body):
            raw=canonical(body);self.send_response(status);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
        def do_GET(self):
            try:
                u=urlparse(self.path);q=parse_qs(u.query)
                if u.path=='/identity': result={'role':role,'index':state.index,'public':state.public}
                elif u.path=='/clock' and role=='witness': result=state.sample()
                elif u.path=='/bundle' and role=='witness':
                    if not state.available: raise ValueError('independent authority unavailable')
                    result=state.bundle(q['capsule'][0],q['nonce'][0])
                else: raise ValueError('route')
                self.respond(200,result)
            except Exception as exc: self.respond(409,{'error':str(exc)})
        def do_POST(self):
            try:
                size=int(self.headers.get('Content-Length','0'))
                if not 0<size<=4_000_000: raise ValueError('body size')
                body=strict_json(self.rfile.read(size));route=urlparse(self.path).path
                if route in ('/enroll','/ready','/test-clock') or route.startswith('/test-'):
                    if not secrets.compare_digest(self.headers.get('Authorization',''),'Bearer '+bootstrap): raise ValueError('bootstrap capability required')
                if route.startswith('/test-') and not state.clock.test and role=='witness': raise ValueError('fault injection disabled')
                if route=='/test-export-share' and role=='custodian':
                    result=state.get(body['capsule'])['share']
                elif route=='/test-availability':
                    state.available=bool(body['available']);result={'available':state.available}
                elif route=='/test-rewrite' and role=='witness':
                    # Deliberately model compromise of the INDEPENDENT witness.
                    r=state.get(body['snapshot']['capsule']);snapshot=body['snapshot']
                    receipt={'v':2,'manifest':digest(r['manifest']),'capsule':snapshot['capsule'],'commitment':snapshot['commitment'],'head':snapshot['head'],'count':len(snapshot['events']),'now':snapshot['now'],'healthy':snapshot['healthy']}
                    r['bundle']={'snapshot':snapshot,'receipt':receipt,'signature':sign(state.key,receipt)}
                    r['candidate_upper']=next((e['time'] for e in reversed(snapshot['events']) if e['kind']=='CANDIDATE'),None)
                    state.put(snapshot['capsule'],r);result={'compromised':True}
                elif route=='/enroll': result=state.register(body)
                elif route=='/ready' and role=='witness': result=state.ready(body)
                elif route=='/test-clock' and role=='witness':
                    result=state.clock.advance(body['now'],healthy=body.get('healthy',True))
                    if 'upper' in body:
                        if type(body['upper']) is not int or body['upper']<body['now']: raise ValueError('clock interval')
                        state.clock.state['upper']=body['upper']
                    state.sample()
                elif route=='/publish' and role=='witness': result=state.publish(body)
                elif route=='/release' and role=='custodian': result=state.release(body,witness)
                else: raise ValueError('route')
                if self.headers.get('X-Lose-Ack')=='1': self.close_connection=True;return
                self.respond(200,result)
            except Exception as exc: self.respond(409,{'error':str(exc)})
    server=HTTPServer(('0.0.0.0',8080),Handler);server.timeout=1
    while True:
        server.handle_request()
        if role=='witness' and not state.clock.test: state.sample()

if __name__=='__main__': main()
