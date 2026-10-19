"""Single-authority transactional laboratory engine. No network delivery."""
import json
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .protocol import canonical, digest, validate_policy, verify
from .evaluator import evaluate


class Engine:
    def __init__(self, root):
        self.root = Path(root); self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root/'authority.db'
        with self.connect() as db:
            db.executescript('''
            CREATE TABLE IF NOT EXISTS capsules(id TEXT PRIMARY KEY, policy TEXT NOT NULL,
                commitment TEXT NOT NULL, payload TEXT NOT NULL, head TEXT NOT NULL, count INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS events(capsule TEXT, seq INTEGER, body TEXT NOT NULL,
                hash TEXT NOT NULL, PRIMARY KEY(capsule,seq));
            CREATE TABLE IF NOT EXISTS clock(id INTEGER PRIMARY KEY CHECK(id=1), now INTEGER NOT NULL,
                healthy INTEGER NOT NULL);
            INSERT OR IGNORE INTO clock VALUES(1,0,1);
            CREATE TABLE IF NOT EXISTS inbox(capsule TEXT PRIMARY KEY, decision TEXT NOT NULL,
                content BLOB NOT NULL);
            ''')

    def connect(self):
        db = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA synchronous=FULL')
        db.execute('PRAGMA foreign_keys=ON')
        return db

    @contextmanager
    def transaction(self):
        db = self.connect()
        try:
            db.execute('BEGIN IMMEDIATE')
            yield db
            db.commit()
        except BaseException:
            db.rollback(); raise
        finally: db.close()

    def append(self, db, cid, kind, data):
        row = db.execute('SELECT * FROM capsules WHERE id=?',(cid,)).fetchone()
        now = db.execute('SELECT now FROM clock').fetchone()[0]
        event = {'v':1,'capsule':cid,'seq':row['count']+1,'time':now,'kind':kind,'data':data,'prev':row['head']}
        h = digest(event)
        db.execute('INSERT INTO events VALUES(?,?,?,?)',(cid,event['seq'],canonical(event).decode(),h))
        db.execute('UPDATE capsules SET head=?,count=? WHERE id=?',(h,event['seq'],cid))
        return event

    def snapshot(self, db, cid):
        row = db.execute('SELECT * FROM capsules WHERE id=?',(cid,)).fetchone()
        if row is None: raise ValueError('unknown capsule')
        p = json.loads(row['policy']); validate_policy(p)
        if digest(p) != row['commitment']: raise ValueError('policy corruption')
        previous = '0'*64; history=[]; last_time=-1
        for i, fact in enumerate(db.execute('SELECT * FROM events WHERE capsule=? ORDER BY seq',(cid,)),1):
            e = json.loads(fact['body'])
            if e['seq']!=i or e['capsule']!=cid or e['prev']!=previous or digest(e)!=fact['hash'] or e['time']<last_time:
                raise ValueError('corrupt history')
            previous=fact['hash']; last_time=e['time']; history.append(e)
        if len(history)!=row['count'] or previous!=row['head'] or not history or history[0]['kind']!='CREATED' or history[0]['data']!={'commitment':row['commitment'],'payload':row['payload']}:
            raise ValueError('corrupt history anchor')
        clock=db.execute('SELECT * FROM clock').fetchone()
        if clock['now']<last_time: raise ValueError('clock rollback')
        local_uncertainty=max((e['seq'] for e in history if e['kind']=='CLOCK' and not e['data']['healthy']),default=0)
        local_recovery=max((e['seq'] for e in history if e['kind']=='RECOVERED'),default=0)
        healthy=bool(clock['healthy']) and local_uncertainty<=local_recovery
        return {'capsule':cid,'commitment':row['commitment'],'policy':p,'events':history,'head':previous,'now':clock['now'],'healthy':healthy}

    def export(self,cid):
        with self.transaction() as db: return self.snapshot(db,cid)

    def create(self, cid, policy, plaintext=b'Otherwise test message'):
        validate_policy(policy); canonical(cid)
        if type(cid) is not str or not cid: raise ValueError('capsule identity')
        # Random filenames avoid user-controlled path traversal. Keys and ciphertext separate.
        ref=os.urandom(16).hex(); key=AESGCM.generate_key(bit_length=256); nonce=os.urandom(12)
        keys=self.root/'keys'; payloads=self.root/'payloads'
        keys.mkdir(exist_ok=True,mode=0o700); payloads.mkdir(exist_ok=True)
        with self.transaction() as db:
            commitment=digest(policy)
            db.execute('INSERT INTO capsules VALUES(?,?,?,?,?,?)',(cid,canonical(policy).decode(),commitment,ref,'0'*64,0))
            fd=os.open(keys/(ref+'.key'),os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as f:
                f.write(key); f.flush(); os.fsync(f.fileno())
            with open(payloads/(ref+'.aes'),'xb') as f:
                f.write(nonce+AESGCM(key).encrypt(nonce,plaintext,canonical({'capsule':cid,'commitment':commitment})))
                f.flush(); os.fsync(f.fileno())
            for directory in (keys,payloads,self.root):
                descriptor=os.open(directory,os.O_RDONLY)
                try: os.fsync(descriptor)
                finally: os.close(descriptor)
            self.append(db,cid,'CREATED',{'commitment':commitment,'payload':ref})
        return commitment

    def import_encrypted(self, cid, policy, ciphertext, *, crash_at=None):
        """Generation 0.2 client ciphertext only. No plaintext or key enters this API.
        Payload identity is its SHA-256; independent custody is provided by Bounded.
        """
        import hashlib
        validate_policy(policy)
        if type(cid) is not str or not cid: raise ValueError('capsule identity')
        canonical(cid)
        ref=hashlib.sha256(ciphertext).hexdigest()
        payloads=self.root/'payloads'; payloads.mkdir(exist_ok=True)
        path=payloads/(ref+'.aes')
        if path.exists():
            if path.read_bytes()!=ciphertext: raise ValueError('payload collision')
        else:
            with open(path,'xb') as f:
                f.write(ciphertext); f.flush(); os.fsync(f.fileno())
            for directory in (payloads,self.root):
                descriptor=os.open(directory,os.O_RDONLY)
                try: os.fsync(descriptor)
                finally: os.close(descriptor)
        if crash_at=='payload': os._exit(71)
        with self.transaction() as db:
            commitment=digest(policy)
            db.execute('INSERT INTO capsules VALUES(?,?,?,?,?,?)',
                       (cid,canonical(policy).decode(),commitment,ref,'0'*64,0))
            self.append(db,cid,'CREATED',{'commitment':commitment,'payload':ref})
            if crash_at=='before_commit': os._exit(72)
        if crash_at=='after_commit': os._exit(73)
        return commitment

    def owner_command(self,cid,action,signature,context=None):
        with self.transaction() as db:
            s=self.snapshot(db,cid)
            m={'v':1,'capsule':cid,'commitment':s['commitment'],'action':action}
            if context is not None:
                if context!={'head':s['head']}: raise ValueError('stale owner command head')
                m={**m,'v':2,'head':s['head']}
            verify(s['policy']['owner'],m,signature)
            kinds=[e['kind'] for e in s['events']]
            if action not in ('ARMED','DISARMED','RECOVERED'): raise ValueError('owner action')
            if action=='RECOVERED':
                if 'AUTHORISED' in kinds or 'DISARMED' in kinds: raise ValueError('terminal')
                db.execute('UPDATE clock SET healthy=1')
                self.append(db,cid,'RECOVERED',{'message':m,'signature':signature})
                return
            if action in kinds: return
            if 'AUTHORISED' in kinds or 'DISARMED' in kinds: raise ValueError('terminal')
            if action=='ARMED' and not s['healthy']: raise ValueError('clock uncertain')
            self.append(db,cid,action,{'message':m,'signature':signature})
            if action=='ARMED':
                for c in s['policy']['contracts']:
                    for ch in c['challenges']:
                        self.append(db,cid,'CHALLENGE',{'contract':c['id'],'contract_version':c['version'],**ch})

    def tick(self, now, outage=False):
        """Trusted test-clock adapter; forward jumps/outage latch uncertainty, rollback rejected."""
        if type(now) is not int or now<0: raise ValueError('clock')
        with self.transaction() as db:
            old=db.execute('SELECT now FROM clock').fetchone()[0]
            if now<old: raise ValueError('clock rollback')
            rows=db.execute('SELECT id,policy FROM capsules').fetchall()
            for row in rows: self.snapshot(db,row['id'])
            bound=min([json.loads(r['policy'])['max_step'] for r in rows] or [60])
            uncertain=outage or now-old>bound
            db.execute('UPDATE clock SET now=?,healthy=CASE WHEN ? THEN 0 ELSE healthy END',(now,uncertain))
            for row in rows: self.append(db,row['id'],'CLOCK',{'healthy':not uncertain and bool(db.execute('SELECT healthy FROM clock').fetchone()[0])})

    def submit(self,cid,message,signature):
        with self.transaction() as db:
            s=self.snapshot(db,cid)
            # Recover a lost receipt even after expiration, revocation or authorisation.
            for e in s['events']:
                if e['kind']=='ACCEPTED' and e['data']['message']['id']==message.get('id'):
                    if e['data']!={'message':message,'signature':signature}: raise ValueError('submission id collision')
                    return {'accepted':True,'receipt':e['seq'],'duplicate':True}
            self.append(db,cid,'SUBMITTED',{'message':message,'signature':signature})
            try:
                kinds={e['kind'] for e in s['events']}
                if 'ARMED' not in kinds or kinds & {'DISARMED','AUTHORISED'}: raise ValueError('not active')
                c=next((c for c in s['policy']['contracts'] if c['id']==message.get('contract')),None)
                if c is None: raise ValueError('unknown contract')
                base={'v','id','capsule','commitment','contract','contract_version','authority','valid_from','valid_until'}
                if set(message)!=base|({'claim'} if c['kind']=='attestation' else {'challenge'}): raise ValueError('evidence schema')
                if type(message['v']) is not int or message['v']!=1 or type(message['contract_version']) is not int or type(message['id']) is not str or not message['id'] or message['capsule']!=cid or message['commitment']!=s['commitment'] or message['contract_version']!=c['version'] or message['authority']!=c['authority']: raise ValueError('evidence scope')
                verify(c['authority'],message,signature)
                if any(e['kind']=='REVOKED' and e['data']['authority']==c['authority'] for e in s['events']): raise ValueError('revoked authority')
                a,b=message['valid_from'],message['valid_until']
                if type(a) is not int or type(b) is not int or not c['start']<=a<=s['now']<b<=c['end']: raise ValueError('stale or invalid proof window')
                if c['kind']=='attestation':
                    if type(message['claim']) is not bool: raise ValueError('claim schema')
                else:
                    ch=next((ch for ch in c['challenges'] if ch['id']==message['challenge']),None)
                    if ch is None or not ch['open']<=s['now']<=ch['deadline']: raise ValueError('challenge deadline')
                e=self.append(db,cid,'ACCEPTED',{'message':message,'signature':signature})
                # Evidence may invalidate a previous release candidate immediately.
                self.append(db,cid,'CANDIDATE_RESET',{'reason':'evidence accepted'})
                return {'accepted':True,'receipt':e['seq'],'duplicate':False}
            except ValueError as exc:
                self.append(db,cid,'REJECTED',{'reason':str(exc),'submission':message.get('id')})
                return {'accepted':False,'reason':str(exc)}

    def revoke(self,cid,authority,signature):
        with self.transaction() as db:
            s=self.snapshot(db,cid)
            m={'v':1,'capsule':cid,'commitment':s['commitment'],'action':'REVOKED','authority':authority}
            verify(s['policy']['owner'],m,signature)
            if authority not in {c['authority'] for c in s['policy']['contracts']}: raise ValueError('unknown authority')
            if any(e['kind'] in ('DISARMED','AUTHORISED') for e in s['events']): raise ValueError('terminal')
            self.append(db,cid,'REVOKED',{'authority':authority,'message':m,'signature':signature})
            self.append(db,cid,'CANDIDATE_RESET',{'reason':'authority revoked'})

    def notify(self,cid,success):
        with self.transaction() as db:
            self.snapshot(db,cid)
            self.append(db,cid,'NOTIFICATION',{'success':bool(success),'meaning':'transport observation only'})

    def authorise(self,cid):
        with self.transaction() as db:
            s=self.snapshot(db,cid); history=s['events']; kinds={e['kind'] for e in history}
            existing=next((e for e in history if e['kind']=='AUTHORISED'),None)
            if existing: return existing
            if 'ARMED' not in kinds or 'DISARMED' in kinds or not s['healthy']: return None
            decision=evaluate(s['policy'],history,s['now'])
            candidate=None
            for e in history:
                if e['kind'] in ('RECOVERED','CANDIDATE_RESET'): candidate=None
                if e['kind']=='CANDIDATE': candidate=e
            if not decision['satisfied']:
                if candidate: self.append(db,cid,'CANDIDATE_RESET',{'reason':'policy unsatisfied'})
                return None
            # Continuous validity checked at each acceptance/revocation, and expiry is monotone.
            if candidate is None:
                self.append(db,cid,'CANDIDATE',{'snapshot':s['head'],'results':decision,'grace':s['policy']['grace']})
                return None
            boundaries={candidate['time'],s['now']}
            for c in s['policy']['contracts']:
                boundaries.update((c['start'],c['end']))
                boundaries.update(ch['deadline']+1 for ch in c['challenges'])
            for e in history:
                if e['kind']=='ACCEPTED':
                    m=e['data']['message']; boundaries.update((m['valid_from'],m['valid_until']))
            if any(not evaluate(s['policy'],history,t)['satisfied'] for t in boundaries if candidate['time']<=t<=s['now']):
                self.append(db,cid,'CANDIDATE_RESET',{'reason':'intervening policy validity gap'})
                reset_snapshot=self.snapshot(db,cid)
                self.append(db,cid,'CANDIDATE',{'snapshot':reset_snapshot['head'],'results':decision,'grace':s['policy']['grace']})
                return None
            if s['now']-candidate['time'] < s['policy']['grace']: return None
            return self.append(db,cid,'AUTHORISED',{'commitment':s['commitment'],'snapshot':s['head'],'results':decision,'candidate':candidate['seq'],'payload':db.execute('SELECT payload FROM capsules WHERE id=?',(cid,)).fetchone()[0]})

    def deliver(self,cid,crash=False):
        """Simulated idempotent recipient is a different durable transaction from audit ack."""
        with self.transaction() as db:
            s=self.snapshot(db,cid)
            decision=next((e for e in s['events'] if e['kind']=='AUTHORISED'),None)
            if decision is None: raise ValueError('not authorised')
            ref=decision['data']['payload']; key=(self.root/'keys'/(ref+'.key')).read_bytes()
            ciphertext=(self.root/'payloads'/(ref+'.aes')).read_bytes()
            plaintext=AESGCM(key).decrypt(ciphertext[:12],ciphertext[12:],canonical({'capsule':cid,'commitment':s['commitment']}))
            db.execute('INSERT OR IGNORE INTO inbox VALUES(?,?,?)',(cid,digest(decision),plaintext))
        if crash: raise RuntimeError('crash after recipient accepted, before acknowledgement')
        with self.transaction() as db:
            s=self.snapshot(db,cid)
            if not any(e['kind']=='RELEASED' for e in s['events']): self.append(db,cid,'RELEASED',{'decision':digest(decision),'adapter':'simulated-inbox','receipt':'durable inbox insertion; not human receipt'})
        return plaintext
