// Independent implementation: prefix state machine, interval partitioning and
// expression proof counting. No Python calls or generated Python decision code.
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import fs from 'node:fs';
import readline from 'node:readline';

function need(test, reason) { if (!test) throw Error(reason); }
export function canonical(x) {
  if (x === null || typeof x === 'boolean') return JSON.stringify(x);
  if (typeof x === 'number') { need(Number.isSafeInteger(x), 'wire integer'); return String(x); }
  if (typeof x === 'string') {
    need(/^[\x00-\x7f]*$/.test(x), 'wire ASCII');
    return JSON.stringify(x).replace(/\x7f/g, '\\u007f');
  }
  if (Array.isArray(x)) return '[' + x.map(canonical).join(',') + ']';
  need(x && Object.getPrototypeOf(x) === Object.prototype, 'wire object');
  return '{' + Object.keys(x).sort().map(k => canonical(k)+':'+canonical(x[k])).join(',') + '}';
}
const hash = x => createHash('sha256').update(canonical(x)).digest('hex');
const same = (a,b) => canonical(a) === canonical(b);
const exact = (x, keys) => x && same(Object.keys(x).sort(), [...keys].sort());
const integer = Number.isSafeInteger;
function signature(key, message, sig) {
  need(typeof key==='string' && /^[0-9a-f]{64}$/.test(key) && typeof sig==='string' && /^[0-9a-f]{128}$/.test(sig), 'signature encoding');
  const publicKey=createPublicKey({key:Buffer.from('302a300506032b6570032100'+key,'hex'),format:'der',type:'spki'});
  need(cryptoVerify(null,Buffer.from(canonical(message)),publicKey,Buffer.from(sig,'hex')), 'signature');
}

// Reject duplicate names before JSON.parse could discard them.
export function parse(raw) {
  let pos=0;
  function ws() { while ([' ','\t','\r','\n'].includes(raw[pos]) && pos<raw.length) pos++; }
  function string() {
    const start=pos++; let escaped=false;
    while(pos<raw.length) {
      const c=raw[pos++];
      if (!escaped && c==='"') return JSON.parse(raw.slice(start,pos));
      if (!escaped && c==='\\') escaped=true; else escaped=false;
    }
    throw Error('unterminated string');
  }
  function value() {
    ws(); const c=raw[pos];
    if (c==='"') return string();
    if (c==='{') {
      pos++; ws(); const result={}; const names=new Set();
      if(raw[pos]==='}') {pos++;return result;}
      while(true) {
        ws();need(raw[pos]==='"','object name');const name=string();
        need(!names.has(name),'duplicate JSON key');names.add(name);
        ws();need(raw[pos++]===':','colon');
        Object.defineProperty(result,name,{value:value(),enumerable:true,writable:true,configurable:true});
        ws();const end=raw[pos++];if(end==='}') return result;need(end===',','comma');
      }
    }
    if(c==='[') {
      pos++;ws();const result=[];if(raw[pos]===']'){pos++;return result;}
      while(true){result.push(value());ws();const end=raw[pos++];if(end===']')return result;need(end===',','comma');}
    }
    const literal=/^(true|false|null|-?(?:0|[1-9][0-9]*))/.exec(raw.slice(pos));
    need(literal,'JSON value');pos+=literal[0].length;return JSON.parse(literal[0]);
  }
  const result=value();ws();need(pos===raw.length,'trailing JSON');canonical(result);return result;
}

function policy(p) {
  need(exact(p,['version','owner','contracts','expression','grace','max_step','destination']), 'policy fields');
  need(p.version===1 && integer(p.grace) && p.grace>0 && integer(p.max_step) && p.max_step>0,'policy version/bounds');
  need(/^[0-9a-f]{64}$/.test(p.owner),'owner');
  need(same(p.destination,{kind:'simulated',verified:true,consented:true}),'destination');
  const ids=new Set();
  for(const c of p.contracts) {
    need(exact(c,['id','version','kind','authority','start','end','challenges']),'contract fields');
    need(typeof c.id==='string' && c.id && !ids.has(c.id) && c.version===1,'contract identity');ids.add(c.id);
    need(['absence','attestation'].includes(c.kind) && /^[0-9a-f]{64}$/.test(c.authority),'contract authority/kind');
    need(integer(c.start) && integer(c.end) && c.start<c.end,'contract time');
    const challengeIds=new Set();
    for(const ch of c.challenges) {
      need(exact(ch,['id','open','deadline']) && typeof ch.id==='string' && ch.id && !challengeIds.has(ch.id),'challenge');challengeIds.add(ch.id);
      need(integer(ch.open) && integer(ch.deadline) && c.start<=ch.open && ch.open<=ch.deadline && ch.deadline<c.end,'challenge time');
    }
    need((c.kind==='absence') === (c.challenges.length>0),'challenge kind');
  }
  const visited=new Set();
  function node(e, depth=0) {
    need(depth<=32,'expression depth');
    if(typeof e==='string') {need(ids.has(e)&&!visited.has(e),'expression leaf');visited.add(e);return;}
    need(e && ['AND','OR','THRESHOLD'].includes(e.op),'operator');
    need(exact(e,e.op==='THRESHOLD'?['op','k','args']:['op','args']) && Array.isArray(e.args) && e.args.length,'expression');
    if(e.op==='THRESHOLD') need(integer(e.k)&&e.k>=1&&e.k<=e.args.length,'threshold');
    for(const child of e.args)node(child,depth+1);
  }
  node(p.expression);need(ids.size>0 && same([...ids].sort(),[...visited].sort()),'unused contracts');
}

// Independent compact-certificate verifier. No Python implementation or history
// projection is used: signatures, complete slot coverage and quorum proofs suffice.
function manifest4(signed) {
  need(exact(signed,['message','signature']),'signed fields');const m=signed.message;
  need(exact(m,['v','capsule','epoch','policy','commitment','payload','witnesses','custody','quorum','slots','operation']),'manifest fields');
  need(m.v===4&&m.epoch===1&&typeof m.capsule==='string'&&m.capsule&&/^[0-9a-f]{64}$/.test(m.payload),'manifest identity');
  need(m.slots.length>=1&&m.slots.length<=8&&m.policy.contracts.length>=1&&m.policy.contracts.length<=8,'bounded profile size');
  policy(m.policy);need(hash(m.policy)===m.commitment,'commitment');signature(m.policy.owner,m,signed.signature);
  need(same(m.quorum,{presence:3,absence:3,faults:1}),'unsafe quorum');
  need(same(Object.keys(m.witnesses).sort(),['1','2','3','4'])&&new Set(Object.values(m.witnesses)).size===4,'witnesses');
  need(exact(m.custody,['k','n','keys'])&&m.custody.k===2&&m.custody.n===3&&same(Object.keys(m.custody.keys).sort(),['1','2','3'])&&new Set(Object.values(m.custody.keys)).size===3,'custody');
  for(const key of [...Object.values(m.witnesses),...Object.values(m.custody.keys)])need(/^[0-9a-f]{64}$/.test(key),'key');
  need(same(m.operation,{attempt:'release-1',kind:'reconstruct-aes-128-gcm'}),'operation');
  const expected=[];
  for(const c of m.policy.contracts) {
    if(c.kind==='absence')for(const ch of c.challenges)expected.push({contract:c.id,challenge:ch.id,open:ch.open,deadline:ch.deadline});
    else {
      const slots=m.slots.filter(s=>s.contract===c.id);need(slots.length===1&&slots[0].challenge==='attestation','claim slot');
      const s=slots[0];need(c.start<=s.open&&s.open<=s.deadline&&s.deadline+1+m.policy.grace<c.end,'claim cutoff');expected.push(s);
    }
  }
  need(same(expected,m.slots)&&m.slots.every(s=>exact(s,['contract','challenge','open','deadline'])&&integer(s.open)&&integer(s.deadline)&&s.open>=0),'slots');return m;
}
function op(m){return hash({v:4,capsule:m.capsule,epoch:m.epoch,manifest:hash(m),commitment:m.commitment,payload:m.payload,...m.operation});}
function findSlot(m,cid,ch){const s=m.slots.find(s=>s.contract===cid&&s.challenge===ch);need(s,'slot domain');return s;}
function proof4(m,signed) {
  need(exact(signed,['message','signature']),'signed fields');const p=signed.message,c=m.policy.contracts.find(c=>c.id===p.contract);
  need(exact(p,['v','id','capsule','manifest','contract','contract_version','challenge','authority','valid_from','valid_until','value']),'proof fields');
  need(p.v===4&&typeof p.id==='string'&&p.id&&p.capsule===m.capsule&&p.manifest===hash(m)&&c&&p.contract_version===c.version&&p.authority===c.authority,'proof domain');
  const s=findSlot(m,p.contract,p.challenge);
  need(typeof p.value==='boolean'&&(c.kind!=='absence'||p.value)&&integer(p.valid_from)&&integer(p.valid_until)&&c.start<=p.valid_from&&p.valid_from<p.valid_until&&p.valid_until<=c.end,'proof value/window');
  signature(c.authority,p,signed.signature);return {c,s,p};
}
function record4(m,signed,kind) {
  need(exact(signed,['message','signature']),'signed fields');const r=signed.message;
  need(exact(r,['v','kind','capsule','manifest','witness','contract','challenge','operation','seq','prev','lower','upper','proof','value','not_before']),'record fields');
  need(r.v===4&&r.kind===kind&&r.capsule===m.capsule&&r.manifest===hash(m)&&r.operation===op(m)&&integer(r.witness)&&m.witnesses[String(r.witness)],'record domain');
  need(integer(r.seq)&&r.seq>=1&&/^[0-9a-f]{64}$/.test(r.prev)&&integer(r.lower)&&integer(r.upper)&&0<=r.lower&&r.lower<=r.upper,'record lineage/time');
  const s=findSlot(m,r.contract,r.challenge),c=m.policy.contracts.find(c=>c.id===s.contract);
  need(r.not_before===s.deadline+1+m.policy.grace,'grace');signature(m.witnesses[String(r.witness)],r,signed.signature);
  let p=null;
  if(r.proof!==null){const info=proof4(m,r.proof);need(info.c.id===c.id&&same(info.s,s),'proof substitution');p=info.p;}
  const value=p?(c.kind==='absence'?'PRESENT':p.value?'TRUE':'FALSE'):(c.kind==='absence'?'ABSENT':'EMPTY');
  need(r.value===value||(kind==='FINAL'&&c.kind==='attestation'&&p===null&&r.value==='CONFLICT'),'record value');
  if(kind==='OBSERVATION')need(p&&s.open<=r.lower&&r.upper<=s.deadline&&p.valid_from<=r.lower&&r.upper<p.valid_until,'late observation');
  else need(r.lower>=r.not_before,'unclosed acceptance window');
  return r;
}
function ack4(object) {
  const m=manifest4(object.manifest),rs=object.receipts.map(r=>record4(m,r,'OBSERVATION'));
  need(rs.length>=3&&new Set(rs.map(r=>r.witness)).size===rs.length,'observation quorum');
  const first=rs[0];need(rs.every(r=>r.contract===first.contract&&r.challenge===first.challenge&&same(r.proof,first.proof)),'mixed evidence');
  return {accepted:true,evidence:hash(first.proof),contract:first.contract,challenge:first.challenge};
}
function release4(cert,retained=[]) {
  need(exact(cert,['v','manifest','finals','operation','authorisation']),'certificate fields');const m=manifest4(cert.manifest);
  need(cert.v===4&&cert.operation===op(m),'operation binding');const {authorisation,...unsigned}=cert;need(authorisation===hash(unsigned),'decision binding');
  need(cert.finals.length===m.slots.length,'incomplete snapshot');
  const results=new Map(),records=[];let latest=0;
  for(let i=0;i<m.slots.length;i++){
    const s=m.slots[i],rs=cert.finals[i].map(r=>record4(m,r,'FINAL'));
    need(rs.length>=3&&new Set(rs.map(r=>r.witness)).size===rs.length&&rs.every(r=>r.contract===s.contract&&r.challenge===s.challenge),'final quorum/domain');
    records.push(...rs);latest=Math.max(latest,...rs.map(r=>r.upper));
    const c=m.policy.contracts.find(c=>c.id===s.contract);
    const yes=c.kind==='absence'?rs.every(r=>r.value==='ABSENT'):rs.every(r=>r.value==='TRUE')&&new Set(rs.map(r=>hash(r.proof))).size===1;
    results.set(JSON.stringify([s.contract,s.challenge]),yes);
  }
  for(const object of retained){need(same(object.manifest,cert.manifest),'retained scope');const a=ack4(object),c=m.policy.contracts.find(c=>c.id===a.contract);need(!(c.kind==='absence'&&results.get(JSON.stringify([a.contract,a.challenge]))),'contradictory retained presence');}
  const contracts={};
  for(const c of m.policy.contracts){
    const active=c.start<=latest&&latest<c.end;
    const slots=m.slots.filter(s=>s.contract===c.id);
    const value=c.kind==='absence'?slots.some(s=>results.get(JSON.stringify([c.id,s.challenge]))):results.get(JSON.stringify([c.id,'attestation']))&&records.filter(r=>r.contract===c.id&&r.value==='TRUE').every(r=>r.proof.message.valid_until>latest);
    Object.defineProperty(contracts,c.id,{value:!!(active&&value),enumerable:true});
  }
  function evalPolicy(e){if(typeof e==='string')return contracts[e];const n=e.args.filter(evalPolicy).length;return n>=(e.op==='AND'?e.args.length:e.op==='OR'?1:e.k);}
  need(evalPolicy(m.policy.expression),'policy unsatisfied');return {authorised:true,contracts,time:latest,operation:op(m)};
}

// v8 terminal certificate checker. This verifies signatures/guards, not global absence
// of a hidden conflicting history or the implementation's liveness.
const P=BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
const Q=BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const B=BigInt('0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b');
const G=[BigInt('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'),BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5')];
const mod=(n,p=P)=>((n%p)+p)%p;
function inv(n,p=P){let a=mod(n,p),b=p,x=1n,y=0n;need(a!==0n,'inverse zero');while(b){const t=a/b;[a,b]=[b,a-t*b];[x,y]=[y,x-t*y];}need(a===1n,'inverse');return mod(x,p);}
function add(a,b){if(a===null)return b;if(b===null)return a;const [x,y]=a,[u,v]=b;if(x===u&&mod(y+v)===0n)return null;const l=x===u?mod((3n*x*x-3n)*inv(2n*y)):mod((v-y)*inv(u-x));const z=mod(l*l-x-u);return [z,mod(l*(x-z)-y)];}
function mul(n,p){let out=null;for(n=mod(n,Q);n;n>>=1n){if(n&1n)out=add(out,p);p=add(p,p);}return out;}
const equal=(a,b)=>a===null?b===null:b!==null&&a[0]===b[0]&&a[1]===b[1];
function point(s){need(typeof s==='string'&&/^04[0-9a-f]{128}$/.test(s),'point encoding');const x=BigInt('0x'+s.slice(2,66)),y=BigInt('0x'+s.slice(66));need(x<P&&y<P&&mod(y*y)===mod(x*x*x-3n*x+B),'curve membership');return [x,y];}
function scalar(s){need(typeof s==='string'&&/^[0-9a-f]{64}$/.test(s),'scalar encoding');const x=BigInt('0x'+s);need(x<Q,'scalar range');return x;}

const checkedRegistries=new Map();
const suite8='otherwise08-pbft-single-terminal-split-dh';
function registry8(reg){
  const cacheKey=hash(reg);if(checkedRegistries.has(cacheKey))return checkedRegistries.get(cacheKey);
  need(exact(reg,['message','signature']),'registry envelope');const r=reg.message;
  need(exact(r,['v','suite','split','committee','model','operation'])&&r.v===8&&r.suite===suite8&&r.model==='AUTHORISATION_WINS'&&r.operation==='terminal-1','registry profile');
  const c=r.split.message,m=manifest4(c.manifest);need(c.v===7&&c.suite==='otherwise07-xor2-threshold-dh-p256-hkdf-sha256-aesgcm-x25519','split profile');signature(m.policy.owner,c,r.split.signature);signature(m.policy.owner,r,reg.signature);
  need(exact(c,['v','suite','epoch','manifest','recipient','domains','wraps','plaintext_commitment'])&&Number.isSafeInteger(c.epoch)&&c.epoch>=1&&/^[0-9a-f]{64}$/.test(c.recipient)&&/^[0-9a-f]{64}$/.test(c.plaintext_commitment)&&exact(c.domains,['custody','authority'])&&exact(c.wraps,['custody','authority']),'split schema');
  const all=[],generations=[];
  for(const domain of ['custody','authority']){const d=c.domains[domain],key=d.key,w=c.wraps[domain];need(exact(d,['epoch','key','members'])&&Number.isSafeInteger(d.epoch)&&d.epoch>=1&&exact(d.members,['1','2','3']),'domain schema');for(const pk of Object.values(d.members)){need(typeof pk==='string'&&/^[0-9a-f]{64}$/.test(pk),'member');all.push(pk);}
    need(exact(key,['v','scheme','k','n','X','Y'])&&key.v===6&&key.scheme==='reference-p256-threshold-dh'&&key.k===2&&key.n===3&&exact(key.Y,['1','2','3'])&&new Set(Object.values(key.Y)).size===3&&!Object.values(key.Y).includes(key.X),'key schema');const X=point(key.X),Y=Object.fromEntries(Object.entries(key.Y).map(([i,y])=>[i,point(y)]));generations.push(key.X);
    for(const [i,j] of [[1n,2n],[1n,3n],[2n,3n]])need(equal(add(mul(mod(j*inv(j-i,Q),Q),Y[i]),mul(mod(i*inv(i-j,Q),Q),Y[j])),X),'public share interpolation');
    need(exact(w,['R','wrapped'])&&typeof w.wrapped==='string'&&/^[0-9a-f]{88}$/.test(w.wrapped),'wrapped component');point(w.R);
  }
  need(new Set(all).size===6&&new Set(generations).size===2&&same(c.domains.custody.members,m.custody.keys),'independent committee identities');
  need(same(r.committee,{epoch:1,keys:m.witnesses}),'membership epoch');checkedRegistries.set(cacheKey,m);return m;
}
function scope8(reg){const m=registry8(reg);return {v:8,suite:suite8,capsule:m.capsule,registry:hash(reg),membership_epoch:1,operation:'terminal-1'};}
function value8(reg,v){const m=registry8(reg);need(exact(v,['scope','kind','arm','evidence','command'])&&same(v.scope,scope8(reg))&&['RELEASE','DISARM'].includes(v.kind),'terminal value');
  const ids=new Set();need(Array.isArray(v.arm)&&v.arm.length>=3&&v.arm.length<=4,'arm quorum');
  for(const signed of v.arm){const a=signed.message;need(exact(a,['v','kind','capsule','manifest','operation','witness','command'])&&a.v===4&&a.kind==='ARM'&&a.capsule===m.capsule&&a.manifest===hash(m)&&a.operation===op(m)&&Number.isInteger(a.witness)&&a.witness>=1&&a.witness<=4&&!ids.has(a.witness),'arm fence');ids.add(a.witness);signature(m.witnesses[a.witness],a,signed.signature);need(same(a.command.message,{v:4,capsule:m.capsule,manifest:hash(m),action:'ARM',operation:op(m)}),'arm command');signature(m.policy.owner,a.command.message,a.command.signature);}
  if(v.kind==='RELEASE'){need(v.command===null&&same(v.evidence.manifest,reg.message.split.message.manifest),'release scope');release4(v.evidence);}
  else{need(v.evidence===null&&same(v.command.message,{...scope8(reg),action:'DISARM'}),'owner command scope');signature(m.policy.owner,v.command.message,v.command.signature);}
}
function votes8(reg,kind,view,v,items){const m=registry8(reg);need(Number.isSafeInteger(view)&&view>=0&&view<=64&&Array.isArray(items)&&items.length>=3&&items.length<=4,'vote bounds');const seen=new Set();
  for(const s of items){need(exact(s,['message','signature']),'vote encoding');const i=s.message.witness;need(Number.isInteger(i)&&i>=1&&i<=4&&!seen.has(i),'distinct vote');seen.add(i);need(same(s.message,{...scope8(reg),kind,view,value:hash(v),witness:i}),'vote scope');signature(m.witnesses[i],s.message,s.signature);}
}
function final8(reg,c){need(exact(c,['v','registry','view','value','prepares','commits'])&&c.v===8&&c.registry===hash(reg),'certificate scope');value8(reg,c.value);votes8(reg,'PREPARE',c.view,c.value,c.prepares);votes8(reg,'COMMIT',c.view,c.value,c.commits);return {kind:c.value.kind,value:hash(c.value),view:c.view};}
function handle8(raw){try{const i=parse(raw);need(exact(i,['registry','certificate']),'input');return {ok:true,...final8(i.registry,i.certificate)};}catch(e){return {ok:false};}}
if(process.argv.includes('--lines')){for await(const line of readline.createInterface({input:process.stdin}))console.log(JSON.stringify(handle8(line)));}
else{const r=handle8(fs.readFileSync(0,'utf8'));console.log(JSON.stringify(r));if(!r.ok)process.exitCode=1;}
