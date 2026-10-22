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

function check(input){
 const sm=input.manifest,m=manifest4(sm),r=input.snapshot.message;
 need(exact(sm,['message','signature'])&&m.v===4&&same(m.quorum,{presence:3,absence:3,faults:1}),'manifest profile');
 signature(m.policy.owner,m,sm.signature);
 need(exact(input.snapshot,['message','signature'])&&exact(r,['v','kind','capsule','manifest','nonce','witness','records','clock']),'snapshot fields');
 need(r.v===5&&r.kind==='INSPECT'&&r.capsule===m.capsule&&r.manifest===hash(m),'snapshot domain');
 need(typeof input.nonce==='string'&&/^[0-9a-f]{64}$/.test(input.nonce)&&r.nonce===input.nonce,'fresh challenge');
 need(integer(input.index)&&r.witness===input.index&&m.witnesses[String(input.index)],'source');
 signature(m.witnesses[String(input.index)],r,input.snapshot.signature);
 need(exact(r.clock,['lower','upper','healthy','reason'])&&r.clock.healthy===true&&integer(r.clock.lower)&&integer(r.clock.upper)&&0<=r.clock.lower&&r.clock.lower<=r.clock.upper&&Array.isArray(r.records),'clock/records');
 return {ok:true,witness:r.witness,nonce:r.nonce};
}
function handle(raw){try{return check(parse(raw))}catch(e){return {ok:false,error:e.message}}}
if(process.argv.includes('--lines')){for await(const line of readline.createInterface({input:process.stdin}))console.log(JSON.stringify(handle(line)))}
else{const r=handle(fs.readFileSync(0,'utf8'));console.log(JSON.stringify(r));if(!r.ok)process.exitCode=1}
