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
function manifest3(signed) {
  need(exact(signed,['message','signature']),'signed fields');const m=signed.message;
  need(exact(m,['v','capsule','epoch','policy','commitment','payload','witnesses','custody','quorum','slots','operation']),'manifest fields');
  need(m.v===3&&m.epoch===1&&typeof m.capsule==='string'&&m.capsule&&/^[0-9a-f]{64}$/.test(m.payload),'manifest identity');
  policy(m.policy);need(hash(m.policy)===m.commitment,'commitment');signature(m.policy.owner,m,signed.signature);
  need(same(m.quorum,{presence:2,absence:3,faults:1}),'unsafe quorum');
  need(same(Object.keys(m.witnesses).sort(),['1','2','3'])&&new Set(Object.values(m.witnesses)).size===3,'witnesses');
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
function op(m){return hash({v:3,capsule:m.capsule,epoch:m.epoch,manifest:hash(m),commitment:m.commitment,payload:m.payload,...m.operation});}
function findSlot(m,cid,ch){const s=m.slots.find(s=>s.contract===cid&&s.challenge===ch);need(s,'slot domain');return s;}
function proof3(m,signed) {
  need(exact(signed,['message','signature']),'signed fields');const p=signed.message,c=m.policy.contracts.find(c=>c.id===p.contract);
  need(exact(p,['v','id','capsule','manifest','contract','contract_version','challenge','authority','valid_from','valid_until','value']),'proof fields');
  need(p.v===3&&typeof p.id==='string'&&p.id&&p.capsule===m.capsule&&p.manifest===hash(m)&&c&&p.contract_version===c.version&&p.authority===c.authority,'proof domain');
  const s=findSlot(m,p.contract,p.challenge);
  need(typeof p.value==='boolean'&&(c.kind!=='absence'||p.value)&&integer(p.valid_from)&&integer(p.valid_until)&&c.start<=p.valid_from&&p.valid_from<p.valid_until&&p.valid_until<=c.end,'proof value/window');
  signature(c.authority,p,signed.signature);return {c,s,p};
}
function record3(m,signed,kind) {
  need(exact(signed,['message','signature']),'signed fields');const r=signed.message;
  need(exact(r,['v','kind','capsule','manifest','witness','contract','challenge','operation','seq','prev','lower','upper','proof','value','not_before']),'record fields');
  need(r.v===3&&r.kind===kind&&r.capsule===m.capsule&&r.manifest===hash(m)&&r.operation===op(m)&&integer(r.witness)&&m.witnesses[String(r.witness)],'record domain');
  need(integer(r.seq)&&r.seq>=1&&/^[0-9a-f]{64}$/.test(r.prev)&&integer(r.lower)&&integer(r.upper)&&0<=r.lower&&r.lower<=r.upper,'record lineage/time');
  const s=findSlot(m,r.contract,r.challenge),c=m.policy.contracts.find(c=>c.id===s.contract);
  need(r.not_before===s.deadline+1+m.policy.grace,'grace');signature(m.witnesses[String(r.witness)],r,signed.signature);
  let p=null;
  if(r.proof!==null){const info=proof3(m,r.proof);need(info.c.id===c.id&&same(info.s,s),'proof substitution');p=info.p;}
  const value=p?(c.kind==='absence'?'PRESENT':p.value?'TRUE':'FALSE'):(c.kind==='absence'?'ABSENT':'EMPTY');
  need(r.value===value,'record value');
  if(kind==='OBSERVATION')need(p&&s.open<=r.lower&&r.upper<=s.deadline&&p.valid_from<=r.lower&&r.upper<p.valid_until,'late observation');
  else need(r.lower>=r.not_before,'unclosed acceptance window');
  return r;
}
function ack3(object) {
  const m=manifest3(object.manifest),rs=object.receipts.map(r=>record3(m,r,'OBSERVATION'));
  need(rs.length>=2&&new Set(rs.map(r=>r.witness)).size===rs.length,'observation quorum');
  const first=rs[0];need(rs.every(r=>r.contract===first.contract&&r.challenge===first.challenge&&same(r.proof,first.proof)),'mixed evidence');
  return {accepted:true,evidence:hash(first.proof),contract:first.contract,challenge:first.challenge};
}
function release3(cert,retained=[]) {
  need(exact(cert,['v','manifest','finals','operation','authorisation']),'certificate fields');const m=manifest3(cert.manifest);
  need(cert.v===3&&cert.operation===op(m),'operation binding');const {authorisation,...unsigned}=cert;need(authorisation===hash(unsigned),'decision binding');
  need(cert.finals.length===m.slots.length,'incomplete snapshot');
  const results=new Map(),records=[];let latest=0;
  for(let i=0;i<m.slots.length;i++){
    const s=m.slots[i],rs=cert.finals[i].map(r=>record3(m,r,'FINAL'));
    need(rs.length>=3&&new Set(rs.map(r=>r.witness)).size===rs.length&&rs.every(r=>r.contract===s.contract&&r.challenge===s.challenge),'final quorum/domain');
    records.push(...rs);latest=Math.max(latest,...rs.map(r=>r.upper));
    const c=m.policy.contracts.find(c=>c.id===s.contract);
    const yes=c.kind==='absence'?rs.every(r=>r.value==='ABSENT'):rs.every(r=>r.value==='TRUE')&&new Set(rs.map(r=>hash(r.proof))).size===1;
    results.set(JSON.stringify([s.contract,s.challenge]),yes);
  }
  for(const object of retained){need(same(object.manifest,cert.manifest),'retained scope');const a=ack3(object),c=m.policy.contracts.find(c=>c.id===a.contract);need(!(c.kind==='absence'&&results.get(JSON.stringify([a.contract,a.challenge]))),'contradictory retained presence');}
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
function handle3(raw){try{const input=parse(raw);const result=input.kind==='ack'?ack3(input.object):release3(input.object,input.retained??[]);return {ok:true,...result};}catch(e){return {ok:false,error:e.message};}}
if(process.argv.includes('--lines')){for await(const line of readline.createInterface({input:process.stdin}))console.log(JSON.stringify(handle3(line)));}
else{const result=handle3(fs.readFileSync(0,'utf8'));console.log(JSON.stringify(result));if(!result.ok)process.exitCode=1;}
