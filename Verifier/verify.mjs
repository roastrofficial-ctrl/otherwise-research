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

function semantics(p, history, time) {
  const disabled=new Set(history.filter(f=>f.kind==='REVOKED').map(f=>f.data.authority));
  const proofs=history.filter(f=>f.kind==='ACCEPTED').map(f=>f.data.message);
  const contracts={};
  for(const c of p.contracts) {
    let result=false;
    if(c.start<=time && time<c.end && !disabled.has(c.authority)) {
      const scoped=proofs.filter(m=>m.contract===c.id && m.contract_version===c.version);
      if(c.kind==='absence') {
        const seen=new Set(scoped.map(m=>m.challenge));
        result=c.challenges.some(ch=>time>ch.deadline && !seen.has(ch.id));
      } else {
        const live=scoped.filter(m=>m.valid_from<=time && time<m.valid_until);
        result=live.some(m=>m.claim===true) && !live.some(m=>m.claim===false);
      }
    }
    Object.defineProperty(contracts,c.id,{value:result,enumerable:true});
  }
  function support(e) {
    if(typeof e==='string') return contracts[e];
    const votes=e.args.map(support).filter(Boolean).length;
    const required=e.op==='AND'?e.args.length:e.op==='OR'?1:e.k;
    return votes>=required;
  }
  return {contracts,satisfied:support(p.expression)};
}

function continuous(p, history, since, until) {
  // Partition time into intervals on every predicate transition, rather than
  // assuming identical endpoint truth implies a continuous true interval.
  const changes=new Set([since,until]);
  for(const c of p.contracts) {changes.add(c.start);changes.add(c.end);for(const ch of c.challenges)changes.add(ch.deadline+1);}
  for(const f of history)if(f.kind==='ACCEPTED'){changes.add(f.data.message.valid_from);changes.add(f.data.message.valid_until);}
  return [...changes].filter(t=>since<=t&&t<=until).every(t=>semantics(p,history,t).satisfied);
}

export function validate(s) {
  need(exact(s,['capsule','commitment','policy','events','head','now','healthy']),'snapshot fields');
  policy(s.policy);need(hash(s.policy)===s.commitment && integer(s.now)&&s.now>=0&&typeof s.healthy==='boolean','snapshot metadata');
  const p=s.policy, history=[];let head='0'.repeat(64),time=-1,armed=false,terminal=null,healthy=true,candidate=null,payload=null;
  const accepted=new Set(),revoked=new Set();
  function eligible(t) {return armed&&!terminal&&healthy&&candidate!==null&&t-candidate.time>=p.grace&&continuous(p,history,candidate.time,t);}
  for(const event of s.events) {
    const {kind,data:d,time:t}=event;
    need(exact(event,['v','capsule','seq','time','kind','data','prev']) && event.v===1 && event.seq===history.length+1 && event.capsule===s.capsule && event.prev===head && integer(t) && time<=t && t<=s.now,'history chain/order');
    if(history.length===0) {need(kind==='CREATED'&&exact(d,['commitment','payload'])&&d.commitment===s.commitment,'genesis');payload=d.payload;}
    else need(kind!=='CREATED','duplicate genesis');
    if(['ARMED','DISARMED','RECOVERED'].includes(kind)) {
      const m=d.message?.v===2?{v:2,capsule:s.capsule,commitment:s.commitment,action:kind,head}:{v:1,capsule:s.capsule,commitment:s.commitment,action:kind};
      need(same(d.message,m)&&!terminal,'owner lifecycle');signature(p.owner,m,d.signature);
      if(kind==='ARMED'){need(!armed&&healthy,'arm');armed=true;}
      else if(kind==='DISARMED')terminal='DISARMED';
      else {healthy=true;candidate=null;}
    } else if(kind==='CLOCK') {need(typeof d.healthy==='boolean','clock');if(!d.healthy)healthy=false;}
    else if(kind==='CHALLENGE') {
      const c=p.contracts.find(c=>c.id===d.contract);
      need(armed&&!terminal&&c&&c.kind==='absence'&&d.contract_version===c.version&&c.challenges.some(ch=>same(d,{contract:c.id,contract_version:c.version,...ch})),'challenge issuance');
    } else if(kind==='ACCEPTED') {
      const m=d.message,c=p.contracts.find(c=>c.id===m.contract);
      need(armed&&!terminal&&c,'acceptance lifecycle');
      need(exact(m,['v','id','capsule','commitment','contract','contract_version','authority','valid_from','valid_until',c.kind==='absence'?'challenge':'claim']),'evidence schema');
      need(m.v===1 && typeof m.id==='string'&&m.id&&!accepted.has(m.id)&&m.capsule===s.capsule&&m.commitment===s.commitment&&m.contract_version===c.version&&m.authority===c.authority&&!revoked.has(c.authority),'evidence domain');
      signature(c.authority,m,d.signature);
      need(integer(m.valid_from)&&integer(m.valid_until)&&c.start<=m.valid_from&&m.valid_from<=t&&t<m.valid_until&&m.valid_until<=c.end,'evidence validity');
      if(c.kind==='absence') {
        const ch=c.challenges.find(ch=>ch.id===m.challenge);
        need(ch&&ch.open<=t&&t<=ch.deadline&&history.some(f=>f.kind==='CHALLENGE'&&f.data.contract===c.id&&f.data.id===ch.id),'presence boundary');
      } else need(typeof m.claim==='boolean','claim');
      accepted.add(m.id);candidate=null;
    } else if(kind==='REVOKED') {
      const m={v:1,capsule:s.capsule,commitment:s.commitment,action:kind,authority:d.authority};
      need(!terminal&&p.contracts.some(c=>c.authority===d.authority)&&same(d.message,m),'revocation domain');signature(p.owner,m,d.signature);revoked.add(d.authority);candidate=null;
    } else if(kind==='CANDIDATE_RESET')candidate=null;
    else if(kind==='CANDIDATE') {
      need(armed&&!terminal&&healthy&&semantics(p,history,t).satisfied&&d.snapshot===head&&same(d.results,semantics(p,history,t))&&d.grace===p.grace,'candidate');
      candidate={time:t,seq:event.seq};
    } else if(kind==='AUTHORISED') {
      need(eligible(t)&&d.commitment===s.commitment&&d.snapshot===head&&d.candidate===candidate.seq&&d.payload===payload&&same(d.results,semantics(p,history,t)),'authorisation');terminal='AUTHORISED';
    } else if(kind==='RELEASED') {
      const decision=history.find(f=>f.kind==='AUTHORISED');need(decision&&d.decision===hash(decision),'delivery');
    } else need(['CREATED','SUBMITTED','REJECTED','NOTIFICATION'].includes(kind),'unknown event');
    history.push(event);time=t;head=hash(event);
  }
  need(history.length&&head===s.head&&(!s.healthy||healthy),'snapshot anchor/health');
  return {results:semantics(p,history,s.now),eligible:terminal==='AUTHORISED'||(s.healthy&&eligible(s.now)),authorised:terminal==='AUTHORISED'};
}

function handle(line) {
  try {const input=parse(line);return {ok:true,...validate(input.snapshot??input)};}
  catch(e){return {ok:false,error:e.message};}
}
if(process.argv.includes('--lines')) {
  const lines=readline.createInterface({input:process.stdin});for await(const line of lines)console.log(JSON.stringify(handle(line)));
} else {
  const file=process.argv[2];const result=handle(file?fs.readFileSync(file,'utf8'):fs.readFileSync(0,'utf8'));console.log(JSON.stringify(result));if(!result.ok)process.exitCode=1;
}
