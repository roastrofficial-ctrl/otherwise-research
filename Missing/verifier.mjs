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

// Independent reference P-256 arithmetic for public proof conformance. No Python calls.
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
function check(input){
  const {key,R,expected_context:ctx,expected_signer:pk,contribution:s}=input;
  need(exact(input,['key','R','expected_context','expected_signer','contribution']),'vector fields');
  need(ctx.v===7&&ctx.suite==='otherwise07-xor2-threshold-dh-p256-hkdf-sha256-aesgcm-x25519'&&['custody','authority'].includes(ctx.domain),'v7 domain');
  need(exact(s,['message','signature'])&&exact(s.message,['context','index','partial'])&&same(s.message.context,ctx),'context binding');
  signature(pk,s.message,s.signature);
  need(exact(key,['v','scheme','k','n','X','Y'])&&key.v===6&&key.scheme==='reference-p256-threshold-dh'&&key.k===2&&key.n===3&&exact(key.Y,['1','2','3']),'reference key schema');
  need(new Set(Object.values(key.Y)).size===3&&!Object.values(key.Y).includes(key.X),'non-degenerate shares');
  const X=point(key.X),Y=Object.fromEntries(Object.entries(key.Y).map(([i,s])=>[i,point(s)]));
  for(const [i,j] of [[1n,2n],[1n,3n],[2n,3n]])need(equal(add(mul(mod(j*inv(j-i,Q),Q),Y[i]),mul(mod(i*inv(i-j,Q),Q),Y[j])),X),'public interpolation');
  const p=s.message.partial;need(exact(p,['index','D','A','B','z'])&&Number.isInteger(p.index)&&p.index>=1&&p.index<=3&&p.index===s.message.index,'partial index');
  const rp=point(R),D=point(p.D),a=point(p.A),b=point(p.B),z=scalar(p.z);
  const c=BigInt('0x'+hash({domain:'otherwise06-cp',key,R,D:p.D,A:p.A,B:p.B,context:ctx,index:p.index}))%Q;
  need(equal(mul(z,G),add(a,mul(c,Y[p.index])))&&equal(mul(z,rp),add(b,mul(c,D))),'DLEQ proof');
  return {ok:true,canonical_sha256:hash(s.message)};
}
function handle(raw){try{return check(parse(raw));}catch(e){return {ok:false};}}
if(process.argv.includes('--lines')){for await(const line of readline.createInterface({input:process.stdin}))console.log(JSON.stringify(handle(line)));}
else{const result=handle(fs.readFileSync(0,'utf8'));console.log(JSON.stringify(result));if(!result.ok)process.exitCode=1;}
