const MASK64 = (1n << 64n) - 1n;
const RC = [
  0x0000000000000001n,0x0000000000008082n,0x800000000000808an,0x8000000080008000n,
  0x000000000000808bn,0x0000000080000001n,0x8000000080008081n,0x8000000000008009n,
  0x000000000000008an,0x0000000000000088n,0x0000000080008009n,0x000000008000000an,
  0x000000008000808bn,0x800000000000008bn,0x8000000000008089n,0x8000000000008003n,
  0x8000000000008002n,0x8000000000000080n,0x000000000000800an,0x800000008000000an,
  0x8000000080008081n,0x8000000000008080n,0x0000000080000001n,0x8000000080008008n
];
const ROT = [0,1,62,28,27,36,44,6,55,20,3,10,43,25,39,41,45,15,21,8,18,2,61,56,14];
const encoder = new TextEncoder();

function rol64(x, n) {
  const s = BigInt(n & 63);
  if (s === 0n) return x & MASK64;
  return ((x << s) | (x >> (64n - s))) & MASK64;
}
function keccakF(a) {
  for (let round=0; round<24; round+=1) {
    const c=new Array(5), d=new Array(5);
    for(let x=0;x<5;x+=1)c[x]=a[x]^a[x+5]^a[x+10]^a[x+15]^a[x+20];
    for(let x=0;x<5;x+=1)d[x]=c[(x+4)%5]^rol64(c[(x+1)%5],1);
    for(let x=0;x<5;x+=1)for(let y=0;y<5;y+=1)a[x+5*y]=(a[x+5*y]^d[x])&MASK64;
    const b=new Array(25).fill(0n);
    for(let x=0;x<5;x+=1)for(let y=0;y<5;y+=1){const nx=y,ny=(2*x+3*y)%5;b[nx+5*ny]=rol64(a[x+5*y],ROT[x+5*y]);}
    for(let x=0;x<5;x+=1)for(let y=0;y<5;y+=1)a[x+5*y]=(b[x+5*y]^((~b[(x+1)%5+5*y])&b[(x+2)%5+5*y]))&MASK64;
    a[0]^=RC[round];
  }
}
function bytesToLane(bytes, offset){let v=0n;for(let i=0;i<8;i+=1)v|=BigInt(bytes[offset+i]||0)<<BigInt(8*i);return v;}
function laneToBytes(v,out,offset,max){for(let i=0;i<8&&offset+i<max;i+=1)out[offset+i]=Number((v>>BigInt(8*i))&0xffn);}

export function shake256Bytes(input, outputBytes=64) {
  const data=input instanceof Uint8Array?input:encoder.encode(String(input));
  const rate=136;
  const paddedLen=Math.ceil((data.length+1)/rate)*rate;
  const p=new Uint8Array(paddedLen);p.set(data);p[data.length]^=0x1f;p[p.length-1]^=0x80;
  const state=new Array(25).fill(0n);
  for(let off=0;off<p.length;off+=rate){for(let i=0;i<rate/8;i+=1)state[i]^=bytesToLane(p,off+i*8);keccakF(state);}
  const out=new Uint8Array(outputBytes);let pos=0;
  while(pos<outputBytes){for(let i=0;i<rate/8&&pos<outputBytes;i+=1){const take=Math.min(8,outputBytes-pos);laneToBytes(state[i],out,pos,outputBytes);pos+=take;}if(pos<outputBytes)keccakF(state);}
  return out;
}
export function hex(bytes){return Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');}
export function shake256Hex(input, outputBytes=64){return hex(shake256Bytes(input,outputBytes));}
