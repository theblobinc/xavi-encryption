const U64_MAX=(1n<<64n)-1n;
const DEC=/^(?:0|[1-9][0-9]*)$/;
const HEX=/^0x[0-9a-f]+$/i;

export function parseWord64(value,{name='word64'}={}){
  let v;
  if(typeof value==='bigint')v=value;
  else if(typeof value==='string'){
    const s=value.trim();
    if(!DEC.test(s)&&!HEX.test(s))throw new TypeError(`${name} must be canonical decimal/hex string or bigint`);
    v=BigInt(s);
  }else if(typeof value==='number'){
    if(!Number.isSafeInteger(value)||value<0)throw new RangeError(`${name} numeric input must be a non-negative safe integer; use a decimal string for full uint64`);
    v=BigInt(value);
  }else throw new TypeError(`${name} must be bigint, canonical string, or safe integer`);
  if(v<0n||v>U64_MAX)throw new RangeError(`${name} outside uint64 range`);
  return v;
}
export function word64ToWire(value,opts){return parseWord64(value,opts).toString(10);}
export function word64ToHex(value,opts){return '0x'+parseWord64(value,opts).toString(16).padStart(16,'0');}
export function word64Equal(a,b){return parseWord64(a)===parseWord64(b);}
export const WORD64_WIRE_SCHEMA=Object.freeze({schema:'XAVI-DUO/WORD64-WIRE/v1',encoding:'unsigned-decimal-string',bits:64,min:'0',max:U64_MAX.toString(10)});
