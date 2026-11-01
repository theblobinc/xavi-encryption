/**
 * DUO-Math Rev007 native numeral/modular semantics.
 *
 * This is the production JavaScript port of the canonical Rev007 corpus and
 * DUO-Math Research Suite. Conventional JS integers are bounded implementation
 * addresses only; emitted DUO glyphs do not contain a native numeric zero.
 *
 * License: MIT OR Apache-2.0
 */
export const DUO_REVISION='007';
export const DUO_NATIVE_SCHEMA='xavi-duo-native/v1';
export const DUO_MODULAR_STATE_SCHEMA='xavi-duo-modular-state/v1';
export const DUO_RECURRENCE_SCHEMA='xavi-duo-recurrence/v1';
export const DUO_STRUCTURAL_LADDER_SCHEMA='xavi-duo-structural-ladder/v1';

const TOKEN_RE=/^(-?)([1-9])([a-z]*)$/;
const COUNT_RE=/^[1-9a]+$/;

function posInt(value,name='value'){
  const n=Number(value);
  if(!Number.isSafeInteger(n)||n<1)throw new RangeError(`${name} must be a safe integer >= 1`);
  return n;
}

export function duoBijectiveLetters(value){
  let n=posInt(value,'letter ordinal');
  let out='';
  while(n){n-=1;out=String.fromCharCode(97+(n%26))+out;n=Math.floor(n/26);}
  return out;
}

export function duoLettersValue(value=''){
  const s=String(value||'').toLowerCase();
  if(!s)return 0;
  if(!/^[a-z]+$/.test(s))throw new RangeError('DUO suffix must contain lowercase a-z only');
  let n=0;
  for(const ch of s)n=n*26+(ch.charCodeAt(0)-96);
  return n;
}

export function duoCountGlyph(value){
  const n=posInt(value,'DUO count');
  return String(n).replaceAll('0','a');
}

export function parseDuoCountGlyph(value){
  const s=String(value||'').trim().toLowerCase();
  if(!COUNT_RE.test(s))throw new RangeError('DUO count glyph uses only 1-9 and completed-place code a');
  const n=Number(s.replaceAll('a','0'));
  if(!Number.isSafeInteger(n)||n<1||duoCountGlyph(n)!==s)throw new RangeError(`Non-canonical Rev007 DUO count glyph: ${value}`);
  return n;
}

export function duoBandsPerCycle(modulus){
  const M=posInt(modulus,'modulus');
  return M===1?1:Math.ceil((M-1)/9);
}

export function parseDuoModularToken(token){
  const s=String(token||'').trim().toLowerCase();
  const m=TOKEN_RE.exec(s);
  if(!m)throw new RangeError('DUO modular token must look like 1, 9, 1a, -7c, 3aa, ...');
  return Object.freeze({
    token:s,
    hand:m[1]==='-'?'-':'+',
    digit:Number(m[2]),
    suffix:m[3],
    bandOrdinal:duoLettersValue(m[3]),
  });
}

export function duoModularStateAt(count,modulus,{hand='+'}={}){
  const c=posInt(count,'count');
  const M=posInt(modulus,'modulus');
  if(hand!=='+'&&hand!=='-')throw new RangeError("hand must be '+' or '-'");
  if(M===1){
    const suffix=duoBijectiveLetters(c);
    return Object.freeze({schema:DUO_MODULAR_STATE_SCHEMA,revision:DUO_REVISION,count:c,duoCount:duoCountGlyph(c),modulus:M,duoModulus:'1',hand,width:0,bandsPerCycle:1,cycle:c,cycleZeroBased:c,phase:1,digit:1,localBand:1,localBandZeroBased:0,globalBand:c,globalBandZeroBased:c,suffix,token:`1${suffix}`,rollover:true,authority:false});
  }
  const width=M-1;
  const bands=duoBandsPerCycle(M);
  const q=Math.floor((c-1)/width);
  const phase=((c-1)%width)+1;
  const digit=((phase-1)%9)+1;
  const localZero=Math.floor((phase-1)/9);
  const globalZero=q*bands+localZero;
  const suffix=globalZero===0?'':duoBijectiveLetters(globalZero);
  let token=`${digit}${suffix}`;
  if(hand==='-'&&phase!==1)token=`-${token}`;
  return Object.freeze({schema:DUO_MODULAR_STATE_SCHEMA,revision:DUO_REVISION,count:c,duoCount:duoCountGlyph(c),modulus:M,duoModulus:duoCountGlyph(M),hand,width,bandsPerCycle:bands,cycle:q+1,cycleZeroBased:q,phase,digit,localBand:localZero+1,localBandZeroBased:localZero,globalBand:globalZero+1,globalBandZeroBased:globalZero,suffix,token,rollover:phase===1&&c>1,authority:false});
}

export function* duoNativeWalk(modulus,countLimit,{hand='+'}={}){
  const M=posInt(modulus,'modulus');
  const limit=posInt(countLimit,'count limit');
  if(hand!=='+'&&hand!=='-')throw new RangeError("hand must be '+' or '-'");
  if(M===1){for(let c=1;c<=limit;c++)yield duoModularStateAt(c,M,{hand});return;}
  const width=M-1;
  const bands=duoBandsPerCycle(M);
  let phase=1,digit=1,globalZero=0,cycle=1;
  for(let count=1;count<=limit;count++){
    const localZero=Math.floor((phase-1)/9);
    const suffix=globalZero===0?'':duoBijectiveLetters(globalZero);
    let token=`${digit}${suffix}`;
    if(hand==='-'&&phase!==1)token=`-${token}`;
    yield Object.freeze({schema:DUO_MODULAR_STATE_SCHEMA,revision:DUO_REVISION,count,duoCount:duoCountGlyph(count),modulus:M,duoModulus:duoCountGlyph(M),hand,width,bandsPerCycle:bands,cycle,cycleZeroBased:cycle-1,phase,digit,localBand:localZero+1,localBandZeroBased:localZero,globalBand:globalZero+1,globalBandZeroBased:globalZero,suffix,token,rollover:phase===1&&count>1,authority:false});
    if(phase===width){phase=1;digit=1;cycle+=1;globalZero+=1;}
    else{phase+=1;if(digit<9)digit+=1;else{digit=1;globalZero+=1;}}
  }
}

export function duoInvertModularToken(token,modulus,{hand='auto'}={}){
  const parsed=parseDuoModularToken(token);
  const M=posInt(modulus,'modulus');
  const effectiveHand=hand==='auto'?parsed.hand:hand;
  if(effectiveHand!=='+'&&effectiveHand!=='-')throw new RangeError("hand must be '+', '-', or 'auto'");
  const coreToken=parsed.token.replace(/^-/, '');
  const beta=parsed.bandOrdinal;
  if(M===1){
    if(parsed.digit!==1||beta<1)return null;
    const state=duoModularStateAt(beta,1,{hand:effectiveHand});
    return state.token===parsed.token||state.token===coreToken?state:null;
  }
  const width=M-1;
  const B=duoBandsPerCycle(M);
  const q=Math.floor(beta/B);
  const lambda=beta%B;
  const phase=9*lambda+parsed.digit;
  if(phase>width)return null;
  const count=q*width+phase;
  const state=duoModularStateAt(count,M,{hand:effectiveHand});
  return state.token===parsed.token?state:null;
}

export function duoTokenRecurrence(token,maxModulus,{hand='auto',moduli=null}={}){
  const mods=Array.isArray(moduli)?moduli.map(m=>posInt(m,'modulus')):Array.from({length:posInt(maxModulus,'max modulus')},(_,i)=>i+1);
  const rows=[];
  for(const M of mods){const r=duoInvertModularToken(token,M,{hand});if(r)rows.push(r);}
  return rows;
}

export function duoCompareModuli(modulusA,modulusB,maxCount,{hand='+'}={}){
  const a=new Map(),b=new Map();
  const limit=posInt(maxCount,'max count');
  for(let c=1;c<=limit;c++){const ra=duoModularStateAt(c,modulusA,{hand}),rb=duoModularStateAt(c,modulusB,{hand});a.set(ra.token,c);b.set(rb.token,c);}
  const out=[];
  for(const [token,c1] of a){if(!b.has(token))continue;const c2=b.get(token);out.push(Object.freeze({token,countA:c1,duoCountA:duoCountGlyph(c1),countB:c2,duoCountB:duoCountGlyph(c2),delta:c2-c1,sameValue:c1===c2}));}
  out.sort((x,y)=>{const px=parseDuoModularToken(x.token),py=parseDuoModularToken(y.token);return px.bandOrdinal-py.bandOrdinal||px.digit-py.digit;});
  return out;
}

export function duoAmbiguityScan(maxModulus,maxCount,{top=null,hand='+'}={}){
  const mm=posInt(maxModulus,'max modulus'),mc=posInt(maxCount,'max count');
  const seen=new Map();
  for(let M=1;M<=mm;M++)for(let c=1;c<=mc;c++){const t=duoModularStateAt(c,M,{hand}).token;if(!seen.has(t))seen.set(t,[]);seen.get(t).push([M,c]);}
  const rows=[];
  for(const [token,occ] of seen){const mods=new Set(occ.map(x=>x[0])),vals=new Set(occ.map(x=>x[1]));if(mods.size<2)continue;const v=[...vals];rows.push({token,modulusCount:mods.size,occurrenceCount:occ.length,distinctValues:vals.size,minCount:Math.min(...v),maxCount:Math.max(...v),valueSpread:Math.max(...v)-Math.min(...v)});}
  rows.sort((a,b)=>b.distinctValues-a.distinctValues||b.modulusCount-a.modulusCount||b.valueSpread-a.valueSpread);
  return top==null?rows:rows.slice(0,posInt(top,'top'));
}

export function duoStructuralLadder(nMax){
  const N=posInt(nMax,'n max');const out=[];let ordinal=1;
  for(let n=1;n<=N;n++)for(const [family,modulus,a,b] of [['square',n*n,n,n],['pronic',n*(n+1),n,n+1]])out.push(Object.freeze({schema:DUO_STRUCTURAL_LADDER_SCHEMA,ordinal:ordinal++,n,family,modulus,duoModulus:duoCountGlyph(modulus),a,b}));
  return out;
}

export function duoLadderToken(token,nMax,{hand='auto'}={}){
  let previous=null;
  return duoStructuralLadder(nMax).map(entry=>{const r=duoInvertModularToken(token,entry.modulus,{hand});const row={...entry,token,present:Boolean(r)};if(r){Object.assign(row,{count:r.count,duoCount:r.duoCount,cycle:r.cycle,phase:r.phase,bandsPerCycle:r.bandsPerCycle,deltaFromPreviousPresent:previous==null?null:r.count-previous});previous=r.count;}else Object.assign(row,{count:null,duoCount:null,cycle:null,phase:null,bandsPerCycle:duoBandsPerCycle(entry.modulus),deltaFromPreviousPresent:null});return Object.freeze(row);});
}

export function duoTokenEventualPlateau(token){
  const p=parseDuoModularToken(token);
  if(p.hand==='-')throw new RangeError('Eventual plateau theorem is stated for positive-hand token glyphs');
  const count=9*p.bandOrdinal+p.digit;
  return Object.freeze({token:p.token,bandOrdinal:p.bandOrdinal,digit:p.digit,plateauCount:count,duoPlateauCount:duoCountGlyph(count),stableFromModulus:count+1,duoStableFromModulus:duoCountGlyph(count+1)});
}

export function duoTokenPiecewiseLaw(token,modulus){
  const p=parseDuoModularToken(token);if(p.hand==='-')throw new RangeError('Piecewise law is stated for positive-hand token glyphs');
  const M=posInt(modulus,'modulus');
  if(M===1)return Object.freeze({token:p.token,modulus:M,present:p.digit===1&&p.bandOrdinal>=1,bandsPerCycle:1,slope:null,phase:1,count:p.digit===1&&p.bandOrdinal>=1?p.bandOrdinal:null,eventual:duoTokenEventualPlateau(token)});
  const B=duoBandsPerCycle(M),q=Math.floor(p.bandOrdinal/B),lambda=p.bandOrdinal%B,phase=9*lambda+p.digit,present=phase<=M-1;
  return Object.freeze({token:p.token,modulus:M,duoModulus:duoCountGlyph(M),bandsPerCycle:B,bandQuotient:q,bandRemainder:lambda,slope:q,phase,present,count:present?q*(M-1)+phase:null,eventual:duoTokenEventualPlateau(token)});
}

function longestEqualRun(values){let best=0,cur=0,prev=Symbol('none');for(const v of values){if(v===prev)cur+=1;else{cur=1;prev=v;}if(cur>best)best=cur;}return best;}
function tailEqualRun(values){if(!values.length)return 0;let n=1;for(let i=values.length-2;i>=0&&values[i]===values.at(-1);i--)n++;return n;}

export function duoRecurrenceSignature(token,maxModulus,{moduli=null,hand='auto'}={}){
  const rows=duoTokenRecurrence(token,maxModulus,{hand,moduli});
  const values=rows.map(r=>r.count),deltas=[];
  for(let i=1;i<values.length;i++)deltas.push(values[i]-values[i-1]);
  const rises=deltas.filter(x=>x>0).length,falls=deltas.filter(x=>x<0).length,plateaus=deltas.filter(x=>x===0).length;
  const signs=deltas.filter(x=>x!==0).map(x=>Math.sign(x));let signChanges=0;for(let i=1;i<signs.length;i++)if(signs[i]!==signs[i-1])signChanges++;
  const tailPlateau=tailEqualRun(values),longestPlateau=longestEqualRun(values);
  let classification='insufficient';
  if(values.length>1){if(new Set(values).size===1)classification='constant';else if(falls===0&&plateaus===0)classification='strict-rise';else if(falls===0)classification='staircase';else if(signChanges>=2&&tailPlateau<3)classification='oscillatory-reset';else if(falls>0&&tailPlateau>=3)classification='reset-to-plateau';else classification='nonmonotone-reset';}
  let eventual=null;try{eventual=duoTokenEventualPlateau(token);}catch{}
  const observedStable=Boolean(eventual&&rows.length&&rows.at(-1).modulus>=eventual.stableFromModulus&&rows.at(-1).count===eventual.plateauCount);
  return Object.freeze({schema:DUO_RECURRENCE_SCHEMA,token:String(token).toLowerCase(),sampledModuli:Array.isArray(moduli)?moduli.length:posInt(maxModulus,'max modulus'),occurrences:rows.length,distinctValues:new Set(values).size,minCount:values.length?Math.min(...values):null,maxCount:values.length?Math.max(...values):null,rises,falls,plateaus,signChanges,longestPlateau,tailPlateau,classification,eventual,observedStable,rows});
}
