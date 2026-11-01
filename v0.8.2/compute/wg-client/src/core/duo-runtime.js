import { hashFeatureTokens, featureResidues } from './utils.js';

/**
 * DUO-Math runtime interoperability primitives.
 *
 * JavaScript storage remains conventional and zero-based internally. These helpers
 * expose explicit one-origin addresses and typed semantic states without assigning
 * semantic meaning to ordinary JS null/undefined values.
 */
export const DUO_STATE_SCHEMA='xavi-duo-math-state/v1';
export const DUO_BACKEND_STATE_SCHEMA='xavi-duo-backend-state/v1';

export const DUO_STATE_NAMES=Object.freeze([
  'ONE','SAME','EMPTY','VOID','MISSING',
  'NULL_DIRECTION','FLAT_CONNECTION','TORSION_FREE','TRIVIAL_TOPOLOGICAL_CLASS',
  'MASSLESS_MODE','KERNEL_MODE','TRIVIAL_STABILIZER','ABSENT_COMPONENT','NO_SOURCE',
  'REFERENCE_CONFIGURATION','DEGENERATE','FLAT_RADIAL_DIRECTION',
]);
const VALID=new Set(DUO_STATE_NAMES);
const SINGLETONS=Object.freeze(Object.fromEntries(DUO_STATE_NAMES.map(state=>[state,Object.freeze({schema:DUO_STATE_SCHEMA,state,authority:false})])));

export const DUO_STATE=SINGLETONS;

export function duoState(name){
  const state=String(name||'').trim().toUpperCase();
  if(!VALID.has(state))throw new RangeError(`Unknown DUO semantic state: ${state||'[empty]'}`);
  return SINGLETONS[state];
}
export function isDuoState(value){return Boolean(value&&typeof value==='object'&&value.schema===DUO_STATE_SCHEMA&&VALID.has(String(value.state||'').toUpperCase()));}
export function duoStateName(value){return isDuoState(value)?String(value.state).toUpperCase():null;}

// Backend adapter states are deliberately NOT DUO semantic states.
export function backendState(value){
  if(value===null)return Object.freeze({schema:DUO_BACKEND_STATE_SCHEMA,state:'BACKEND_NULL',authority:false});
  if(value===undefined)return Object.freeze({schema:DUO_BACKEND_STATE_SCHEMA,state:'BACKEND_MISSING',authority:false});
  return null;
}

export function duoIndexFromBackend(index){
  const n=Number(index);if(!Number.isInteger(n)||n<0)throw new RangeError('Backend index must be an integer >= 0');return n+1;
}
export function backendIndexFromDuo(index){
  const n=Number(index);if(!Number.isInteger(n)||n<1)throw new RangeError('DUO index must be an integer >= 1');return n-1;
}
export function assertDuoIndex(index,{max=null}={}){
  const n=Number(index);if(!Number.isInteger(n)||n<1)throw new RangeError('DUO index must be an integer >= 1');if(max!=null&&n>Number(max))throw new RangeError(`DUO index ${n} exceeds maximum ${Number(max)}`);return n;
}

export const DUO_RESIDUE_SCHEMA='xavi-duo-residue/v1';
export function duoResidueSignature(tokens=[]){
  const values=Array.isArray(tokens)?tokens.map(v=>String(v)):[];
  const [r65521,r65519,count]=featureResidues(hashFeatureTokens(values));
  return Object.freeze({schema:DUO_RESIDUE_SCHEMA,moduli:Object.freeze([65521,65519]),residues:Object.freeze([r65521,r65519]),count,authority:false,identity:false});
}
export function duoResidueKey(signature){
  if(!signature||signature.schema!==DUO_RESIDUE_SCHEMA)return null;
  return `${signature.residues?.[0]??0}:${signature.residues?.[1]??0}:${Number(signature.count||0)}`;
}
// Rev007 numeral/modular semantics live in the canonical DUO simulator and are ported here.
export * from './duo-native.js';
