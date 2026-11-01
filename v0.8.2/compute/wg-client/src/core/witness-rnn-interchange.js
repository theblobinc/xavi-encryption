import { shake256Hex } from './crypto.js';

export const WG_RNN_INTERCHANGE_SCHEMA='xavi-wg-rnn-interchange/v1';
export const WG_RNN_JS_RECURRENT_SCHEMA='xavi-browser-recurrent/v2';
export const WG_RNN_PY_CORE_SCHEMA='xavi-learned-wg-rnn/v1';
export const WG_RNN_JS_TEACHER_PROJECTION_SCHEMA='xavi-wg-rnn-js-teacher-projection/v1';
export const WG_RNN_INTERCHANGE_PROFILE='WG-RNN-INTERCHANGE/1';
export const WG_RNN_INTERCHANGE_FIXTURE_MANIFEST_SCHEMA='wg-rnn-cross-language-fixture-manifest/v1';
export const WG_RNN_INTERCHANGE_FIXTURE_VERIFICATION_SCHEMA='wg-rnn-cross-language-fixture-manifest-verification/v1';
export const WG_RNN_NO_AUTHORITY=Object.freeze({truth_authority:false,proof_authority:false,promotion_authority:false,learning_authority:false,execution_authority:false,self_model_write_authority:false,self_kernel_write_authority:false});

export class WGRNNInterchangeError extends Error{constructor(message){super(message);this.name='WGRNNInterchangeError';}}

function finite(value,{defaultValue=0}={}){let n;try{n=Number(value??defaultValue);}catch{n=Number(defaultValue);}if(!Number.isFinite(n))throw new WGRNNInterchangeError('non-finite WG-RNN value');return n;}
function nonnegativeInt(value){const n=Number(value);return Number.isFinite(n)?Math.max(0,Math.trunc(n)):0;}
function vector(value,{name='vector',expected=null,allowEmpty=false}={}){if(!Array.isArray(value))throw new WGRNNInterchangeError(`${name} must be an array`);const row=value.map(v=>finite(v));if(expected!==null&&row.length!==expected)throw new WGRNNInterchangeError(`${name} length mismatch: expected ${expected}, got ${row.length}`);if(!allowEmpty&&!row.length)throw new WGRNNInterchangeError(`${name} cannot be empty`);return row;}
function authorityGuard(value,{where='WG-RNN value'}={}){for(const key of ['truth_authority','truthAuthority','proof_authority','proofAuthority','promotion_authority','promotionAuthority','learning_authority','learningAuthority','execution_authority','executionAuthority','self_model_write_authority','selfModelWriteAuthority','self_kernel_write_authority','selfKernelWriteAuthority'])if(value?.[key]===true)throw new WGRNNInterchangeError(`${where} attempts authority escalation via ${key}`);}
function clamp(n,min,max){return Math.min(max,Math.max(min,n));}

function pythonFloatString(n){
  if(Object.is(n,-0))return'-0.0';if(n===0)return'0.0';const neg=n<0,abs=Math.abs(n),exp=Math.floor(Math.log10(abs));let body;
  if(exp>=-4&&exp<16){body=abs.toString();if(/[eE]/.test(body)){body=abs.toFixed(Math.max(0,-exp));body=body.replace(/(\.\d*?[1-9])0+$/,'$1').replace(/\.0+$/,'');}if(!body.includes('.'))body+='.0';}
  else{let raw=abs.toExponential(),[mant,e]=raw.split('e'),ei=Number(e);mant=mant.replace(/\.0+$/,'').replace(/(\.\d*?[1-9])0+$/,'$1');const sign=ei>=0?'+':'-',digits=String(Math.abs(ei)).padStart(2,'0');body=`${mant}e${sign}${digits}`;}
  return neg?`-${body}`:body;
}
const FLOAT_FIELDS=new Set(['state','input_trace','rotational_trace','predictions','key','value','strength','novelty','prediction_errors']);
function pyCanonicalString(value,{floatContext=false}={}){
  if(value===null)return'null';if(typeof value==='boolean')return value?'true':'false';if(typeof value==='string')return JSON.stringify(value);if(typeof value==='number'){if(!Number.isFinite(value))throw new WGRNNInterchangeError('non-finite WG-RNN value in interchange digest');return floatContext?pythonFloatString(value):String(value);}if(Array.isArray(value))return`[${value.map(v=>pyCanonicalString(v,{floatContext})).join(',')}]`;if(!value||typeof value!=='object')return JSON.stringify(String(value));
  const parts=[];for(const key of Object.keys(value).sort()){const childFloat=floatContext||FLOAT_FIELDS.has(key);parts.push(`${JSON.stringify(key)}:${pyCanonicalString(value[key],{floatContext:childFloat})}`);}return`{${parts.join(',')}}`;
}
export function digestRnnInterchangeValue(value){return`shake256-512:${shake256Hex(pyCanonicalString(value),64)}`;}

export function normalizeJsRnnSnapshot(snapshot){
  if(!snapshot||typeof snapshot!=='object'||Array.isArray(snapshot))throw new WGRNNInterchangeError('JS recurrent snapshot must be an object');authorityGuard(snapshot,{where:'JS WG-RNN snapshot'});const schema=String(snapshot.schemaVersion??snapshot.schema_version??'');if(schema!==WG_RNN_JS_RECURRENT_SCHEMA)throw new WGRNNInterchangeError(`unsupported JS recurrent schema ${JSON.stringify(schema)}`);
  const state=vector(snapshot.state,{name:'state'}),trace=vector(snapshot.trace,{name:'trace'}),stateDim=state.length,inputDim=trace.length,rotRaw=Array.isArray(snapshot.rotationalTrace)&&snapshot.rotationalTrace.length?snapshot.rotationalTrace:Array(stateDim).fill(0),rotational=vector(rotRaw,{name:'rotational_trace',expected:stateDim});
  const predictions={};if(snapshot.predictions&&typeof snapshot.predictions==='object'&&!Array.isArray(snapshot.predictions))for(const [horizon,values] of Object.entries(snapshot.predictions)){const h=Number(horizon);if(!Number.isInteger(h)||h<1)continue;predictions[String(h)]=vector(values,{name:`prediction[${h}]`,expected:stateDim});}
  const associative=[];for(const raw of Array.isArray(snapshot.associative)?snapshot.associative:[]){if(!raw||typeof raw!=='object'||Array.isArray(raw))continue;associative.push({key:vector(raw.key,{name:'associative.key',expected:inputDim}),value:vector(raw.value,{name:'associative.value',expected:stateDim}),strength:Math.max(0,finite(raw.strength)),updated_at_ms:nonnegativeInt(raw.updatedAt||raw.updated_at_ms||0)});}
  const steps=nonnegativeInt(snapshot.steps),predictionErrors={};if(snapshot.lastPredictionErrors&&typeof snapshot.lastPredictionErrors==='object'&&!Array.isArray(snapshot.lastPredictionErrors))for(const [k,v] of Object.entries(snapshot.lastPredictionErrors))predictionErrors[String(k)]=finite(v);
  const body={schema:WG_RNN_INTERCHANGE_SCHEMA,source_runtime:'javascript',source_schema:schema,source_model:'RecurrentCore',state_dim:stateDim,input_dim:inputDim,state,input_trace:trace,rotational_trace:rotational,predictions,associative,steps,train_steps:0,observation_steps:steps,novelty:Math.max(0,finite(snapshot.lastNovelty)),prediction_errors:predictionErrors,native_weights_portable:false,native_checkpoint_portable:false,direct_state_overwrite_allowed:false,temporal_witness_required_for_learning:true,authority:false,...WG_RNN_NO_AUTHORITY};
  body.state_digest=digestRnnInterchangeValue(body);return body;
}

export function verifyRnnHandoff(handoff){
  if(!handoff||typeof handoff!=='object'||Array.isArray(handoff)||String(handoff.schema??'')!==WG_RNN_INTERCHANGE_SCHEMA)throw new WGRNNInterchangeError('unsupported WG-RNN handoff schema');authorityGuard(handoff,{where:'WG-RNN handoff'});const supplied=String(handoff.state_digest??''),body=structuredClone(handoff);delete body.state_digest;const expected=digestRnnInterchangeValue(body);if(!supplied||supplied!==expected)throw new WGRNNInterchangeError('WG-RNN handoff digest mismatch');if(handoff.native_weights_portable!==false||handoff.direct_state_overwrite_allowed!==false)throw new WGRNNInterchangeError('WG-RNN handoff attempts unsafe native state portability');vector(handoff.state,{name:'state',expected:Number(handoff.state_dim)||0});return structuredClone(handoff);
}

export function javascriptRnnTeacherProjection(handoff,{confidence=.75,teacherBlend=.12}={}){const row=verifyRnnHandoff(handoff);return{schema:WG_RNN_JS_TEACHER_PROJECTION_SCHEMA,teacherState:[...row.state],teacherConfidence:clamp(finite(confidence),0,1),teacherBlend:clamp(finite(teacherBlend),0,.25),sourceStateDigest:row.state_digest,requiresWitnessGateForLearning:true,nativeWeightsPortable:false,directStateOverwriteAllowed:false,authority:false,...WG_RNN_NO_AUTHORITY};}

export function projectRnnInterchangeFixtureManifest(fixture){if(!fixture||typeof fixture!=='object'||Array.isArray(fixture))throw new WGRNNInterchangeError('WG-RNN fixture must be an object');return{schema:WG_RNN_INTERCHANGE_FIXTURE_MANIFEST_SCHEMA,profile_id:WG_RNN_INTERCHANGE_PROFILE,fixture_schema:String(fixture.schema??''),reference_runtime:String(fixture.reference_runtime??''),reference_provenance:structuredClone(fixture.reference_provenance??{}),js_snapshot:{canonical:structuredClone(fixture.js_snapshot?.canonical??null),teacher_projection:structuredClone(fixture.js_snapshot?.teacher_projection??null)},python_snapshot:{canonical:structuredClone(fixture.python_snapshot?.canonical??null),teacher_projection:structuredClone(fixture.python_snapshot?.teacher_projection??null)},authority:false,...WG_RNN_NO_AUTHORITY};}
export function digestRnnInterchangeFixtureManifest(fixture){return digestRnnInterchangeValue(projectRnnInterchangeFixtureManifest(fixture));}
export function verifyRnnInterchangeFixtureManifest(fixture){const expected=String(fixture?.fixture_manifest_digest??''),observed=digestRnnInterchangeFixtureManifest(fixture),profile=String(fixture?.fixture_profile_id??'');return{schema:WG_RNN_INTERCHANGE_FIXTURE_VERIFICATION_SCHEMA,profile_id:WG_RNN_INTERCHANGE_PROFILE,fixture_profile_id:profile,fixture_manifest_digest:expected,observed_manifest_digest:observed,profile_matches:profile===WG_RNN_INTERCHANGE_PROFILE,digest_matches:Boolean(expected&&expected===observed),verified:profile===WG_RNN_INTERCHANGE_PROFILE&&expected===observed,authority:false,...WG_RNN_NO_AUTHORITY};}

export const normalize_js_snapshot=normalizeJsRnnSnapshot;
export const verify_handoff=verifyRnnHandoff;
export const javascript_teacher_projection=javascriptRnnTeacherProjection;
