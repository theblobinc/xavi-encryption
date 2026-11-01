import { clamp, dot, featureTokens, hashFeatureTokens, featurizeFeatureHashes } from './utils.js';
import { SEMANTIC_MAINTENANCE_TRANSPARENT } from './semantic-maintenance.js';
import { normalizeSfmSnapshot, sfmTargetCompatibility, toPythonSfmSnapshot, toJsSfmSnapshot, normalizeSfmProposal, verifySfmInterchangeProjection } from './witness-sfm-interchange.js';

export const WG_SFM_SCHEMA='xavi-wg-sfm-js/v1';
export const WG_SFM_MODEL_ID='wg-sfm-js-shared-cell-v1';
export const WG_SFM_TRANSPARENT_WITNESS_TYPES=SEMANTIC_MAINTENANCE_TRANSPARENT;

const OPERATIONS=['route','inspect','retrieve','reconcile','execute','reason','transform','act','defer','store_hot','store_cold','place_local','place_remote'];
function stableSfmContext(value,key=''){
  if(Array.isArray(value))return value.map(v=>stableSfmContext(v));
  if(!value||typeof value!=='object')return value;
  const out={};for(const [k,v] of Object.entries(value)){if(k==='wgSfm')continue;if(key==='evidenceSession'&&(k==='updatedAt'||k==='expiresAt'||k==='createdAt'))continue;out[k]=stableSfmContext(v,k);}return out;
}
const EXPECTED_DELTAS={
  route:{routingResolved:true,newObservationExpected:true},
  inspect:{evidenceCount:'+',uncertainty:'expected-down'},
  retrieve:{memoryContext:'+',truthAuthority:false},
  reconcile:{conflict:'re-evaluate',evidenceAlignment:'expected-up'},
  execute:{runtimeState:'advance-if-gate-passes',outcomeWitnessRequired:true},
  reason:{derivedEvidence:'+',truthAuthority:false},
  transform:{artifactState:'changed-if-validated'},
  act:{externalState:'changed-if-authorized'},
  defer:{queueState:'deferred',mutation:false},
  store_hot:{hotResidency:true,accessLatency:'expected-down'},
  store_cold:{coldResidency:true,hotPressure:'expected-down'},
  place_local:{placement:'local',queuePressure:'expected-down'},
  place_remote:{placement:'remote',localPressure:'expected-down'},
};

function cosine(a,b){
  if(!a||!b)return 0;let aa=0,bb=0,d=0,n=Math.min(a.length,b.length),i=0;
  // Numeric-vector type is validated at construction/restore boundaries. The hot path
  // therefore performs direct arithmetic instead of re-coercing each element.
  for(;i+3<n;i+=4){const a0=a[i],b0=b[i],a1=a[i+1],b1=b[i+1],a2=a[i+2],b2=b[i+2],a3=a[i+3],b3=b[i+3];d+=a0*b0+a1*b1+a2*b2+a3*b3;aa+=a0*a0+a1*a1+a2*a2+a3*a3;bb+=b0*b0+b1*b1+b2*b2+b3*b3;}
  for(;i<n;i+=1){const x=a[i],y=b[i];d+=x*y;aa+=x*x;bb+=y*y;}
  return aa>0&&bb>0?d/Math.sqrt(aa*bb):0;
}
function vectorBlend(current,next,rate){
  const n=Math.min(current.length,next.length);for(let i=0;i<n;i+=1)current[i]=(1-rate)*current[i]+rate*next[i];return current;
}
function operationHintText(text){
  const s=String(text??'').toLowerCase();
  if(/store[_ -]?hot|hot storage|hot tier|cache hot|hot residency/.test(s))return'store_hot';
  if(/store[_ -]?cold|cold storage|cold tier|archive/.test(s))return'store_cold';
  if(/place[_ -]?local|local placement|local node|local host/.test(s))return'place_local';
  if(/place[_ -]?remote|remote placement|remote node|remote host|offload remote/.test(s))return'place_remote';
  if(/recall|retrieve|memory|search/.test(s))return'retrieve';
  if(/conflict|contradict|reconcile|repair/.test(s))return'reconcile';
  if(/inspect|verify|observe|analy[sz]e|evidence/.test(s))return'inspect';
  if(/execute|runtime|worker|command|job/.test(s))return'execute';
  if(/transform|convert|rewrite|render/.test(s))return'transform';
  if(/reason|infer|derive|calculate|math/.test(s))return'reason';
  if(/route|observer|strategy|capability/.test(s))return'route';
  if(/defer|retry|wait|queue/.test(s))return'defer';
  if(/action|apply|perform|act/.test(s))return'act';
  return'inspect';
}
function compactRecent(receipt){return receipt?{type:String(receipt.type||'unknown'),semanticSignature:receipt.semanticSignature||null,metaObjectSignature:receipt.metaObjectSignature||null,digest:receipt.digest||null}:null;}
function finiteVector(value,n){return Array.isArray(value)&&value.length===n&&value.every(Number.isFinite);}

export class WitnessSFM {
  constructor({store,recurrent,gate,ledger,namespace='default',featureDim=64,learningRate=0.08,teacherBlend=0.12,window=24,maxPrototypes=24}={}){
    this.store=store;this.recurrent=recurrent;this.gate=gate;this.ledger=ledger;this.namespace=namespace;
    this.featureDim=Math.max(16,Math.floor(featureDim));this.learningRate=clamp(Number(learningRate)||0.08,0.005,0.3);this.teacherBlend=clamp(Number(teacherBlend)||0.12,0,0.25);
    this.window=Math.max(4,Math.floor(window));this.maxPrototypes=Math.max(4,Math.floor(maxPrototypes));this.recent=[];this.prototypes=new Map();this.updates=0;this.revision=0;this.inferCache=null;
  }
  get stateKey(){return`wg-sfm-state:${this.namespace}`;}
  async init(){const row=await this.store?.get?.('records',this.stateKey);if(row?.state)this.restore(row.state);return this;}
  ingest(receipt){if(!receipt||WG_SFM_TRANSPARENT_WITNESS_TYPES.has(String(receipt.type||'')))return null;const row=compactRecent(receipt);this.recent.push(row);if(this.recent.length>this.window)this.recent.splice(0,this.recent.length-this.window);this.revision+=1;this.inferCache=null;return row;}

  normalizeInterchangeSnapshot(snapshot=this.snapshot()){return normalizeSfmSnapshot(snapshot);}
  normalize_interchange_snapshot(snapshot=this.snapshot()){return this.normalizeInterchangeSnapshot(snapshot);}
  interchangeTargetCompatibility(snapshot=this.snapshot(),options={}){return sfmTargetCompatibility(snapshot,options);}
  interchange_target_compatibility(snapshot=this.snapshot(),options={}){return this.interchangeTargetCompatibility(snapshot,options);}
  toPythonInterchangeSnapshot(snapshot=this.snapshot()){return toPythonSfmSnapshot(snapshot);}
  to_python_interchange_snapshot(snapshot=this.snapshot()){return this.toPythonInterchangeSnapshot(snapshot);}
  toJsInterchangeSnapshot(snapshot=this.snapshot(),options={}){return toJsSfmSnapshot(snapshot,options);}
  to_js_interchange_snapshot(snapshot=this.snapshot(),options={}){return this.toJsInterchangeSnapshot(snapshot,options);}
  normalizeInterchangeProposal(proposal){return normalizeSfmProposal(proposal);}
  normalize_interchange_proposal(proposal){return this.normalizeInterchangeProposal(proposal);}
  verifyInterchangeProjection(projection,options={}){return verifySfmInterchangeProjection(projection,options);}
  verify_interchange_projection(projection,options={}){return this.verifyInterchangeProjection(projection,options);}
  snapshot(){return{schema:WG_SFM_SCHEMA,modelId:WG_SFM_MODEL_ID,featureDim:this.featureDim,stateDim:this.recurrent?.stateDim||0,inputDim:this.recurrent?.inputDim||0,updates:this.updates,prototypes:Object.fromEntries([...this.prototypes.entries()].map(([k,v])=>[k,structuredClone(v)])),authority:false};}
  restore(snapshot={}){this.updates=Math.max(0,Number(snapshot.updates||0));this.prototypes.clear();const inputDim=Number(this.recurrent?.inputDim||0),stateDim=Number(this.recurrent?.stateDim||0);for(const [k,v] of Object.entries(snapshot.prototypes||{})){if(!OPERATIONS.includes(k)||!v||typeof v!=='object')continue;if(!finiteVector(v.positiveInput,inputDim)||!finiteVector(v.positiveField,stateDim)||!finiteVector(v.negativeInput,inputDim))continue;this.prototypes.set(k,structuredClone(v));}this.revision+=1;this.inferCache=null;return this;}
  sharedCellView(){const temporal=this.recurrent?.temporalState?.()||{};return{state:Array.from(this.recurrent?.state||[]),trace:Array.from(this.recurrent?.trace||[]),rotationalTrace:Array.from(this.recurrent?.rotationalTrace||[]),steps:Number(this.recurrent?.steps||0),novelty:Number(temporal.novelty||0),predictionErrors:{...(temporal.predictionErrors||{})}};}
  infer(context={}, {domain='router',semantic=null}={}){
    const clean=stableSfmContext(context&&typeof context==='object'?context:context),semanticView=semantic?{intent:semantic.intent||null,nextOperation:semantic.nextOperation||null,targetHint:semantic.targetHint||null,predictedNextWitnessType:semantic.predictedNextWitnessType||null}:null,cleanJson=JSON.stringify(clean),semanticJson=JSON.stringify(semanticView),cacheKey=`${domain}|${this.revision}|${Number(this.recurrent?.revision||0)}|${cleanJson}|${semanticJson}`;
    if(this.inferCache?.key===cacheKey)return structuredClone(this.inferCache.value);
    const cell=this.sharedCellView(),source={domain,context:clean,recent:this.recent.slice(-8),temporal:{steps:cell.steps,novelty:cell.novelty,predictionErrors:cell.predictionErrors},semantic:semanticView},sourceHashes=hashFeatureTokens(featureTokens(source));
    const input=Array.from(featurizeFeatureHashes(sourceHashes,this.recurrent.inputDim)),seed=Array.from(featurizeFeatureHashes(sourceHashes,this.recurrent.stateDim)),fieldState=new Array(this.recurrent.stateDim),meanPredictionError=Object.values(cell.predictionErrors).reduce((a,b)=>a+(Number(b)||0),0)/Math.max(1,Object.keys(cell.predictionErrors).length);
    for(let i=0;i<fieldState.length;i+=1){const sv=cell.state[i]||0,t=cell.rotationalTrace[i]||0,tr=cell.trace[i%Math.max(1,cell.trace.length)]||0;fieldState[i]=Math.tanh(0.57*seed[i]+0.23*sv+0.10*t+0.06*tr+0.04*meanPredictionError);}
    const bootstrap=String(semantic?.nextOperation||operationHintText(cleanJson)),scored=[];
    for(const op of OPERATIONS){const p=this.prototypes.get(op);let score=op===bootstrap?0.34:0;if(p){const pos=cosine(input,p.positiveInput||[]),field=cosine(fieldState,p.positiveField||[]),neg=cosine(input,p.negativeInput||[]),reliability=(Number(p.successes||0)+1)/(Number(p.attempts||0)+2);score+=0.36*pos+0.22*field-0.22*Math.max(0,neg)+0.16*reliability;}scored.push([op,score]);}
    scored.sort((a,b)=>b[1]-a[1]||a[0].localeCompare(b[0]));const [operation,raw]=scored[0]||[bootstrap,0],confidence=clamp(0.46+0.42*Math.max(0,raw)-0.12*cell.novelty,0.05,0.95),value={schema:WG_SFM_SCHEMA,modelId:WG_SFM_MODEL_ID,engine:'fixed-feature-witness-state-field',domain,operation,targetHint:semantic?.targetHint||null,expectedWitnessType:semantic?.predictedNextWitnessType||null,expectedWitnessDelta:semantic?.expectedWitnessDelta||EXPECTED_DELTAS[operation]||{},confidence,uncertainty:1-confidence,inputVector:input,fieldState,sharedCell:{stateDim:this.recurrent.stateDim,inputDim:this.recurrent.inputDim,steps:cell.steps,novelty:cell.novelty,meanPredictionError},actionScores:Object.fromEntries(scored.map(([k,v])=>[k,Number(v.toFixed(6))])),teacherBlend:this.teacherBlend,authority:false,witnessGateRequired:true};
    this.inferCache={key:cacheKey,value:structuredClone(value)};return value;
  }
  publicProjection(inference){if(!inference)return null;return{schema:inference.schema,modelId:inference.modelId,engine:inference.engine,domain:inference.domain,operation:inference.operation,targetHint:inference.targetHint,expectedWitnessType:inference.expectedWitnessType,expectedWitnessDelta:inference.expectedWitnessDelta,confidence:inference.confidence,uncertainty:inference.uncertainty,sharedCell:inference.sharedCell,actionScores:inference.actionScores,teacherBlend:inference.teacherBlend,authority:false,witnessGateRequired:true};}
  async learnValidated({inference,reward=0,outcome={},routeWitnessDigest=null,outcomeWitnessDigest=null,learningWitnessDigest=null,promotionWitnessDigest=null,runtime=null,source='live',sourceExampleId=null}={}){
    if(!inference||!promotionWitnessDigest||outcome?.validated===false)return{updated:false,reason:'learning-gate-not-admitted'};
    const stateAssessment=this.gate?.assessState?.(inference.fieldState)||{admissible:true};if(!stateAssessment.admissible)return{updated:false,reason:'sfm-field-state-rejected',stateAssessment};
    const op=String(inference.operation||'inspect');const success=Boolean(outcome.ok)&&Number(reward)>=0;let p=this.prototypes.get(op);
    if(!p)p={operation:op,positiveInput:new Array(this.recurrent.inputDim).fill(0),positiveField:new Array(this.recurrent.stateDim).fill(0),negativeInput:new Array(this.recurrent.inputDim).fill(0),attempts:0,successes:0,failures:0,rewardSum:0,updatedAt:0};
    const rate=clamp(this.learningRate*(0.55+0.45*Math.abs(Number(reward)||0)),0.005,0.25);p.attempts+=1;p.rewardSum+=Number(reward)||0;p.updatedAt=Date.now();
    if(success){p.successes+=1;vectorBlend(p.positiveInput,inference.inputVector,rate);vectorBlend(p.positiveField,Array.from(this.recurrent.state),rate);}else{p.failures+=1;vectorBlend(p.negativeInput,inference.inputVector,rate);}
    this.prototypes.set(op,p);if(this.prototypes.size>this.maxPrototypes){const oldest=[...this.prototypes.entries()].sort((a,b)=>(a[1].updatedAt||0)-(b[1].updatedAt||0))[0]?.[0];if(oldest&&oldest!==op)this.prototypes.delete(oldest);}
    this.updates+=1;this.revision+=1;this.inferCache=null;
    const rnnTeaching=success?this.recurrent.teachFromWitness({input:inference.inputVector,targetState:inference.fieldState,confidence:inference.confidence,reward,learningRate:Math.min(0.12,this.learningRate)}):{updated:false,reason:'negative-outcome-trains-sfm-avoidance-only'};
    const state=this.snapshot();await this.store?.set?.('records',this.stateKey,{schema:'xavi-wg-sfm-state-record/v1',state,updatedAt:Date.now(),authority:false});
    const witness=await this.ledger?.append?.('wg-sfm-cross-trained',{operation:op,success,reward:Number(reward)||0,routeWitnessDigest,outcomeWitnessDigest,learningWitnessDigest,promotionWitnessDigest,sharedCellSteps:Number(this.recurrent.steps||0),prototype:{attempts:p.attempts,successes:p.successes,failures:p.failures,reliability:(p.successes+1)/(p.attempts+2)},runtime,source,sourceExampleId,rnnTeaching,authority:false});
    return{updated:true,operation:op,success,prototype:structuredClone(p),rnnTeaching,witness,authority:false};
  }
}
