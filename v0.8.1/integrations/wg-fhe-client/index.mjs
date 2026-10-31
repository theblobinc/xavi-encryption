import { createHash } from 'node:crypto';
import { RecurrentCore } from '../../compute/wg-client/src/core/recurrent.js';
import { WitnessSFM } from '../../compute/wg-client/src/core/witness-sfm.js';
import { WitnessGatedSelfReferentialNeuralNetwork } from '../../compute/wg-client/src/core/witness-srnn.js';

const clone=(v)=>structuredClone(v);
const stable=(v)=>JSON.stringify(v,Object.keys(v??{}).sort());
const sha=(v)=>createHash('sha256').update(typeof v==='string'?v:JSON.stringify(v)).digest('hex');

export class InMemoryWitnessStore {
  constructor(){this.rows=new Map();}
  _k(bucket,key){return `${bucket}:${key}`;}
  async get(bucket,key){const v=this.rows.get(this._k(bucket,key));return v===undefined?null:clone(v);}
  async set(bucket,key,value){this.rows.set(this._k(bucket,key),clone(value));return clone(value);}
  async compareAndSet(bucket,key,expected,value){const k=this._k(bucket,key),cur=this.rows.get(k);if(JSON.stringify(cur??null)!==JSON.stringify(expected??null))return{updated:false};this.rows.set(k,clone(value));return{updated:true,value:clone(value)};}
}

export class InMemoryWitnessLedger {
  constructor(){this.rows=[];this.sequence=0;}
  async append(type,payload={}){this.sequence+=1;const row={sequence:this.sequence,type,payload:clone(payload),authority:false};row.digest=`sha256:${sha(row)}`;this.rows.push(row);return clone(row);}
}

function safeKeyView(key={}){
  return {
    scheme:String(key.scheme||'tfhe'),
    keyId:String(key.keyId||''),
    parameterSet:String(key.parameterSet||''),
    deterministicClient:Boolean(key.deterministicClient),
    evaluationKeyBytes:Math.max(0,Number(key.evaluationKeyBytes||0)),
    ciphertextExpansion:Math.max(0,Number(key.ciphertextExpansion||0)),
    clientSecretPresent:Boolean(key.clientSecretPresent),
    custodyRef:key.custodyRef?String(key.custodyRef):null,
  };
}

export function sanitizeEvaluatorView(plan={}){
  const safe={
    schema:'XAVI-DUO/WG-FHE-EVALUATOR-VIEW/v1',
    programId:plan.programId||null,
    irCommitment:plan.irCommitment||null,
    encryptedInputCommitment:plan.encryptedInputCommitment||null,
    evaluationKeyId:plan.key?.keyId||null,
    provider:plan.provider||null,
    device:plan.device||null,
    acceleratorAbi:plan.acceleratorAbi||null,
    acceleratorProfile:plan.acceleratorProfile||null,
    acceleratorVendor:plan.acceleratorVendor||null,
    executionClass:clone(plan.executionClass||{}),
    batchSize:Number(plan.batchSize||1),
    checkpointInterval:Number(plan.checkpointInterval||1),
    cacheHints:clone(plan.cacheHints||{}),
    witnessContext:clone(plan.witnessContext||{}),
    authority:false,
  };
  const forbidden=JSON.stringify(safe);
  for(const marker of ['clientSecret','privateKey','plaintext','decrypted','secretKeyBytes'])if(forbidden.includes(marker))throw new Error(`forbidden evaluator field: ${marker}`);
  return safe;
}

export class WGTrustedFHEClient {
  constructor({namespace='xavi-encrypt-fhe',stateDim=128,inputDim=32,store=null,ledger=null}={}){
    this.store=store||new InMemoryWitnessStore();this.ledger=ledger||new InMemoryWitnessLedger();
    this.recurrent=new RecurrentCore({stateDim,inputDim});
    this.sfm=new WitnessSFM({store:this.store,recurrent:this.recurrent,ledger:this.ledger,namespace:`${namespace}:sfm`});
    this.srnn=new WitnessGatedSelfReferentialNeuralNetwork({store:this.store,ledger:this.ledger,namespace:`${namespace}:srnn`});
    this.namespace=namespace;this.history=[];
  }
  async init(){await this.srnn.init();return this;}
  context({program,key,candidates=[],history=[],trustedPlaintextFeatures={}}={}){
    return {
      schema:'XAVI-DUO/WG-FHE-TRUSTED-CLIENT-CONTEXT/v1',
      program:{id:program?.id||null,irCommitment:program?.irCommitment||null,booleanOps:Number(program?.booleanOps||0),wordOps:Number(program?.wordOps||0),depth:Number(program?.depth||0),bootstraps:Number(program?.bootstraps||0),ciphertextBytes:Number(program?.ciphertextBytes||0),recursiveDepth:Number(program?.recursiveDepth||0),operationProfile:Object.fromEntries(Object.entries(program?.operationProfile||{}).map(([k,v])=>[String(k),Math.max(0,Number(v)||0)]))},
      key:safeKeyView(key),
      trustedPlaintextFeatures:clone(trustedPlaintextFeatures),
      candidates:candidates.map(c=>({id:String(c.id),provider:String(c.provider),device:String(c.device),acceleratorAbi:c.acceleratorAbi?String(c.acceleratorAbi):null,acceleratorProfile:c.acceleratorProfile?String(c.acceleratorProfile):null,acceleratorVendor:c.acceleratorVendor?String(c.acceleratorVendor):null,remote:Boolean(c.remote),fhe:Boolean(c.fhe),role:String(c.role||'evaluator'),hasClientSecret:Boolean(c.hasClientSecret),queue:Number(c.queue||0),wallMs:Number(c.wallMs||0),bootstrapMs:Number(c.bootstrapMs||0),cacheHitRate:Number(c.cacheHitRate||0),ciphertextBytes:Number(c.ciphertextBytes||0),supportsResidentSessions:Boolean(c.supportsResidentSessions),supportsBulkRegisters:Boolean(c.supportsBulkRegisters),keyId:c.keyId||null,operationCostsMs:Object.fromEntries(Object.entries(c.operationCostsMs||{}).map(([k,v])=>[String(k),Math.max(0,Number(v)||0)])),costBounds:Object.fromEntries(Object.entries(c.costBounds||{}).map(([k,v])=>[String(k),Math.max(0,Number(v)||0)]))})),
      prior:[...this.history.slice(-16),...history.slice(-16)],
      authority:false,
    };
  }
  async plan(input={}){
    const ctx=this.context(input);
    const temporal=this.recurrent.candidate(ctx);this.recurrent.commit(temporal);
    const sfm=this.sfm.infer(ctx,{domain:'fhe-client',semantic:{intent:'optimize encrypted execution',nextOperation:'execute',targetHint:'fhe-evaluator',predictedNextWitnessType:'fhe-execution-outcome'}});
    const eligible=ctx.candidates.filter(c=>c.fhe&&c.role==='evaluator'&&!c.hasClientSecret&&(!ctx.key.keyId||!c.keyId||c.keyId===ctx.key.keyId));
    if(!eligible.length)throw new Error('no remote-safe FHE evaluator candidate');
    const srnnContext=this.srnn.publicProjection({capability:'fhe-evaluate',limit:8});
    const adviceByStrategy=new Map((srnnContext.strategyAdvice||[]).map(row=>[String(row.strategyId),Math.max(-.12,Math.min(.12,Number(row.adjustment)||0))]));
    const scored=eligible.map(c=>{
      const latency=1/(1+Math.max(0,c.wallMs)/1000);
      const queue=1/(1+Math.max(0,c.queue));
      const cache=Math.max(0,Math.min(1,c.cacheHitRate));
      const resident=c.supportsResidentSessions?1:0;
      const bulk=c.supportsBulkRegisters?1:0;
      const localPenalty=c.remote?0:0.005;
      const observed=ctx.prior.filter(row=>String(row?.strategyId||'')===c.id&&(!c.acceleratorProfile||!row?.acceleratorProfile||String(row.acceleratorProfile)===c.acceleratorProfile));
      const attempts=observed.length;
      const successes=observed.filter(row=>row?.ok).length;
      const successRate=attempts?successes/attempts:.5;
      const meanReward=attempts?observed.reduce((sum,row)=>sum+Math.max(-1,Math.min(1,Number(row?.reward)||0)),0)/attempts:0;
      const meanObservedMs=attempts?observed.reduce((sum,row)=>sum+Math.max(0,Number(row?.wallMs)||0),0)/attempts:0;
      const observedLatency=attempts?1/(1+meanObservedMs/1000):.5;
      const srnnAdjustment=adviceByStrategy.get(c.id)||0;
      const opRows=Object.entries(ctx.program.operationProfile||{}).filter(([,count])=>Number(count)>0);
      const observedOpCost=op=>{const rows=observed.map(row=>Number(row?.operationCostsMs?.[op])).filter(Number.isFinite);return rows.length?rows.reduce((a,v)=>a+v,0)/rows.length:null;};
      const costFor=op=>{const direct=Number(c.operationCostsMs?.[op]);if(Number.isFinite(direct))return{value:direct,source:'candidate'};const learned=observedOpCost(op);if(Number.isFinite(learned))return{value:learned,source:'history'};const bound=Number(c.costBounds?.[op]);if(Number.isFinite(bound))return{value:bound,source:'bound'};return{value:0,source:'unknown'};};
      const opPricing=Object.fromEntries(opRows.map(([op])=>[op,costFor(op)]));
      const estimatedOperationMs=opRows.reduce((sum,[op,count])=>sum+Number(count)*opPricing[op].value,0);
      const pricedOps=opRows.filter(([op])=>opPricing[op].source!=='unknown').length;
      const operationCoverage=opRows.length?pricedOps/opRows.length:1;
      const operationFit=opRows.length&&pricedOps?1/(1+estimatedOperationMs/1000):.5;
      const score=0.29*latency+0.13*queue+0.13*cache+0.08*resident+0.07*bulk+localPenalty+0.02*(1-temporal.novelty)+0.12*successRate+0.10*((meanReward+1)/2)+0.04*observedLatency+0.02*srnnAdjustment+0.10*operationFit*operationCoverage;
      return{...c,score,learning:{attempts,successRate,meanReward,meanObservedMs,srnnAdjustment,estimatedOperationMs,operationCoverage,operationFit,operationPricing:opPricing}};
    }).sort((a,b)=>b.score-a.score||a.id.localeCompare(b.id));
    const selected=scored[0];
    const directive=await this.srnn.proposeDirective({author:'wg-rnn-fhe-client',capability:'fhe-evaluate',strategyId:selected.id,goal:'evaluate encrypted program with minimum witnessed cost',proposedAction:`route:${selected.id}`,confidence:Math.max(.05,Math.min(.95,.5+.4*(selected.score||0))),expectedOutcome:{ok:true,provider:selected.provider,device:selected.device,acceleratorAbi:selected.acceleratorAbi||null,acceleratorProfile:selected.acceleratorProfile||null,acceleratorVendor:selected.acceleratorVendor||null},wgSfm:sfm,selfContext:{temporal:{novelty:temporal.novelty,predictionErrors:temporal.predictionErrors},fhe:{keyId:ctx.key.keyId,programId:ctx.program.id}},commit:false});
    const plan={schema:'XAVI-DUO/WG-FHE-CLIENT-PLAN/v1',programId:ctx.program.id,irCommitment:ctx.program.irCommitment,key:ctx.key,provider:selected.provider,device:selected.device,acceleratorAbi:selected.acceleratorAbi||null,acceleratorProfile:selected.acceleratorProfile||null,acceleratorVendor:selected.acceleratorVendor||null,evaluatorId:selected.id,batchSize:selected.supportsBulkRegisters?32:8,checkpointInterval:selected.supportsResidentSessions?8:2,cacheHints:{resident:selected.supportsResidentSessions,keyId:ctx.key.keyId},wg:{temporal:{novelty:temporal.novelty,predictionErrors:temporal.predictionErrors},sfm:{operation:sfm.operation,confidence:sfm.confidence},srnn:{directiveDigest:directive.directive.directiveDigest,strategyId:selected.id}},witnessContext:{directiveDigest:directive.directive.directiveDigest,authority:false},authority:false};
    const clientLearning={schema:'XAVI-DUO/WG-FHE-CLIENT-LEARNING/v1',input:Array.from(temporal.input),targetState:Array.from(temporal.state),novelty:Number(temporal.novelty||0),authority:false};
    return{trustedContext:ctx,plan,evaluatorView:sanitizeEvaluatorView(plan),ranked:scored,clientLearning};
  }
  async settle({planned,outcome={}}={}){
    const ok=Boolean(outcome.ok);
    const wallMs=Math.max(0,Number(outcome.wallMs||0));
    const approximationError=Math.max(0,Number(outcome.approximationError||0));
    const tolerance=Math.max(1e-9,Number(outcome.tolerance||1));
    const latencyReward=1/(1+wallMs/1000);
    const qualityReward=Math.max(0,Math.min(1,1-approximationError/tolerance));
    const reward=ok?Math.max(0,Math.min(1,.65*latencyReward+.35*qualityReward)):-1;
    const recurrentTeaching=ok&&planned?.clientLearning?this.recurrent.teachFromWitness({input:planned.clientLearning.input,targetState:planned.clientLearning.targetState,confidence:Math.max(.1,reward),reward:Math.max(0,reward),learningRate:.06}):{updated:false,reason:ok?'missing-client-learning':'failed-outcome'};
    await this.srnn.settleDirective({directiveDigest:planned?.plan?.wg?.srnn?.directiveDigest,outcome:{ok,wallMs,provider:outcome.provider||planned?.plan?.provider,device:outcome.device||planned?.plan?.device,acceleratorAbi:outcome.acceleratorAbi||planned?.plan?.acceleratorAbi||null,acceleratorProfile:outcome.acceleratorProfile||planned?.plan?.acceleratorProfile||null,acceleratorVendor:outcome.acceleratorVendor||planned?.plan?.acceleratorVendor||null,cacheHit:Boolean(outcome.cacheHit),bootstrapCount:Number(outcome.bootstrapCount||0),approximationError,tolerance},reward,goalComplete:ok});
    const row={strategyId:planned?.plan?.evaluatorId,acceleratorAbi:outcome.acceleratorAbi||planned?.plan?.acceleratorAbi||null,acceleratorProfile:outcome.acceleratorProfile||planned?.plan?.acceleratorProfile||null,acceleratorVendor:outcome.acceleratorVendor||planned?.plan?.acceleratorVendor||null,ok,wallMs,cacheHit:Boolean(outcome.cacheHit),bootstrapCount:Number(outcome.bootstrapCount||0),approximationError,tolerance,operationProfile:clone(planned?.trustedContext?.program?.operationProfile||{}),operationCostsMs:Object.fromEntries(Object.entries(outcome.operationCostsMs||{}).map(([k,v])=>[String(k),Math.max(0,Number(v)||0)])),latencyReward,qualityReward,reward,recurrentTeaching,at:Date.now()};this.history.push(row);if(this.history.length>64)this.history.splice(0,this.history.length-64);
    this.sfm.ingest({type:'fhe-execution-outcome',digest:`sha256:${sha(row)}`,semanticSignature:planned?.plan?.irCommitment||null,metaObjectSignature:planned?.plan?.evaluatorId||null});
    return{row,recurrentTeaching,reflection:this.srnn.reflect({capability:'fhe-evaluate',limit:8}),strategyComparison:this.srnn.strategyComparison({directiveDigest:planned?.plan?.wg?.srnn?.directiveDigest}),authority:false};
  }
}
