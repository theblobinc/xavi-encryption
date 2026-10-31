import { SMALL_MODEL_RUNTIME_SCHEMA } from './small-model-runtime.js';

const clamp=(x,lo=-1,hi=1)=>Math.max(lo,Math.min(hi,Number(x)||0));
const COST=Object.freeze({'very-low':0.05,low:0.03,medium:0,high:-0.03,'very-high':-0.05});
const keyOf=d=>d?.id?`small-model-runtime-policy:${d.id}`:null;

export class SmallModelRuntimePolicy {
  constructor({store,ledger=null,enabled=true,maxAdjustment=0.14,learningRate=0.18}={}){
    this.store=store;this.ledger=ledger;this.enabled=enabled!==false;this.maxAdjustment=Math.max(0,Number(maxAdjustment)||0.14);this.learningRate=clamp(learningRate,0.01,0.5);this.rows=new Map();this.schema='xavi-small-model-runtime-policy/v1';
  }
  async init(){if(!this.store)return this;for(const row of await this.store.values('records'))if(row?.schema===this.schema&&row?.runtimeId)this.rows.set(row.runtimeId,row);return this;}
  score({strategy,context={}}={}){
    const d=strategy?.metadata?.smallModelRuntime||null;if(!this.enabled||!d)return{adjustment:0,descriptor:d,reasons:[],authority:false};
    const prefs=context?.smallModelPolicy||context?.runtimePolicy||{};let raw=0;const reasons=[];
    const add=(value,reason)=>{if(!value)return;raw+=value;reasons.push([reason,Number(value.toFixed(6))]);};
    add(COST[d.costClass]??0,`cost:${d.costClass||'unknown'}`);
    if(d.offline)add(0.018,'offline');
    if(d.deterministic)add(0.012,'deterministic');
    const requiredModalities=[...(Array.isArray(prefs.modalities)?prefs.modalities:[]),...(context.modality?[context.modality]:[])].map(String);
    if(requiredModalities.length){const hit=requiredModalities.every(m=>(d.modalities||[]).includes(m));add(hit?0.022:-0.035,hit?'modality-fit':'modality-mismatch');}
    if(prefs.environment){add(d.environment===prefs.environment?0.018:-0.025,d.environment===prefs.environment?'environment-fit':'environment-mismatch');}
    if(Array.isArray(prefs.preferredBackends)&&prefs.preferredBackends.includes(d.backend))add(0.025,'preferred-backend');
    if(Array.isArray(prefs.avoidBackends)&&prefs.avoidBackends.includes(d.backend))add(-0.04,'avoided-backend');
    const budget=Number(prefs.latencyBudgetMs??context.latencyBudgetMs);if(Number.isFinite(budget)&&budget>0){if(budget<=50&&['high','very-high'].includes(d.costClass))add(-0.04,'tight-latency-budget');else if(budget<=150&&d.costClass==='high')add(-0.02,'latency-budget');else if(budget<=150&&['very-low','low'].includes(d.costClass))add(0.018,'latency-budget-fit');}
    const learned=this.rows.get(d.id)||null;
    if(learned?.attempts){const reliability=(Number(learned.successes||0)+1)/(Number(learned.attempts||0)+2);const learnedAdj=(reliability-.5)*0.12;add(learnedAdj,'witnessed-reliability');if(Number.isFinite(learned.latencyEwmaMs)&&Number.isFinite(budget)&&budget>0){const ratio=learned.latencyEwmaMs/budget;if(ratio>1)add(-Math.min(.04,(ratio-1)*.025),'observed-latency-over-budget');}}
    const adjustment=clamp(raw,-this.maxAdjustment,this.maxAdjustment);
    return{schema:'xavi-small-model-runtime-policy-decision/v1',runtimeId:d.id,backend:d.backend,modelId:d.modelId,adjustment,rawAdjustment:raw,reasons:reasons.slice(0,10),attempts:Number(learned?.attempts||0),successes:Number(learned?.successes||0),reliability:learned?.attempts?(Number(learned.successes||0)+1)/(Number(learned.attempts||0)+2):null,latencyEwmaMs:learned?.latencyEwmaMs??null,authority:false};
  }
  async recordOutcome(descriptor,{ok=false,reward=0,latencyMs=null,routeWitnessDigest=null,outcomeWitnessDigest=null,learningWitnessDigest=null,promotionWitnessDigest=null}={}){
    if(!this.enabled||descriptor?.schema!==SMALL_MODEL_RUNTIME_SCHEMA||!promotionWitnessDigest)return{updated:false,reason:'runtime-policy-not-admitted'};
    const prior=this.rows.get(descriptor.id)||{schema:this.schema,runtimeId:descriptor.id,backend:descriptor.backend,modelId:descriptor.modelId,attempts:0,successes:0,failures:0,rewardSum:0,latencyEwmaMs:null,updatedAt:0,authority:false};
    const row={...prior};row.attempts+=1;if(ok)row.successes+=1;else row.failures+=1;row.rewardSum+=Number(reward)||0;const ms=Number(latencyMs);if(Number.isFinite(ms)&&ms>=0)row.latencyEwmaMs=row.latencyEwmaMs==null?ms:(1-this.learningRate)*Number(row.latencyEwmaMs)+this.learningRate*ms;row.updatedAt=Date.now();row.authority=false;
    this.rows.set(descriptor.id,row);if(this.store)await this.store.set('records',keyOf(descriptor),row);
    const body={runtime:descriptor,runtimeId:descriptor.id,backend:descriptor.backend,modelId:descriptor.modelId,routeWitnessDigest,outcomeWitnessDigest,learningWitnessDigest,promotionWitnessDigest,ok:Boolean(ok),reward:Number(reward)||0,latencyMs:Number.isFinite(ms)?ms:null,attempts:row.attempts,successes:row.successes,failures:row.failures,reliability:(row.successes+1)/(row.attempts+2),latencyEwmaMs:row.latencyEwmaMs,authority:false};
    const witness=await this.ledger?.append?.('small-model-runtime-calibrated',body);
    return{updated:true,row:structuredClone(row),witness,authority:false};
  }
}
