import { clamp, dot, featurize, sigmoid } from './utils.js';
import { normalizeJsRnnSnapshot, verifyRnnHandoff, javascriptRnnTeacherProjection } from './witness-rnn-interchange.js';

const DEFAULT_HORIZONS = [1, 4, 16, 64];

function finiteArray(value, length) {
  return Array.isArray(value) && value.length === length && value.every(Number.isFinite);
}
function cosine(a,b) {
  const d=dot(a,b); let aa=0,bb=0;
  for(let i=0;i<Math.min(a.length,b.length);i+=1){aa+=a[i]*a[i];bb+=b[i]*b[i];}
  return aa>0&&bb>0?d/Math.sqrt(aa*bb):0;
}
function meanAbsDelta(a,b){let s=0;const n=Math.min(a.length,b.length);for(let i=0;i<n;i+=1)s+=Math.abs(a[i]-b[i]);return n?s/n:0;}

export class RecurrentCore {
  constructor({ stateDim = 256, inputDim = 32, traceDecay = 0.92, horizons = DEFAULT_HORIZONS, associativeSlots = 24 } = {}) {
    this.stateDim = stateDim;
    this.inputDim = inputDim;
    this.traceDecay = traceDecay;
    this.horizons = [...new Set(horizons.map(Number).filter(v=>Number.isFinite(v)&&v>=1))].sort((a,b)=>a-b);
    this.associativeSlots = Math.max(0, Math.floor(associativeSlots));
    this.state = new Float64Array(stateDim);
    this.trace = new Float64Array(inputDim);
    this.rotationalTrace = new Float64Array(stateDim);
    this.predictions = new Map(this.horizons.map(h=>[h,new Float64Array(stateDim)]));
    this.associative = [];
    this.steps = 0;
    this.revision = 0;
    this.lastNovelty = 0;
    this.lastPredictionErrors = Object.fromEntries(this.horizons.map(h=>[h,0]));
  }

  restore(snapshot = {}) {
    if (finiteArray(snapshot.state,this.stateDim)) this.state.set(snapshot.state);
    if (finiteArray(snapshot.trace,this.inputDim)) this.trace.set(snapshot.trace);
    if (finiteArray(snapshot.rotationalTrace,this.stateDim)) this.rotationalTrace.set(snapshot.rotationalTrace);
    const source=snapshot.predictions && typeof snapshot.predictions==='object'?snapshot.predictions:{};
    for(const h of this.horizons){const row=source[h] ?? source[String(h)]; if(finiteArray(row,this.stateDim)) this.predictions.get(h).set(row);}
    if (Array.isArray(snapshot.associative)) {
      this.associative=snapshot.associative.slice(0,this.associativeSlots).filter(row=>finiteArray(row?.key,this.inputDim)&&finiteArray(row?.value,this.stateDim)).map(row=>({key:[...row.key],value:[...row.value],strength:Math.max(0,Number(row.strength)||0),updatedAt:Number(row.updatedAt)||0}));
    }
    this.steps = Math.max(0, Number(snapshot.steps || 0));
    this.lastNovelty = Math.max(0, Number(snapshot.lastNovelty || 0));
    if(snapshot.lastPredictionErrors&&typeof snapshot.lastPredictionErrors==='object') this.lastPredictionErrors={...this.lastPredictionErrors,...snapshot.lastPredictionErrors};
    this.revision += 1;
  }

  snapshot() {
    return {
      schemaVersion:'xavi-browser-recurrent/v2',
      state:Array.from(this.state), trace:Array.from(this.trace), rotationalTrace:Array.from(this.rotationalTrace),
      predictions:Object.fromEntries(this.horizons.map(h=>[h,Array.from(this.predictions.get(h))])),
      associative:this.associative.map(row=>({key:[...row.key],value:[...row.value],strength:row.strength,updatedAt:row.updatedAt})),
      steps:this.steps,lastNovelty:this.lastNovelty,lastPredictionErrors:{...this.lastPredictionErrors},
    };
  }

  normalizeInterchangeSnapshot(snapshot=this.snapshot()){return normalizeJsRnnSnapshot(snapshot);}
  normalize_interchange_snapshot(snapshot=this.snapshot()){return this.normalizeInterchangeSnapshot(snapshot);}
  verifyInterchangeHandoff(handoff){return verifyRnnHandoff(handoff);}
  verify_interchange_handoff(handoff){return this.verifyInterchangeHandoff(handoff);}
  interchangeTeacherProjection(handoff,options={}){return javascriptRnnTeacherProjection(handoff,options);}
  interchange_teacher_projection(handoff,options={}){return this.interchangeTeacherProjection(handoff,options);}

  recall(input) {
    if(!this.associative.length) return {vector:new Float64Array(this.stateDim),confidence:0};
    const ranked=this.associative.map(row=>({row,score:cosine(input,row.key)*Math.min(1,row.strength)})).filter(x=>x.score>0).sort((a,b)=>b.score-a.score).slice(0,4);
    const out=new Float64Array(this.stateDim); let total=0;
    for(const {row,score} of ranked){total+=score;for(let i=0;i<this.stateDim;i+=1)out[i]+=score*row.value[i];}
    if(total>0)for(let i=0;i<this.stateDim;i+=1)out[i]/=total;
    return {vector:out,confidence:Math.min(1,total/Math.max(1,ranked.length))};
  }

  candidate(context, {teacherState=null,teacherConfidence=0,teacherBlend=0} = {}) {
    const x = featurize(context, this.inputDim);
    const teacher=finiteArray(teacherState,this.stateDim)?teacherState:null;
    const teacherWeight=teacher?clamp(Number(teacherBlend)||0,0,0.25)*clamp(Number(teacherConfidence)||0,0,1):0;
    const recalled=this.recall(x);
    const next = new Float64Array(this.stateDim);
    for (let i = 0; i < this.stateDim; i += 1) {
      const xi = x[i % x.length];
      const prev = this.state[i];
      const neighbor = this.state[(i + this.stateDim - 1) % this.stateDim];
      const temporal=this.rotationalTrace[i];
      const assoc=recalled.vector[i];
      const z = sigmoid(0.78 * xi + 0.34 * prev - 0.08 * neighbor + 0.05*temporal);
      const r = sigmoid(0.52 * xi + 0.21 * neighbor + 0.13 * prev + 0.04*assoc);
      const proposal = Math.tanh(0.91 * xi + 0.63 * (r * prev) + 0.07 * neighbor + 0.10*temporal + 0.12*recalled.confidence*assoc + teacherWeight*(teacher?teacher[i]:0));
      next[i] = clamp((1 - z) * prev + z * proposal, -1, 1);
    }
    const predictionErrors={};
    for(const h of this.horizons) predictionErrors[h]=meanAbsDelta(next,this.predictions.get(h));
    const novelty=Math.min(1,0.65*(predictionErrors[this.horizons[0]]||0)+0.35*meanAbsDelta(next,this.state));
    return {state:next,input:x,novelty,predictionErrors,associativeConfidence:recalled.confidence,teacher:{applied:Boolean(teacherWeight),weight:teacherWeight,confidence:teacher?clamp(Number(teacherConfidence)||0,0,1):0}};
  }

  commit(candidate) {
    this.state.set(candidate.state);
    for (let i = 0; i < this.trace.length; i += 1) this.trace[i] = this.traceDecay * this.trace[i] + candidate.input[i];

    for(let i=0;i<this.stateDim;i+=2){
      const pair=Math.floor(i/2); const h=this.horizons[pair%this.horizons.length]||1;
      const decay=Math.exp(-1/h), angle=1/Math.max(1,h);
      const a=this.rotationalTrace[i]||0,b=i+1<this.stateDim?(this.rotationalTrace[i+1]||0):0;
      const ca=Math.cos(angle),sa=Math.sin(angle);
      this.rotationalTrace[i]=clamp(decay*(ca*a-sa*b)+(1-decay)*candidate.state[i],-1,1);
      if(i+1<this.stateDim)this.rotationalTrace[i+1]=clamp(decay*(sa*a+ca*b)+(1-decay)*candidate.state[i+1],-1,1);
    }

    for(const h of this.horizons){
      const prediction=this.predictions.get(h), alpha=Math.exp(-1/h);
      for(let i=0;i<this.stateDim;i+=1)prediction[i]=alpha*prediction[i]+(1-alpha)*candidate.state[i];
    }
    this._writeAssociation(candidate.input,candidate.state,candidate.novelty);
    this.steps += 1;
    this.lastNovelty=Number(candidate.novelty)||0;
    this.lastPredictionErrors={...(candidate.predictionErrors||{})};
    this.revision += 1;
    return this.snapshot();
  }

  teachFromWitness({input,targetState,confidence=0,reward=1,learningRate=0.06} = {}) {
    if(!finiteArray(input,this.inputDim)||!finiteArray(targetState,this.stateDim)) return {updated:false,reason:'invalid-teaching-vector'};
    if(!(Number(reward)>0)) return {updated:false,reason:'non-positive-teaching-outcome'};
    const strength=clamp((Number(confidence)||0)*Math.min(1,Math.abs(Number(reward)||0)),0,1);
    if(strength<=0) return {updated:false,reason:'zero-teaching-strength'};
    const rate=clamp((Number(learningRate)||0.06)*strength,0.001,0.12);
    const before={};
    for(const h of this.horizons){const prediction=this.predictions.get(h);before[h]=meanAbsDelta(prediction,targetState);for(let i=0;i<this.stateDim;i+=1)prediction[i]=(1-rate)*prediction[i]+rate*targetState[i];}
    this._writeAssociation(input,targetState,Math.min(1,strength));
    const after={};for(const h of this.horizons)after[h]=meanAbsDelta(this.predictions.get(h),targetState);
    this.revision += 1;
    return {updated:true,rate,strength,predictionErrorBefore:before,predictionErrorAfter:after,authority:false};
  }

  _writeAssociation(input,state,novelty=0) {
    if(!this.associativeSlots)return;
    let best=-1,bestScore=-Infinity;
    for(let i=0;i<this.associative.length;i+=1){const score=cosine(input,this.associative[i].key);if(score>bestScore){bestScore=score;best=i;}}
    if(best>=0&&bestScore>=0.82){
      const row=this.associative[best],rate=0.12+0.18*Math.min(1,Math.max(0,Number(novelty)||0));
      for(let i=0;i<this.inputDim;i+=1)row.key[i]=(1-rate)*row.key[i]+rate*input[i];
      for(let i=0;i<this.stateDim;i+=1)row.value[i]=(1-rate)*row.value[i]+rate*state[i];
      row.strength=Math.min(1.5,row.strength+0.08);row.updatedAt=this.steps+1;return;
    }
    const row={key:Array.from(input),value:Array.from(state),strength:0.55+0.35*Math.min(1,Math.max(0,Number(novelty)||0)),updatedAt:this.steps+1};
    if(this.associative.length<this.associativeSlots)this.associative.push(row);
    else {let weakest=0;for(let i=1;i<this.associative.length;i+=1)if(this.associative[i].strength<this.associative[weakest].strength)weakest=i;this.associative[weakest]=row;}
    for(const item of this.associative)item.strength*=0.997;
  }

  temporalCredit() { return Array.from(this.trace); }
  temporalState() { return {rotationalTrace:Array.from(this.rotationalTrace),novelty:this.lastNovelty,predictionErrors:{...this.lastPredictionErrors}}; }
}
