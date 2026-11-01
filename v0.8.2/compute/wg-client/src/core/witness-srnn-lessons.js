export const WG_SRNN_LESSON_STATE_SCHEMA='xavi-wg-srnn-lesson-state/v1';
export const WG_SRNN_LESSON_PROMOTED_SCHEMA='xavi-wg-srnn-lesson-promoted/v1';
export const WG_SRNN_LESSON_EVALUATED_SCHEMA='xavi-wg-srnn-lesson-evaluated/v1';
export const WG_SRNN_LESSON_DEMOTED_SCHEMA='xavi-wg-srnn-lesson-demoted/v1';
export const WG_SRNN_LESSON_SUPERSEDED_SCHEMA='xavi-wg-srnn-lesson-superseded/v1';

export const WG_SRNN_LESSON_WITNESS_TYPES=new Set([
  'wg-srnn-lesson-promoted','wg-srnn-lesson-evaluated','wg-srnn-lesson-demoted','wg-srnn-lesson-superseded',
]);

function clamp(value,min=0,max=1,fallback=.5){const n=Number(value);return Number.isFinite(n)?Math.max(min,Math.min(max,n)):fallback;}
function text(value,max=768){const s=String(value??'').trim();return s?s.slice(0,max):null;}
function clone(value){return value==null?value:structuredClone(value);}
function bodyOf(event){return event?.body&&typeof event.body==='object'?event.body:event||{};}
function digestOf(event){return event?.digest||event?.witnessDigest||null;}
function timeOf(event){const body=bodyOf(event);return Number(body.at||event?.createdAt||Date.now());}

export function wgSrnnLessonId(candidateDigest){const d=text(candidateDigest,192);return d?`lesson:${d}`:null;}

export function wgSrnnLessonReliability(row){
  const uses=Math.max(0,Number(row?.uses||0)),positive=Math.max(0,Number(row?.positive||0));
  return (positive+1)/(uses+2);
}

export function projectWgSrnnLesson(row,{maxAdjustment=.08}={}){
  if(!row)return null;
  const uses=Math.max(0,Number(row.uses||0)),positive=Math.max(0,Number(row.positive||0)),negative=Math.max(0,Number(row.negative||0));
  const reliability=wgSrnnLessonReliability(row),meanCredit=uses?Math.max(-1,Math.min(1,Number(row.rewardSum||0)/uses)):0;
  const candidateMeanCredit=Math.max(-1,Math.min(1,Number(row.candidateMeanCredit||0)));
  const maturity=Math.min(1,Math.max(.25,(Math.max(0,Number(row.candidateCreditCount||0))+uses)/4));
  const support=clamp(.5+candidateMeanCredit*.25+(reliability-.5)*.5,0,1,.5);
  const adjustment=row.status==='active'?Math.max(-maxAdjustment,Math.min(maxAdjustment,(support-.5)*2*maxAdjustment*maturity)):0;
  return{schema:WG_SRNN_LESSON_STATE_SCHEMA,lessonId:row.lessonId||wgSrnnLessonId(row.candidateDigest),candidateDigest:row.candidateDigest||null,capability:row.capability||null,strategyId:row.strategyId||null,concept:row.concept||null,status:row.status||'candidate',candidateCreditCount:Math.max(0,Number(row.candidateCreditCount||0)),candidateMeanCredit,independentProvenanceGroups:(Array.isArray(row.independentProvenanceGroups)?row.independentProvenanceGroups:[]).slice(0,8),uses,positive,negative,reliability,meanCredit,support,adjustment,promotedAt:Number(row.promotedAt||0),updatedAt:Number(row.updatedAt||0),lastWitnessDigest:row.lastWitnessDigest||null,lastEvaluationWitnessDigest:row.lastEvaluationWitnessDigest||null,demotionWitnessDigest:row.demotionWitnessDigest||null,supersededByCandidateDigest:row.supersededByCandidateDigest||null,authority:false};
}

export function applyWgSrnnLessonEvent(states,event){
  const rows=Array.isArray(states)?states:[],body=bodyOf(event),type=event?.type||body.type,digest=digestOf(event),at=timeOf(event);
  if(type==='wg-srnn-lesson-promoted'){
    const candidateDigest=text(body.candidateDigest,192),lessonId=text(body.lessonId,256)||wgSrnnLessonId(candidateDigest);if(!candidateDigest||!lessonId)return rows;
    const next={schema:WG_SRNN_LESSON_STATE_SCHEMA,lessonId,candidateDigest,capability:text(body.capability,192),strategyId:text(body.strategyId,256),concept:text(body.concept,768),status:'active',candidateCreditCount:Math.max(0,Number(body.creditCount||0)),candidateMeanCredit:Number(body.meanCredit||0),independentProvenanceGroups:(Array.isArray(body.independentProvenanceGroups)?body.independentProvenanceGroups:[]).slice(0,16),uses:0,positive:0,negative:0,rewardSum:0,promotedAt:at,updatedAt:at,lastWitnessDigest:digest,authority:false};
    const i=rows.findIndex(row=>row.lessonId===lessonId);if(i>=0)rows[i]=next;else rows.push(next);return rows;
  }
  const lessonId=text(body.lessonId,256)||wgSrnnLessonId(body.candidateDigest),i=rows.findIndex(row=>row.lessonId===lessonId);if(i<0)return rows;
  const row=rows[i];
  if(type==='wg-srnn-lesson-evaluated'){
    const credit=Math.max(-1,Math.min(1,Number(body.credit||0)));row.uses=Math.max(0,Number(row.uses||0))+1;row.rewardSum=Number(row.rewardSum||0)+credit;if(credit>0)row.positive=Math.max(0,Number(row.positive||0))+1;else row.negative=Math.max(0,Number(row.negative||0))+1;row.updatedAt=at;row.lastEvaluationWitnessDigest=digest;row.lastWitnessDigest=digest;
  }else if(type==='wg-srnn-lesson-demoted'){
    row.status='demoted';row.updatedAt=at;row.demotedAt=at;row.demotionReason=text(body.reason,192);row.demotionWitnessDigest=digest;row.lastWitnessDigest=digest;
  }else if(type==='wg-srnn-lesson-superseded'){
    row.status='superseded';row.updatedAt=at;row.supersededAt=at;row.supersededByCandidateDigest=text(body.replacementCandidateDigest,192);row.supersedeWitnessDigest=digest;row.lastWitnessDigest=digest;
  }
  return rows;
}

export function cloneWgSrnnLessonStates(rows,max=128){return (Array.isArray(rows)?rows:[]).slice(-Math.max(1,Number(max)||128)).map(clone);}
