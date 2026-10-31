export const WG_SRNN_CONFIDENCE_CALIBRATION_SCHEMA='wg-srnn-confidence-calibration/v1';
export const WG_SRNN_STRATEGY_COMPARISON_SCHEMA='wg-srnn-strategy-comparison/v1';
export const WG_SRNN_RECONSIDERATION_SCHEMA='wg-srnn-reconsideration-context/v1';
export const WG_SRNN_REFLECTION_AGENDA_SCHEMA='wg-srnn-reflection-agenda/v1';

export const WG_SRNN_CONFIDENCE_CALIBRATION_PROFILE='WG-SRNN-CONFIDENCE-CALIBRATION/1';
export const WG_SRNN_STRATEGY_COMPARISON_PROFILE='WG-SRNN-STRATEGY-COMPARISON/1';
export const WG_SRNN_RECONSIDERATION_PROFILE='WG-SRNN-RECONSIDERATION/1';
export const WG_SRNN_REFLECTION_AGENDA_PROFILE='WG-SRNN-REFLECTION-AGENDA/1';

const AUTHORITY_PROFILE=Object.freeze({
  truth_authority:false,promotion_authority:false,learning_authority:false,
  self_model_write_authority:false,selection_authority:false,execution_authority:false,
});

function clamp01(value,fallback=0){const n=Number(value);return Number.isFinite(n)?Math.max(0,Math.min(1,n)):fallback;}
function text(value,max=4096){const s=String(value??'').trim();return s?s.slice(0,max):'';}
function conceptKey(row){return text(row?.conceptKey??row?.metadata?.concept_key??row?.metadata?.conceptKey??row?.capability,512);}
function actionKey(row){return text(row?.proposedAction??row?.proposed_action??row?.strategyId??row?.strategy_id,4096);}
function directiveId(row){return text(row?.directiveId??row?.directive_id,256);}
function directiveDigest(row){return text(row?.directiveDigest??row?.directive_digest,256);}
function outcomeObserved(status){
  const s=text(status,64).toLowerCase();
  if(['confirmed','succeeded','success','successful','ok','passed'].includes(s))return 1;
  if(['contradicted','failed','failure','error'].includes(s))return 0;
  return null;
}
function outcomeGroup(row,assessmentsByDigest){
  const direct=text(row?.observer?.provenanceGroup??row?.observer?.provenance_group??row?.observerProvenanceGroup,256);
  if(direct)return direct;
  const assessment=assessmentsByDigest.get(text(row?.assessmentDigest??row?.assessment_digest,256));
  return text(assessment?.assessor?.provenanceGroup??assessment?.assessor?.provenance_group??assessment?.assessorProvenanceGroup,256);
}
function finiteConfidence(row){
  const n=Number(row?.baseConfidence??row?.base_confidence??row?.confidence);
  return Number.isFinite(n)&&n>=0&&n<=1?n:null;
}
function normalizedInputs({directives=[],stages=null}={}){
  const dirs=Array.isArray(directives)?directives:[];
  const outcomes=Array.isArray(stages?.outcomes)?stages.outcomes:[];
  const assessments=Array.isArray(stages?.assessments)?stages.assessments:[];
  const byDigest=new Map(dirs.map(row=>[directiveDigest(row),row]).filter(([key])=>key));
  const assessmentsByDigest=new Map(assessments.map(row=>[text(row?.witnessDigest??row?.digest,256),row]).filter(([key])=>key));
  const latest=new Map();
  for(const outcome of outcomes){
    const observed=outcomeObserved(outcome?.status);if(observed==null)continue;
    const origin=byDigest.get(text(outcome?.directiveDigest??outcome?.directive_digest,256));if(!origin)continue;
    const group=outcomeGroup(outcome,assessmentsByDigest);if(!group)continue;
    const conf=finiteConfidence(origin);if(conf==null)continue;
    const id=directiveId(origin)||directiveDigest(origin);if(!id)continue;
    const key=`${group}\u0000${id}`;
    const order=[Number(outcome?.sequence??outcome?.createdAt??outcome?.created_at_ms??0)||0,text(outcome?.witnessDigest??outcome?.digest,256)];
    const prev=latest.get(key);if(prev&&((prev.order[0]>order[0])||(prev.order[0]===order[0]&&prev.order[1]>=order[1])))continue;
    latest.set(key,{origin,outcome,group,confidence:conf,observed,order});
  }
  return{directives:dirs,outcomes,assessments,latest:[...latest.values()]};
}
function aggregate(values){
  const grouped=new Map();
  for(const row of values){const list=grouped.get(row.group)||[];list.push(row);grouped.set(row.group,list);}
  let episodes=0,bias=0,brier=0,confidence=0,success=0;
  for(const rows of grouped.values()){
    episodes+=rows.length;let gb=0,gbr=0,gc=0,gs=0;
    for(const row of rows){const err=row.confidence-row.observed;gb+=err;gbr+=err*err;gc+=row.confidence;gs+=row.observed;}
    const n=rows.length;bias+=gb/n;brier+=gbr/n;confidence+=gc/n;success+=gs/n;
  }
  const groups=grouped.size;
  return{terminal_episode_count:episodes,independent_group_count:groups,balanced_prediction_bias:groups?bias/groups:0,balanced_brier_score:groups?brier/groups:0,balanced_mean_stated_confidence:groups?confidence/groups:0,balanced_observed_success_rate:groups?success/groups:0};
}
function authorityFields(authority){return{proposal_confidence_override:null,self_model_patch:null,recommended_action:null,action_override:null,selection_authority:false,truth_authority:false,promotion_authority:false,learning_authority:false,self_model_write_authority:false,authority,authority_profile:{...AUTHORITY_PROFILE}};}

export function wgSrnnConfidenceCalibrationContext(directive,{directives=[],stages=null,minimumIndependentGroups=2,biasThreshold=.25,brierThreshold=.25}={}){
  if(!directive)throw new TypeError('directive is required');
  const required=Math.max(2,Math.floor(Number(minimumIndependentGroups)||2)),biasLimit=clamp01(biasThreshold,.25),brierLimit=clamp01(brierThreshold,.25);
  const concept=conceptKey(directive),action=actionKey(directive),input=normalizedInputs({directives,stages});
  const rows=input.latest.filter(row=>conceptKey(row.origin)===concept&&actionKey(row.origin)===action);
  const a=aggregate(rows);let state;
  if(!concept||!action)state='undeclared-pattern';
  else if(a.independent_group_count<required)state='insufficient-independent-history';
  else if(a.balanced_prediction_bias>=biasLimit)state='historically-overconfident';
  else if(a.balanced_prediction_bias<=-biasLimit)state='historically-underconfident';
  else if(a.balanced_brier_score<=brierLimit)state='roughly-calibrated';
  else state='high-error-mixed';
  return{schema:WG_SRNN_CONFIDENCE_CALIBRATION_SCHEMA,profile_id:WG_SRNN_CONFIDENCE_CALIBRATION_PROFILE,target_directive_id:directiveId(directive),concept_key:concept,pattern_action:action,...a,minimum_independent_groups:required,bias_threshold:biasLimit,brier_threshold:brierLimit,calibration_state:state,aggregation:'equal-weight-mean-per-outcome-independence-group',included_terminal_statuses:['failed','succeeded'],...authorityFields('derived-confidence-calibration-not-confidence-control'),authority:false};
}


export function wgSrnnStrategyComparisonContext(directive,{directives=[],stages=null,minimumIndependentGroups=2,supportThreshold=.75,actionLimit=12}={}){
  if(!directive)throw new TypeError('directive is required');
  const required=Math.max(2,Math.floor(Number(minimumIndependentGroups)||2)),threshold=clamp01(supportThreshold,.75),limit=Math.max(1,Math.min(64,Math.floor(Number(actionLimit)||12)));
  const concept=conceptKey(directive),currentAction=actionKey(directive),input=normalizedInputs({directives,stages});
  const byAction=new Map();
  for(const row of input.latest){if(conceptKey(row.origin)!==concept)continue;const action=actionKey(row.origin);if(!action)continue;const rows=byAction.get(action)||[];rows.push(row);byAction.set(action,rows);}
  const items=[];
  for(const [action,rows] of byAction){const a=aggregate(rows);let evidence_state;if(a.independent_group_count<required)evidence_state='insufficient-independent-history';else if(a.balanced_observed_success_rate>=threshold)evidence_state='historically-supported';else if(a.balanced_observed_success_rate<=1-threshold)evidence_state='historically-contradicted';else evidence_state='mixed-or-uncertain';items.push({action,is_current_action:action===currentAction,...a,evidence_state,authority:'historical-comparison-only'});}
  items.sort((a,b)=>(a.is_current_action?0:1)-(b.is_current_action?0:1)||a.action.localeCompare(b.action));
  const visible=items.slice(0,limit),current=items.find(row=>row.is_current_action)||null;
  return{schema:WG_SRNN_STRATEGY_COMPARISON_SCHEMA,profile_id:WG_SRNN_STRATEGY_COMPARISON_PROFILE,target_directive_id:directiveId(directive),concept_key:concept,current_action:currentAction,historical_action_count:items.length,visible_action_count:visible.length,omitted_action_count:Math.max(0,items.length-visible.length),items:visible,current_action_summary:current,minimum_independent_groups:required,support_threshold:threshold,aggregation:'equal-weight-mean-per-action-outcome-independence-group',ordering:'current-action-first-then-lexical-not-quality-ranking',included_terminal_statuses:['failed','succeeded'],...authorityFields('derived-strategy-comparison-not-action-selection'),authority:false};
}

export function wgSrnnReconsiderationContext(directive,{directives=[],stages=null,minimumIndependentGroups=2,supportThreshold=.75,biasThreshold=.25,brierThreshold=.25}={}){
  const strategies=wgSrnnStrategyComparisonContext(directive,{directives,stages,minimumIndependentGroups,supportThreshold,actionLimit:64});
  const confidence=wgSrnnConfidenceCalibrationContext(directive,{directives,stages,minimumIndependentGroups,biasThreshold,brierThreshold});
  const current=strategies.current_action_summary||{},currentState=current.evidence_state||'insufficient-independent-history',confidenceState=confidence.calibration_state||'insufficient-independent-history';
  const alternatives=(strategies.items||[]).filter(row=>!row.is_current_action&&row.evidence_state==='historically-supported');const reasons=[];
  if(currentState==='historically-contradicted')reasons.push('current-action-historically-contradicted');else if(currentState==='mixed-or-uncertain')reasons.push('current-action-history-mixed');else if(currentState==='insufficient-independent-history')reasons.push('current-action-insufficient-independent-history');
  if(confidenceState==='historically-overconfident')reasons.push('current-confidence-historically-overconfident');else if(confidenceState==='historically-underconfident')reasons.push('current-confidence-historically-underconfident');else if(confidenceState==='high-error-mixed')reasons.push('current-confidence-high-error-mixed');else if(['insufficient-independent-history','undeclared-pattern'].includes(confidenceState))reasons.push('current-confidence-insufficient-independent-history');
  if(alternatives.length)reasons.push('independently-supported-alternative-exists');
  const contradicted=currentState==='historically-contradicted',overconfident=confidenceState==='historically-overconfident',mixed=currentState==='mixed-or-uncertain'||confidenceState==='high-error-mixed',bothInsufficient=currentState==='insufficient-independent-history'&&['insufficient-independent-history','undeclared-pattern'].includes(confidenceState);
  let state;if(contradicted||(overconfident&&alternatives.length))state='reconsideration-warranted';else if(bothInsufficient&&!alternatives.length)state='insufficient';else if(overconfident||mixed||confidenceState==='historically-underconfident'||alternatives.length)state='caution';else state='stable';
  return{schema:WG_SRNN_RECONSIDERATION_SCHEMA,profile_id:WG_SRNN_RECONSIDERATION_PROFILE,target_directive_id:directiveId(directive),state,reason_codes:reasons.slice(0,8),current_action_evidence_state:currentState,confidence_calibration_state:confidenceState,supported_alternative_count:alternatives.length,reassessment_candidate:state==='reconsideration-warranted',reassessment_authority:'candidate-only-not-command',recommended_action:null,action_override:null,proposal_confidence_override:null,automatic_action:false,selection_authority:false,truth_authority:false,promotion_authority:false,learning_authority:false,self_model_write_authority:false,authority:'derived-reconsideration-signal-not-command',authority_profile:{...AUTHORITY_PROFILE}};
}

function agendaItem(kind,question,{targetAction='',reasonCodes=[]}={}){return{kind,question:text(question,4096),target_action:text(targetAction,4096),reason_codes:(Array.isArray(reasonCodes)?reasonCodes:[]).map(v=>text(v,256)).filter(Boolean).slice(0,8),requested_witness_role:'independent-semantic-assessor',requested_assessor:'wg-sfm',response_expected:'witnessed-semantic-assessment',authority:'assessment-request-candidate-only',execution_authority:false,selection_authority:false,truth_authority:false};}
export function wgSrnnReflectionAgendaContext(directive,{directives=[],stages=null,itemLimit=4,minimumIndependentGroups=2,supportThreshold=.75,biasThreshold=.25,brierThreshold=.25}={}){
  const limit=Math.max(1,Math.min(12,Math.floor(Number(itemLimit)||4))),reconsideration=wgSrnnReconsiderationContext(directive,{directives,stages,minimumIndependentGroups,supportThreshold,biasThreshold,brierThreshold}),strategies=wgSrnnStrategyComparisonContext(directive,{directives,stages,minimumIndependentGroups,supportThreshold,actionLimit:12});
  const state=reconsideration.state,reasons=reconsideration.reason_codes||[],currentAction=actionKey(directive),alternatives=(strategies.items||[]).filter(row=>!row.is_current_action&&row.evidence_state==='historically-supported'),items=[];
  if(state==='reconsideration-warranted'){
    items.push(agendaItem('reassess-current-action','Given the witnessed outcomes and prior semantic evidence, is the current proposed action still justified?',{targetAction:currentAction,reasonCodes:reasons}));
    for(const alt of alternatives){if(items.length>=limit)break;items.push(agendaItem('compare-alternative','Does independent semantic evidence support comparing this historically successful alternative against the current proposal, without selecting it automatically?',{targetAction:alt.action,reasonCodes:['independently-supported-alternative-exists']}));}
  }else if(state==='caution'){
    items.push(agendaItem('collect-independent-evidence','What additional independent evidence would resolve the mixed or calibration-uncertain history for the current action?',{targetAction:currentAction,reasonCodes:reasons}));
    const confidenceReasons=reasons.filter(code=>String(code).includes('confidence'));if(confidenceReasons.length&&items.length<limit)items.push(agendaItem('reassess-confidence','Is the stated confidence for the current proposal semantically justified by the available witnessed evidence?',{targetAction:currentAction,reasonCodes:confidenceReasons}));
  }else if(state==='insufficient')items.push(agendaItem('collect-independent-outcome-evidence','What independent outcome evidence is required before this proposal can be meaningfully self-evaluated?',{targetAction:currentAction,reasonCodes:reasons}));
  const visible=items.slice(0,limit);return{schema:WG_SRNN_REFLECTION_AGENDA_SCHEMA,profile_id:WG_SRNN_REFLECTION_AGENDA_PROFILE,target_directive_id:directiveId(directive),agenda_state:state,item_count:visible.length,items:visible,item_limit:limit,omitted_item_count:Math.max(0,items.length-visible.length),reconsideration_reason_codes:reasons.slice(0,8),recommended_action:null,action_override:null,proposal_confidence_override:null,automatic_execution:false,execution_authority:false,selection_authority:false,truth_authority:false,promotion_authority:false,learning_authority:false,self_model_write_authority:false,authority:'derived-reflection-agenda-for-independent-assessment-only',authority_profile:{...AUTHORITY_PROFILE}};
}

export const confidence_calibration_context=wgSrnnConfidenceCalibrationContext;
export const strategy_comparison_context=wgSrnnStrategyComparisonContext;
export const reconsideration_context=wgSrnnReconsiderationContext;
export const reflection_agenda_context=wgSrnnReflectionAgendaContext;
