import { WitnessGate } from './core/gates.js';
import { WitnessLedger } from './core/witness.js';
import { RecurrentCore } from './core/recurrent.js';
import { WitnessSFM, WG_SFM_SCHEMA, WG_SFM_MODEL_ID, WG_SFM_TRANSPARENT_WITNESS_TYPES } from './core/witness-sfm.js';
import { normalizeSfmSnapshot, sfmTargetCompatibility, toPythonSfmSnapshot, toJsSfmSnapshot, normalizeSfmProposal, normalize_snapshot, target_compatibility, to_python_snapshot, to_js_snapshot, normalize_proposal, projectSfmInterchangeFixtureManifest, digestSfmInterchangeFixtureManifest, verifySfmInterchangeFixtureManifest, verifySfmInterchangeProjection, project_sfm_fixture_manifest, digest_sfm_fixture_manifest, verify_sfm_fixture_manifest, verify_sfm_interchange_projection, digestSfmInterchangeValue, WG_SFM_INTERCHANGE_SCHEMA, WG_SFM_PROPOSAL_INTERCHANGE_SCHEMA, WG_SFM_CONTRACT_SCHEMA, WG_SFM_JS_SHARED_SCHEMA, WG_SFM_JS_SHARED_MODEL_ID, WG_SFM_PY_SHARED_SCHEMA, WG_SFM_PY_SHARED_MODEL_ID, WG_SFM_PY_FAST_SCHEMA, WG_SFM_PY_FAST_MODEL_ID, WG_SFM_CANONICAL_OPERATIONS, WG_SFM_JS_LEGACY_V070_OPERATIONS, WG_SFM_AUTHORITY_PROFILE, WG_SFM_INTERCHANGE_PROFILE, WG_SFM_INTERCHANGE_FIXTURE_MANIFEST_SCHEMA, WG_SFM_INTERCHANGE_FIXTURE_VERIFICATION_SCHEMA, WG_SFM_INTERCHANGE_VERIFICATION_SCHEMA, WGSFMInterchangeError } from './core/witness-sfm-interchange.js';
import { WitnessGatedSelfReferentialNeuralNetwork, WG_SRNN_SCHEMA, WG_SRNN_DIRECTIVE_SCHEMA, WG_SRNN_COMMITMENT_SCHEMA } from './core/witness-srnn.js';
import { wgSrnnConfidenceCalibrationContext, wgSrnnStrategyComparisonContext, wgSrnnReconsiderationContext, wgSrnnReflectionAgendaContext, confidence_calibration_context, strategy_comparison_context, reconsideration_context, reflection_agenda_context, WG_SRNN_CONFIDENCE_CALIBRATION_SCHEMA, WG_SRNN_STRATEGY_COMPARISON_SCHEMA, WG_SRNN_RECONSIDERATION_SCHEMA, WG_SRNN_REFLECTION_AGENDA_SCHEMA } from './core/witness-srnn-reflection.js';
import { normalizeSrnnInterchangeValue, projectSrnnInterchangeRecord, digestSrnnInterchangeRecord, srnnInterchangeLineage, projectSrnnInterchangeFixtureManifest, digestSrnnInterchangeFixtureManifest, verifySrnnInterchangeFixtureManifest, verifySrnnInterchangeProjection, normalizeSrnnRuntimeInterchangeRecord, srnnRuntimeInterchangeLineageKey, srnnRuntimeImportRequirements, normalize_record, lineage_key, import_requirements, normalize_runtime_interchange_record, runtime_interchange_lineage_key, runtime_import_requirements, normalize_interchange_value, project_interchange_record, digest_interchange_record, interchange_lineage, project_fixture_manifest, digest_fixture_manifest, verify_fixture_manifest, verify_interchange_projection, WG_SRNN_INTERCHANGE_PROFILE, WG_SRNN_INTERCHANGE_PROJECTION_SCHEMA, WG_SRNN_INTERCHANGE_LINEAGE_SCHEMA, WG_SRNN_INTERCHANGE_FIXTURE_MANIFEST_SCHEMA, WG_SRNN_INTERCHANGE_VERIFICATION_SCHEMA, WG_SRNN_RUNTIME_INTERCHANGE_SCHEMA, WG_SRNN_IMPORT_REQUIREMENTS_SCHEMA, WG_SRNN_RUNTIME_INTERCHANGE_NO_AUTHORITY, WG_SRNN_INTERCHANGE_AUTHORITY_PROFILE, WGSRNNInterchangeError } from './core/witness-srnn-interchange.js';
import { evaluateSrnnReleaseGate, evaluate_release_gate, WG_SRNN_RELEASE_GATE_PROFILE, WG_SRNN_REQUIRED_TRACKED_PATHS, WG_SRNN_CRITICAL_PATHS, WG_SRNN_RELEASE_GATE_AUTHORITY_PROFILE, WGSRNNReleaseGateError } from './core/witness-srnn-release-gate.js';
import { witnessWgStackCapabilityHandshake, inspectWgStackCapabilityHandshakeHistory } from './core/witness-stack-capability.js';
import { planWgStackPortableImport, witnessWgStackPortableImportPlan } from './core/witness-stack-portable-import.js';
import { stageWgStackPortableImport, witnessWgStackPortableStage } from './core/witness-stack-portable-stage.js';
import { assessWgStackPortableFamilyAdmission, witnessWgStackPortableFamilyAdmission } from './core/witness-stack-portable-admission.js';
import { evaluateWgStackPortableFamilyGate, witnessWgStackPortableFamilyGateDecision } from './core/witness-stack-portable-gate-decision.js';
import { witnessWgStackPortableApplicationPermit, applyWgStackPortableFamilyTransaction, applyWgStackPortableStackTransaction, inspectWgStackPortableStackRecovery, listWgStackPortableOpenTransactions, reconcileWgStackPortableStackRecovery, reconcileWgStackPortableStackRecoveryChain, withWgStackPortableStackMutationLease, digestWgStackPortableLiveStackState, WG_STACK_PORTABLE_APPLICATION_SCHEMA, WG_STACK_PORTABLE_APPLICATION_PROFILE, WG_STACK_PORTABLE_APPLICATION_PERMIT_SCHEMA, WG_STACK_PORTABLE_APPLICATION_PERMIT_WITNESS_TYPE, WG_STACK_PORTABLE_APPLICATION_WITNESS_SCHEMA, WG_STACK_PORTABLE_APPLICATION_ROLLBACK_WITNESS_SCHEMA, WG_STACK_PORTABLE_STACK_APPLICATION_SCHEMA, WG_STACK_PORTABLE_STACK_APPLICATION_PROFILE, WG_STACK_PORTABLE_STACK_APPLICATION_WITNESS_SCHEMA, WG_STACK_PORTABLE_STACK_APPLICATION_ROLLBACK_WITNESS_SCHEMA, WG_STACK_PORTABLE_STACK_APPLICATION_STARTED_WITNESS_SCHEMA, WG_STACK_PORTABLE_STACK_RECOVERY_SCHEMA, WG_STACK_PORTABLE_STACK_RECOVERY_CHAIN_SCHEMA, WG_STACK_PORTABLE_RECOVERY_READINESS_ASSESSMENT_SCHEMA, WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY, WGStackPortableApplicationError, digestWgStackPortableApplication, digestWgStackPortableStackApplication } from './core/witness-stack-portable-application.js';
import { WGSRNNCanaryScope, WGSRNNCanaryValidator, WGSRNNCanaryValidationError, consensusCollapseProbe, dependencyCausalReport, adversarialProbe, consensus_collapse_probe, dependency_causal_report, adversarial_probe, WG_SRNN_CANARY_PROFILE, WG_SRNN_CANARY_AUTHORITY_PROFILE } from './core/witness-srnn-canary.js';
import { collapseSrnnArbitrationObservations, compactSrnnConsensusContext, srnnConsensusToAssessmentInputs, WG_SRNN_ARBITRATION_PROFILE, WG_SRNN_ARBITRATION_AUTHORITY_PROFILE, WG_SRNN_ARBITRATION_COLLAPSE_SCHEMA, WG_SRNN_COMPACT_CONSENSUS_SCHEMA } from './core/witness-srnn-arbitration.js';
import { buildWgSfmAssessmentRequests, wgSfmAssessmentClaim, compactWgSfmConsensus, wgSfmSemanticAssessmentResponse, sealWgSfmAssessmentFromConsensus, build_assessment_requests, assessment_claim, semantic_assessment_response, seal_assessment_from_consensus, WG_SRNN_SFM_ASSESSMENT_REQUEST_SCHEMA, WG_SRNN_SFM_ASSESSMENT_REQUEST_SET_SCHEMA, WG_SFM_SEMANTIC_ASSESSMENT_RESPONSE_SCHEMA, WG_SFM_SEALED_SEMANTIC_ASSESSMENT_SCHEMA, WG_SFM_REFLECTION_CLAIM_PREDICATE } from './core/witness-sfm-assessor.js';
import { wgSrnnSelfCalibrationContext, wgSrnnDependencyReflectionContext, wgSrnnEpisodicPostureSummary, wgSrnnEpisodicSelfSummaryContext, wgSrnnCommitmentSelfReferenceContext, wgSrnnResumeContext, self_calibration_context, dependency_reflection_context, episodic_self_summary_context, commitment_self_reference_context, resume_context } from './core/witness-srnn-resume.js';
import { WitnessGatedSelfReferentialStages, WG_SRNN_STAGES_SCHEMA, WG_SRNN_SEMANTIC_ASSESSMENT_SCHEMA, WG_SRNN_OUTCOME_WITNESS_SCHEMA, WG_SRNN_TEMPORAL_CREDIT_SCHEMA, WG_SRNN_LESSON_CANDIDATE_SCHEMA, WG_SRNN_CAUSAL_GRAPH_SCHEMA, WG_SRNN_CAUSAL_TRACE_SCHEMA, WG_SRNN_LESSON_EXPLANATION_SCHEMA, WG_SRNN_INTEGRITY_REPORT_SCHEMA, WG_SRNN_INTEGRITY_MONITOR_SCHEMA, WG_SRNN_INTEGRITY_TELEMETRY_SCHEMA, WG_SRNN_STAGE_WITNESS_TYPES, WG_SRNN_LESSON_STATE_SCHEMA, WG_SRNN_LESSON_PROMOTED_SCHEMA, WG_SRNN_LESSON_EVALUATED_SCHEMA, WG_SRNN_LESSON_DEMOTED_SCHEMA, WG_SRNN_LESSON_SUPERSEDED_SCHEMA, WG_SRNN_LESSON_WITNESS_TYPES, wgSrnnLessonId, wgSrnnLessonReliability, projectWgSrnnLesson } from './core/witness-srnn-stages.js';
import { DUO_STATE_SCHEMA, DUO_BACKEND_STATE_SCHEMA, DUO_RESIDUE_SCHEMA, DUO_STATE_NAMES, DUO_STATE, duoState, isDuoState, duoStateName, backendState, duoIndexFromBackend, backendIndexFromDuo, assertDuoIndex, duoResidueSignature, duoResidueKey } from './core/duo-runtime.js';
import { StrategyRouter } from './core/router.js';
import { WitnessSemanticLayer, RouteGraphScorer } from './core/route-graph.js';
import { SEMANTIC_TRANSPARENT_WITNESS_TYPES } from './core/witness-semantic.js';
import { WitnessWorkingMemory } from './core/witness-working-memory.js';
import { WitnessSemanticHeads, SEMANTIC_OPERATIONS } from './core/witness-semantic-heads.js';
import { LearningAuthority } from './core/learning-authority.js';
import { WitnessPlanContinuationTracker } from './core/witness-plan-continuation.js';
import { WitnessEvidenceSessionTracker } from './core/witness-evidence-session.js';
import { EvidenceResolutionController } from './core/evidence-resolution-controller.js';
import { BrowserRuntime } from './runtime/browser-runtime.js';
import { SmallModelRuntimePolicy } from './runtime/small-model-policy.js';
import { MemoryStore } from './storage/memory-store.js';
import { IndexedDBStore } from './storage/indexeddb-store.js';
import { BrowserAuthority, PolicyBus, assertBrowserAuthorityProof } from './sync/authority.js';
import { digest } from './core/utils.js';
import { RouteHealth } from './core/route-health.js';
import { DeferredLearningQueue } from './runtime/deferred-learning.js';
import { CreditGraph } from './core/credit-graph.js';
import { InvestigationQueue } from './core/investigation-queue.js';
import { KnowledgeCorpus, SecurityFaculty, BrowserSecurityFaculty, SecurityMonitor, AdPolicyFaculty, LexiconFaculty, LexicalFaculty, LanguageFaculty, TranslationFaculty, MathFaculty, createBrowserFaculties } from './faculties/index.js';
import { createPublisherIframeStrategy, SAFE_IFRAME_PROFILES } from './adapters/publisher-preview.js';
import { SandboxPolicy, SandboxManager, createWorkerRpcExecutor, createContainer2WasmExecutor, CONTAINER2WASM_NOTES, FirstPartyImageRegistry, APPROVED_DISTRIBUTION_LICENSES, PROJECT_DISTRIBUTION_LICENSE, createNativeWasmExecutor } from './sandbox/index.js';
import { EvidenceObserverRegistry, APPROVED_OBSERVER_LICENSES, SPECIALIST_OBSERVER_CATALOG, OBSERVER_RUNTIME_CATALOG, CURRICULUM_SOURCE_CATALOG } from './observers/index.js';
import { WitnessVectorStore, HashFeatureEmbedder, FunctionEmbedder, HnswIndex, HnswWitnessVectorStore, ShardedWitnessVectorStore, TransformersJsEmbedder } from './vector/index.js';
import { WitnessMemory, AutoRetentionController, WitnessEpisodePatternIndex, EPISODE_PATTERN_TOKEN_VERSION, episodePatternTokensFromEpisode, episodePatternTokensFromSemantic } from './memory/index.js';
import { projectWitnessEpisodeHint, buildWitnessEpisodeGuidance, episodeStrategyAdjustment, compareEpisodeGuidanceToHeads, buildWitnessEpisodeTransitionPlan, episodePlanStrategyAdjustment, summarizeEpisodePlanBranches, selectWitnessEpisodeTransitionPlanForStrategy, assessWitnessEpisodeBranchPosterior, assessWitnessEpisodeTransitionPlan } from './core/witness-episode-guidance.js';
import { SelfTrainingCoordinator, WitnessReplayDataset, WitnessReplayBackfillTrainer, WitnessSfmReplayTrainer, SelfManagementController } from './training/index.js';

function wgSrnnGoalFromContext(context={}) {
  for (const key of ['goal','objective','commitment','longLivedGoal','taskGoal']) {
    const value=context?.[key];
    if (typeof value==='string'&&value.trim()) return value.trim().slice(0,768);
    if (value&&typeof value==='object') {
      const nested=value.goal??value.objective??value.text??value.description;
      if (typeof nested==='string'&&nested.trim()) return nested.trim().slice(0,768);
    }
  }
  return null;
}
function wgSrnnShouldCommit(context={},goal=null) {
  if(!goal)return false;
  return context?.goal!=null||context?.objective!=null||context?.commitment!=null||context?.longLivedGoal!=null||context?.persistGoal===true||context?.internalCommitment===true;
}
function wgSrnnExpectedOutcome(semantic={}) {
  const expectedNextType=semantic?.expectedWitnessDelta?.expectedNextType??semantic?.chainContinuation?.type??null;
  const feasible=semantic?.feasibility==null?null:Number(semantic.feasibility)>=0.5;
  return {expectedNextType,targetHint:semantic?.targetHint??null,operation:semantic?.nextOperation??null,feasible};
}

function compactWgSrnnConsensus(value){
  if(!value||typeof value!=='object')return null;
  return{score:Number(value.score||0),threshold:Number(value.threshold||0),agreement:Number(value.agreement||0),sourceDiversity:Number(value.sourceDiversity||0),independentEvidenceCount:Number(value.independentEvidenceCount??value.sourceCount??0),validatedEvidenceCount:Number(value.validatedEvidenceCount||0),conflictingEvidenceCount:Number(value.conflictingEvidenceCount||0),meanSourceReliability:Number(value.meanSourceReliability??.5),representedEvidenceFamilies:(value.representedEvidenceFamilies||[]).slice(0,8),claimSupport:(value.claimSupport||[]).slice(0,8).map(row=>({claimKey:row?.claimKey||null,independentValidatedSources:Number(row?.independentValidatedSources||0),representedEvidenceFamilies:(row?.representedEvidenceFamilies||[]).slice(0,6),supported:Boolean(row?.supported)})),authority:false};
}
function wgSrnnAssessmentSpec({semantic=null,wgSfm=null,evidenceWitnessDigests=[]}={}){
  const evidence=[...new Set((evidenceWitnessDigests||[]).filter(Boolean))].slice(0,24);if(!evidence.length)return null;
  const consensus=compactWgSrnnConsensus(semantic?.evidenceSufficiency),families=(consensus?.representedEvidenceFamilies||[]).filter(Boolean);
  if(consensus&&consensus.independentEvidenceCount>0&&families.length){
    const agreement=Math.max(0,Math.min(1,Number(consensus.agreement||0))),score=Math.max(0,Math.min(1,Number(consensus.score||0))),threshold=Math.max(0,Math.min(1,Number(consensus.threshold||0))),conflicts=Math.max(0,Number(consensus.conflictingEvidenceCount||0));
    const verdict=conflicts>0&&agreement<.45?'contradict':(conflicts>0?'mixed':(score>=threshold&&agreement>=.5?'support':'uncertain'));
    return{assessorIdentity:'evidence-consensus',assessorProvenanceGroup:'evidence-consensus',verdict,confidence:Math.max(.05,Math.min(.95,.55*score+.45*agreement)),evidenceWitnessDigests:evidence,provenanceGroups:families,consensusSummary:consensus};
  }
  if(wgSfm){
    const expected=semantic?.nextOperation||null,observed=wgSfm?.operation||null,verdict=expected&&observed?(expected===observed?'support':'contradict'):'uncertain';
    return{assessorIdentity:WG_SFM_MODEL_ID,assessorProvenanceGroup:'wg-sfm',verdict,confidence:Math.max(.05,Math.min(.95,Number(wgSfm?.confidence??.5))),evidenceWitnessDigests:evidence,provenanceGroups:['wg-sfm'],consensusSummary:null};
  }
  return null;
}
function compactWgSrnnStages(stages){
  if(!stages)return null;return{schema:stages.schema||'xavi-wg-srnn-stages-context/v1',assessments:(stages.assessments||[]).slice(-3).map(row=>({witnessDigest:row.witnessDigest||null,directiveDigest:row.directiveDigest||null,verdict:row.verdict||null,confidence:Number(row.confidence||0),provenanceGroups:(row.provenanceGroups||[]).slice(0,6),authority:false})),outcomes:(stages.outcomes||[]).slice(-3).map(row=>({witnessDigest:row.witnessDigest||null,directiveDigest:row.directiveDigest||null,status:row.status||null,authority:false})),credits:(stages.credits||[]).slice(-3).map(row=>({witnessDigest:row.witnessDigest||null,directiveDigest:row.directiveDigest||null,capability:row.capability||null,strategyId:row.strategyId||null,credit:Number(row.credit||0),provenanceGroups:(row.provenanceGroups||[]).slice(0,6),authority:false})),lessons:(stages.lessons||[]).slice(-3).map(row=>({witnessDigest:row.witnessDigest||null,capability:row.capability||null,strategyId:row.strategyId||null,concept:row.concept||null,creditCount:Number(row.creditCount||0),independentProvenanceGroups:(row.independentProvenanceGroups||[]).slice(0,6),authority:'candidate'})),graph:stages.graph?{verified:Boolean(stages.graph.verified),edgeCount:Number(stages.graph.edges?.length||0),authority:false}:null,authority:false};
}

function srnnAssessmentFromPending(pending,stages){
  const digestValue=pending?.wgSrnnSemanticAssessmentDigest;if(!digestValue)return null;const row=stages?.state?.assessments?.find(item=>item?.witnessDigest===digestValue)||null;if(!row)return{witness:{digest:digestValue},assessment:null,authority:false};return{witness:{digest:digestValue},assessment:{witnessDigest:row.witnessDigest,directiveDigest:row.directiveDigest||null,assessor:row.assessor||null,verdict:row.verdict||null,confidence:Number(row.confidence||0),provenanceGroups:(row.provenanceGroups||[]).slice(0,8),consensusSummary:compactWgSrnnConsensus(row.consensusSummary),authority:false},authority:false};
}

function compactWgSrnnContext(srnn){
  if(!srnn)return null;
  return {schema:srnn.schema||'xavi-wg-srnn-context/v1',currentGoals:(srnn.currentGoals||[]).slice(0,6),commitments:(srnn.commitments||[]).slice(0,6).map(row=>({commitmentId:row.commitmentId||null,goal:row.goal||null,status:row.status||null,authority:false})),directives:(srnn.directives||[]).slice(0,6).map(row=>({directiveDigest:row.directiveDigest||null,goal:row.goal||null,proposedAction:row.proposedAction||null,strategyId:row.strategyId||null,status:row.status||null,authority:false})),outcomes:(srnn.outcomes||[]).slice(0,6).map(row=>({directiveDigest:row.directiveDigest||null,goal:row.goal||null,proposedAction:row.proposedAction||null,status:row.status||null,reward:row.reward??null,authority:false})),strategyAdvice:(srnn.strategyAdvice||[]).slice(0,8).map(row=>({strategyId:row.strategyId||null,capability:row.capability||null,attempts:Number(row.attempts||0),successes:Number(row.successes||0),reliability:Number(row.reliability??.5),meanReward:Number(row.meanReward||0),adjustment:Number(row.adjustment||0),lastCalibrationWitnessDigest:row.lastCalibrationWitnessDigest||null,authority:false})),stages:compactWgSrnnStages(srnn.stages),metrics:srnn.metrics||null,authority:false};
}

function rewardFrom(outcome = {}) {
  if (Number.isFinite(outcome.reward)) return Math.max(-1, Math.min(1, Number(outcome.reward)));
  if (!outcome.ok) return -1;
  const latency = Math.max(0, Number(outcome.latencyMs || 0));
  return Math.max(0.2, 1 - Math.min(0.6, latency / 10000));
}

function compactEvidenceSession(session){if(!session)return null;return{schema:'xavi-witness-evidence-session/v1',id:session.id,keyDigest:session.keyDigest,capability:session.capability,status:session.status,entryCount:Number(session.entryCount||session.entries?.length||0),requiredClaims:(session.requiredClaims||[]).slice(0,8),claimDependencies:(session.claimDependencies||[]).slice(0,8).map(row=>({claimKey:row?.claimKey||null,requires:(row?.requires||[]).slice(0,7)})),lastSufficiency:session.lastSufficiency||null,expiresAt:session.expiresAt||null,authority:false};}


const normalizeEvidenceClaimKey=value=>String(value??'').trim().replace(/\s+/g,' ').slice(0,128).toLowerCase();
function evidenceClaimTargetFromSession(session,context={}){
  if(!session)return null;const required=(session.requiredClaims||[]).map(normalizeEvidenceClaimKey).filter(Boolean).slice(0,8);if(!required.length)return null;
  const entries=Array.isArray(session.entries)?session.entries:[],support=required.map((claimKey,index)=>{const families=new Set(entries.filter(row=>normalizeEvidenceClaimKey(row?.claimKey)===claimKey&&row?.validated===true&&row?.ok!==false&&row?.conflict!==true).map(row=>String(row?.evidenceFamily||row?.modelId||row?.source||'').trim().toLowerCase()).filter(Boolean));return{claimKey,index,independentValidatedSources:families.size,representedEvidenceFamilies:[...families].slice(0,6),covered:families.size>=2};}),covered=new Set(support.filter(row=>row.covered).map(row=>row.claimKey)),depMap=new Map((session.claimDependencies||[]).map(row=>[normalizeEvidenceClaimKey(row?.claimKey),(row?.requires||[]).map(normalizeEvidenceClaimKey).filter(Boolean)]));
  const state=new Map(support.map(row=>{const prerequisites=(depMap.get(row.claimKey)||[]).filter(dep=>required.includes(dep)),unmetPrerequisites=prerequisites.filter(dep=>!covered.has(dep));return[row.claimKey,{...row,prerequisites,unmetPrerequisites,prerequisitesMet:unmetPrerequisites.length===0}];}));
  let dependencyCycle=false;{const visiting=new Set(),done=new Set(),visit=claim=>{if(done.has(claim))return false;if(visiting.has(claim))return true;visiting.add(claim);for(const dep of depMap.get(claim)||[])if(required.includes(dep)&&visit(dep))return true;visiting.delete(claim);done.add(claim);return false;};dependencyCycle=required.some(visit);}
  const explicit=normalizeEvidenceClaimKey(context?.evidenceClaimKey??context?.evidenceClaim);let selected=null,selectionSource='none';if(explicit){selected=state.get(explicit)||{claimKey:explicit,index:-1,independentValidatedSources:0,representedEvidenceFamilies:[],covered:false,prerequisites:[],unmetPrerequisites:[],prerequisitesMet:true};selectionSource='explicit';}else if(!dependencyCycle){selected=[...state.values()].filter(row=>!row.covered&&row.prerequisitesMet).sort((a,b)=>a.independentValidatedSources-b.independentValidatedSources||a.index-b.index)[0]||null;selectionSource=selected?'least-covered-ready':([...state.values()].some(row=>!row.covered)?'blocked-by-prerequisites':'complete');}else selectionSource='dependency-cycle';
  const readyClaimCount=[...state.values()].filter(row=>!row.covered&&row.prerequisitesMet).length,blockedClaimCount=[...state.values()].filter(row=>!row.covered&&!row.prerequisitesMet).length,dependencyCount=[...depMap.values()].reduce((sum,rows)=>sum+rows.length,0);if(selectionSource==='least-covered-ready'&&dependencyCount===0)selectionSource='least-covered-uncovered';
  if(!selected)return{schema:'xavi-evidence-claim-target/v1',claimKey:null,selectionSource,autoSelected:false,requiredClaimCount:required.length,independentValidatedSources:0,representedEvidenceFamilies:[],claimDeficit:selectionSource==='complete'?0:1,dependencyCount,readyClaimCount,blockedClaimCount,dependencyCycle,prerequisites:[],unmetPrerequisites:[],prerequisitesMet:false,authority:false};
  return{schema:'xavi-evidence-claim-target/v1',claimKey:selected.claimKey,selectionSource,autoSelected:selectionSource!=='explicit',requiredClaimCount:required.length,independentValidatedSources:selected.independentValidatedSources,representedEvidenceFamilies:selected.representedEvidenceFamilies,claimDeficit:Math.max(0,2-selected.independentValidatedSources)/2,dependencyCount,readyClaimCount,blockedClaimCount,dependencyCycle,prerequisites:selected.prerequisites||[],unmetPrerequisites:selected.unmetPrerequisites||[],prerequisitesMet:selected.prerequisitesMet!==false,authority:false};
}

function publicCostRegimePersistence(schedule){
  if(!schedule||!Number(schedule.recommendedCostRegimeHysteresisVersion||0))return null;
  const epochVersion=Math.max(0,Number(schedule.recommendedCostRegimeEpochVersion||0));
  return{schema:epochVersion>=1?'xavi-cost-regime-persistence-audit/v2':'xavi-cost-regime-persistence-audit/v1',hysteresisVersion:Number(schedule.recommendedCostRegimeHysteresisVersion||0),confirmed:Boolean(schedule.recommendedCostRegimeConfirmed),confirmedDirection:schedule.recommendedCostRegimeConfirmedDirection||'stable',confirmedConfidence:Number(schedule.recommendedCostRegimeConfirmedConfidence||0),effectiveDetected:Boolean(schedule.recommendedCostRegimeEffectiveDetected),effectiveDirection:schedule.recommendedCostRegimeEffectiveDirection||'stable',transitionCount:Number(schedule.recommendedCostRegimeTransitionCount||0),epochVersion,epochDirection:schedule.recommendedCostRegimeEpochDirection||'stable',epochSamples:Number(schedule.recommendedCostRegimeEpochSamples||0),epochMean:schedule.recommendedCostRegimeEpochMean==null?null:Number(schedule.recommendedCostRegimeEpochMean),epochStdDev:Number(schedule.recommendedCostRegimeEpochStdDev||0),epochStrength:Number(schedule.recommendedCostRegimeEpochStrength||0),epochActive:Boolean(schedule.recommendedCostRegimeEpochActive),epochWeight:Number(schedule.recommendedCostRegimeEpochWeight||0),authority:false};
}

function publicEpisodeTransitionPlan(plan){
  if(!plan)return null;const step=row=>({recordId:row?.recordId??null,witnessDigest:row?.witnessDigest??null,from:row?.from??null,to:row?.to??null,operation:row?.operation??null,targetHint:row?.targetHint??null,strategyId:row?.strategyId??null,confidence:Number(row?.confidence??0),authority:false});
  return{schema:'xavi-witness-episode-transition-plan/v1',continuationId:plan.continuationId??plan.id??null,currentWitnessType:plan.currentWitnessType??null,depth:Number(plan.depth||0),confidence:Number(plan.confidence||0),baseConfidence:plan.baseConfidence==null?null:Number(plan.baseConfidence),ageFactor:plan.ageFactor==null?null:Number(plan.ageFactor),structuralFactor:plan.structuralFactor==null?null:Number(plan.structuralFactor),advanceCount:Number(plan.advanceCount||0),repairCount:Number(plan.repairCount||0),branchSelectionCount:Number(plan.branchSelectionCount||0),branchCount:Number(plan.branchCount??plan.alternatives?.length??0),branchDisagreement:plan.branchDisagreement==null?null:Number(plan.branchDisagreement),branchEntropy:plan.branchEntropy==null?(plan.branchDisagreement==null?null:Number(plan.branchDisagreement)):Number(plan.branchEntropy),branchCalibrationApplied:Boolean(plan.branchCalibrationApplied),branchCalibrationEvidence:Number(plan.branchCalibrationEvidence||0),branchCalibrationHalfLifeMs:plan.branchCalibrationHalfLifeMs==null?null:Number(plan.branchCalibrationHalfLifeMs),basePrimaryProbability:plan.basePrimaryProbability==null?null:Number(plan.basePrimaryProbability),primaryCalibrationReliability:plan.primaryCalibrationReliability==null?null:Number(plan.primaryCalibrationReliability),primaryAdaptiveCalibrationReliability:plan.primaryAdaptiveCalibrationReliability==null?null:Number(plan.primaryAdaptiveCalibrationReliability),primaryCalibrationDrift:plan.primaryCalibrationDrift==null?null:Number(plan.primaryCalibrationDrift),primaryAdaptiveCalibrationWeight:plan.primaryAdaptiveCalibrationWeight==null?null:Number(plan.primaryAdaptiveCalibrationWeight),primaryAdaptiveCalibrationUpdatedAt:plan.primaryAdaptiveCalibrationUpdatedAt==null?null:Number(plan.primaryAdaptiveCalibrationUpdatedAt),primaryEffectiveCalibrationReliability:plan.primaryEffectiveCalibrationReliability==null?null:Number(plan.primaryEffectiveCalibrationReliability),primaryCalibrationAttempts:plan.primaryCalibrationAttempts==null?null:Number(plan.primaryCalibrationAttempts),primaryCalibrationUpdatedAt:plan.primaryCalibrationUpdatedAt==null?null:Number(plan.primaryCalibrationUpdatedAt),primaryCalibrationFreshness:plan.primaryCalibrationFreshness==null?null:Number(plan.primaryCalibrationFreshness),primaryCalibrationEvidenceStrength:plan.primaryCalibrationEvidenceStrength==null?null:Number(plan.primaryCalibrationEvidenceStrength),primaryCalibrationStrength:plan.primaryCalibrationStrength==null?null:Number(plan.primaryCalibrationStrength),primaryProbability:plan.primaryProbability==null?null:Number(plan.primaryProbability),dominantBranchId:plan.dominantBranchId??null,dominantBranchProbability:plan.dominantBranchProbability==null?null:Number(plan.dominantBranchProbability),terminalWitnessType:plan.terminalWitnessType??null,connected:Boolean(plan.connected),steps:(Array.isArray(plan.steps)?plan.steps:[]).slice(0,3).map(step),alternatives:(Array.isArray(plan.alternatives)?plan.alternatives:[]).slice(0,3).map(row=>{const rows=Array.isArray(row?.steps)?row.steps:[];const first=rows[0]||null;return{id:row?.id||null,source:row?.source||null,depth:Number(row?.depth||rows.length||0),confidence:Number(row?.confidence||0),baseProbability:row?.baseProbability==null?null:Number(row.baseProbability),calibrationReliability:row?.calibrationReliability==null?null:Number(row.calibrationReliability),adaptiveCalibrationReliability:row?.adaptiveCalibrationReliability==null?null:Number(row.adaptiveCalibrationReliability),calibrationDrift:row?.calibrationDrift==null?null:Number(row.calibrationDrift),adaptiveCalibrationWeight:row?.adaptiveCalibrationWeight==null?null:Number(row.adaptiveCalibrationWeight),adaptiveCalibrationUpdatedAt:row?.adaptiveCalibrationUpdatedAt==null?null:Number(row.adaptiveCalibrationUpdatedAt),effectiveCalibrationReliability:row?.effectiveCalibrationReliability==null?null:Number(row.effectiveCalibrationReliability),calibrationAttempts:row?.calibrationAttempts==null?null:Number(row.calibrationAttempts),calibrationUpdatedAt:row?.calibrationUpdatedAt==null?null:Number(row.calibrationUpdatedAt),calibrationFreshness:row?.calibrationFreshness==null?null:Number(row.calibrationFreshness),calibrationEvidenceStrength:row?.calibrationEvidenceStrength==null?null:Number(row.calibrationEvidenceStrength),calibrationStrength:row?.calibrationStrength==null?null:Number(row.calibrationStrength),probability:row?.probability==null?null:Number(row.probability),terminalWitnessType:row?.terminalWitnessType??rows.at(-1)?.to??null,firstWitnessDigest:first?.witnessDigest??null,firstRecordId:first?.recordId??null,firstFrom:first?.from??null,firstTo:first?.to??null,firstOperation:first?.operation??null,firstTargetHint:first?.targetHint??null,firstStrategyId:first?.strategyId??null,firstConfidence:Number(first?.confidence??0),remainingTransitionSignature:rows.slice(1,3).map(x=>`${x?.from||''}>${x?.to||''}:${x?.strategyId||''}`).join('|'),authority:false};}),avoidedTransitions:(Array.isArray(plan.avoidedTransitions)?plan.avoidedTransitions:[]).slice(0,3).map(step),authority:false};
}

function publicEvidenceResolutionSchedule(schedule){
  if(!schedule)return null;
  const row=x=>x?{
    strategyId:x.strategyId??null,sourceId:x.sourceId??null,evidenceFamily:x.evidenceFamily??null,evidenceClass:x.evidenceClass??null,familyRepresented:Boolean(x.familyRepresented),familyNovel:Boolean(x.familyNovel),diversityAdjustment:Number(x.diversityAdjustment||0),sourceReliability:x.sourceReliability??null,sourceGlobalReliability:x.sourceGlobalReliability??null,sourceClaimReliability:x.sourceClaimReliability??null,sourceCalibrationScope:x.sourceCalibrationScope??null,sourceCalibrationAttempts:Number(x.sourceCalibrationAttempts||0),costClass:x.costClass??null,
    declaredCostValue:x.declaredCostValue??x.costValue??null,calibratedCostValue:x.calibratedCostValue??null,adaptiveCostValue:x.adaptiveCostValue??null,riskAdjustedCostValue:x.riskAdjustedCostValue??null,
    costCalibrationAttempts:Number(x.costCalibrationAttempts||0),costCalibrationStrength:Number(x.costCalibrationStrength||0),costCalibrationFreshness:x.costCalibrationFreshness==null?1:Number(x.costCalibrationFreshness),
    costObservedMean:x.costObservedMean??null,costObservedStdDev:Number(x.costObservedStdDev||0),costRecentSamples:Number(x.costRecentSamples||0),costRecentMean:x.costRecentMean??null,costRecentStdDev:Number(x.costRecentStdDev||0),
    costRecentOutlierCount:Number(x.costRecentOutlierCount||0),costRecentOutlierRate:Number(x.costRecentOutlierRate||0),costRecentLastWasOutlier:Boolean(x.costRecentLastWasOutlier),
    costRegimeDrift:Number(x.costRegimeDrift||0),costRegimeConfidence:Number(x.costRegimeEffectiveConfidence??x.costRegimeConfidence??0),costRegimeDirection:x.costRegimeEffectiveDirection||x.costRegimeDirection||'stable',costRegimeDetected:Boolean(x.costRegimeEffectiveDetected??x.costRegimeDetected),costRegimeSignal:Number(x.costRegimeSignal||0),costRegimeThreshold:Number(x.costRegimeThreshold||0),costRegimeStrengthBoost:Number(x.costRegimeStrengthBoost||0),
    costRiskMargin:Number(x.costRiskMargin||0),resolutionEfficiency:x.resolutionEfficiency??null,rawResolutionEfficiency:x.rawResolutionEfficiency??null,resolutionEfficiencyAttempts:Number(x.resolutionEfficiencyAttempts||0),resolutionProductiveSteps:Number(x.resolutionProductiveSteps||0),resolutionMeanGain:Number(x.resolutionMeanGain||0),resolutionMeanGainPerCost:Number(x.resolutionMeanGainPerCost||0),resolutionAdjustment:Number(x.resolutionAdjustment||0),basePriority:Number(x.basePriority||0),baseClosureProbability:x.baseClosureProbability??x.closureProbability??null,closureProbability:x.closureProbability??null,closureEvidenceStrength:Number(x.closureEvidenceStrength||0),oneStepClosable:Boolean(x.oneStepClosable),expectedPostClaimDeficit:x.expectedPostClaimDeficit??null,closureSchedulingProbability:x.closureSchedulingProbability??null,
    expectedClosureCost:x.expectedClosureCost??null,calibratedExpectedClosureCost:x.calibratedExpectedClosureCost??null,adaptiveExpectedClosureCost:x.adaptiveExpectedClosureCost??null,riskAdjustedExpectedClosureCost:x.riskAdjustedExpectedClosureCost??null,
    closureCostEfficiency:x.closureCostEfficiency??null,closureAdjustment:Number(x.closureAdjustment||0),closureCostAdjustment:Number(x.closureCostAdjustment||0),priority:Number(x.priority||0),authority:false,
  }:null;
  return{
    schema:schedule.schema??'xavi-evidence-resolution-schedule/v1',claimKey:schedule.claimKey??null,dependencyAware:Boolean(schedule.dependencyAware),actionable:Boolean(schedule.actionable),reason:schedule.reason??null,strength:Number(schedule.strength||0),claimDeficit:Number(schedule.claimDeficit||0),
    sufficientlyObservedEvidenceCount:Number(schedule.sufficientlyObservedEvidenceCount||0),unexploredEvidenceCount:Number(schedule.unexploredEvidenceCount||0),lowExpectedValueCount:Number(schedule.lowExpectedValueCount||0),marginalValueStop:Boolean(schedule.marginalValueStop),marginalValueMinAttempts:Number(schedule.marginalValueMinAttempts||0),marginalValueEfficiencyThreshold:Number(schedule.marginalValueEfficiencyThreshold||0),
    oneStepClosable:Boolean(schedule.oneStepClosable),closureForecastEvidenceCount:Number(schedule.closureForecastEvidenceCount||0),bestClosureStrategyId:schedule.bestClosureStrategyId??null,bestClosureProbability:schedule.bestClosureProbability??null,bestClosureEvidenceStrength:Number(schedule.bestClosureEvidenceStrength||0),bestClosureExpectedPostDeficit:schedule.bestClosureExpectedPostDeficit??null,bestClosureLikely:Boolean(schedule.bestClosureLikely),
    recommendedStrategyId:schedule.recommendedStrategyId??null,recommendedSourceId:schedule.recommendedSourceId??null,recommendedEvidenceFamily:schedule.recommendedEvidenceFamily??null,recommendedCostClass:schedule.recommendedCostClass??null,
    recommendedDeclaredCostValue:schedule.recommendedDeclaredCostValue??null,recommendedCalibratedCostValue:schedule.recommendedCalibratedCostValue??null,recommendedAdaptiveCostValue:schedule.recommendedAdaptiveCostValue??null,recommendedRiskAdjustedCostValue:schedule.recommendedRiskAdjustedCostValue??null,
    recommendedCostCalibrationAttempts:Number(schedule.recommendedCostCalibrationAttempts||0),recommendedCostCalibrationBaseStrength:Number(schedule.recommendedCostCalibrationBaseStrength||0),recommendedCostCalibrationStrength:Number(schedule.recommendedCostCalibrationStrength||0),recommendedCostCalibrationFreshness:schedule.recommendedCostCalibrationFreshness==null?1:Number(schedule.recommendedCostCalibrationFreshness),recommendedCostCalibrationAgeMs:Number(schedule.recommendedCostCalibrationAgeMs||0),
    recommendedCostObservedMean:schedule.recommendedCostObservedMean??null,recommendedCostObservedStdDev:Number(schedule.recommendedCostObservedStdDev||0),recommendedCostRecentSamples:Number(schedule.recommendedCostRecentSamples||0),recommendedCostRecentMean:schedule.recommendedCostRecentMean??null,recommendedCostRecentStdDev:Number(schedule.recommendedCostRecentStdDev||0),recommendedCostRecentOutlierCount:Number(schedule.recommendedCostRecentOutlierCount||0),recommendedCostRecentOutlierRate:Number(schedule.recommendedCostRecentOutlierRate||0),recommendedCostRecentLastWasOutlier:Boolean(schedule.recommendedCostRecentLastWasOutlier),
    recommendedCostRegimeDrift:Number(schedule.recommendedCostRegimeDrift||0),recommendedCostRegimeConfidence:Number(schedule.recommendedCostRegimeEffectiveConfidence??schedule.recommendedCostRegimeConfidence??0),recommendedCostRegimeDirection:schedule.recommendedCostRegimeEffectiveDirection||schedule.recommendedCostRegimeDirection||'stable',recommendedCostRegimeDetected:Boolean(schedule.recommendedCostRegimeEffectiveDetected??schedule.recommendedCostRegimeDetected),recommendedCostRegimeSignal:Number(schedule.recommendedCostRegimeSignal||0),recommendedCostRegimeThreshold:Number(schedule.recommendedCostRegimeThreshold||0),recommendedCostRegimeStrengthBoost:Number(schedule.recommendedCostRegimeStrengthBoost||0),
    recommendedCostRiskMargin:Number(schedule.recommendedCostRiskMargin||0),recommendedResolutionEfficiency:schedule.recommendedResolutionEfficiency??null,recommendedClosureProbability:schedule.recommendedClosureProbability??null,recommendedClosureInfluenceStrength:Number(schedule.recommendedClosureInfluenceStrength||0),recommendedClosureSchedulingProbability:schedule.recommendedClosureSchedulingProbability??null,
    recommendedExpectedClosureCost:schedule.recommendedExpectedClosureCost??null,recommendedCalibratedExpectedClosureCost:schedule.recommendedCalibratedExpectedClosureCost??null,recommendedAdaptiveExpectedClosureCost:schedule.recommendedAdaptiveExpectedClosureCost??null,recommendedRiskAdjustedExpectedClosureCost:schedule.recommendedRiskAdjustedExpectedClosureCost??null,recommendedClosureCostEfficiency:schedule.recommendedClosureCostEfficiency??null,recommendedClosureCostAdjustment:Number(schedule.recommendedClosureCostAdjustment||0),recommendedExpectedPostDeficit:schedule.recommendedExpectedPostDeficit??null,
    ranked:(Array.isArray(schedule.ranked)?schedule.ranked:[]).slice(0,6).map(row).filter(Boolean),authority:false,
  };
}

function publicSemanticDecision(value) {
  if (!value) return null;
  return {
    intent:value.intent ?? null, semanticClass:value.semanticClass ?? null,
    nextOperation:value.nextOperation ?? null, operationConfidence:value.operationConfidence ?? null,
    calibration:value.calibration ?? null, targetHint:value.targetHint ?? null, targetConfidence:value.targetConfidence ?? null, rankedTargets:value.rankedTargets || [],
    chainContinuation:value.chainContinuation ?? null, compatibility:value.compatibility ?? null,
    conflict:value.conflict ?? null, feasibility:value.feasibility ?? null,
    expectedWitnessDelta:value.expectedWitnessDelta ?? null, semanticMatch:value.semanticMatch ?? null,
    witnessContinuity:value.witnessContinuity ?? null, gatePressure:value.gatePressure ?? null,
    confidence:value.confidence ?? null, uncertainty:value.uncertainty ?? null, evidenceNeed:value.evidenceNeed ?? null, evidenceUrgency:value.evidenceUrgency ?? null, evidenceSufficiency:value.evidenceSufficiency ?? null, evidenceClaimTarget:value.evidenceClaimTarget ?? null, evidenceFrontier:value.evidenceFrontier ?? null, evidenceResolutionSchedule:publicEvidenceResolutionSchedule(value.evidenceResolutionSchedule), evidenceScheduleMatch:Boolean(value.evidenceScheduleMatch), evidenceScheduleAdjustment:value.evidenceScheduleAdjustment ?? 0, evidenceMarket:value.evidenceMarket ?? null, evidenceProducer:Boolean(value.evidenceProducer), evidenceClass:value.evidenceClass ?? null, evidenceDeterministic:Boolean(value.evidenceDeterministic), evidenceLocal:Boolean(value.evidenceLocal), evidenceNetworkRequired:Boolean(value.evidenceNetworkRequired), evidenceSourceId:value.evidenceSourceId ?? null, evidenceFamily:value.evidenceFamily ?? null, evidenceFamilyRepresented:Boolean(value.evidenceFamilyRepresented), evidenceFamilyNovel:Boolean(value.evidenceFamilyNovel), evidenceDiversityAdjustment:value.evidenceDiversityAdjustment ?? 0, evidenceSourceReliability:value.evidenceSourceReliability ?? null, evidenceSourceGlobalReliability:value.evidenceSourceGlobalReliability ?? null, evidenceSourceClaimReliability:value.evidenceSourceClaimReliability ?? null, evidenceSourceCalibrationScope:value.evidenceSourceCalibrationScope ?? null, evidenceSourceCalibrationAttempts:value.evidenceSourceCalibrationAttempts ?? null, evidenceResolutionEfficiency:value.evidenceResolutionEfficiency ?? null, evidenceRawResolutionEfficiency:value.evidenceRawResolutionEfficiency ?? null, evidenceResolutionEfficiencyAttempts:value.evidenceResolutionEfficiencyAttempts ?? null, evidenceResolutionEfficiencyScope:value.evidenceResolutionEfficiencyScope ?? null, evidenceFit:value.evidenceFit ?? null, evidenceAdjustment:value.evidenceAdjustment ?? null, costClass:value.costClass ?? null,
    shortTermSignature:value.shortTermSignature ?? null, chainMotifs:value.chainMotifs || [], recentTypes:(value.recentTypes || []).slice(-6),
    episodicGuidance:value.episodicGuidance ?? null, episodicConsistency:value.episodicConsistency ?? null, episodicPlan:publicEpisodeTransitionPlan(value.episodicPlan), episodicRepairPlan:publicEpisodeTransitionPlan(value.episodicRepairPlan), episodicBranchSummary:value.episodicBranchSummary ?? null, episodicDriftPressure:value.episodicDriftPressure ?? value.episodicBranchSummary?.calibrationDriftPressure ?? 0,
    workingMemory:value.workingMemory ?? null, authority:false,
  };
}

function normalizeRoutingRecall(capability, context = {}, option = false) {
  if (!option) return null;
  const cfg = typeof option === 'object' && option !== null ? {...option} : {};
  const explicit = typeof option === 'string' ? option : cfg.query;
  const query = explicit ?? cfg.memoryQuery ?? context?.memoryQuery ?? context?.prompt ?? context?.taskHint ?? capability;
  const limit = Math.max(1, Math.min(32, Number(cfg.limit ?? 6) || 6));
  const candidateLimit = Math.max(limit, Math.min(256, Number(cfg.candidateLimit ?? Math.max(32, limit * 6)) || Math.max(32, limit * 6)));
  return {
    query:String(query ?? capability ?? ''),
    options:{limit,candidateLimit,filter:cfg.filter ?? null,minScore:cfg.minScore ?? -1,requireWitness:cfg.requireWitness !== false},
    pattern:{enabled:cfg.episodePatterns !== false,limit:Math.max(1,Math.min(16,Number(cfg.patternLimit ?? limit)||limit)),minPatternScore:Math.max(0,Math.min(1,Number(cfg.minPatternScore ?? .18)||.18))},
    inject:cfg.inject !== false,
  };
}

function mergeRoutingRecall(vectorRecall,patternRecall,limit=6){
  const merged=new Map();
  const add=(row,source)=>{if(!row?.witnessDigest)return;const key=row.recordId||row.witnessDigest||row.id;const current=merged.get(key);if(!current){merged.set(key,{...row,retrievalSources:[source]});return;}merged.set(key,{...current,score:Math.max(Number(current.score??-1),Number(row.score??-1)),trustScore:Math.max(Number(current.trustScore??0),Number(row.trustScore??0)),patternScore:Math.max(Number(current.patternScore??0),Number(row.patternScore??0)),patternMatches:row.patternMatches||current.patternMatches||[],metadata:{...(current.metadata||{}),...(row.metadata||{})},retrievalSources:[...new Set([...(current.retrievalSources||[]),source])]});};
  for(const row of vectorRecall?.results||[])add(row,'vector');for(const row of patternRecall?.hits||[])add(row,'witness-pattern');
  const rank=row=>.58*Number(row.trustScore??0)+.27*((Number(row.score??-1)+1)/2)+.15*Number(row.patternScore??0);
  const mergedCandidates=merged.size,sourceRows=Number(vectorRecall?.results?.length||0)+Number(patternRecall?.hits?.length||0);
  const results=[...merged.values()].sort((a,b)=>rank(b)-rank(a)||Number(b.score??0)-Number(a.score??0)).slice(0,Math.max(1,Number(limit)||6));
  const diagnostics={schema:'xavi-routing-recall-merge-diagnostics/v1',mergedCandidates,returned:results.length,duplicateCollapses:Math.max(0,sourceRows-mergedCandidates),authority:false};
  return{schema:'xavi-routing-memory-merge/v1',query:vectorRecall?.query||null,receipt:vectorRecall?.receipt||null,patternReceipt:patternRecall?.receipt||null,results,vectorRecall,patternRecall,diagnostics,authority:false};
}

function compactRoutingMemory(recall, semanticPreview = null) {
  if (!recall) return null;
  const rows=recall.results || [];
  const evidence=rows.map(row=>({
    id:row.id ?? null, recordId:row.recordId ?? null, witnessDigest:row.witnessDigest ?? null,
    score:Number(row.score ?? 0), trustScore:Number(row.trustScore ?? 0), epistemicStatus:row.epistemicStatus ?? 'reported',patternScore:row.patternScore==null?null:Number(row.patternScore),planReliability:row.planReliability==null?(row.utility?.planReliability==null?null:Number(row.utility.planReliability)):Number(row.planReliability),branchCalibrationReliability:row.branchCalibrationReliability==null?(row.utility?.branchCalibrationReliability==null?null:Number(row.utility.branchCalibrationReliability)):Number(row.branchCalibrationReliability),branchCalibrationAttempts:row.branchCalibrationAttempts==null?(row.utility?.branchCalibrationAttempts==null?null:Number(row.utility.branchCalibrationAttempts)):Number(row.branchCalibrationAttempts),branchCalibrationUpdatedAt:row.branchCalibrationUpdatedAt==null?(row.utility?.branchCalibrationUpdatedAt==null?null:Number(row.utility.branchCalibrationUpdatedAt)):Number(row.branchCalibrationUpdatedAt),branchCalibrationRecentReliability:row.branchCalibrationRecentReliability==null?(row.utility?.branchCalibrationRecentReliability==null?null:Number(row.utility.branchCalibrationRecentReliability)):Number(row.branchCalibrationRecentReliability),branchCalibrationRecentWeight:row.branchCalibrationRecentWeight==null?(row.utility?.branchCalibrationRecentWeight==null?null:Number(row.utility.branchCalibrationRecentWeight)):Number(row.branchCalibrationRecentWeight),branchCalibrationRecentUpdatedAt:row.branchCalibrationRecentUpdatedAt==null?(row.utility?.branchCalibrationRecentUpdatedAt==null?null:Number(row.utility.branchCalibrationRecentUpdatedAt)):Number(row.branchCalibrationRecentUpdatedAt),branchCalibrationDrift:row.branchCalibrationDrift==null?(row.utility?.branchCalibrationDrift==null?null:Number(row.utility.branchCalibrationDrift)):Number(row.branchCalibrationDrift),retrievalSources:row.retrievalSources||[],
  })).filter(row=>row.witnessDigest);
  const episodeHints=rows.map(projectWitnessEpisodeHint).filter(Boolean).slice(0,8);
  return {
    schema:'xavi-routing-memory-evidence/v1', authority:false,
    witness:recall.receipt ? {id:recall.receipt.id,digest:recall.receipt.digest,sequence:recall.receipt.sequence} : null,
    patternWitness:recall.patternReceipt ? {id:recall.patternReceipt.id,digest:recall.patternReceipt.digest,sequence:recall.patternReceipt.sequence} : null,
    sources:{vectorCount:Number(recall.vectorRecall?.results?.length||0),patternCount:Number(recall.patternRecall?.hits?.length||0),mergedCount:rows.length},
    diagnostics:{vector:recall.vectorRecall?.diagnostics?structuredClone(recall.vectorRecall.diagnostics):null,pattern:recall.patternRecall?.diagnostics?structuredClone(recall.patternRecall.diagnostics):null,merge:recall.diagnostics?structuredClone(recall.diagnostics):null,authority:false},
    semanticPreview:semanticPreview?{entryWitnessType:(semanticPreview.recentTypes||[]).at(-1)||null,shortTermSignature:semanticPreview.shortTermSignature||null,chainMotifs:(semanticPreview.chainMotifs||[]).slice(-6),recentTypes:(semanticPreview.recentTypes||[]).slice(-6),workingRelations:{...(semanticPreview.workingMemory?.relations||{})},authority:false}:null,
    evidence, episodeHints,
  };
}

function attributeRoutingMemoryEvidence(evidence=[],episodeHints=[],chosenStrategyId=null,episodicPlan=null){
  const hints=new Map((Array.isArray(episodeHints)?episodeHints:[]).filter(row=>row?.witnessDigest).map(row=>[row.witnessDigest,row]));
  const futureSteps=new Set();for(const row of (episodicPlan?.steps||[]).slice(1)){if(row?.witnessDigest)futureSteps.add(`w:${row.witnessDigest}`);if(row?.recordId)futureSteps.add(`r:${row.recordId}`);}
  return (Array.isArray(evidence)?evidence:[]).map(item=>{
    const hint=hints.get(item?.witnessDigest);if(!hint)return{...item,creditWeight:1,creditReason:'general-recalled-evidence'};
    const same=String(hint.strategyId||'')===String(chosenStrategyId||''),success=Boolean(hint.validated&&hint.outcomeOk&&!hint.demoted),plannedFuture=futureSteps.has(`w:${hint.witnessDigest}`)||futureSteps.has(`r:${hint.recordId}`);
    let creditWeight=1,creditReason='episode-supports-chosen-route';
    if(same&&!success){creditWeight=-1;creditReason='episode-warned-against-chosen-route';}
    else if(plannedFuture&&success){creditWeight=0;creditReason='episode-planned-future-transition-unobserved';}
    else if(!same&&success){creditWeight=-0.25;creditReason='episode-supported-unchosen-alternative';}
    else if(!same&&!success){creditWeight=0.45;creditReason='episode-warned-against-avoided-route';}
    return{...item,creditWeight,creditReason,episodeStrategyId:hint.strategyId||null,episodeOutcomeOk:Boolean(hint.outcomeOk),episodeValidated:Boolean(hint.validated),plannedFuture};
  });
}

export class XaviBrowser {
  static async create(options = {}) {
    const namespace = options.namespace || 'default';
    let store = options.store;
    if (!store) {
      if (typeof indexedDB !== 'undefined') store = await new IndexedDBStore({name:`xavi-browser-js:${namespace}`}).init();
      else store = new MemoryStore();
    }
    const xavi = new XaviBrowser({...options, namespace, store});
    try { await xavi.init(); return xavi; }
    catch (error) { await xavi.close().catch(()=>{}); throw error; }
  }

  constructor({ namespace='default', store, stateDim=256, featureDim=32, vectorDim=64, embedder=null, vectorStoreFactory=null, exploration=0.2, learningRate=0.12, defaultTimeoutMs=8000, semanticRouting=true, semanticFeatureDim=32, semanticLearningRate=0.08, semanticBlend=0.34, semanticWindow=16, semanticWorkingObjects=96, semanticWorkingEdges=384, semanticHeadLearningRate=0.06, semanticBranchCalibrationHalfLifeMs=7*24*3600*1000, graphRouting=undefined, graphFeatureDim=undefined, graphLearningRate=undefined, graphBlend=undefined, selfManagement=true, autoPromotion=true, autoDemotion=true, autoCanary=true, autoCalibration=true, selfManagementIntervalMs=30000, selfManagementInitialDelayMs=30000, selfManagementOptions={}, autoRetention=true, autoRetainObservations=true, autoRetainOutcomes=true, autoRetainObserverEvidence=true, autoRetainPolicyEvents=true, autoRetainRaw=true, autoRetentionMaxBytes=24576, autoRetireMemory=true, autoRetentionOptions={}, adaptiveMemoryRecall=true, memoryRecallUncertainty=0.42, memoryRecallConflict=0.45, memoryRecallContinuity=0.45, memoryRecallGatePressure=0.60, evidenceSessions=true, evidenceSessionOptions={}, autoEvidenceResolution=true, evidenceResolutionMaxSteps=6, evidenceResolutionMaxCost=3, evidenceResolutionOptions={}, planContinuationOptions={}, portableStackStartupRecovery=true, portableStackRecoveryStrict=true, portableStackRecoveryOptions={}, wgSfm=true, wgSfmFeatureDim=64, wgSfmLearningRate=0.08, wgSfmTeacherBlend=0.12, wgSfmWindow=24, runtimeBrokering=true, runtimePolicyMaxAdjustment=0.14, runtimePolicyLearningRate=0.18, wgSrnn=true, wgSrnnMaxDirectives=64, wgSrnnMaxCommitments=32, wgSrnnMaxHistory=128, wgSrnnAutoIntegrity=true, wgSrnnIntegrityAutoEveryWitnesses=32, wgSrnnIntegrityFullEvery=16, wgSrnnIntegrityFullAfterWitnesses=512, wgSrnnMaxIntegrityTelemetryEvents=32 } = {}) {
    this.namespace = namespace;
    this.store = store;
    this.adaptiveMemoryRecall = adaptiveMemoryRecall!==false;
    this.memoryRecallThresholds={uncertainty:Number(memoryRecallUncertainty),conflict:Number(memoryRecallConflict),continuity:Number(memoryRecallContinuity),gatePressure:Number(memoryRecallGatePressure)};
    this.memoryRecallTelemetry={startedAt:Date.now(),decisions:0,recalls:0,skips:0,explicitEnable:0,explicitDisable:0,triggerCounts:{},last:null};
    this.gate = new WitnessGate({expectedStateDim:stateDim});
    this.ledger = new WitnessLedger({store, namespace});
    this.recurrent = new RecurrentCore({stateDim, inputDim:featureDim});
    this.sfm = wgSfm!==false ? new WitnessSFM({store,recurrent:this.recurrent,gate:this.gate,ledger:this.ledger,namespace,featureDim:wgSfmFeatureDim,learningRate:wgSfmLearningRate,teacherBlend:wgSfmTeacherBlend,window:wgSfmWindow}) : null;
    this.srnnStages = wgSrnn!==false ? new WitnessGatedSelfReferentialStages({store,ledger:this.ledger,namespace,autoIntegrity:wgSrnnAutoIntegrity,integrityAutoEveryWitnesses:wgSrnnIntegrityAutoEveryWitnesses,integrityFullEvery:wgSrnnIntegrityFullEvery,integrityFullAfterWitnesses:wgSrnnIntegrityFullAfterWitnesses,maxIntegrityTelemetryEvents:wgSrnnMaxIntegrityTelemetryEvents}) : null;
    this.srnn = wgSrnn!==false ? new WitnessGatedSelfReferentialNeuralNetwork({store,ledger:this.ledger,namespace,maxDirectives:wgSrnnMaxDirectives,maxCommitments:wgSrnnMaxCommitments,maxHistory:wgSrnnMaxHistory,stages:this.srnnStages}) : null;
    this.selfModel = this.srnn; // compatibility/readability alias; WG-SRNN is canonical
    this.runtime = new BrowserRuntime({defaultTimeoutMs});
    this.routeHealth = new RouteHealth({store});
    this.runtimePolicy = runtimeBrokering!==false ? new SmallModelRuntimePolicy({store,ledger:this.ledger,enabled:true,maxAdjustment:runtimePolicyMaxAdjustment,learningRate:runtimePolicyLearningRate}) : null;
    this.authority = new BrowserAuthority({namespace,store});
    this.portableStackRecoveryConfig={enabled:portableStackStartupRecovery!==false,strict:portableStackRecoveryStrict!==false,options:portableStackRecoveryOptions&&typeof portableStackRecoveryOptions==='object'?portableStackRecoveryOptions:{}};
    this.portableStackRecoveryState={schema:'xavi-wg-stack-portable-startup-recovery/v1',status:this.portableStackRecoveryConfig.enabled?'pending':'disabled',enabled:this.portableStackRecoveryConfig.enabled,strict:this.portableStackRecoveryConfig.strict,openTransactionCount:0,transactionId:null,action:null,reason:this.portableStackRecoveryConfig.enabled?null:'startup-recovery-disabled',reconciled:false,checkedAt:null,quarantined:false,authority:false};
    const semanticEnabled = graphRouting === false ? false : semanticRouting !== false;
    this.semantic = semanticEnabled ? new WitnessSemanticLayer({store,namespace,durableState:true,recurrent:this.recurrent,gate:this.gate,featureDim:graphFeatureDim ?? semanticFeatureDim,learningRate:graphLearningRate ?? semanticLearningRate,blend:graphBlend ?? semanticBlend,window:semanticWindow,workingObjects:semanticWorkingObjects,workingEdges:semanticWorkingEdges,headLearningRate:semanticHeadLearningRate,branchCalibrationHalfLifeMs:semanticBranchCalibrationHalfLifeMs,requireAuthorityProof:true}) : null;
    this.routeGraph = this.semantic; // compatibility alias for v0.6 callers
    this.ledger.subscribe(receipt => this.semantic?.ingest(receipt));
    this.ledger.subscribe(receipt => this.sfm?.ingest(receipt));
    this.router = new StrategyRouter({store, featureDim, exploration, learningRate, routeHealth:this.routeHealth, semanticScorer:this.semantic, runtimePolicy:this.runtimePolicy,requireAuthorityProof:true});
    this.bus = new PolicyBus(namespace);
    this.learning = new LearningAuthority({gate:this.gate, authority:this.authority, ledger:this.ledger, router:this.router, bus:this.bus});
    this.deferred = new DeferredLearningQueue({store,runtime:this.runtime});
    this.credit = new CreditGraph();
    this.investigations = new InvestigationQueue({store});
    this.embedder = embedder || new HashFeatureEmbedder({dimensions:vectorDim});
    this.vectorMemory = vectorStoreFactory ? vectorStoreFactory({store,namespace,dimensions:this.embedder.dimensions || vectorDim}) : new WitnessVectorStore({store, namespace, dimensions:this.embedder.dimensions || vectorDim});
    this.knowledge = new KnowledgeCorpus(this);
    this.security = new SecurityFaculty(this);
    this.ads = new AdPolicyFaculty(this);
    this.lexicon = new LexiconFaculty(this);
    this.language = new LanguageFaculty(this);
    this.math = new MathFaculty(this);
    this.sandbox = new SandboxManager(this);
    this.images = new FirstPartyImageRegistry(this);
    this.observers = new EvidenceObserverRegistry(this);
    this.memory = new WitnessMemory({store,ledger:this.ledger,vectorStore:this.vectorMemory,embedder:this.embedder,namespace});
    this.episodePatterns = new WitnessEpisodePatternIndex({store,ledger:this.ledger,namespace});
    this.planContinuations = new WitnessPlanContinuationTracker({store,ledger:this.ledger,namespace,branchCalibrationHalfLifeMs:semanticBranchCalibrationHalfLifeMs,...planContinuationOptions});
    this.evidenceSessions = evidenceSessions!==false ? new WitnessEvidenceSessionTracker({store,ledger:this.ledger,namespace,...evidenceSessionOptions}) : null;
    this.autoEvidenceResolution=autoEvidenceResolution!==false;
    this.evidenceResolver=this.evidenceSessions?new EvidenceResolutionController({xavi:this,enabled:this.autoEvidenceResolution,maxSteps:evidenceResolutionMaxSteps,maxCost:evidenceResolutionMaxCost,...evidenceResolutionOptions}):null;
    this.autoRetention = autoRetention!==false ? new AutoRetentionController(this,{enabled:true,retainObservations:autoRetainObservations,retainOutcomes:autoRetainOutcomes,retainObserverEvidence:autoRetainObserverEvidence,retainPolicyEvents:autoRetainPolicyEvents,retainRaw:autoRetainRaw,maxBytes:autoRetentionMaxBytes,autoRetire:autoRetireMemory,...autoRetentionOptions}) : null;
    this.trainer = new SelfTrainingCoordinator(this);
    this.replay = new WitnessReplayDataset({store,namespace});
    this.backfill = this.semantic ? new WitnessReplayBackfillTrainer(this) : null;
    this.sfmReplay = this.sfm ? new WitnessSfmReplayTrainer(this) : null;
    this.pending = new Map();
    this.disposables = new Set();
    if(this.srnnStages) this.disposables.add(this.srnnStages);
    this.selfManager = this.backfill ? new SelfManagementController(this,{enabled:selfManagement!==false,autoPromotion,autoDemotion,autoCanary,autoCalibration,intervalMs:selfManagementIntervalMs,initialDelayMs:selfManagementInitialDelayMs,...selfManagementOptions}) : null;
    if(this.autoRetention){
      this.disposables.add(this.autoRetention);
      this.ledger.subscribe(receipt=>{this.autoRetention?.enqueueWitness(receipt);});
    }
    if(this.selfManager) this.disposables.add(this.selfManager);
  }

  async init() {
    await this.ledger.init();
    await this.srnn?.init?.();
    await this.sfm?.init?.();
    await this.routeHealth.init();
    await this.router.init();
    if(this.semantic?.durableStateEnabled&&!this.semantic.durableStateHead)await this.authority.withLease(authorityProof=>this.semantic.ensureDurableStateHead({authorityProof,source:'startup-migration'}));
    await this.vectorMemory.init();
    await this.memory.init();
    await this.episodePatterns.init();
    await this.planContinuations.init();
    await this.evidenceSessions?.init?.();
    const snapshot = await this.store.get('state','recurrent');
    if (snapshot) this.recurrent.restore(snapshot);
    this.bus.subscribe(async message => {
      if (message?.type === 'policy-promoted' || message?.type === 'policy-demoted') {
        const row = await this.store.get('policy', message.strategyId);
        if (row?.policy) this.router.policy.set(message.strategyId, row.policy);
        if(this.semantic?.durableStateEnabled)await this.semantic.reloadDurableStateHead();
        return;
      }
      if (message?.type === 'semantic-calibration-rebuilt' && this.semantic) {
        if(this.semantic.durableStateEnabled)await this.semantic.reloadDurableStateHead();
        else await this.semantic.heads.rebuildCalibrationFromWitnesses({persist:false});
        return;
      }
      if ((message?.type === 'semantic-backfill-promoted' || message?.type === 'semantic-backfill-reverted') && this.semantic) {
        if(this.semantic.durableStateEnabled)await this.semantic.reloadDurableStateHead();
        else {const row = await this.store.get('records','semantic-backfill-latest');if (row?.state) await this.semantic.importState(row.state,{persist:false,replace:true});}
      }
    });
    const startupRecovery=await this._runPortableStackStartupRecovery();
    if(startupRecovery?.status!=='blocked'){if(startupRecovery?.status==='disabled'){if(typeof this.selfManager?.activate==='function')await this.selfManager.activate();else this.selfManager?.start();}else try{await this._resumeSelfManagementAfterPortableStackRecovery({source:'startup'});}catch(error){if(this.portableStackRecoveryConfig?.strict!==false)throw error;}}
    return this;
  }

  portableStackRecoveryStatus() {
    return {...this.portableStackRecoveryState};
  }

  _portableStackRecoveryIncidentKey(transactionId=null) {
    const id=String(transactionId||'unscoped').replace(/[^a-zA-Z0-9._:-]/g,'_').slice(0,240)||'unscoped';
    return `wg-stack-portable-startup-recovery-incident:${this.namespace}:${id}`;
  }

  _portableStackRecoveryIncidentLatestKey() {
    return `wg-stack-portable-startup-recovery-incident-latest:${this.namespace}`;
  }

  _portableStackRecoveryResolutionBatchKey(batchId) {
    const id=String(batchId||'unknown').replace(/[^a-zA-Z0-9._:-]/g,'_').slice(0,240)||'unknown';
    return `wg-stack-portable-recovery-resolution-batch:${this.namespace}:${id}`;
  }

  _portableStackRecoveryResolutionBatchLatestKey() {
    return `wg-stack-portable-recovery-resolution-batch-latest:${this.namespace}`;
  }

  async _portableStackRecoveryResolutionBatch() {
    const pointer=await this.store.get('records',this._portableStackRecoveryResolutionBatchLatestKey()).catch(()=>null);
    return pointer?.key?await this.store.get('records',pointer.key).catch(()=>null):null;
  }

  async _persistPortableStackRecoveryResolutionBatch(batch) {
    if(!batch?.batchId)throw new Error('portable recovery resolution batch id required');
    const key=this._portableStackRecoveryResolutionBatchKey(batch.batchId),row={schema:'xavi-wg-stack-portable-recovery-resolution-batch/v1',namespace:this.namespace,...batch,authority:false};
    await this.store.set('records',key,row);
    await this.store.set('records',this._portableStackRecoveryResolutionBatchLatestKey(),{schema:'xavi-wg-stack-portable-recovery-resolution-batch-pointer/v1',namespace:this.namespace,batchId:row.batchId,key,status:row.status,updatedAt:Date.now(),authority:false});
    return row;
  }

  async _portableStackRecoveryPendingBatchTransactionIds() {
    const batch=await this._portableStackRecoveryResolutionBatch();
    if(!batch||batch.status==='committed'||batch.status==='superseded')return [];
    return [...new Set((Array.isArray(batch.transactionIds)?batch.transactionIds:[]).filter(Boolean).map(String))];
  }

  async _persistPortableStackRecoveryIncident(state,{resolved=false,resolution=null,resolutionBatch=null}={}) {
    if(!state||typeof state!=='object')return null;
    const transactionId=state.transactionId??state.reconciliation?.inspection?.stack_transaction_id??null;
    const key=this._portableStackRecoveryIncidentKey(transactionId),now=Date.now(),inspection=state.reconciliation?.inspection||state.inspection||resolution?.inspection||null;
    const transactions=Array.isArray(state.transactions)?state.transactions.map(String).slice(0,16):[];
    const fingerprint={schema:'xavi-wg-stack-portable-recovery-incident-fingerprint/v1',namespace:this.namespace,transactionId,transactions,status:resolved?'resolved':'open',reason:state.reason??resolution?.reason??null,action:state.action??resolution?.action??null,transactionStatus:inspection?.transaction_status??null,recoveryRequired:inspection?.recovery_required??null,beforeDigest:inspection?.before_digest??null,currentDigest:inspection?.current_digest??null,expectedTerminalDigest:inspection?.expected_terminal_digest??null,journalDigest:inspection?.journal_state_digest??null,familyApplicationCount:Number(inspection?.family_application_count??0),familyRollbackCount:Number(inspection?.family_rollback_count??0),authority:false};
    const incidentDigest=await digest(fingerprint);
    let row=null;
    for(let attempt=0;attempt<8;attempt++){
      const prior=await this.store.get('records',key).catch(()=>null);
      if(prior?.status==='resolved'&&!resolved){row=prior;break;}
      const candidate={schema:'xavi-wg-stack-portable-recovery-incident/v1',namespace:this.namespace,transactionId,transactions,status:resolved?'resolved':'open',reason:fingerprint.reason,action:fingerprint.action,transactionStatus:fingerprint.transactionStatus,recoveryRequired:fingerprint.recoveryRequired,beforeDigest:fingerprint.beforeDigest,currentDigest:fingerprint.currentDigest,expectedTerminalDigest:fingerprint.expectedTerminalDigest,journalDigest:fingerprint.journalDigest,familyApplicationCount:fingerprint.familyApplicationCount,familyRollbackCount:fingerprint.familyRollbackCount,incidentDigest,firstSeenAt:prior?.firstSeenAt??now,lastSeenAt:now,occurrenceCount:Number(prior?.occurrenceCount||0)+(resolved?0:1),resolvedAt:resolved?now:null,resolutionAction:resolved?(resolution?.action??state.action??null):null,resolutionWitnessDigest:resolved?(resolution?.witness?.digest??null):null,resolutionBatchId:resolved?(resolutionBatch?.batchId??null):null,resolutionMutationLeaseId:resolved?(resolutionBatch?.mutationLeaseId??null):null,resolutionAuthorityLeaseId:resolved?(resolutionBatch?.authorityLeaseId??null):null,authority:false};
      if(typeof this.store.compareAndSet==='function'){
        const cas=await this.store.compareAndSet('records',key,prior,candidate);
        if(cas?.updated){row=candidate;break;}
      }else{await this.store.set('records',key,candidate);row=candidate;break;}
    }
    if(!row)throw new Error('portable recovery incident CAS retry exhausted');
    await this.store.set('records',this._portableStackRecoveryIncidentLatestKey(),{schema:'xavi-wg-stack-portable-recovery-incident-pointer/v1',namespace:this.namespace,transactionId,key,incidentDigest:row.incidentDigest,status:row.status,updatedAt:Date.now(),authority:false});
    return row;
  }

  async portableStackRecoveryIncident({transactionId=null}={}) {
    let key=transactionId?this._portableStackRecoveryIncidentKey(transactionId):null;
    if(!key){const pointer=await this.store.get('records',this._portableStackRecoveryIncidentLatestKey());key=pointer?.key||null;}
    return key?await this.store.get('records',key):null;
  }

  async portableStackRecoveryIncidents() {
    const rows=await this.store.values('records');
    return rows.filter(row=>row?.schema==='xavi-wg-stack-portable-recovery-incident/v1'&&row?.namespace===this.namespace).sort((a,b)=>Number(b.lastSeenAt||0)-Number(a.lastSeenAt||0));
  }

  _assertPortableStackOperational(operation='operation') {
    const state=this.portableStackRecoveryState;
    if(state?.quarantined!==true&&state?.status!=='blocked')return;
    const error=new WGStackPortableApplicationError(`portable stack recovery quarantine blocks ${operation}`);
    error.startupRecovery={...state};error.operation=operation;error.recoveryQuarantined=true;throw error;
  }

  _setPortableStackRecoveryBlocked(patch={}) {
    this.selfManager?.stop?.();
    this.portableStackRecoveryState={...this.portableStackRecoveryState,...patch,status:'blocked',reconciled:false,quarantined:true,checkedAt:Date.now(),authority:false};
    return this.portableStackRecoveryState;
  }

  async _inspectPortableStackRecoveryReadiness() {
    const open=await this.listOpenStackPortableTransactions();
    if(open.length){
      const transactions=open.map(row=>row?.stack_transaction_id).filter(Boolean);
      return{ready:false,reason:'recovery-readiness-open-transaction',openTransactionCount:open.length,transactionId:transactions[0]??null,transactions,inspection:null,authority:false};
    }
    const rows=(await this.store.values('witness')||[]).slice().sort((a,b)=>Number(a?.sequence??0)-Number(b?.sequence??0));
    const latestStarted=rows.filter(row=>row?.type==='wg-stack-portable-stack-application-started'&&row?.body?.stackTransactionId).at(-1)||null;
    if(!latestStarted)return{ready:true,reason:'recovery-readiness-no-stack-transactions',openTransactionCount:0,transactionId:null,transactions:[],inspection:null,authority:false};
    const transactionId=latestStarted.body.stackTransactionId,inspection=await this.inspectStackPortableRecovery({stackTransactionId:transactionId});
    const ready=inspection?.recovery_required!==true&&inspection?.state_matches_terminal===true&&(inspection?.transaction_status==='committed'||inspection?.transaction_status==='compensated');
    return{ready,reason:ready?'recovery-readiness-latest-transaction-consistent':'recovery-readiness-latest-transaction-mismatch',openTransactionCount:0,transactionId,transactions:[transactionId],inspection,authority:false};
  }

  async _inspectPortableStackRecoveryIncidentReadiness() {
    const incidents=await this.portableStackRecoveryIncidents();
    const open=incidents.filter(row=>row?.status==='open');
    const transactions=[...new Set(open.map(row=>row?.transactionId).filter(Boolean))];
    const unscopedIncidentCount=open.filter(row=>!row?.transactionId).length;
    const ready=open.length===0;
    return{ready,reason:ready?'recovery-incident-readiness-clean':(unscopedIncidentCount?'recovery-incident-readiness-unscoped-open-incident':'recovery-incident-readiness-open-incident'),openIncidentCount:open.length,transactionId:transactions[0]??null,transactions,unscopedIncidentCount,authority:false};
  }

  async _appendPortableStackRecoveryReadinessAssessment({readiness,incidentReadiness,resolution=null}={}) {
    const readinessDigest=await digest(readiness??null),incidentReadinessDigest=await digest(incidentReadiness??null),resolutionDigest=await digest(resolution??null);
    return this.ledger.append('wg-stack-portable-recovery-readiness-assessed',{
      schema:WG_STACK_PORTABLE_RECOVERY_READINESS_ASSESSMENT_SCHEMA,namespace:this.namespace,
      readinessDigest,incidentReadinessDigest,resolutionDigest,
      stackReady:readiness?.ready===true,incidentReady:incidentReadiness?.ready===true,
      stackReason:readiness?.reason??null,incidentReason:incidentReadiness?.reason??null,
      transactionId:readiness?.transactionId??incidentReadiness?.transactionId??null,
      transactions:[...new Set([...(Array.isArray(readiness?.transactions)?readiness.transactions:[]),...(Array.isArray(incidentReadiness?.transactions)?incidentReadiness.transactions:[])].filter(Boolean))],
      openTransactionCount:Number(readiness?.openTransactionCount||0),openIncidentCount:Number(incidentReadiness?.openIncidentCount||0),
      quarantineClearEligible:readiness?.ready===true&&incidentReadiness?.ready===true,conditional:true,authority:false,
    });
  }

  async _commitPortableStackRecoveryResolution(nextState,{resolution=null,incidentStates=[]}={}) {
    return this.authority.withLease(async authorityProof=>{try{return await withWgStackPortableStackMutationLease({store:this.store,ledger:this.ledger,operation:'recovery-readiness-commit',mutationLeaseOptions:this.portableStackRecoveryConfig?.options?.mutationLeaseOptions||{}},async({lease,refresh})=>{
      let readiness;
      try{readiness=await this._inspectPortableStackRecoveryReadiness();}
      catch(error){
        let blocked=this._setPortableStackRecoveryBlocked({openTransactionCount:Number(nextState?.openTransactionCount??0),transactionId:nextState?.transactionId??null,transactions:Array.isArray(nextState?.transactions)?[...nextState.transactions]:[],action:nextState?.action??resolution?.action??null,reason:'recovery-readiness-inspection-failed',reconciliation:resolution??null,readinessInspectionError:String(error?.message??error)});
        try{await this._persistPortableStackRecoveryIncident(blocked);}catch(incidentError){blocked=this.portableStackRecoveryState={...blocked,incidentFallbackPersistenceError:String(incidentError?.message??incidentError)};}
        const wrapped=new WGStackPortableApplicationError('portable stack recovery readiness inspection failed',{cause:error});wrapped.startupRecovery={...blocked};wrapped.reconciliation=resolution;wrapped.recoveryQuarantined=true;throw wrapped;
      }
      if(readiness.ready!==true){
        let blocked=this._setPortableStackRecoveryBlocked({openTransactionCount:Number(readiness.openTransactionCount||0),transactionId:readiness.transactionId??nextState?.transactionId??null,transactions:Array.isArray(readiness.transactions)?[...readiness.transactions]:[],action:nextState?.action??resolution?.action??null,reason:readiness.reason||'recovery-readiness-revalidation-failed',reconciliation:resolution??null,readiness});
        try{await this._persistPortableStackRecoveryIncident(blocked);}catch(incidentError){blocked=this.portableStackRecoveryState={...blocked,incidentFallbackPersistenceError:String(incidentError?.message??incidentError)};}
        const error=new WGStackPortableApplicationError('portable stack recovery readiness revalidation failed');error.startupRecovery={...blocked};error.reconciliation=resolution;error.readiness=readiness;error.recoveryQuarantined=true;throw error;
      }
      assertBrowserAuthorityProof(authorityProof);
      await refresh();
      const incidentIds=[...new Set([...(Array.isArray(incidentStates)?incidentStates:[]).map(state=>state?.transactionId),nextState?.transactionId].filter(Boolean).map(String))];
      const pendingBatchIds=await this._portableStackRecoveryPendingBatchTransactionIds();
      if(pendingBatchIds.some(id=>!incidentIds.includes(id))){
        const blocked=this._setPortableStackRecoveryBlocked({openTransactionCount:0,openIncidentCount:pendingBatchIds.length,transactionId:pendingBatchIds[0]??null,transactions:pendingBatchIds,action:nextState?.action??resolution?.action??null,reason:'recovery-resolution-batch-incomplete',reconciliation:resolution??null,readiness});
        const error=new WGStackPortableApplicationError('portable stack recovery resolution batch is incomplete');error.startupRecovery={...blocked};error.reconciliation=resolution;error.readiness=readiness;error.recoveryQuarantined=true;throw error;
      }
      let resolutionBatch=null;
      if(incidentIds.length){
        const priorBatch=await this._portableStackRecoveryResolutionBatch();
        const batchId=await digest({schema:'xavi-wg-stack-portable-recovery-resolution-batch-id/v1',namespace:this.namespace,transactionIds:incidentIds,mutationLeaseId:lease?.leaseId??null,authorityLeaseId:authorityProof?.leaseId??null,createdAt:Date.now(),nonce:Math.random()});
        resolutionBatch=await this._persistPortableStackRecoveryResolutionBatch({batchId,status:'open',transactionIds:incidentIds,mutationLeaseId:lease?.leaseId??null,authorityLeaseId:authorityProof?.leaseId??null,supersedesBatchId:priorBatch?.status==='open'?priorBatch.batchId:null,createdAt:Date.now(),updatedAt:Date.now()});
      }
      let resolvingState=nextState;
      try{
        for(const state of incidentStates){resolvingState=state;assertBrowserAuthorityProof(authorityProof);await this._persistPortableStackRecoveryIncident(state,{resolved:true,resolution:state.resolution??resolution,resolutionBatch});await refresh();}
        resolvingState=nextState;
        assertBrowserAuthorityProof(authorityProof);await this._persistPortableStackRecoveryIncident(nextState,{resolved:true,resolution,resolutionBatch});
        assertBrowserAuthorityProof(authorityProof);await refresh();
        if(resolutionBatch){
          for(const transactionId of incidentIds){const row=await this.portableStackRecoveryIncident({transactionId});if(row?.status!=='resolved'||row?.resolutionBatchId!==resolutionBatch.batchId||row?.resolutionMutationLeaseId!==resolutionBatch.mutationLeaseId||row?.resolutionAuthorityLeaseId!==resolutionBatch.authorityLeaseId)throw new Error(`portable recovery incident batch binding mismatch: ${transactionId}`);}
        }
      }catch(error){
        const failedTransactionId=resolvingState?.transactionId??nextState?.transactionId??null;
        let blocked=this._setPortableStackRecoveryBlocked({openTransactionCount:Number(nextState?.openTransactionCount??0),transactionId:failedTransactionId,transactions:Array.isArray(nextState?.transactions)?[...nextState.transactions]:[],action:nextState?.action??resolution?.action??null,reason:'incident-resolution-persistence-failed',reconciliation:resolution??null,incidentPersistenceError:String(error?.message??error)});
        try{
          const existing=await this.portableStackRecoveryIncident({transactionId:blocked.transactionId??null});
          if(existing?.status!=='open')await this._persistPortableStackRecoveryIncident(blocked);
        }catch(incidentError){blocked=this.portableStackRecoveryState={...blocked,incidentFallbackPersistenceError:String(incidentError?.message??incidentError)};}
        const wrapped=new WGStackPortableApplicationError('portable stack recovery could not durably resolve recovery incident',{cause:error});
        wrapped.startupRecovery={...blocked};wrapped.reconciliation=resolution;wrapped.recoveryQuarantined=true;throw wrapped;
      }
      await refresh();
      let incidentReadiness;
      try{incidentReadiness=await this._inspectPortableStackRecoveryIncidentReadiness();}
      catch(error){
        let blocked=this._setPortableStackRecoveryBlocked({openTransactionCount:0,openIncidentCount:Number(nextState?.openIncidentCount??0),transactionId:nextState?.transactionId??null,transactions:Array.isArray(nextState?.transactions)?[...nextState.transactions]:[],action:nextState?.action??resolution?.action??null,reason:'recovery-incident-readiness-inspection-failed',reconciliation:resolution??null,readiness,incidentReadinessInspectionError:String(error?.message??error)});
        try{await this._persistPortableStackRecoveryIncident(blocked);}catch(incidentError){blocked=this.portableStackRecoveryState={...blocked,incidentFallbackPersistenceError:String(incidentError?.message??incidentError)};}
        const wrapped=new WGStackPortableApplicationError('portable stack recovery incident readiness inspection failed',{cause:error});wrapped.startupRecovery={...blocked};wrapped.reconciliation=resolution;wrapped.readiness=readiness;wrapped.recoveryQuarantined=true;throw wrapped;
      }
      if(incidentReadiness.ready!==true){
        let blocked=this._setPortableStackRecoveryBlocked({openTransactionCount:0,openIncidentCount:Number(incidentReadiness.openIncidentCount||0),transactionId:incidentReadiness.transactionId??nextState?.transactionId??null,transactions:Array.isArray(incidentReadiness.transactions)?[...incidentReadiness.transactions]:[],action:nextState?.action??resolution?.action??null,reason:incidentReadiness.reason||'recovery-incident-readiness-failed',reconciliation:resolution??null,readiness,incidentReadiness});
        try{const existing=await this.portableStackRecoveryIncident({transactionId:blocked.transactionId??null});if(existing?.status!=='open')await this._persistPortableStackRecoveryIncident(blocked);}catch(incidentError){blocked=this.portableStackRecoveryState={...blocked,incidentFallbackPersistenceError:String(incidentError?.message??incidentError)};}
        const error=new WGStackPortableApplicationError('portable stack recovery incident readiness revalidation failed');error.startupRecovery={...blocked};error.reconciliation=resolution;error.readiness=readiness;error.incidentReadiness=incidentReadiness;error.recoveryQuarantined=true;throw error;
      }
      let readinessAssessment;
      try{readinessAssessment=await this._appendPortableStackRecoveryReadinessAssessment({readiness,incidentReadiness,resolution});}
      catch(error){
        let blocked=this._setPortableStackRecoveryBlocked({openTransactionCount:0,openIncidentCount:0,transactionId:nextState?.transactionId??readiness?.transactionId??null,transactions:Array.isArray(nextState?.transactions)?[...nextState.transactions]:[],action:nextState?.action??resolution?.action??null,reason:'recovery-readiness-assessment-persistence-failed',reconciliation:resolution??null,readiness,incidentReadiness,readinessAssessmentError:String(error?.message??error)});
        try{await this._persistPortableStackRecoveryIncident(blocked);}catch(incidentError){blocked=this.portableStackRecoveryState={...blocked,incidentFallbackPersistenceError:String(incidentError?.message??incidentError)};}
        const wrapped=new WGStackPortableApplicationError('portable stack recovery readiness assessment could not be witnessed',{cause:error});wrapped.startupRecovery={...blocked};wrapped.reconciliation=resolution;wrapped.readiness=readiness;wrapped.incidentReadiness=incidentReadiness;wrapped.recoveryQuarantined=true;throw wrapped;
      }
      await refresh();
      let finalIncidentReadiness;
      try{finalIncidentReadiness=await this._inspectPortableStackRecoveryIncidentReadiness();}
      catch(error){
        let blocked=this._setPortableStackRecoveryBlocked({openTransactionCount:0,openIncidentCount:0,transactionId:nextState?.transactionId??readiness?.transactionId??null,transactions:Array.isArray(nextState?.transactions)?[...nextState.transactions]:[],action:nextState?.action??resolution?.action??null,reason:'recovery-final-incident-readiness-inspection-failed',reconciliation:resolution??null,readiness,incidentReadiness,readinessAssessmentDigest:readinessAssessment?.digest??null,finalIncidentReadinessInspectionError:String(error?.message??error)});
        try{await this._persistPortableStackRecoveryIncident(blocked);}catch(incidentError){blocked=this.portableStackRecoveryState={...blocked,incidentFallbackPersistenceError:String(incidentError?.message??incidentError)};}
        const wrapped=new WGStackPortableApplicationError('portable stack recovery final incident readiness inspection failed',{cause:error});wrapped.startupRecovery={...blocked};wrapped.reconciliation=resolution;wrapped.readiness=readiness;wrapped.incidentReadiness=incidentReadiness;wrapped.readinessAssessment=readinessAssessment;wrapped.recoveryQuarantined=true;throw wrapped;
      }
      if(finalIncidentReadiness.ready!==true){
        let blocked=this._setPortableStackRecoveryBlocked({openTransactionCount:0,openIncidentCount:Number(finalIncidentReadiness.openIncidentCount||0),transactionId:finalIncidentReadiness.transactionId??nextState?.transactionId??null,transactions:Array.isArray(finalIncidentReadiness.transactions)?[...finalIncidentReadiness.transactions]:[],action:nextState?.action??resolution?.action??null,reason:finalIncidentReadiness.reason||'recovery-final-incident-readiness-failed',reconciliation:resolution??null,readiness,incidentReadiness,readinessAssessmentDigest:readinessAssessment?.digest??null,finalIncidentReadiness});
        try{const existing=await this.portableStackRecoveryIncident({transactionId:blocked.transactionId??null});if(existing?.status!=='open')await this._persistPortableStackRecoveryIncident(blocked);}catch(incidentError){blocked=this.portableStackRecoveryState={...blocked,incidentFallbackPersistenceError:String(incidentError?.message??incidentError)};}
        const error=new WGStackPortableApplicationError('portable stack recovery final incident readiness revalidation failed');error.startupRecovery={...blocked};error.reconciliation=resolution;error.readiness=readiness;error.incidentReadiness=incidentReadiness;error.finalIncidentReadiness=finalIncidentReadiness;error.readinessAssessment=readinessAssessment;error.recoveryQuarantined=true;throw error;
      }
      return{nextState,readiness,incidentReadiness:finalIncidentReadiness,readinessAssessment,resolutionBatch,incidentIds};
    },{finalize:async candidate=>{
      assertBrowserAuthorityProof(authorityProof);
      let committedBatch=candidate?.resolutionBatch??null;
      if(committedBatch){
        for(const transactionId of candidate.incidentIds||[]){
          const row=await this.portableStackRecoveryIncident({transactionId});
          if(row?.status!=='resolved'||row?.resolutionBatchId!==committedBatch.batchId||row?.resolutionMutationLeaseId!==committedBatch.mutationLeaseId||row?.resolutionAuthorityLeaseId!==committedBatch.authorityLeaseId)throw new WGStackPortableApplicationError(`portable recovery incident final batch binding mismatch: ${transactionId}`);
        }
        committedBatch=await this._persistPortableStackRecoveryResolutionBatch({...committedBatch,status:'committed',committedAt:Date.now(),updatedAt:Date.now()});
      }
      this.portableStackRecoveryState={...candidate.nextState,readiness:candidate.readiness,incidentReadiness:candidate.incidentReadiness,readinessAssessmentDigest:candidate.readinessAssessment?.digest??null,readinessAssessmentSequence:candidate.readinessAssessment?.sequence??null,resolutionBatchId:committedBatch?.batchId??null,resolutionMutationLeaseId:committedBatch?.mutationLeaseId??null,resolutionAuthorityLeaseId:committedBatch?.authorityLeaseId??null,quarantined:false,checkedAt:Date.now(),authority:false};
      return this.portableStackRecoveryState;
    }});}catch(error){
      if(error?.recoveryQuarantined===true)throw error;
      const batch=await this._portableStackRecoveryResolutionBatch().catch(()=>null);
      const transactions=[...new Set([...(Array.isArray(batch?.transactionIds)?batch.transactionIds:[]),...(Array.isArray(nextState?.transactions)?nextState.transactions:[]),nextState?.transactionId].filter(Boolean).map(String))];
      const blocked=this._setPortableStackRecoveryBlocked({openTransactionCount:Number(nextState?.openTransactionCount??0),openIncidentCount:transactions.length,transactionId:transactions[0]??nextState?.transactionId??null,transactions,action:nextState?.action??resolution?.action??null,reason:'recovery-resolution-final-lease-fence-failed',reconciliation:resolution??null,resolutionBatchId:batch?.batchId??null,resolutionMutationLeaseId:batch?.mutationLeaseId??null,resolutionAuthorityLeaseId:batch?.authorityLeaseId??null,finalFenceError:String(error?.message??error)});
      const wrapped=new WGStackPortableApplicationError('portable stack recovery final lease fence failed',{cause:error});wrapped.startupRecovery={...blocked};wrapped.reconciliation=resolution;wrapped.recoveryQuarantined=true;throw wrapped;
    }});
  }

  async _resumeSelfManagementAfterPortableStackRecovery({source='recovery'}={}) {
    if(typeof this.selfManager?.start!=='function'&&typeof this.selfManager?.activate!=='function')return this.portableStackRecoveryState;
    const assertReady=(readiness,incidentReadiness,pendingBatchIds,phase)=>{
      const pending=Array.isArray(pendingBatchIds)?pendingBatchIds:[];
      if(readiness?.ready===true&&incidentReadiness?.ready===true&&pending.length===0)return;
      const error=new WGStackPortableApplicationError('portable stack recovery self-management resume fence is not ready');
      error.resumeFence={phase,readiness,incidentReadiness,pendingBatchIds:pending};
      throw error;
    };
    return this.authority.withLease(async authorityProof=>{
      try{return await withWgStackPortableStackMutationLease({store:this.store,ledger:this.ledger,operation:'recovery-self-management-resume',mutationLeaseOptions:this.portableStackRecoveryConfig?.options?.mutationLeaseOptions||{}},async({lease,refresh})=>{
        assertBrowserAuthorityProof(authorityProof);
        await refresh();
        const readiness=await this._inspectPortableStackRecoveryReadiness();
        const incidentReadiness=await this._inspectPortableStackRecoveryIncidentReadiness();
        const pendingBatchIds=await this._portableStackRecoveryPendingBatchTransactionIds();
        assertReady(readiness,incidentReadiness,pendingBatchIds,'pre-resume');
        return{readiness,incidentReadiness,pendingBatchIds,mutationLeaseId:lease?.leaseId??null,authorityLeaseId:authorityProof?.leaseId??null};
      },{finalize:async(candidate,{refresh})=>{
        assertBrowserAuthorityProof(authorityProof);
        await refresh();
        const finalReadiness=await this._inspectPortableStackRecoveryReadiness();
        const finalIncidentReadiness=await this._inspectPortableStackRecoveryIncidentReadiness();
        const finalPendingBatchIds=await this._portableStackRecoveryPendingBatchTransactionIds();
        assertReady(finalReadiness,finalIncidentReadiness,finalPendingBatchIds,'final-resume');
        let scheduler=null;
        if(typeof this.selfManager?.activate==='function'){await this.selfManager.activate();scheduler=this.selfManager.schedulerStatus?.()??null;}else this.selfManager?.start?.();
        const resumedAt=Date.now();
        this.portableStackRecoveryState={...this.portableStackRecoveryState,readiness:finalReadiness,incidentReadiness:finalIncidentReadiness,selfManagementResumed:true,selfManagementResumeSource:source,selfManagementResumeMutationLeaseId:candidate.mutationLeaseId,selfManagementResumeAuthorityLeaseId:candidate.authorityLeaseId,selfManagementSchedulerRole:scheduler?.role??(this.selfManager?'legacy':'none'),selfManagementSchedulerLeaseId:scheduler?.leaseId??null,selfManagementSchedulerLeaseExpiresAt:scheduler?.expiresAt??null,selfManagementResumedAt:resumedAt,quarantined:false,checkedAt:resumedAt,authority:false};
        return this.portableStackRecoveryState;
      }});}catch(error){
        if(error?.recoveryQuarantined===true)throw error;
        const fence=error?.resumeFence||{},readiness=fence.readiness??null,incidentReadiness=fence.incidentReadiness??null,pendingBatchIds=Array.isArray(fence.pendingBatchIds)?fence.pendingBatchIds:[];
        const transactions=[...new Set([...(Array.isArray(readiness?.transactions)?readiness.transactions:[]),...(Array.isArray(incidentReadiness?.transactions)?incidentReadiness.transactions:[]),...pendingBatchIds].filter(Boolean).map(String))];
        const reason=pendingBatchIds.length?'recovery-self-management-resume-pending-batch':readiness?.ready===false?(readiness.reason||'recovery-self-management-resume-stack-not-ready'):incidentReadiness?.ready===false?(incidentReadiness.reason||'recovery-self-management-resume-incident-not-ready'):'recovery-self-management-resume-fence-failed';
        let blocked=this._setPortableStackRecoveryBlocked({openTransactionCount:Number(readiness?.openTransactionCount||0),openIncidentCount:Number(incidentReadiness?.openIncidentCount||pendingBatchIds.length||0),transactionId:transactions[0]??readiness?.transactionId??incidentReadiness?.transactionId??null,transactions,action:'self-management-resume',reason,recoveryResumeSource:source,recoveryResumeFencePhase:fence.phase??null,recoveryResumeFenceError:String(error?.message??error)});
        if(blocked.transactionId)try{await this._persistPortableStackRecoveryIncident(blocked);}catch(incidentError){blocked=this.portableStackRecoveryState={...blocked,incidentFallbackPersistenceError:String(incidentError?.message??incidentError)};}
        const wrapped=new WGStackPortableApplicationError('portable stack recovery could not safely resume self-management',{cause:error});wrapped.startupRecovery={...blocked};wrapped.resumeFence=fence;wrapped.recoveryQuarantined=true;throw wrapped;
      }
    });
  }

  async _runPortableStackStartupRecovery() {
    const config=this.portableStackRecoveryConfig||{enabled:false,strict:true,options:{}};
    const finish=(patch={})=>{const status=patch.status??this.portableStackRecoveryState?.status;this.portableStackRecoveryState={...this.portableStackRecoveryState,...patch,checkedAt:Date.now(),quarantined:status==='blocked',authority:false};return this.portableStackRecoveryState;};
    const persistBlocked=async state=>{try{const incident=await this._persistPortableStackRecoveryIncident(state);return finish({...state,incidentKey:this._portableStackRecoveryIncidentKey(state.transactionId??null),incidentDigest:incident?.incidentDigest??null});}catch(error){return finish({...state,incidentPersistenceError:String(error?.message??error)});}};
    const fail=(message,state,cause=null)=>{const error=new WGStackPortableApplicationError(message,{cause});error.startupRecovery={...state};throw error;};
    if(config.enabled!==true)return finish({status:'disabled',enabled:false,reason:'startup-recovery-disabled'});
    let open;
    try{open=await this.listOpenStackPortableTransactions();}
    catch(error){const state=await persistBlocked({status:'blocked',reason:'open-transaction-discovery-failed',error:String(error?.message??error)});if(config.strict)fail('portable stack startup recovery could not inspect open transactions',state,error);return state;}
    if(open.length===0){
      let openIncidents=[];
      try{
        const incidents=await this.portableStackRecoveryIncidents(),pendingBatchIds=await this._portableStackRecoveryPendingBatchTransactionIds(),byId=new Map(incidents.filter(row=>row?.transactionId).map(row=>[String(row.transactionId),row]));
        openIncidents=incidents.filter(row=>row?.status==='open');
        const present=new Set(openIncidents.map(row=>String(row?.transactionId||'')));
        for(const transactionId of pendingBatchIds){if(present.has(transactionId))continue;openIncidents.push(byId.get(transactionId)||{schema:'xavi-wg-stack-portable-recovery-incident/v1',namespace:this.namespace,transactionId,status:'resolution-batch-open',authority:false});present.add(transactionId);}
      }
      catch(error){const state=await persistBlocked({status:'blocked',openTransactionCount:0,reason:'recovery-incident-discovery-failed',error:String(error?.message??error)});if(config.strict)fail('portable stack startup recovery could not inspect recovery incidents',state,error);return state;}
      if(openIncidents.length===0)return finish({status:'clean',openTransactionCount:0,openIncidentCount:0,reason:'no-open-transactions-or-incidents',reconciled:false});
      const transactionIds=[...new Set(openIncidents.map(row=>row?.transactionId).filter(Boolean))];
      if(transactionIds.length!==openIncidents.length){const state=await persistBlocked({status:'blocked',openTransactionCount:0,openIncidentCount:openIncidents.length,transactions:transactionIds,reason:'open-recovery-incident-missing-transaction-id'});if(config.strict)fail('portable stack startup recovery found an unscoped open recovery incident',state);return state;}
      const resolutions=[];
      for(const transactionId of transactionIds){
        let resolution;
        try{resolution=await this.reconcileStackPortableRecovery({stackTransactionId:transactionId,mutationLeaseOptions:config.options?.mutationLeaseOptions||{},manageRecoveryLifecycle:false});}
        catch(error){const state=await persistBlocked({status:'blocked',openTransactionCount:0,openIncidentCount:openIncidents.length,transactionId,transactions:transactionIds,reason:'open-recovery-incident-verification-failed',error:String(error?.message??error)});if(config.strict)fail('portable stack startup recovery could not verify an open recovery incident',state,error);return state;}
        const safe=resolution?.reconciled===true||(resolution?.action==='none'&&resolution?.inspection?.recovery_required!==true);
        if(!safe){const state=await persistBlocked({status:'blocked',openTransactionCount:0,openIncidentCount:openIncidents.length,transactionId,transactions:transactionIds,action:resolution?.action??null,reason:resolution?.reason||'open-recovery-incident-manual-review-required',reconciliation:resolution});if(config.strict)fail('portable stack startup recovery requires manual review of an open recovery incident',state);return state;}
        resolutions.push({transactionId,resolution});
      }
      const state={...this.portableStackRecoveryState,status:'clean',openTransactionCount:0,openIncidentCount:openIncidents.length,transactionId:null,transactions:transactionIds,action:'resolved-audit-only-incidents',reason:'open-recovery-incidents-resolved',reconciled:false,quarantined:false,checkedAt:Date.now(),authority:false};
      const incidentStates=resolutions.map(({transactionId,resolution})=>({...state,transactionId,resolution}));
      try{await this._commitPortableStackRecoveryResolution(state,{resolution:{action:'resolved-audit-only-incidents',reason:'open-recovery-incidents-resolved',results:resolutions,authority:false},incidentStates});}
      catch(error){if(config.strict)throw error;return this.portableStackRecoveryState;}
      return this.portableStackRecoveryState;
    }
    if(open.length>1){
      const transactions=open.slice().sort((a,b)=>Number(b.started_sequence??0)-Number(a.started_sequence??0)).map(row=>row.stack_transaction_id);
      let chain;
      try{chain=await this.reconcileStackPortableRecoveryChain({maxTransactions:config.options?.maxTransactions??8,mutationLeaseOptions:config.options?.mutationLeaseOptions||{},manageRecoveryLifecycle:false});}
      catch(error){const state=await persistBlocked({status:'blocked',openTransactionCount:open.length,transactions,reason:'recovery-chain-error',error:String(error?.message??error)});if(config.strict)fail('portable stack startup recovery failed during reverse-chain reconciliation',state,error);return state;}
      if(chain?.reconciled!==true){const state=await persistBlocked({status:'blocked',openTransactionCount:open.length,transactions,transactionId:chain?.failed_transaction_id??null,action:chain?.action??null,reason:chain?.reason||'multiple-open-transactions-manual-review-required',reconciled:false,reconciliationChain:chain});if(config.strict)fail('portable stack startup recovery requires manual review of multiple open transactions',state);return state;}
      const state={...this.portableStackRecoveryState,status:'reconciled',openTransactionCount:open.length,transactionId:null,transactions,action:chain.action,reason:chain.reason,reconciled:true,reconciliationChain:chain,quarantined:false,checkedAt:Date.now(),authority:false};
      const incidentStates=(chain?.results||[]).map(result=>{const tx=result?.inspection?.stack_transaction_id??null;return tx?{...state,transactionId:tx,resolution:result}:null;}).filter(Boolean);
      try{await this._commitPortableStackRecoveryResolution(state,{resolution:chain,incidentStates});}
      catch(error){if(config.strict)throw error;return this.portableStackRecoveryState;}
      return this.portableStackRecoveryState;
    }
    const transaction=open[0],transactionId=transaction.stack_transaction_id;
    let reconciliation;
    try{reconciliation=await this.reconcileStackPortableRecovery({stackTransactionId:transactionId,mutationLeaseOptions:config.options?.mutationLeaseOptions||{},manageRecoveryLifecycle:false});}
    catch(error){const state=await persistBlocked({status:'blocked',openTransactionCount:1,transactionId,reason:'reconciliation-error',error:String(error?.message??error)});if(config.strict)fail('portable stack startup recovery failed during reconciliation',state,error);return state;}
    const reconciled=reconciliation?.reconciled===true;
    const consistentNoop=reconciliation?.action==='none'&&reconciliation?.inspection?.recovery_required!==true;
    if(!reconciled&&!consistentNoop){const state=await persistBlocked({status:'blocked',openTransactionCount:1,transactionId,action:reconciliation?.action??null,reason:reconciliation?.reason||'manual-review-required',reconciled:false,reconciliation});if(config.strict)fail('portable stack startup recovery requires manual review',state);return state;}
    const state={...this.portableStackRecoveryState,status:reconciled?'reconciled':'clean',openTransactionCount:1,transactionId,action:reconciliation?.action??'none',reason:reconciliation?.reason??null,reconciled,reconciliation,quarantined:false,checkedAt:Date.now(),authority:false};
    try{await this._commitPortableStackRecoveryResolution(state,{resolution:reconciliation});}
    catch(error){if(config.strict)throw error;return this.portableStackRecoveryState;}
    return this.portableStackRecoveryState;
  }

  async rebuildSemanticCalibration() {
    if (!this.semantic) throw new Error('semantic routing disabled');
    return this.authority.withLease(async authorityProof => {
      const before=this.semantic.heads.exportState();
      const beforeDigest=await digest(before.calibration||{});
      try {
        const preview=await this.semantic.heads.rebuildCalibrationFromWitnesses({persist:false});
        const calibrationDigest=await digest(preview.calibration);
        const latest=await this.store.get('records','semantic-calibration-rebuild-latest');
        if (latest?.assessmentCount===preview.assessmentCount && latest?.sourceLastDigest===preview.sourceLastDigest && latest?.calibrationDigest===calibrationDigest && beforeDigest===calibrationDigest) {
          return {...preview,calibrationDigest,rebuilt:false,skipped:true,receipt:null};
        }
        const rebuilt=await this.semantic.heads.rebuildCalibrationFromWitnesses({persist:true,authorityProof});
        const receipt=await this.ledger.append('semantic-calibration-rebuilt',{
          assessmentCount:rebuilt.assessmentCount,sourceFirstSequence:rebuilt.sourceFirstSequence,sourceLastSequence:rebuilt.sourceLastSequence,sourceLastDigest:rebuilt.sourceLastDigest,calibrationDigest,operationCount:Object.keys(rebuilt.calibration||{}).filter(id=>id.startsWith('operation:')).length,semanticAuthority:false,policyMutation:true,
        });
        const record={schema:'xavi-semantic-calibration-rebuild-state/v1',assessmentCount:rebuilt.assessmentCount,sourceLastDigest:rebuilt.sourceLastDigest,calibrationDigest,receiptDigest:receipt.digest,updatedAt:Date.now(),authority:false};
        await this.store.set('records','semantic-calibration-rebuild-latest',record);
        await this.semantic.commitDurableState({authorityProof,source:'semantic-calibration-rebuild'});
        this.bus?.publish({type:'semantic-calibration-rebuilt',sourceLastDigest:rebuilt.sourceLastDigest,updatedAt:record.updatedAt});
        return {...rebuilt,calibrationDigest,rebuilt:true,skipped:false,receipt};
      } catch (error) {
        await this.semantic.heads.importState(before,{persist:true,replace:true,authorityProof}).catch(()=>{});
        throw error;
      }
    });
  }

  async observe(event, { epistemicStatus='observed', evidence={observedDirectly:true}, provenance={sourceKind:'browser'}, freshness={observedAt:Date.now()}, dependencies=[] } = {}) {
    this._assertPortableStackOperational?.('observe');
    const sfmInference=this.sfm?.infer(event,{domain:'runtime'})||null;
    const candidate = this.recurrent.candidate(event,{teacherState:sfmInference?.fieldState||null,teacherConfidence:sfmInference?.confidence||0,teacherBlend:sfmInference?.teacherBlend||0});
    const stateAssessment = this.gate.assessState(candidate.state);
    const stateWitness = await this.ledger.append('state-candidate', {assessment:stateAssessment, eventDigest:await digest(event), wgSfm:this.sfm?.publicProjection(sfmInference)||null, sharedCellTeacher:candidate.teacher||null});
    if (!stateAssessment.admissible) return {committed:false, stateAssessment, stateWitness};

    const snapshot = await this.authority.withLease(async () => {
      const committed = this.recurrent.commit(candidate);
      await this.store.set('state','recurrent',committed);
      return committed;
    });
    const retention = this.gate.assessRetention({epistemicStatus,evidence,provenance,freshness,dependencies,addressable:true});
    const receipt = await this.ledger.append('state-committed', {parentCandidate:stateWitness.digest, retention, steps:snapshot.steps});
    if(this.autoRetention) this.autoRetention.enqueueObservation({event,receipt,retention,provenance,freshness,evidence,dependencies});
    return {committed:true, stateAssessment, retention, receipt, snapshot, sfm:this.sfm?.publicProjection(sfmInference)||null, sfmTraining:sfmInference?{operation:sfmInference.operation,confidence:sfmInference.confidence,inputVector:sfmInference.inputVector,fieldState:sfmInference.fieldState,expectedWitnessType:sfmInference.expectedWitnessType,expectedWitnessDelta:sfmInference.expectedWitnessDelta,authority:false}:null, autoRetentionQueued:Boolean(this.autoRetention)};
  }

  async witnessStackCapabilityHandshake({localDescriptor,remoteDescriptor,stackManifest,peerLabel=null}={}) {
    this._assertPortableStackOperational?.('witnessStackCapabilityHandshake');
    return witnessWgStackCapabilityHandshake({ledger:this.ledger,localDescriptor,remoteDescriptor,stackManifest,peerLabel});
  }

  async stackCapabilityHandshakeHistory(options={}) {
    return inspectWgStackCapabilityHandshakeHistory({store:this.store,...options});
  }

  async planStackPortableImport(options={}) {
    return planWgStackPortableImport(options);
  }

  async witnessStackPortableImportPlan(options={}) {
    this._assertPortableStackOperational?.('witnessStackPortableImportPlan');
    return witnessWgStackPortableImportPlan({ledger:this.ledger,...options});
  }

  async stageStackPortableImport(options={}) {
    return stageWgStackPortableImport(options);
  }

  async witnessStackPortableImportStage(options={}) {
    this._assertPortableStackOperational?.('witnessStackPortableImportStage');
    return witnessWgStackPortableStage({ledger:this.ledger,...options});
  }

  async assessStackPortableFamilyAdmission(options={}) {
    return assessWgStackPortableFamilyAdmission(options);
  }

  async witnessStackPortableFamilyAdmission(options={}) {
    this._assertPortableStackOperational?.('witnessStackPortableFamilyAdmission');
    return witnessWgStackPortableFamilyAdmission({ledger:this.ledger,...options});
  }

  async evaluateStackPortableFamilyGate(options={}) {
    return evaluateWgStackPortableFamilyGate(options);
  }

  async witnessStackPortableFamilyGateDecision(options={}) {
    this._assertPortableStackOperational?.('witnessStackPortableFamilyGateDecision');
    return witnessWgStackPortableFamilyGateDecision({ledger:this.ledger,...options});
  }

  async witnessStackPortableApplicationPermit(options={}) {
    this._assertPortableStackOperational?.('witnessStackPortableApplicationPermit');
    return witnessWgStackPortableApplicationPermit({ledger:this.ledger,...options});
  }

  async applyStackPortableFamilyTransaction(options={}) {
    this._assertPortableStackOperational?.('applyStackPortableFamilyTransaction');
    return applyWgStackPortableFamilyTransaction({recurrent:this.recurrent,sfm:this.sfm,srnn:this.srnn,store:this.store,ledger:this.ledger,...options});
  }

  async applyStackPortableStackTransaction(options={}) {
    this._assertPortableStackOperational?.('applyStackPortableStackTransaction');
    return this.authority.withLease(async () => applyWgStackPortableStackTransaction({recurrent:this.recurrent,sfm:this.sfm,srnn:this.srnn,store:this.store,ledger:this.ledger,...options}));
  }

  async inspectStackPortableRecovery(options={}) {
    return inspectWgStackPortableStackRecovery({recurrent:this.recurrent,sfm:this.sfm,srnn:this.srnn,ledger:this.ledger,...options});
  }

  async listOpenStackPortableTransactions(options={}) {
    return listWgStackPortableOpenTransactions({recurrent:this.recurrent,sfm:this.sfm,srnn:this.srnn,ledger:this.ledger,...options});
  }

  async reconcileStackPortableRecoveryChain(options={}) {
    const {manageRecoveryLifecycle=true,...reconcileOptions}=options||{};
    const wasQuarantined=this.portableStackRecoveryState?.quarantined===true||this.portableStackRecoveryState?.status==='blocked';
    const out=await this.authority.withLease(async () => reconcileWgStackPortableStackRecoveryChain({recurrent:this.recurrent,sfm:this.sfm,srnn:this.srnn,store:this.store,ledger:this.ledger,...reconcileOptions}));
    const safe=out?.reconciled===true||(out?.action==='none'&&Array.isArray(out?.remaining_open_transactions)&&out.remaining_open_transactions.length===0);
    if(safe){
      const transactions=Array.isArray(out?.transactions)?[...out.transactions]:[];
      const priorAuditTransactions=[this.portableStackRecoveryState?.transactionId,...(Array.isArray(this.portableStackRecoveryState?.transactions)?this.portableStackRecoveryState.transactions:[])].filter(Boolean);
      const incidentTransactionIds=[...new Set([...transactions,...priorAuditTransactions])];
      const nextState={...this.portableStackRecoveryState,status:out.reconciled?'reconciled':'clean',openTransactionCount:transactions.length,transactionId:null,transactions:incidentTransactionIds,action:out?.action??null,reason:out?.reason??null,reconciled:out?.reconciled===true,quarantined:false,checkedAt:Date.now(),authority:false};
      const resultByTransaction=new Map((out?.results||[]).map(result=>[result?.inspection?.stack_transaction_id,result]).filter(([tx])=>Boolean(tx)));
      const incidentStates=incidentTransactionIds.map(tx=>({...nextState,transactionId:tx,resolution:resultByTransaction.get(tx)||out}));
      if(manageRecoveryLifecycle){await this._commitPortableStackRecoveryResolution(nextState,{resolution:out,incidentStates});if(wasQuarantined)await this._resumeSelfManagementAfterPortableStackRecovery({source:'reconcile-chain'});}
    }else if(out?.action==='manual-review-required'&&manageRecoveryLifecycle){
      const blocked=this._setPortableStackRecoveryBlocked({openTransactionCount:Number(out?.remaining_open_transactions?.length??0),transactionId:out?.failed_transaction_id??null,transactions:(out?.remaining_open_transactions||[]).map(row=>row?.stack_transaction_id).filter(Boolean),action:out.action,reason:out.reason??'manual-review-required'});
      try{await this._persistPortableStackRecoveryIncident(blocked);}catch(error){this.portableStackRecoveryState={...blocked,incidentPersistenceError:String(error?.message??error)};}
    }
    return out;
  }

  async reconcileStackPortableRecovery(options={}) {
    const {manageRecoveryLifecycle=true,...reconcileOptions}=options||{};
    const wasQuarantined=this.portableStackRecoveryState?.quarantined===true||this.portableStackRecoveryState?.status==='blocked';
    const out=await this.authority.withLease(async () => reconcileWgStackPortableStackRecovery({recurrent:this.recurrent,sfm:this.sfm,srnn:this.srnn,store:this.store,ledger:this.ledger,...reconcileOptions}));
    const safe=out?.reconciled===true||(out?.action==='none'&&out?.inspection?.recovery_required!==true);
    if(safe){
      const nextState={...this.portableStackRecoveryState,status:out.reconciled?'reconciled':'clean',transactionId:out?.inspection?.stack_transaction_id??this.portableStackRecoveryState?.transactionId??null,action:out?.action??null,reason:out?.reason??null,reconciled:out?.reconciled===true,quarantined:false,checkedAt:Date.now(),authority:false};
      if(manageRecoveryLifecycle){await this._commitPortableStackRecoveryResolution(nextState,{resolution:out});if(wasQuarantined)await this._resumeSelfManagementAfterPortableStackRecovery({source:'reconcile-single'});}
    }else if(out?.action==='manual-review-required'&&manageRecoveryLifecycle){
      const blocked=this._setPortableStackRecoveryBlocked({transactionId:out?.inspection?.stack_transaction_id??this.portableStackRecoveryState?.transactionId??null,action:out.action,reason:out.reason??'manual-review-required'});
      try{await this._persistPortableStackRecoveryIncident(blocked);}catch(error){this.portableStackRecoveryState={...blocked,incidentPersistenceError:String(error?.message??error)};}
    }
    return out;
  }

  async remember(record, options = {}) {
    this._assertPortableStackOperational?.('remember');
    const retention = this.gate.assessRetention({
      epistemicStatus: options.epistemicStatus || 'observed',
      evidence: options.evidence || {observedDirectly:true},
      provenance: options.provenance || {sourceKind:'browser'},
      freshness: options.freshness || {observedAt:Date.now()},
      dependencies: options.dependencies || [], addressable:true,
    });
    const id = await digest({namespace:this.namespace, record});
    const witness = await this.ledger.append('memory-retention-assessment', {id, retention});
    const row={id, record, retention, witnessDigest:witness.digest, witnessId:witness.id, retainedAt:Date.now()};
    await this.store.set('records', id, row);
    if (options.index !== false) await this.memory.indexRetainedRecord(row,{text:options.text ?? null,kind:options.kind || 'memory',metadata:options.metadata || {}});
    return {id, retention, witness};
  }

  async recallForRouting(capability, context = {}, option = true, semanticPreview = null) {
    const cfg=normalizeRoutingRecall(capability,context,option);
    if(!cfg) return null;
    const vectorRecall=await this.memory.recall(cfg.query,cfg.options);
    const patternRecall=cfg.pattern.enabled&&semanticPreview&&Number(this.episodePatterns?.stats?.().count||0)>0
      ? await this.episodePatterns.recall({capability,semantic:semanticPreview},{limit:cfg.pattern.limit,minPatternScore:cfg.pattern.minPatternScore,witness:true})
      : null;
    const recall=mergeRoutingRecall(vectorRecall,patternRecall,cfg.options.limit);this._recordMemoryRecallResult(recall);
    return {config:cfg,recall,vectorRecall,patternRecall,public:compactRoutingMemory(recall,semanticPreview)};
  }

  _recordMemoryRecallDecision(decision) {
    if(!decision)return decision;
    const t=this.memoryRecallTelemetry||(this.memoryRecallTelemetry={startedAt:Date.now(),decisions:0,recalls:0,skips:0,explicitEnable:0,explicitDisable:0,triggerCounts:{},last:null});
    t.decisions+=1;if(decision.recall)t.recalls+=1;else t.skips+=1;
    for(const trigger of decision.triggers||[]){const key=String(trigger);t.triggerCounts[key]=(t.triggerCounts[key]||0)+1;if(key==='explicit-enable')t.explicitEnable+=1;if(key==='explicit-disable')t.explicitDisable+=1;}
    t.last={at:Date.now(),recall:Boolean(decision.recall),enabled:Boolean(decision.enabled),triggers:[...(decision.triggers||[])].slice(0,12),indexCount:Number(decision.indexCount||0),episodePatternCount:Number(decision.episodePatternCount||0),semantic:decision.semantic?{intent:decision.semantic.intent??null,uncertainty:decision.semantic.uncertainty??null,conflict:decision.semantic.conflict??null,witnessContinuity:decision.semantic.witnessContinuity??null,gatePressure:decision.semantic.gatePressure??null}:null,authority:false};
    return decision;
  }

  _recordMemoryRecallResult(recall) {
    if(!recall)return recall;
    const t=this.memoryRecallTelemetry||(this.memoryRecallTelemetry={startedAt:Date.now(),decisions:0,recalls:0,skips:0,explicitEnable:0,explicitDisable:0,triggerCounts:{},last:null});
    const v=recall.vectorRecall?.diagnostics||{},p=recall.patternRecall?.diagnostics||{},m=recall.diagnostics||{};
    const totals=t.resultTotals||(t.resultTotals={calls:0,vector:{rawHits:0,missingRecord:0,retired:0,missingWitness:0,accepted:0,returned:0},pattern:{bucketCandidates:0,scoredCandidates:0,missingRecord:0,retired:0,wrongKind:0,accepted:0,returned:0},merge:{mergedCandidates:0,returned:0,duplicateCollapses:0}});
    totals.calls+=1;
    for(const k of ['rawHits','missingRecord','retired','missingWitness','accepted','returned'])totals.vector[k]+=Number(v[k]||0);
    for(const k of ['bucketCandidates','scoredCandidates','missingRecord','retired','wrongKind','accepted','returned'])totals.pattern[k]+=Number(p[k]||0);
    for(const k of ['mergedCandidates','returned','duplicateCollapses'])totals.merge[k]+=Number(m[k]||0);
    t.lastResult={at:Date.now(),vector:v?{rawHits:Number(v.rawHits||0),missingRecord:Number(v.missingRecord||0),retired:Number(v.retired||0),missingWitness:Number(v.missingWitness||0),accepted:Number(v.accepted||0),returned:Number(v.returned||0)}:null,pattern:recall.patternRecall?{bucketCandidates:Number(p.bucketCandidates||0),scoredCandidates:Number(p.scoredCandidates||0),missingRecord:Number(p.missingRecord||0),retired:Number(p.retired||0),wrongKind:Number(p.wrongKind||0),accepted:Number(p.accepted||0),returned:Number(p.returned||0)}:null,merge:{mergedCandidates:Number(m.mergedCandidates||0),returned:Number(m.returned||0),duplicateCollapses:Number(m.duplicateCollapses||0)},authority:false};
    return recall;
  }

  memoryRecallStatus() {
    const t=this.memoryRecallTelemetry||{startedAt:Date.now(),decisions:0,recalls:0,skips:0,explicitEnable:0,explicitDisable:0,triggerCounts:{},last:null};
    return{schema:'xavi-memory-recall-telemetry/v1',startedAt:t.startedAt,decisions:t.decisions,recalls:t.recalls,skips:t.skips,recallRate:t.decisions?t.recalls/t.decisions:0,explicitEnable:t.explicitEnable,explicitDisable:t.explicitDisable,triggerCounts:{...t.triggerCounts},thresholds:{...this.memoryRecallThresholds},vectorCount:Number(this.vectorMemory?.stats?.().count||0),episodePatternCount:Number(this.episodePatterns?.stats?.().count||0),autoRetention:this.autoRetention?.status?.()||null,resultTotals:t.resultTotals?structuredClone(t.resultTotals):{calls:0,vector:{rawHits:0,missingRecord:0,retired:0,missingWitness:0,accepted:0,returned:0},pattern:{bucketCandidates:0,scoredCandidates:0,missingRecord:0,retired:0,wrongKind:0,accepted:0,returned:0},merge:{mergedCandidates:0,returned:0,duplicateCollapses:0}},last:t.last?structuredClone(t.last):null,lastResult:t.lastResult?structuredClone(t.lastResult):null,authority:false};
  }

  _adaptiveRecallDecision(choice, capability, context = {}) {
    const semantic=choice?.semantic||null,stats=this.vectorMemory?.stats?.()||null,count=Number(stats?.count||0),patternCount=Number(this.episodePatterns?.stats?.().count||0);
    const triggers=[];
    if(String(semantic?.intent||'')==='recall')triggers.push('intent:recall');
    if(Number.isFinite(Number(semantic?.uncertainty))&&Number(semantic.uncertainty)>=this.memoryRecallThresholds.uncertainty)triggers.push('uncertainty');
    if(Number.isFinite(Number(semantic?.conflict))&&Number(semantic.conflict)>=this.memoryRecallThresholds.conflict)triggers.push('conflict');
    if(Number.isFinite(Number(semantic?.witnessContinuity))&&Number(semantic.witnessContinuity)<=this.memoryRecallThresholds.continuity)triggers.push('low-continuity');
    if(Number.isFinite(Number(semantic?.gatePressure))&&Number(semantic.gatePressure)>=this.memoryRecallThresholds.gatePressure)triggers.push('gate-pressure');
    if(context?.memoryNeeded===true||context?.recall===true)triggers.push('context-request');
    return{schema:'xavi-adaptive-memory-recall/v1',enabled:this.adaptiveMemoryRecall,indexCount:count,episodePatternCount:patternCount,recall:this.adaptiveMemoryRecall&&(count>0||patternCount>0)&&triggers.length>0,triggers,semantic:{intent:semantic?.intent??null,uncertainty:semantic?.uncertainty??null,conflict:semantic?.conflict??null,witnessContinuity:semantic?.witnessContinuity??null,gatePressure:semantic?.gatePressure??null},authority:false};
  }

  async _prepareRoutingContext(capability, context = {}, option = 'auto', {explore=false,excludeStrategyIds=[]} = {}) {
    const evidenceSession=this.evidenceSessions?await this.evidenceSessions.prepare(capability,context):null;const evidenceSourceCalibration=this.evidenceSessions?.calibrationSnapshot?.()||{},evidenceClaimTarget=evidenceClaimTargetFromSession(evidenceSession,context),claimContext=evidenceClaimTarget?{...context,...(evidenceClaimTarget.claimKey?{evidenceClaimKey:evidenceClaimTarget.claimKey}:{}),evidenceClaimTarget}:{...context};const sessionContext=evidenceSession?{...claimContext,evidenceSession,evidenceSourceCalibration}: {...claimContext,evidenceSourceCalibration};
    const wgSrnn=this.srnn?.publicProjection({capability})||null;const selfContext=wgSrnn?{...sessionContext,wgSrnn}:sessionContext;
    const sfmPreview=this.sfm?.infer({capability,context:selfContext},{domain:'router'})||null;const sfmContext=sfmPreview?{...selfContext,wgSfm:this.sfm.publicProjection(sfmPreview)}:selfContext;
    const carried=this.planContinuations?.peek(capability)||null;const baseContext=carried?{...sfmContext,planContinuation:carried}:sfmContext;
    if(option===false){const memoryDecision=this._recordMemoryRecallDecision({schema:'xavi-adaptive-memory-recall/v1',enabled:false,recall:false,indexCount:Number(this.vectorMemory?.stats?.().count||0),episodePatternCount:Number(this.episodePatterns?.stats?.().count||0),triggers:['explicit-disable'],planContinuationId:carried?.id||null,authority:false});return{context:baseContext,memory:null,choice:null,evidenceSession,memoryDecision};}
    if(option==='auto'||option==null){
      const choice=this.router.select(capability,baseContext,{explore,excludeStrategyIds});
      const memoryDecision=this._recordMemoryRecallDecision({...this._adaptiveRecallDecision(choice,capability,baseContext),planContinuationId:carried?.id||null});
      if(!memoryDecision.recall)return{context:baseContext,memory:null,choice,evidenceSession,memoryDecision};
      const memory=await this.recallForRouting(capability,baseContext,true,choice.semantic);
      if(!memory||!memory.config.inject)return{context:baseContext,memory,choice,evidenceSession,memoryDecision};
      return{context:{...baseContext,memoryEvidence:memory.public},memory,choice:null,evidenceSession,memoryDecision};
    }
    const choice=this.router.select(capability,baseContext,{explore,excludeStrategyIds});
    const memory=await this.recallForRouting(capability,baseContext,option,choice.semantic);
    const memoryDecision=this._recordMemoryRecallDecision({schema:'xavi-adaptive-memory-recall/v1',enabled:this.adaptiveMemoryRecall,recall:Boolean(memory),indexCount:Number(this.vectorMemory?.stats?.().count||0),episodePatternCount:Number(this.episodePatterns?.stats?.().count||0),planContinuationId:carried?.id||null,triggers:['explicit-enable'],authority:false});
    if(!memory || !memory.config.inject) return {context:baseContext,memory,choice,evidenceSession,memoryDecision};
    return {context:{...baseContext,memoryEvidence:memory.public},memory,choice:null,evidenceSession,memoryDecision};
  }

  async propose(capability, context = {}, {witness=true,memoryRecall='auto',excludeStrategyIds=[]} = {}) {
    this._assertPortableStackOperational?.('propose');
    const routing=await this._prepareRoutingContext(capability,context,memoryRecall,{explore:false,excludeStrategyIds});
    const choice=routing.choice||this.router.select(capability,routing.context,{explore:false,excludeStrategyIds});
    const semantic=publicSemanticDecision(choice.semantic);
    const memory= routing.memory?.public || null;
    const proposal={schema:'xavi-semantic-route-proposal/v1',capability,strategyId:choice.strategy.id,score:choice.score,baseScore:choice.baseScore??choice.score,ranked:choice.ranked,smallModelRuntime:choice.strategy.metadata?.smallModelRuntime||null,semantic,memory,wgSrnn:compactWgSrnnContext(routing.context?.wgSrnn),evidenceSession:compactEvidenceSession(routing.evidenceSession),memoryDecision:routing.memoryDecision||null,authority:false};
    let receipt=null;
    if(witness) receipt=await this.ledger.append('semantic-route-proposal',{...proposal,contextDigest:await digest(context),memoryRecallWitnessDigest:memory?.witness?.digest || null,memoryPatternRecallWitnessDigest:memory?.patternWitness?.digest || null});
    return {...proposal,witness:receipt?{id:receipt.id,digest:receipt.digest,sequence:receipt.sequence}:null};
  }

  async execute(capability, context = {}, options = {}) {
    this._assertPortableStackOperational?.('execute');
    const explore=options.explore!==false;
    const routing=await this._prepareRoutingContext(capability,context,options.memoryRecall===undefined?'auto':options.memoryRecall,{explore,excludeStrategyIds:options.excludeStrategyIds||[]});
    const routedContext=routing.context;
    const observation = await this.observe({type:'execution-context', capability, context:routedContext}, {
      provenance:{sourceKind:'browser-runtime'}, evidence:{observedDirectly:true}, freshness:{observedAt:Date.now()}
    });
    const choice = routing.choice || this.router.select(capability, routedContext, {explore,excludeStrategyIds:options.excludeStrategyIds||[]});
    const selectedEpisodePlan = selectWitnessEpisodeTransitionPlanForStrategy(choice.semantic?.episodicPlan||null,choice.strategy.id);
    const semanticDecision = publicSemanticDecision(choice.semantic);
    const routeWitness = await this.ledger.append('route-selected', {
      capability, strategyId:choice.strategy.id, score:choice.score, baseScore:choice.baseScore ?? choice.score, ranked:choice.ranked, smallModelRuntime:choice.strategy.metadata?.smallModelRuntime||null, runtimePolicy:choice.runtimeDecision||null,
      semantic: semanticDecision, wgSfm:observation.sfm||routedContext?.wgSfm||null, wgSrnn:compactWgSrnnContext(routedContext?.wgSrnn), costRegimePersistence:publicCostRegimePersistence(choice.semantic?.evidenceResolutionSchedule),
      stateWitnessDigest:observation.receipt?.digest || observation.stateWitness?.digest || null,
      memoryRecallWitnessDigest:routing.memory?.recall?.receipt?.digest || null, memoryPatternRecallWitnessDigest:routing.memory?.recall?.patternReceipt?.digest || null, evidenceSession:compactEvidenceSession(routing.evidenceSession), memoryDecision:routing.memoryDecision||null,
    });
    if (observation.receipt?.id) this.credit.link(routeWitness.id, observation.receipt.id, 0.35);
    if (routing.memory?.recall?.receipt?.id) this.credit.link(routeWitness.id, routing.memory.recall.receipt.id, 0.40);
    if (routing.memory?.recall?.patternReceipt?.id) this.credit.link(routeWitness.id, routing.memory.recall.patternReceipt.id, 0.40);
    const evidenceSessionDecision=routing.evidenceSession?await this.evidenceSessions?.recordSufficiency?.(routing.evidenceSession.id,choice.semantic?.evidenceSufficiency||null,{routeWitnessDigest:routeWitness.digest}):null;
    const srnnGoal=wgSrnnGoalFromContext(context);
    const srnnDirective=this.srnn?await this.srnn.proposeDirective({author:'wg-rnn',capability,strategyId:choice.strategy.id,goal:srnnGoal,proposedAction:semanticDecision?.nextOperation||choice.strategy.id,justificationEdges:[routeWitness.digest,routing.memory?.recall?.receipt?.digest,routing.memory?.recall?.patternReceipt?.digest,evidenceSessionDecision?.witness?.digest].filter(Boolean),sourceStateDigest:observation.receipt?.digest||observation.stateWitness?.digest||null,routeWitnessDigest:routeWitness.digest,confidence:semanticDecision?.confidence??choice.semantic?.confidence??0.5,expectedOutcome:wgSrnnExpectedOutcome(semanticDecision),semantic:semanticDecision,wgSfm:observation.sfm||routedContext?.wgSfm||null,selfContext:routedContext?.wgSrnn||null,commit:wgSrnnShouldCommit(context,srnnGoal)}):null;
    const srnnAssessmentSpec=srnnDirective?wgSrnnAssessmentSpec({semantic:semanticDecision,wgSfm:observation.sfm||routedContext?.wgSfm||null,evidenceWitnessDigests:[routeWitness.digest,observation.receipt?.digest,observation.stateWitness?.digest,routing.memory?.recall?.receipt?.digest,routing.memory?.recall?.patternReceipt?.digest,evidenceSessionDecision?.witness?.digest]}):null;
    const srnnAssessment=srnnDirective&&srnnAssessmentSpec?await this.srnn.assessDirective({directiveDigest:srnnDirective.witness.digest,...srnnAssessmentSpec}):null;
    const pending = {receiptId:routeWitness.id, receiptDigest:routeWitness.digest, capability, strategyId:choice.strategy.id, smallModelRuntime:choice.strategy.metadata?.smallModelRuntime||null, features:choice.features, semanticFeatures:choice.semanticFeatures || null, semanticDecision, sfmTraining:observation.sfmTraining||null, costRegimePersistence:routeWitness.body?.costRegimePersistence||null, memoryRecallWitnessDigest:routing.memory?.recall?.receipt?.digest || null, memoryPatternRecallWitnessDigest:routing.memory?.recall?.patternReceipt?.digest || null, routingMemoryEvidence:routing.memory?.public?.evidence || [], routingEpisodeHints:routing.memory?.public?.episodeHints || [], memoryDecision:routing.memoryDecision||null, evidenceSessionId:routing.evidenceSession?.id||null,evidenceSessionKeyDigest:routing.evidenceSession?.keyDigest||null,evidenceSessionDecisionWitnessDigest:evidenceSessionDecision?.witness?.digest||null, wgSrnnDirectiveDigest:srnnDirective?.witness?.digest||null, wgSrnnDirectiveId:srnnDirective?.directive?.directiveId||null, wgSrnnCommitmentId:srnnDirective?.commitment?.commitment?.commitmentId||null, wgSrnnSemanticAssessmentDigest:srnnAssessment?.witness?.digest||null, wgSrnnSemanticAssessmentVerdict:srnnAssessment?.assessment?.verdict||null, wgSrnnSemanticAssessmentProvenanceGroups:srnnAssessment?.assessment?.provenanceGroups||[], wgSrnnLessonAdvice:srnnDirective?.directive?.lessonAdvice||[], selectedEpisodePlan:selectedEpisodePlan||null, planContinuationId:semanticDecision?.episodicPlan?.continuationId||routedContext?.planContinuation?.id||null, contextDigest:await digest(context), createdAt:Date.now()};
    this.pending.set(routeWitness.id, pending);
    await this.store.set('records', `pending:${routeWitness.id}`, pending);
    const runtimeOptions = {...options, timeoutMs: options.timeoutMs ?? choice.strategy.timeoutMs ?? this.runtime.defaultTimeoutMs};
    const runtimeContext=routing.evidenceSession?{...routedContext,evidenceSession:{...routing.evidenceSession,routeWitnessDigest:routeWitness.digest},routeWitnessDigest:routeWitness.digest}:routedContext;
    const runtime = await this.runtime.run(choice.strategy, runtimeContext, runtimeOptions);
    const executionWitness = await this.ledger.append('route-executed', {
      routeWitnessDigest:routeWitness.digest, strategyId:choice.strategy.id,
      runtime:{ok:runtime.ok, latencyMs:runtime.latencyMs, error:runtime.error || null}
    });
    pending.executionWitnessDigest=executionWitness.digest;
    const srnnAction=this.srnn&&pending.wgSrnnDirectiveDigest?await this.srnn.recordAction({directiveDigest:pending.wgSrnnDirectiveDigest,routeWitnessDigest:pending.receiptDigest,executionWitnessDigest:executionWitness.digest,strategyId:pending.strategyId}):null;
    pending.wgSrnnActionWitnessDigest=srnnAction?.witness?.digest||null;
    pending.actualNextWitnessType='route-executed';
    pending.execution={ok:runtime.ok,latencyMs:runtime.latencyMs,error:runtime.error||null};
    this.pending.set(routeWitness.id,pending);
    await this.store.set('records', `pending:${routeWitness.id}`, pending);
    return {...runtime, receiptId:routeWitness.id, routeWitness, executionWitness, observation, memory:routing.memory?.public || null, evidenceSession:compactEvidenceSession(routing.evidenceSession), memoryDecision:routing.memoryDecision||null};
  }

  async outcome(receiptId, outcome = {}) {
    this._assertPortableStackOperational?.('outcome');
    let pending = this.pending.get(receiptId);
    if (!pending) pending = await this.store.get('records', `pending:${receiptId}`);
    if (!pending) throw new Error(`unknown route receipt: ${receiptId}`);
    if (pending.closed) throw new Error(`route receipt already closed: ${receiptId}`);
    const outcomeWitness = await this.ledger.append('terminal-outcome', {
      routeWitnessDigest:pending.receiptDigest, strategyId:pending.strategyId,
      outcome:{...outcome, sensitivePayload:undefined},
    });
    const predictedDelta=pending.semanticDecision?.expectedWitnessDelta||null;
    const expectedNextType=predictedDelta?.expectedNextType||pending.semanticDecision?.chainContinuation?.type||null;
    const actualNextType=outcome?.semanticActual?.nextWitnessType||outcome?.nextWitnessType||pending.actualNextWitnessType||'route-executed';
    const nextWitnessMatch=expectedNextType==null?null:expectedNextType===actualNextType;
    const predictedFeasible=pending.semanticDecision?.feasibility==null?null:Number(pending.semanticDecision.feasibility)>=0.5;
    const feasibilityMatch=predictedFeasible==null?null:predictedFeasible===Boolean(outcome.ok);
    const actualTarget=String(outcome.semanticTarget ?? outcome.targetHint ?? pending.strategyId ?? '').trim()||null;
    const predictedTarget=pending.semanticDecision?.targetHint||null;
    const targetMatch=predictedTarget==null||actualTarget==null?null:String(predictedTarget)===String(actualTarget);
    const actualCompatible=Boolean(outcome.ok&&outcome.validated!==false);
    const predictedCompatible=pending.semanticDecision?.compatibility==null?null:Number(pending.semanticDecision.compatibility)>=0.5;
    const compatibilityMatch=predictedCompatible==null?null:predictedCompatible===actualCompatible;
    const actualConflict=typeof outcome.semanticConflict==='boolean'?outcome.semanticConflict:(typeof outcome.conflict==='boolean'?outcome.conflict:null);
    const evidenceSessionSettlement=pending.evidenceSessionId?await this.evidenceSessions?.settle?.(pending.evidenceSessionId,{routeWitnessDigest:pending.receiptDigest,outcomeWitnessDigest:outcomeWitness.digest,validated:outcome.validated!==false,ok:Boolean(outcome.ok),conflict:actualConflict}):null;
    const predictedConflict=pending.semanticDecision?.conflict==null?null:Number(pending.semanticDecision.conflict)>=0.5;
    const conflictMatch=actualConflict==null||predictedConflict==null?null:predictedConflict===actualConflict;
    const semanticMatch={nextWitness:nextWitnessMatch,target:targetMatch,feasibility:feasibilityMatch,compatibility:compatibilityMatch,conflict:conflictMatch};
    const observedDeltaMatches=Object.values(semanticMatch).filter(value=>typeof value==='boolean');
    const witnessDeltaObserved=observedDeltaMatches.length,witnessDeltaCorrect=observedDeltaMatches.filter(Boolean).length;
    const witnessDeltaAccuracy=witnessDeltaObserved?witnessDeltaCorrect/witnessDeltaObserved:null;
    const witnessDeltaAssessment={observed:witnessDeltaObserved,correct:witnessDeltaCorrect,accuracy:witnessDeltaAccuracy,error:witnessDeltaAccuracy==null?null:1-witnessDeltaAccuracy};
    const predictionAssessment=await this.ledger.append('semantic-prediction-assessment',{
      routeWitnessDigest:pending.receiptDigest,strategyId:pending.strategyId,
      predicted:{nextOperation:pending.semanticDecision?.nextOperation||null,targetHint:predictedTarget,feasibility:pending.semanticDecision?.feasibility??null,compatibility:pending.semanticDecision?.compatibility??null,conflict:pending.semanticDecision?.conflict??null,expectedWitnessDelta:predictedDelta},
      actual:{nextWitnessType:actualNextType,targetHint:actualTarget,compatibility:actualCompatible,conflict:actualConflict,terminalWitnessType:outcomeWitness.type,ok:Boolean(outcome.ok),validated:outcome.validated!==false},
      match:semanticMatch,witnessDelta:witnessDeltaAssessment,
      predictionError:nextWitnessMatch==null?null:(nextWitnessMatch?0:1),authority:false,
    });
    const selectedEpisodePlan=pending.selectedEpisodePlan||selectWitnessEpisodeTransitionPlanForStrategy(pending.semanticDecision?.episodicPlan||null,pending.strategyId);const planAssessmentBody=assessWitnessEpisodeTransitionPlan(selectedEpisodePlan,{actualNextWitnessType:actualNextType,chosenStrategyId:pending.strategyId,validated:outcome.validated!==false});
    const planAssessment=await this.ledger.append('episodic-plan-assessment',{routeWitnessDigest:pending.receiptDigest,strategyId:pending.strategyId,...planAssessmentBody,authority:false});
    const branchPosteriorAssessmentBody=assessWitnessEpisodeBranchPosterior(pending.semanticDecision?.episodicPlan||null,{actualNextWitnessType:actualNextType,chosenStrategyId:pending.strategyId,validated:outcome.validated!==false});
    const branchPosteriorAssessment=branchPosteriorAssessmentBody?.applicable?await this.ledger.append('episodic-branch-posterior-assessment',{routeWitnessDigest:pending.receiptDigest,strategyId:pending.strategyId,...branchPosteriorAssessmentBody,authority:false}):null;
    const repairPlanAssessmentBody=pending.planContinuationId&&pending.semanticDecision?.episodicRepairPlan?assessWitnessEpisodeTransitionPlan(pending.semanticDecision.episodicRepairPlan,{actualNextWitnessType:actualNextType,chosenStrategyId:pending.strategyId,validated:outcome.validated!==false}):null;
    const repairPlanAssessment=repairPlanAssessmentBody?await this.ledger.append('episodic-plan-repair-assessment',{routeWitnessDigest:pending.receiptDigest,continuationId:pending.planContinuationId,strategyId:pending.strategyId,...repairPlanAssessmentBody,authority:false}):null;
    const routeExecutionHealthy=Boolean(pending.execution?.ok)&&outcome.validated!==false;
    if (routeExecutionHealthy) await this.routeHealth.success(pending.strategyId);
    else await this.routeHealth.failure(pending.strategyId, pending.execution?.error || outcome.error || outcome.reason || (outcome.validated===false?'terminal-outcome-validation-failed':'route-runtime-failed'));
    this.credit.link(outcomeWitness.id, receiptId, 1);
    const reward = rewardFrom(outcome);
    const dependencyCredit = this.credit.distribute(outcomeWitness.id, reward);
    if (outcome.validated === false) await this.investigations.add(receiptId, 'outcome-validation-failed', {strategyId:pending.strategyId, outcomeWitnessDigest:outcomeWitness.digest});
    let srnnOutcomeStage=null;
    if(this.srnn&&pending.wgSrnnDirectiveDigest){
      srnnOutcomeStage=await this.srnn.recordOutcomeStage({directiveDigest:pending.wgSrnnDirectiveDigest,assessmentDigest:pending.wgSrnnSemanticAssessmentDigest||null,outcomeWitnessDigest:outcomeWitness.digest,observerIdentity:'browser-runtime',observerProvenanceGroup:'browser-runtime',status:outcome.validated===false?'unverified':(outcome.ok?'confirmed':'contradicted'),actual:{ok:Boolean(outcome.ok),validated:outcome.validated!==false,nextWitnessType:actualNextType,targetHint:actualTarget,conflict:actualConflict,reward}});
      pending.wgSrnnOutcomeStageDigest=srnnOutcomeStage?.witness?.digest||null;
    }
    const promotion = await this.learning.promote({
      strategyId: pending.strategyId,
      features: pending.features,
      semanticFeatures: pending.semanticFeatures || null,
      reward,
      outcome:{...outcome,semanticActual:{nextWitnessType:actualNextType,targetHint:actualTarget,feasible:Boolean(outcome.ok),compatible:Boolean(outcome.ok&&outcome.validated!==false),conflict:actualConflict},semanticPrediction:{operation:pending.semanticDecision?.nextOperation||null,nextWitnessMatch,targetMatch,feasibilityMatch,compatibilityMatch,conflictMatch,witnessDeltaAccuracy}},
      learningEvidence: {
        outcomeWitnessed:true,
        temporalCreditAvailable:this.recurrent.steps > 0,
        dependencyCreditAvailable:Object.keys(dependencyCredit).length > 1,
        validationPassed: outcome.validated !== false,
        lineageSafe:true,
      },
    });
    let srnnTemporalCredit=null,srnnLessonEvaluation=null,srnnLessonCandidate=null;
    if(this.srnn&&promotion.promoted&&pending.wgSrnnDirectiveDigest&&pending.wgSrnnSemanticAssessmentDigest&&pending.wgSrnnOutcomeStageDigest&&promotion.receipt?.digest&&promotion.mutationWitness?.digest){
      srnnTemporalCredit=await this.srnn.assignTemporalCredit({directiveDigest:pending.wgSrnnDirectiveDigest,assessmentDigest:pending.wgSrnnSemanticAssessmentDigest,outcomeStageDigest:pending.wgSrnnOutcomeStageDigest,learningWitnessDigest:promotion.receipt.digest,promotionWitnessDigest:promotion.mutationWitness.digest,credit:reward,creditorIdentity:'learning-authority',creditorProvenanceGroup:'learning-authority',provenanceGroups:pending.wgSrnnSemanticAssessmentProvenanceGroups||[]});
      pending.wgSrnnTemporalCreditDigest=srnnTemporalCredit?.witness?.digest||null;
      if(srnnTemporalCredit?.credited){
        srnnLessonEvaluation=await this.srnn.evaluateDirectiveLessons({directiveDigest:pending.wgSrnnDirectiveDigest,creditWitnessDigest:srnnTemporalCredit.witness.digest,routeWitnessDigest:pending.receiptDigest,outcomeWitnessDigest:outcomeWitness.digest});
        pending.wgSrnnLessonEvaluationWitnessDigests=(srnnLessonEvaluation?.evaluated||[]).map(row=>row.witness?.digest).filter(Boolean);pending.wgSrnnLessonDemotionWitnessDigests=(srnnLessonEvaluation?.demoted||[]).map(row=>row.witness?.digest).filter(Boolean);
      }
      if(srnnTemporalCredit?.credited&&Number(reward)>0){
        srnnLessonCandidate=await this.srnn.maybeFormLessonCandidate({directiveDigest:pending.wgSrnnDirectiveDigest,concept:`Repeated independent witnessed outcomes support ${pending.strategyId} for ${pending.capability}`,minCredits:2,minIndependentGroups:2,minMeanCredit:.25});
        pending.wgSrnnLessonCandidateDigest=srnnLessonCandidate?.witness?.digest||null;pending.wgSrnnLessonPromotionDigest=srnnLessonCandidate?.promotion?.witness?.digest||null;
      }
    }
    let srnnSettlement=null;
    if(this.srnn&&pending.wgSrnnDirectiveDigest){
      srnnSettlement=await this.srnn.settleDirective({directiveDigest:pending.wgSrnnDirectiveDigest,routeWitnessDigest:pending.receiptDigest,outcomeWitnessDigest:outcomeWitness.digest,predictionAssessmentDigest:predictionAssessment.digest,learningWitnessDigest:promotion.receipt?.digest||null,promotionWitnessDigest:promotion.promoted?promotion.mutationWitness?.digest||null:null,outcome:{...outcome,semanticActual:{nextWitnessType:actualNextType,targetHint:actualTarget,conflict:actualConflict}},reward,goalComplete:outcome.goalComplete===true});
      pending.wgSrnnSettlementWitnessDigest=srnnSettlement?.witness?.digest||null;pending.wgSrnnStatus=srnnSettlement?.status||null;
    }
    let srnnCalibration=null;
    if(this.srnn&&promotion.promoted&&pending.wgSrnnDirectiveDigest){
      srnnCalibration=await this.srnn.learnSelfReference({directiveDigest:pending.wgSrnnDirectiveDigest,capability:pending.capability,strategyId:pending.strategyId,reward,outcome,routeWitnessDigest:pending.receiptDigest,outcomeWitnessDigest:outcomeWitness.digest,learningWitnessDigest:promotion.receipt?.digest||null,promotionWitnessDigest:promotion.mutationWitness?.digest||null});
      pending.wgSrnnCalibrationWitnessDigest=srnnCalibration?.witness?.digest||null;
    }
    let sfmCrossTraining=null;
    if(this.sfm&&promotion.promoted&&pending.sfmTraining){
      sfmCrossTraining=await this.sfm.learnValidated({inference:pending.sfmTraining,reward,outcome,routeWitnessDigest:pending.receiptDigest,outcomeWitnessDigest:outcomeWitness.digest,learningWitnessDigest:promotion.receipt?.digest||null,promotionWitnessDigest:promotion.mutationWitness?.digest||null,runtime:pending.smallModelRuntime||null});
    }
    let runtimeCalibration=null;
    if(promotion.promoted&&this.runtimePolicy&&pending.smallModelRuntime){
      runtimeCalibration=await this.runtimePolicy.recordOutcome(pending.smallModelRuntime,{ok:Boolean(outcome.ok),reward,latencyMs:outcome.latencyMs,routeWitnessDigest:pending.receiptDigest,outcomeWitnessDigest:outcomeWitness.digest,learningWitnessDigest:promotion.receipt?.digest||null,promotionWitnessDigest:promotion.mutationWitness?.digest||null});
    }
    let evidenceSourceCalibration=null;
    if(promotion.promoted&&evidenceSessionSettlement?.entry?.witnessDigest){
      evidenceSourceCalibration=await this.evidenceSessions?.calibrateSource?.(evidenceSessionSettlement.entry,{validated:outcome.validated!==false,ok:Boolean(outcome.ok),conflict:actualConflict},{routeWitnessDigest:pending.receiptDigest,outcomeWitnessDigest:outcomeWitness.digest,learningWitnessDigest:promotion.receipt?.digest||null});
    }
    let memoryCredit=null;
    if(promotion.promoted && Array.isArray(pending.routingMemoryEvidence) && pending.routingMemoryEvidence.length){
      const attributedMemoryEvidence=attributeRoutingMemoryEvidence(pending.routingMemoryEvidence,pending.routingEpisodeHints||[],pending.strategyId,selectedEpisodePlan);memoryCredit=await this.memory.credit(attributedMemoryEvidence,reward,{routeWitnessDigest:pending.receiptDigest,outcomeWitnessDigest:outcomeWitness.digest,learningWitnessDigest:promotion.receipt?.digest||null});
    }
    let planCalibration=null;
    if(promotion.promoted&&planAssessmentBody.observed&&planAssessmentBody.firstStep?.witnessDigest){
      planCalibration=await this.memory.calibratePlan(planAssessmentBody.firstStep,planAssessmentBody,{routeWitnessDigest:pending.receiptDigest,outcomeWitnessDigest:outcomeWitness.digest,learningWitnessDigest:promotion.receipt?.digest||null});
    }
    let branchPosteriorCalibration=null;
    if(promotion.promoted&&branchPosteriorAssessmentBody?.observed&&branchPosteriorAssessmentBody?.selectedSupported&&selectedEpisodePlan?.steps?.[0]?.witnessDigest){
      branchPosteriorCalibration=await this.memory.calibrateBranchPosterior(selectedEpisodePlan.steps[0],branchPosteriorAssessmentBody,{routeWitnessDigest:pending.receiptDigest,outcomeWitnessDigest:outcomeWitness.digest,learningWitnessDigest:promotion.receipt?.digest||null,calibrationHalfLifeMs:this.semantic?.branchCalibrationHalfLifeMs||7*24*3600*1000});
    }
    let repairPlanCalibration=null;
    if(promotion.promoted&&repairPlanAssessmentBody?.observed&&repairPlanAssessmentBody.firstStep?.witnessDigest){
      repairPlanCalibration=await this.memory.calibratePlan(repairPlanAssessmentBody.firstStep,repairPlanAssessmentBody,{routeWitnessDigest:pending.receiptDigest,outcomeWitnessDigest:outcomeWitness.digest,learningWitnessDigest:promotion.receipt?.digest||null});
    }
    let planContinuation=null;
    if(pending.planContinuationId){
      planContinuation=await this.planContinuations.settle({id:pending.planContinuationId,routeWitnessDigest:pending.receiptDigest,assessment:planAssessmentBody,promotion,calibrationWitnessDigest:planCalibration?.witness?.digest||null,repairPlan:pending.semanticDecision?.episodicRepairPlan||null,repairAssessment:repairPlanAssessmentBody,repairAssessmentWitnessDigest:repairPlanAssessment?.digest||null,repairCalibrationWitnessDigest:repairPlanCalibration?.witness?.digest||null});
    }else if(promotion.promoted&&planAssessmentBody.observed&&planAssessmentBody.match===true&&Number(pending.semanticDecision?.episodicPlan?.depth||0)>1){
      planContinuation=await this.planContinuations.start({capability:pending.capability,sourceRouteWitnessDigest:pending.receiptDigest,plan:selectedEpisodePlan,assessment:planAssessmentBody,calibrationWitnessDigest:planCalibration?.witness?.digest||null});
    }
    pending.branchPosteriorAssessmentWitnessDigest=branchPosteriorAssessment?.digest||null;pending.branchPosteriorCalibrationWitnessDigest=branchPosteriorCalibration?.witness?.digest||null;pending.planRepairAssessmentWitnessDigest=repairPlanAssessment?.digest||null;pending.planRepairCalibrationWitnessDigest=repairPlanCalibration?.witness?.digest||null;pending.planContinuationWitnessDigest=planContinuation?.witness?.digest||planContinuation?.repairWitness?.digest||planContinuation?.stepWitness?.digest||planContinuation?.closeWitness?.digest||null;pending.evidenceSessionSettlementWitnessDigest=evidenceSessionSettlement?.witness?.digest||null;pending.evidenceSourceCalibrationWitnessDigest=evidenceSourceCalibration?.witness?.digest||null;pending.evidenceSourceClaimCalibrationWitnessDigest=evidenceSourceCalibration?.claimCalibration?.witness?.digest||null;
    const compactWitness=w=>w?{id:w.id||null,digest:w.digest||null,sequence:w.sequence??null,type:w.type||null}:null;
    const outcomeResultSummary={schema:'xavi-outcome-result-summary/v1',outcomeWitness:compactWitness(outcomeWitness),promotion:{promoted:Boolean(promotion?.promoted),demoted:Boolean(promotion?.demoted),mutationType:promotion?.mutationType||null,receipt:compactWitness(promotion?.receipt),mutationWitness:compactWitness(promotion?.mutationWitness),authority:false},wgSrnn:srnnSettlement?{directiveDigest:pending.wgSrnnDirectiveDigest||null,status:srnnSettlement.status||null,settlementWitness:compactWitness(srnnSettlement.witness),authority:false}:null,evidenceSessionSettlement:evidenceSessionSettlement?{entry:evidenceSessionSettlement.entry||null,witness:compactWitness(evidenceSessionSettlement.witness),authority:false}:null,reward:Number(reward||0),authority:false};
    this.pending.delete(receiptId);
    await this.store.set('records', `pending:${receiptId}`, {...pending, closed:true, outcomeWitnessDigest:outcomeWitness.digest, outcomeResultSummary, reward, memoryCreditWitnessDigest:memoryCredit?.witness?.digest||null,planAssessmentWitnessDigest:planAssessment?.digest||null,branchPosteriorAssessmentWitnessDigest:branchPosteriorAssessment?.digest||null,branchPosteriorCalibrationWitnessDigest:branchPosteriorCalibration?.witness?.digest||null,planCalibrationWitnessDigest:planCalibration?.witness?.digest||null,planRepairAssessmentWitnessDigest:repairPlanAssessment?.digest||null,planRepairCalibrationWitnessDigest:repairPlanCalibration?.witness?.digest||null,planContinuationWitnessDigest:pending.planContinuationWitnessDigest||null,evidenceSessionSettlementWitnessDigest:evidenceSessionSettlement?.witness?.digest||null,evidenceSourceCalibrationWitnessDigest:evidenceSourceCalibration?.witness?.digest||null,evidenceSourceClaimCalibrationWitnessDigest:evidenceSourceCalibration?.claimCalibration?.witness?.digest||null,sfmCrossTrainingWitnessDigest:sfmCrossTraining?.witness?.digest||null,runtimeCalibrationWitnessDigest:runtimeCalibration?.witness?.digest||null,wgSrnnSemanticAssessmentDigest:pending.wgSrnnSemanticAssessmentDigest||null,wgSrnnOutcomeStageDigest:srnnOutcomeStage?.witness?.digest||pending.wgSrnnOutcomeStageDigest||null,wgSrnnTemporalCreditDigest:srnnTemporalCredit?.witness?.digest||pending.wgSrnnTemporalCreditDigest||null,wgSrnnLessonCandidateDigest:srnnLessonCandidate?.witness?.digest||pending.wgSrnnLessonCandidateDigest||null,wgSrnnLessonPromotionDigest:srnnLessonCandidate?.promotion?.witness?.digest||pending.wgSrnnLessonPromotionDigest||null,wgSrnnLessonEvaluationWitnessDigests:pending.wgSrnnLessonEvaluationWitnessDigests||[],wgSrnnLessonDemotionWitnessDigests:pending.wgSrnnLessonDemotionWitnessDigests||[],wgSrnnSettlementWitnessDigest:srnnSettlement?.witness?.digest||null,wgSrnnCalibrationWitnessDigest:srnnCalibration?.witness?.digest||null,wgSrnnStatus:srnnSettlement?.status||null});
    if(this.autoRetention) this.autoRetention.enqueueOutcome({pending,outcome,outcomeWitness,predictionAssessment,planAssessment,branchPosteriorAssessment,branchPosteriorCalibration,planCalibration,promotion,srnnSettlement,srnnCalibration,srnnSemanticAssessment:srnnAssessmentFromPending(pending,this.srnnStages),srnnOutcomeStage,srnnTemporalCredit,srnnLessonEvaluation,srnnLessonCandidate});
    return {outcomeWitness, predictionAssessment, planAssessment, branchPosteriorAssessment, branchPosteriorCalibration, planCalibration, repairPlanAssessment, repairPlanCalibration, planContinuation, evidenceSessionSettlement, evidenceSourceCalibration, srnnSemanticAssessment:srnnAssessmentFromPending(pending,this.srnnStages), srnnOutcomeStage, srnnTemporalCredit, srnnLessonEvaluation, srnnLessonCandidate, srnnSettlement, srnnCalibration, sfmCrossTraining, runtimeCalibration, reward, dependencyCredit, promotion, memoryCredit, autoRetentionQueued:Boolean(this.autoRetention)};
  }

  async resolveEvidence(capability, context = {}, options = {}) {
    this._assertPortableStackOperational?.('resolveEvidence');
    if(!this.evidenceResolver)return{schema:'xavi-evidence-resolution-cycle/v1',enabled:false,capability,stopReason:'evidence-sessions-disabled',complete:false,steps:[],spentCost:0,pendingValidation:null,authority:false};
    return this.evidenceResolver.resolve(capability,context,options);
  }

  async resumeEvidence(capability, context = {}, options = {}) {
    this._assertPortableStackOperational?.('resumeEvidence');
    if(!this.evidenceResolver)throw new Error('evidence resolution is unavailable');
    return this.evidenceResolver.resume(capability,context,options);
  }

  async queueOutcome(receiptId, outcome = {}) {
    this._assertPortableStackOperational?.('queueOutcome');
    const row = await this.deferred.enqueue({receiptId,outcome},{key:`outcome:${receiptId}`});
    this.deferred.schedule(payload => this.outcome(payload.receiptId,payload.outcome));
    return row;
  }

  async flushLearning({limit=8}={}) { this._assertPortableStackOperational?.('flushLearning'); return this.deferred.drain(payload => this.outcome(payload.receiptId,payload.outcome),{limit}); }

  async learn(capability, context, options = {}) {
    this._assertPortableStackOperational?.('learn');
    const claimScoped=Boolean((Array.isArray(context?.evidenceClaims)&&context.evidenceClaims.length)||context?.evidenceClaimKey||context?.evidenceClaim||context?.evidenceClaimDependencies);
    let evidenceResolution=null;
    if(this.autoEvidenceResolution&&this.evidenceResolver&&claimScoped&&options.evidenceResolution!==false){
      const resolutionOptions=options.evidenceResolution&&typeof options.evidenceResolution==='object'?options.evidenceResolution:{};
      evidenceResolution=await this.resolveEvidence(capability,context,resolutionOptions);
      const proceed=['evidence-sufficient','complete','no-evidence-deficit'].includes(evidenceResolution.stopReason);
      if(!proceed)return{schema:'xavi-evidence-resolution-learning/v1',ok:false,capability,evidenceResolution,pendingValidation:evidenceResolution.pendingValidation||null,learning:null,authority:false};
    }
    const finalExcludeStrategyIds=evidenceResolution?[...this.router.strategies.values()].filter(strategy=>Boolean(strategy?.metadata?.evidenceClass||strategy?.metadata?.observerId||String(strategy?.id||'').startsWith('observer:'))).map(strategy=>strategy.id):(options.excludeStrategyIds||[]);
    let execution;
    try{execution=await this.execute(capability, context, {...options,excludeStrategyIds:finalExcludeStrategyIds});}
    catch(error){
      if(evidenceResolution&&String(error?.message||error).includes('no strategy for capability'))return{schema:'xavi-evidence-resolution-learning/v1',ok:true,capability,evidenceResolution,reason:'evidence-resolution-complete-no-final-action',pendingValidation:null,learning:null,authority:false};
      throw error;
    }
    const outcome = options.outcome ? await options.outcome(execution, context) : {ok:execution.ok, latencyMs:execution.latencyMs, validated:true};
    const learning = await this.outcome(execution.receiptId, outcome);
    return {...execution, learning, evidenceResolution};
  }

  addDisposable(resource) { if (resource?.dispose || resource?.close) this.disposables.add(resource); return resource; }

  async close() {
    this.selfManager?.stop?.();
    if(this.autoRetention) await this.autoRetention.close().catch(()=>{});
    if(this.selfManager?.close) await this.selfManager.close().catch(()=>{});
    if(this.srnnStages?.flushIntegrityMonitor) await this.srnnStages.flushIntegrityMonitor().catch(()=>{});
    if(this.srnnStages?.flushIntegrityTelemetry) await this.srnnStages.flushIntegrityTelemetry().catch(()=>{});
    this.bus.close();
    for (const resource of this.disposables) {
      if(resource===this.selfManager||resource===this.autoRetention)continue;
      try { if (resource?.dispose) await resource.dispose(); else await resource?.close?.(); } catch {}
    }
    this.disposables.clear();
    await this.embedder?.dispose?.();
    await this.store?.close?.();
  }
}

export { normalizeSfmSnapshot, sfmTargetCompatibility, toPythonSfmSnapshot, toJsSfmSnapshot, normalizeSfmProposal, normalize_snapshot, target_compatibility, to_python_snapshot, to_js_snapshot, normalize_proposal, projectSfmInterchangeFixtureManifest, digestSfmInterchangeFixtureManifest, verifySfmInterchangeFixtureManifest, verifySfmInterchangeProjection, project_sfm_fixture_manifest, digest_sfm_fixture_manifest, verify_sfm_fixture_manifest, verify_sfm_interchange_projection, digestSfmInterchangeValue, WG_SFM_INTERCHANGE_SCHEMA, WG_SFM_PROPOSAL_INTERCHANGE_SCHEMA, WG_SFM_CONTRACT_SCHEMA, WG_SFM_JS_SHARED_SCHEMA, WG_SFM_JS_SHARED_MODEL_ID, WG_SFM_PY_SHARED_SCHEMA, WG_SFM_PY_SHARED_MODEL_ID, WG_SFM_PY_FAST_SCHEMA, WG_SFM_PY_FAST_MODEL_ID, WG_SFM_CANONICAL_OPERATIONS, WG_SFM_JS_LEGACY_V070_OPERATIONS, WG_SFM_AUTHORITY_PROFILE, WG_SFM_INTERCHANGE_PROFILE, WG_SFM_INTERCHANGE_FIXTURE_MANIFEST_SCHEMA, WG_SFM_INTERCHANGE_FIXTURE_VERIFICATION_SCHEMA, WG_SFM_INTERCHANGE_VERIFICATION_SCHEMA, WGSFMInterchangeError, WitnessGate, WitnessLedger, RecurrentCore, WitnessSFM, WG_SFM_SCHEMA, WG_SFM_MODEL_ID, WG_SFM_TRANSPARENT_WITNESS_TYPES, WitnessGatedSelfReferentialNeuralNetwork, WG_SRNN_SCHEMA, WG_SRNN_DIRECTIVE_SCHEMA, WG_SRNN_COMMITMENT_SCHEMA, wgSrnnConfidenceCalibrationContext, wgSrnnStrategyComparisonContext, wgSrnnReconsiderationContext, wgSrnnReflectionAgendaContext, confidence_calibration_context, strategy_comparison_context, reconsideration_context, reflection_agenda_context, WG_SRNN_CONFIDENCE_CALIBRATION_SCHEMA, WG_SRNN_STRATEGY_COMPARISON_SCHEMA, WG_SRNN_RECONSIDERATION_SCHEMA, WG_SRNN_REFLECTION_AGENDA_SCHEMA, buildWgSfmAssessmentRequests, wgSfmAssessmentClaim, compactWgSfmConsensus, wgSfmSemanticAssessmentResponse, sealWgSfmAssessmentFromConsensus, build_assessment_requests, assessment_claim, semantic_assessment_response, seal_assessment_from_consensus, WG_SRNN_SFM_ASSESSMENT_REQUEST_SCHEMA, WG_SRNN_SFM_ASSESSMENT_REQUEST_SET_SCHEMA, WG_SFM_SEMANTIC_ASSESSMENT_RESPONSE_SCHEMA, WG_SFM_SEALED_SEMANTIC_ASSESSMENT_SCHEMA, WG_SFM_REFLECTION_CLAIM_PREDICATE, wgSrnnSelfCalibrationContext, wgSrnnDependencyReflectionContext, wgSrnnEpisodicPostureSummary, wgSrnnEpisodicSelfSummaryContext, wgSrnnCommitmentSelfReferenceContext, wgSrnnResumeContext, self_calibration_context, dependency_reflection_context, episodic_self_summary_context, commitment_self_reference_context, resume_context, normalizeSrnnInterchangeValue, projectSrnnInterchangeRecord, digestSrnnInterchangeRecord, srnnInterchangeLineage, projectSrnnInterchangeFixtureManifest, digestSrnnInterchangeFixtureManifest, verifySrnnInterchangeFixtureManifest, verifySrnnInterchangeProjection, normalizeSrnnRuntimeInterchangeRecord, srnnRuntimeInterchangeLineageKey, srnnRuntimeImportRequirements, normalize_record, lineage_key, import_requirements, normalize_runtime_interchange_record, runtime_interchange_lineage_key, runtime_import_requirements, normalize_interchange_value, project_interchange_record, digest_interchange_record, interchange_lineage, project_fixture_manifest, digest_fixture_manifest, verify_fixture_manifest, verify_interchange_projection, WG_SRNN_INTERCHANGE_PROFILE, WG_SRNN_INTERCHANGE_PROJECTION_SCHEMA, WG_SRNN_INTERCHANGE_LINEAGE_SCHEMA, WG_SRNN_INTERCHANGE_FIXTURE_MANIFEST_SCHEMA, WG_SRNN_INTERCHANGE_VERIFICATION_SCHEMA, WG_SRNN_RUNTIME_INTERCHANGE_SCHEMA, WG_SRNN_IMPORT_REQUIREMENTS_SCHEMA, WG_SRNN_RUNTIME_INTERCHANGE_NO_AUTHORITY, WG_SRNN_INTERCHANGE_AUTHORITY_PROFILE, WGSRNNInterchangeError, witnessWgStackPortableApplicationPermit, applyWgStackPortableFamilyTransaction, applyWgStackPortableStackTransaction, inspectWgStackPortableStackRecovery, listWgStackPortableOpenTransactions, reconcileWgStackPortableStackRecovery, reconcileWgStackPortableStackRecoveryChain, digestWgStackPortableLiveStackState, WG_STACK_PORTABLE_APPLICATION_SCHEMA, WG_STACK_PORTABLE_APPLICATION_PROFILE, WG_STACK_PORTABLE_APPLICATION_PERMIT_SCHEMA, WG_STACK_PORTABLE_APPLICATION_PERMIT_WITNESS_TYPE, WG_STACK_PORTABLE_APPLICATION_WITNESS_SCHEMA, WG_STACK_PORTABLE_APPLICATION_ROLLBACK_WITNESS_SCHEMA, WG_STACK_PORTABLE_STACK_APPLICATION_SCHEMA, WG_STACK_PORTABLE_STACK_APPLICATION_PROFILE, WG_STACK_PORTABLE_STACK_APPLICATION_WITNESS_SCHEMA, WG_STACK_PORTABLE_STACK_APPLICATION_ROLLBACK_WITNESS_SCHEMA, WG_STACK_PORTABLE_STACK_APPLICATION_STARTED_WITNESS_SCHEMA, WG_STACK_PORTABLE_STACK_RECOVERY_SCHEMA, WG_STACK_PORTABLE_STACK_RECOVERY_CHAIN_SCHEMA, WG_STACK_PORTABLE_APPLICATION_NO_SELF_AUTHORITY, WGStackPortableApplicationError, digestWgStackPortableApplication, digestWgStackPortableStackApplication, evaluateSrnnReleaseGate, evaluate_release_gate, WG_SRNN_RELEASE_GATE_PROFILE, WG_SRNN_REQUIRED_TRACKED_PATHS, WG_SRNN_CRITICAL_PATHS, WG_SRNN_RELEASE_GATE_AUTHORITY_PROFILE, WGSRNNReleaseGateError, WGSRNNCanaryScope, WGSRNNCanaryValidator, WGSRNNCanaryValidationError, consensusCollapseProbe, dependencyCausalReport, adversarialProbe, consensus_collapse_probe, dependency_causal_report, adversarial_probe, WG_SRNN_CANARY_PROFILE, WG_SRNN_CANARY_AUTHORITY_PROFILE, collapseSrnnArbitrationObservations, compactSrnnConsensusContext, srnnConsensusToAssessmentInputs, WG_SRNN_ARBITRATION_PROFILE, WG_SRNN_ARBITRATION_AUTHORITY_PROFILE, WG_SRNN_ARBITRATION_COLLAPSE_SCHEMA, WG_SRNN_COMPACT_CONSENSUS_SCHEMA, WitnessGatedSelfReferentialStages, WG_SRNN_STAGES_SCHEMA, WG_SRNN_SEMANTIC_ASSESSMENT_SCHEMA, WG_SRNN_OUTCOME_WITNESS_SCHEMA, WG_SRNN_TEMPORAL_CREDIT_SCHEMA, WG_SRNN_LESSON_CANDIDATE_SCHEMA, WG_SRNN_CAUSAL_GRAPH_SCHEMA, WG_SRNN_CAUSAL_TRACE_SCHEMA, WG_SRNN_LESSON_EXPLANATION_SCHEMA, WG_SRNN_INTEGRITY_REPORT_SCHEMA, WG_SRNN_INTEGRITY_MONITOR_SCHEMA, WG_SRNN_INTEGRITY_TELEMETRY_SCHEMA, WG_SRNN_STAGE_WITNESS_TYPES, WG_SRNN_LESSON_STATE_SCHEMA, WG_SRNN_LESSON_PROMOTED_SCHEMA, WG_SRNN_LESSON_EVALUATED_SCHEMA, WG_SRNN_LESSON_DEMOTED_SCHEMA, WG_SRNN_LESSON_SUPERSEDED_SCHEMA, WG_SRNN_LESSON_WITNESS_TYPES, wgSrnnLessonId, wgSrnnLessonReliability, projectWgSrnnLesson, DUO_STATE_SCHEMA, DUO_BACKEND_STATE_SCHEMA, DUO_RESIDUE_SCHEMA, DUO_STATE_NAMES, DUO_STATE, duoState, isDuoState, duoStateName, backendState, duoIndexFromBackend, backendIndexFromDuo, assertDuoIndex, duoResidueSignature, duoResidueKey, StrategyRouter, WitnessSemanticLayer, RouteGraphScorer, SEMANTIC_TRANSPARENT_WITNESS_TYPES, WitnessWorkingMemory, WitnessSemanticHeads, SEMANTIC_OPERATIONS, WitnessPlanContinuationTracker, WitnessEvidenceSessionTracker, EvidenceResolutionController, projectWitnessEpisodeHint, buildWitnessEpisodeGuidance, episodeStrategyAdjustment, compareEpisodeGuidanceToHeads, buildWitnessEpisodeTransitionPlan, episodePlanStrategyAdjustment, summarizeEpisodePlanBranches, selectWitnessEpisodeTransitionPlanForStrategy, assessWitnessEpisodeBranchPosterior, assessWitnessEpisodeTransitionPlan, LearningAuthority, BrowserRuntime, MemoryStore, IndexedDBStore, BrowserAuthority, PolicyBus, RouteHealth, DeferredLearningQueue, CreditGraph, InvestigationQueue, KnowledgeCorpus, SecurityFaculty, BrowserSecurityFaculty, SecurityMonitor, AdPolicyFaculty, LexiconFaculty, LexicalFaculty, LanguageFaculty, TranslationFaculty, MathFaculty, createBrowserFaculties, createPublisherIframeStrategy, SAFE_IFRAME_PROFILES, SandboxPolicy, SandboxManager, createWorkerRpcExecutor, createContainer2WasmExecutor, CONTAINER2WASM_NOTES, FirstPartyImageRegistry, APPROVED_DISTRIBUTION_LICENSES, PROJECT_DISTRIBUTION_LICENSE, createNativeWasmExecutor, EvidenceObserverRegistry, APPROVED_OBSERVER_LICENSES, SPECIALIST_OBSERVER_CATALOG, OBSERVER_RUNTIME_CATALOG, CURRICULUM_SOURCE_CATALOG, WitnessVectorStore, HashFeatureEmbedder, FunctionEmbedder, WitnessMemory, WitnessEpisodePatternIndex, EPISODE_PATTERN_TOKEN_VERSION, episodePatternTokensFromEpisode, episodePatternTokensFromSemantic, SelfTrainingCoordinator, WitnessReplayDataset, WitnessReplayBackfillTrainer, WitnessSfmReplayTrainer, SelfManagementController, AutoRetentionController, HnswIndex, HnswWitnessVectorStore, ShardedWitnessVectorStore, TransformersJsEmbedder };
export { PreviewLearner, createIframeStrategy } from './adapters/preview.js';

export { normalizeJsRnnSnapshot, verifyRnnHandoff, javascriptRnnTeacherProjection, projectRnnInterchangeFixtureManifest, digestRnnInterchangeFixtureManifest, verifyRnnInterchangeFixtureManifest, normalize_js_snapshot as normalize_rnn_js_snapshot, verify_handoff as verify_rnn_handoff, javascript_teacher_projection as javascript_rnn_teacher_projection, digestRnnInterchangeValue, WG_RNN_INTERCHANGE_SCHEMA, WG_RNN_JS_RECURRENT_SCHEMA, WG_RNN_PY_CORE_SCHEMA, WG_RNN_JS_TEACHER_PROJECTION_SCHEMA, WG_RNN_INTERCHANGE_PROFILE, WG_RNN_INTERCHANGE_FIXTURE_MANIFEST_SCHEMA, WG_RNN_INTERCHANGE_FIXTURE_VERIFICATION_SCHEMA, WG_RNN_NO_AUTHORITY, WGRNNInterchangeError } from './core/witness-rnn-interchange.js';

export * from './core/witness-stack-interchange.js';

export * from './core/witness-stack-capability.js';

export * from './core/witness-stack-portable-envelope.js';
export * from './core/witness-stack-portable-import.js';
export * from './core/witness-stack-portable-stage.js';
export * from './core/witness-stack-portable-admission.js';
export * from './core/witness-stack-portable-gate-decision.js';
export * from './core/witness-stack-portable-application.js';
