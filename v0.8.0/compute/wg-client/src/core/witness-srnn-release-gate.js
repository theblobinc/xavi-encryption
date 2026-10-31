export const WG_SRNN_RELEASE_GATE_PROFILE='WG-SRNN-RELEASE-GATE/1';

export const WG_SRNN_REQUIRED_TRACKED_PATHS=Object.freeze([
  'src/core/witness-stack-interchange.js',
  'src/core/witness-stack-capability.js',
  'src/core/witness-stack-portable-envelope.js',
  'src/core/witness-stack-portable-import.js',
  'src/core/witness-stack-portable-stage.js',
  'src/core/witness-stack-portable-admission.js',
  'src/core/witness-stack-portable-gate-decision.js',
  'src/core/witness-stack-portable-application.js',
  'src/core/witness-rnn-interchange.js',
  'src/core/recurrent.js',
  'src/core/witness-sfm.js',
  'src/core/witness-sfm-assessor.js',
  'src/core/witness-sfm-interchange.js',
  'src/core/witness-srnn.js',
  'src/core/witness-srnn-stages.js',
  'src/core/witness-srnn-lessons.js',
  'src/core/witness-srnn-resume.js',
  'src/core/witness-srnn-arbitration.js',
  'src/core/witness-srnn-canary.js',
  'src/core/witness-srnn-interchange.js',
  'fixtures/wg-srnn-cross-language-v1.json',
  'fixtures/wg-srnn-runtime-interchange-v1.json',
  'fixtures/wg-sfm-interchange-v1.json',
  'fixtures/wg-rnn-interchange-v1.json',
  'fixtures/wg-stack-interchange-v1.json',
  'fixtures/wg-stack-capability-js-v1.json',
  'fixtures/wg-stack-portable-envelope-v1.json',
  'fixtures/wg-stack-portable-import-plan-v1.json',
  'fixtures/wg-stack-portable-import-stage-v1.json',
  'fixtures/wg-stack-portable-family-admissions-v1.json',
  'fixtures/wg-stack-portable-family-gate-decisions-v1.json',
  'fixtures/wg-stack-portable-family-application-contract-v1.json',
]);

export const WG_SRNN_CRITICAL_PATHS=Object.freeze([
  ...WG_SRNN_REQUIRED_TRACKED_PATHS,
  'src/index.js',
  'package.json',
]);

export const WG_SRNN_RELEASE_GATE_AUTHORITY_PROFILE=Object.freeze({
  promotion_authority:false,
  deployment_authority:false,
  mutation_authority:false,
  truth_authority:false,
});

export class WGSRNNReleaseGateError extends Error{
  constructor(message){super(message);this.name='WGSRNNReleaseGateError';}
}

function cleanSet(values){return new Set(Array.from(values??[],value=>String(value??'').trim()).filter(Boolean));}
function dirtyMap(value){if(value instanceof Map)return new Map([...value].map(([k,v])=>[String(k),String(v)]));return new Map(Object.entries(value&&typeof value==='object'?value:{}).map(([k,v])=>[String(k),String(v)]));}

export function evaluateSrnnReleaseGate({head='',trackedPaths=[],dirtyPaths={},candidateCommit=null,requiredPaths=WG_SRNN_REQUIRED_TRACKED_PATHS,criticalPaths=WG_SRNN_CRITICAL_PATHS,interchangeRequirement=null,interchangeEvidence=null}={}){
  const current=String(head??'').trim(),candidate=String(candidateCommit??'').trim()||null,tracked=cleanSet(trackedPaths),dirty=dirtyMap(dirtyPaths),required=[],blockers=[],criticalDirty=[];
  for(const raw of requiredPaths){const path=String(raw);const isTracked=tracked.has(path);required.push({path,tracked:isTracked});if(!isTracked)blockers.push({kind:'required-path-untracked',path});}
  for(const raw of criticalPaths){const path=String(raw),status=dirty.get(path);if(status){const row={path,status};criticalDirty.push(row);blockers.push({kind:'critical-path-dirty',path,status});}}
  let interchange=null;
  if(interchangeRequirement!==null){
    const expectedProfile=String(interchangeRequirement?.profile_id??'').trim(),expectedDigest=String(interchangeRequirement?.fixture_digest??'').trim(),observedProfile=String(interchangeEvidence?.profile_id??'').trim(),observedDigest=String(interchangeEvidence?.fixture_digest??'').trim();
    if(!expectedProfile||!expectedDigest)blockers.push({kind:'interchange-requirement-invalid'});
    if(!observedProfile||!observedDigest)blockers.push({kind:'interchange-evidence-missing'});
    const profileMatches=!!expectedProfile&&observedProfile===expectedProfile,digestMatches=!!expectedDigest&&observedDigest===expectedDigest;
    if(observedProfile&&expectedProfile&&!profileMatches)blockers.push({kind:'interchange-profile-mismatch',expected:expectedProfile,observed:observedProfile});
    if(observedDigest&&expectedDigest&&!digestMatches)blockers.push({kind:'interchange-fixture-digest-mismatch',expected:expectedDigest,observed:observedDigest});
    interchange={required:true,expected_profile_id:expectedProfile||null,observed_profile_id:observedProfile||null,profile_matches:profileMatches,expected_fixture_digest:expectedDigest||null,observed_fixture_digest:observedDigest||null,fixture_digest_matches:digestMatches,ready:profileMatches&&digestMatches,authority:false};
  }else interchange={required:false,ready:null,authority:false};
  let candidateMatchesHead=null;
  if(candidate!==null){candidateMatchesHead=candidate===current||current.startsWith(candidate)||candidate.startsWith(current);if(!candidateMatchesHead)blockers.push({kind:'candidate-not-current-head',candidate_commit:candidate,head:current});}
  return{schema:'wg-srnn-release-gate/v1',profile_id:WG_SRNN_RELEASE_GATE_PROFILE,head:current,candidate_commit:candidate,candidate_matches_head:candidateMatchesHead,required_tracked_paths:required,critical_dirty_paths:criticalDirty,source_gate_ready:blockers.length===0,blocker_count:blockers.length,blockers,packaged_test_requirement:{suite:'xavi-memory-js packaged tests',known_allowed_exclusion:null,must_be_reverified_after_source_gate:true},canary_requirement:{profile_id:'WG-SRNN-CANARY-VALIDATION/1',must_be_reverified_after_source_gate:true},interchange_requirement:interchange,promotion_authority:false,deployment_authority:false,interpretation:'source-provenance-gate-only-not-deployment-approval',authority_profile:{...WG_SRNN_RELEASE_GATE_AUTHORITY_PROFILE}};
}

export const evaluate_release_gate=evaluateSrnnReleaseGate;
