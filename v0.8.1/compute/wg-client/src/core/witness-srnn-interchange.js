import { digest } from './utils.js';

export const WG_SRNN_INTERCHANGE_PROFILE='WG-SRNN-INTERCHANGE/1';
export const WG_SRNN_INTERCHANGE_PROJECTION_SCHEMA='wg-srnn-cross-language-projection/v1';
export const WG_SRNN_INTERCHANGE_LINEAGE_SCHEMA='wg-srnn-cross-language-lineage/v1';
export const WG_SRNN_INTERCHANGE_FIXTURE_MANIFEST_SCHEMA='wg-srnn-cross-language-fixture-manifest/v1';
export const WG_SRNN_INTERCHANGE_VERIFICATION_SCHEMA='wg-srnn-cross-language-projection-verification/v1';

export const WG_SRNN_RUNTIME_INTERCHANGE_SCHEMA='xavi-wg-srnn-interchange/v1';
export const WG_SRNN_IMPORT_REQUIREMENTS_SCHEMA='xavi-wg-srnn-import-requirements/v1';
export const WG_SRNN_RUNTIME_INTERCHANGE_NO_AUTHORITY=Object.freeze({truth_authority:false,proof_authority:false,promotion_authority:false,learning_authority:false,execution_authority:false,selection_authority:false,self_model_write_authority:false,self_kernel_write_authority:false});
const WG_SRNN_PY_SCHEMAS=Object.freeze({'wg-srnn-internal-directive/v1':'internal_directive','wg-srnn-semantic-assessment/v1':'semantic_assessment','wg-srnn-outcome-witness/v1':'outcome_witness','wg-srnn-temporal-credit/v1':'temporal_credit','wg-srnn-lesson-candidate/v1':'lesson_candidate'});
const WG_SRNN_JS_SCHEMAS=Object.freeze({'xavi-wg-srnn-directive/v1':'internal_directive','xavi-wg-srnn-semantic-assessment/v1':'semantic_assessment','xavi-wg-srnn-outcome-witness/v1':'outcome_witness','xavi-wg-srnn-temporal-credit/v1':'temporal_credit','xavi-wg-srnn-lesson-candidate/v1':'lesson_candidate'});
const WG_SRNN_JS_TYPES=Object.freeze({'wg-srnn-directive-proposed':'internal_directive','wg-srnn-semantic-assessment':'semantic_assessment','wg-srnn-outcome-witness':'outcome_witness','wg-srnn-temporal-credit':'temporal_credit','wg-srnn-lesson-candidate':'lesson_candidate'});
const WG_SRNN_PY_RECORD_TYPES=Object.freeze({INTERNAL_DIRECTIVE:'internal_directive',SEMANTIC_ASSESSMENT:'semantic_assessment',OUTCOME_WITNESS:'outcome_witness',TEMPORAL_CREDIT:'temporal_credit',LESSON_CANDIDATE:'lesson_candidate'});

export const WG_SRNN_INTERCHANGE_AUTHORITY_PROFILE=Object.freeze({
  truth_authority:false,
  proof_authority:false,
  promotion_authority:false,
  learning_authority:false,
  mutation_authority:false,
  native_seal_authority:false,
});

export class WGSRNNInterchangeError extends Error{
  constructor(message){super(message);this.name='WGSRNNInterchangeError';}
}

function f64Hex(value){
  let number=Number(value);
  if(!Number.isFinite(number))throw new WGSRNNInterchangeError('interchange numbers must be finite');
  if(Object.is(number,-0))number=0;
  if(Number.isInteger(number)&&!Number.isSafeInteger(number))throw new WGSRNNInterchangeError('interchange integer exceeds IEEE-754 safe integer range');
  const bytes=new Uint8Array(8),view=new DataView(bytes.buffer);view.setFloat64(0,number,false);
  return Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
}

export function normalizeSrnnInterchangeValue(value,{depth=0,maxDepth=32}={}){
  if(depth>maxDepth)throw new WGSRNNInterchangeError('interchange value exceeds maximum depth');
  if(value===null||typeof value==='string'||typeof value==='boolean')return value;
  if(typeof value==='number')return{$f64:f64Hex(value)};
  if(Array.isArray(value))return value.map(item=>normalizeSrnnInterchangeValue(item,{depth:depth+1,maxDepth}));
  if(typeof value!=='object')throw new WGSRNNInterchangeError(`unsupported interchange type: ${typeof value}`);
  const out={};
  for(const key of Object.keys(value).sort()){
    if(key==='record_digest')continue;
    const child=value[key];
    if(child===undefined)throw new WGSRNNInterchangeError(`undefined interchange value at ${key}`);
    out[key]=normalizeSrnnInterchangeValue(child,{depth:depth+1,maxDepth});
  }
  return out;
}

export function projectSrnnInterchangeRecord(record){
  if(!record||typeof record!=='object'||Array.isArray(record))throw new WGSRNNInterchangeError('record must be an object');
  return{
    schema:WG_SRNN_INTERCHANGE_PROJECTION_SCHEMA,
    profile_id:WG_SRNN_INTERCHANGE_PROFILE,
    source_schema:String(record.schema??''),
    source_record_type:String(record.record_type??record.recordType??''),
    content:normalizeSrnnInterchangeValue(record),
    authority:false,
    authority_profile:{...WG_SRNN_INTERCHANGE_AUTHORITY_PROFILE},
  };
}

export async function digestSrnnInterchangeRecord(record){return digest(projectSrnnInterchangeRecord(record));}

export function projectSrnnInterchangeFixtureManifest(fixtureSet){
  if(!fixtureSet||typeof fixtureSet!=='object'||Array.isArray(fixtureSet))throw new WGSRNNInterchangeError('fixture set must be an object');
  if(!Array.isArray(fixtureSet.records))throw new WGSRNNInterchangeError('fixture set records must be an array');
  const records=[...fixtureSet.records].sort((a,b)=>String(a?.id??'').localeCompare(String(b?.id??''))).map(row=>normalizeSrnnInterchangeValue(row));
  return{
    schema:WG_SRNN_INTERCHANGE_FIXTURE_MANIFEST_SCHEMA,
    profile_id:WG_SRNN_INTERCHANGE_PROFILE,
    fixture_schema:String(fixtureSet.schema??''),
    reference_runtime:String(fixtureSet.reference_runtime??''),
    native_digest_contract:normalizeSrnnInterchangeValue(fixtureSet.native_digest_contract??{}),
    interchange_contract:normalizeSrnnInterchangeValue(fixtureSet.interchange_contract??{}),
    record_count:records.length,
    records,
    authority:false,
    authority_profile:{...WG_SRNN_INTERCHANGE_AUTHORITY_PROFILE},
  };
}

export async function digestSrnnInterchangeFixtureManifest(fixtureSet){return digest(projectSrnnInterchangeFixtureManifest(fixtureSet));}

export async function verifySrnnInterchangeFixtureManifest(fixtureSet){
  const expected=String(fixtureSet?.fixture_manifest_digest??'').trim()||null;
  const observed=await digestSrnnInterchangeFixtureManifest(fixtureSet);
  const profile=String(fixtureSet?.fixture_profile_id??fixtureSet?.interchange_contract?.profile_id??'').trim()||null;
  return{schema:'wg-srnn-cross-language-fixture-manifest-verification/v1',profile_id:WG_SRNN_INTERCHANGE_PROFILE,fixture_profile_id:profile,fixture_manifest_digest:expected,observed_manifest_digest:observed,profile_matches:profile===WG_SRNN_INTERCHANGE_PROFILE,digest_matches:expected===observed,verified:profile===WG_SRNN_INTERCHANGE_PROFILE&&expected===observed,authority:false,authority_profile:{...WG_SRNN_INTERCHANGE_AUTHORITY_PROFILE}};
}



function runtimeFinite(value,defaultValue=null){if(value==null)return defaultValue;const n=Number(value);if(!Number.isFinite(n))throw new WGSRNNInterchangeError('non-finite numeric field in WG-SRNN record');return n;}
function runtimeList(value){return Array.isArray(value)?value:[];}
function runtimeAuthorityGuard(value,where){
  const keys=['truth_authority','truthAuthority','proof_authority','proofAuthority','promotion_authority','promotionAuthority','learning_authority','learningAuthority','execution_authority','executionAuthority','selection_authority','selectionAuthority','self_model_write_authority','selfModelWriteAuthority','self_kernel_write_authority','selfKernelWriteAuthority'];
  for(const key of keys)if(value?.[key]===true)throw new WGSRNNInterchangeError(`${where} attempts authority escalation via ${key}`);
  const profile=value?.authority_profile??value?.authorityProfile;
  if(profile&&typeof profile==='object'&&!Array.isArray(profile))for(const key of keys)if(profile[key]===true)throw new WGSRNNInterchangeError(`${where} authority profile escalates via ${key}`);
}
function runtimeStageType(schema,recordType,nativeType){const result=WG_SRNN_PY_SCHEMAS[schema]??WG_SRNN_JS_SCHEMAS[schema]??WG_SRNN_PY_RECORD_TYPES[recordType]??WG_SRNN_JS_TYPES[nativeType];if(!result)throw new WGSRNNInterchangeError(`unsupported WG-SRNN stage: schema=${JSON.stringify(schema)} type=${JSON.stringify(recordType||nativeType)}`);return result;}
function runtimeWitnessSummary(body,sourceRuntime){
  if(sourceRuntime==='python'){
    const w=body?.witness&&typeof body.witness==='object'&&!Array.isArray(body.witness)?body.witness:{};
    return{observer_id:String(w.observer_id??''),provenance_group:String(w.independence_group??''),provenance_digest:String(w.provenance_digest??''),payload_digest:String(w.payload_digest??''),witness_id:String(w.witness_id??'')};
  }
  const candidate=body?.assessor??body?.observer??body?.creditor,actor=candidate&&typeof candidate==='object'&&!Array.isArray(candidate)?candidate:{};
  return{observer_id:String(actor.identity??actor.id??''),provenance_group:String(actor.provenanceGroup??actor.provenance_group??''),provenance_digest:'',payload_digest:'',witness_id:''};
}
function runtimeJsUnwrap(record){
  if(record?.body&&typeof record.body==='object'&&!Array.isArray(record.body)&&WG_SRNN_JS_TYPES[String(record.type??'')])return{body:structuredClone(record.body),meta:{native_digest:String(record.digest??''),native_digest_kind:'witness_digest',native_type:String(record.type??''),sequence:Math.trunc(Number(record.sequence)||0),container:'javascript-ledger-witness'}};
  return{body:structuredClone(record),meta:{native_digest:String(record?.witnessDigest??record?.digest??''),native_digest_kind:'witness_digest',native_type:String(record?.type??''),sequence:Math.trunc(Number(record?.sequence)||0),container:'javascript-stage-record'}};
}

export async function normalizeSrnnRuntimeInterchangeRecord(record,{jsLedgerVerified=null}={}){
  if(!record||typeof record!=='object'||Array.isArray(record))throw new WGSRNNInterchangeError('WG-SRNN record must be an object');
  if(record.schema===WG_SRNN_RUNTIME_INTERCHANGE_SCHEMA)return structuredClone(record);
  const schema0=String(record.schema??''),recordType0=String(record.record_type??''),pythonNative=!!(WG_SRNN_PY_SCHEMAS[schema0]||WG_SRNN_PY_RECORD_TYPES[recordType0]||record.record_digest);
  let body,meta,sourceRuntime,nativeVerified;
  if(pythonNative){
    body=structuredClone(record);runtimeAuthorityGuard(body,'Python WG-SRNN record');
    const nativeDigest=String(body.record_digest??'');const unsigned=structuredClone(body);delete unsigned.record_digest;const computed=await digest(unsigned);
    if(!nativeDigest||nativeDigest!==computed)throw new WGSRNNInterchangeError('Python WG-SRNN record digest mismatch');
    meta={native_digest:nativeDigest,native_digest_kind:'record_digest',native_type:recordType0,sequence:0,container:'python-sealed-record'};sourceRuntime='python';nativeVerified=true;
  }else{
    ({body,meta}=runtimeJsUnwrap(record));runtimeAuthorityGuard(body,'JavaScript WG-SRNN stage');sourceRuntime='javascript';nativeVerified=jsLedgerVerified;
    if(!meta.native_digest)throw new WGSRNNInterchangeError('JavaScript WG-SRNN stage requires its native witness digest');
  }
  const schema=String(body.schema??schema0??''),recordType=String(body.record_type??''),stageType=runtimeStageType(schema,recordType,meta.native_type),nativeDigest=meta.native_digest;
  const directiveId=String(body.directive_id??body.directiveId??''),directiveDigest0=String(body.directive_digest??body.directiveDigest??''),directiveDigest=stageType==='internal_directive'&&!directiveDigest0?nativeDigest:directiveDigest0;
  const assessmentDigest=String(body.assessment_digest??body.assessmentDigest??''),outcomeDigest=String(body.outcome_digest??body.outcomeStageDigest??body.outcomeWitnessDigest??'');
  const provenanceGroups=runtimeList(body.provenanceGroups??body.independentProvenanceGroups).map(v=>String(v)).filter(Boolean);const witness=runtimeWitnessSummary(body,sourceRuntime);if(witness.provenance_group&&!provenanceGroups.includes(witness.provenance_group))provenanceGroups.push(witness.provenance_group);
  const normalized={schema:WG_SRNN_RUNTIME_INTERCHANGE_SCHEMA,stage_type:stageType,source_runtime:sourceRuntime,source_schema:schema,source_record_type:recordType||meta.native_type,native_container:meta.container,native_digest:nativeDigest,native_digest_kind:meta.native_digest_kind,native_integrity_verified:nativeVerified,native_integrity_verifier:sourceRuntime==='python'?'python-shake256-record':'javascript-ledger-integrity-monitor',sequence:Math.trunc(meta.sequence),created_at_ms:Math.trunc(Number(body.created_at_ms??body.createdAt??body.at??0)||0),directive_id:directiveId,directive_digest:directiveDigest,assessment_digest:assessmentDigest,outcome_digest:outcomeDigest,verdict:String(body.verdict??''),status:String(body.status??''),relation:String(body.relation??''),credit:runtimeFinite(body.credit),confidence:runtimeFinite(body.confidence),concept:String(body.concept??''),capability:String(body.capability??''),strategy_id:String(body.strategy_id??body.strategyId??''),provenance_groups:[...new Set(provenanceGroups)].sort(),witness,native_payload:structuredClone(body),native_digest_preserved:true,reverification_required:true,import_authority:false,authority:false,...WG_SRNN_RUNTIME_INTERCHANGE_NO_AUTHORITY,interpretation:'cross-runtime-lineage-evidence-not-native-certification'};
  normalized.interchange_digest=await digest(normalized);return normalized;
}

export async function srnnRuntimeInterchangeLineageKey(record,options={}){const row=record?.schema===WG_SRNN_RUNTIME_INTERCHANGE_SCHEMA?record:await normalizeSrnnRuntimeInterchangeRecord(record,options);return[String(row.stage_type??''),String(row.directive_digest??''),String(row.assessment_digest??''),String(row.outcome_digest??'')];}

export async function srnnRuntimeImportRequirements(record,{targetRuntime,jsLedgerVerified=null}={}){
  const row=record?.schema===WG_SRNN_RUNTIME_INTERCHANGE_SCHEMA?record:await normalizeSrnnRuntimeInterchangeRecord(record,{jsLedgerVerified});let target=String(targetRuntime??'').trim().toLowerCase();if(!['python','javascript','js'].includes(target))throw new WGSRNNInterchangeError(`unsupported WG-SRNN target runtime ${JSON.stringify(targetRuntime)}`);if(target==='js')target='javascript';const sameRuntime=target===row.source_runtime;
  return{schema:WG_SRNN_IMPORT_REQUIREMENTS_SCHEMA,source_runtime:row.source_runtime,target_runtime:target,same_runtime:sameRuntime,native_digest_may_be_reused_as_reference:true,native_digest_may_be_reused_as_target_signature:false,must_reverify_source_integrity:row.native_integrity_verified!==true,must_rewitness_before_native_history:!sameRuntime,must_reseal_or_reledger:!sameRuntime,may_grant_authority:false,authority:false,...WG_SRNN_RUNTIME_INTERCHANGE_NO_AUTHORITY};
}

function inspectNormalizedInterchangeValue(value,path='$',issues=[]){
  if(value===null||typeof value==='string'||typeof value==='boolean')return issues;
  if(typeof value==='number'){issues.push({kind:'raw-number-not-normalized',path});return issues;}
  if(Array.isArray(value)){for(let i=0;i<value.length;i++)inspectNormalizedInterchangeValue(value[i],`${path}[${i}]`,issues);return issues;}
  if(!value||typeof value!=='object'){issues.push({kind:'unsupported-normalized-type',path,type:typeof value});return issues;}
  const keys=Object.keys(value);
  if(keys.includes('$f64')){
    if(keys.length!==1||typeof value.$f64!=='string'||!/^[0-9a-f]{16}$/.test(value.$f64))issues.push({kind:'invalid-f64-identity',path});
    return issues;
  }
  for(const key of keys)inspectNormalizedInterchangeValue(value[key],`${path}.${key}`,issues);
  return issues;
}

export async function verifySrnnInterchangeProjection({projection=null,projection_digest=null,lineage=null,requireLineage=true}={}){
  const issues=[];
  if(!projection||typeof projection!=='object'||Array.isArray(projection))issues.push({kind:'projection-not-object'});
  const claimed=String(projection_digest??lineage?.projection_digest??'').trim()||null;
  let observed=null;
  if(projection&&typeof projection==='object'&&!Array.isArray(projection)){
    if(projection.schema!==WG_SRNN_INTERCHANGE_PROJECTION_SCHEMA)issues.push({kind:'projection-schema-mismatch',expected:WG_SRNN_INTERCHANGE_PROJECTION_SCHEMA,observed:projection.schema??null});
    if(projection.profile_id!==WG_SRNN_INTERCHANGE_PROFILE)issues.push({kind:'projection-profile-mismatch',expected:WG_SRNN_INTERCHANGE_PROFILE,observed:projection.profile_id??null});
    if(projection.authority!==false)issues.push({kind:'projection-authority-not-false'});
    for(const [key,value] of Object.entries(WG_SRNN_INTERCHANGE_AUTHORITY_PROFILE))if(projection.authority_profile?.[key]!==value)issues.push({kind:'projection-authority-profile-mismatch',field:key,expected:value,observed:projection.authority_profile?.[key]??null});
    inspectNormalizedInterchangeValue(projection.content,'$.content',issues);
    observed=await digest(projection);
  }
  if(!claimed)issues.push({kind:'projection-digest-missing'});
  else if(observed!==claimed)issues.push({kind:'projection-digest-mismatch',expected:claimed,observed});
  let lineageMatches=null;
  if(lineage==null){
    if(requireLineage)issues.push({kind:'lineage-missing'});
  }else if(typeof lineage!=='object'||Array.isArray(lineage)){
    issues.push({kind:'lineage-not-object'});lineageMatches=false;
  }else{
    const before=issues.length;
    if(lineage.schema!==WG_SRNN_INTERCHANGE_LINEAGE_SCHEMA)issues.push({kind:'lineage-schema-mismatch',expected:WG_SRNN_INTERCHANGE_LINEAGE_SCHEMA,observed:lineage.schema??null});
    if(lineage.profile_id!==WG_SRNN_INTERCHANGE_PROFILE)issues.push({kind:'lineage-profile-mismatch',expected:WG_SRNN_INTERCHANGE_PROFILE,observed:lineage.profile_id??null});
    if(String(lineage.projection_digest??'')!==String(observed??''))issues.push({kind:'lineage-projection-digest-mismatch',expected:observed,observed:lineage.projection_digest??null});
    if(!String(lineage.native_record_digest??'').trim())issues.push({kind:'lineage-native-digest-missing'});
    if(lineage.native_digest_is_authoritative_for_source_runtime!==true)issues.push({kind:'lineage-native-source-authority-flag-invalid'});
    if(lineage.projection_digest_is_interchange_identity_only!==true)issues.push({kind:'lineage-projection-authority-flag-invalid'});
    if(lineage.authority!==false)issues.push({kind:'lineage-authority-not-false'});
    for(const [key,value] of Object.entries(WG_SRNN_INTERCHANGE_AUTHORITY_PROFILE))if(lineage.authority_profile?.[key]!==value)issues.push({kind:'lineage-authority-profile-mismatch',field:key,expected:value,observed:lineage.authority_profile?.[key]??null});
    lineageMatches=issues.length===before;
  }
  const verified=issues.length===0;
  return{schema:WG_SRNN_INTERCHANGE_VERIFICATION_SCHEMA,profile_id:WG_SRNN_INTERCHANGE_PROFILE,claimed_projection_digest:claimed,observed_projection_digest:observed,digest_matches:!!claimed&&claimed===observed,normalized_content:!issues.some(row=>['raw-number-not-normalized','unsupported-normalized-type','invalid-f64-identity'].includes(row.kind)),lineage_required:!!requireLineage,lineage_supplied:lineage!=null,lineage_matches:lineageMatches,verified,issue_count:issues.length,issues,interchange_identity_only:true,native_seal_authority:false,truth_authority:false,promotion_authority:false,learning_authority:false,mutation_authority:false,authority:false,authority_profile:{...WG_SRNN_INTERCHANGE_AUTHORITY_PROFILE},verified_projection:verified?projection:null};
}

export async function srnnInterchangeLineage(record){
  const projection=projectSrnnInterchangeRecord(record),projectionDigest=await digest(projection);
  return{
    schema:WG_SRNN_INTERCHANGE_LINEAGE_SCHEMA,
    profile_id:WG_SRNN_INTERCHANGE_PROFILE,
    source_schema:projection.source_schema,
    source_record_type:projection.source_record_type,
    native_record_digest:String(record?.record_digest??record?.recordDigest??''),
    projection_digest:projectionDigest,
    native_digest_is_authoritative_for_source_runtime:true,
    projection_digest_is_interchange_identity_only:true,
    authority:false,
    authority_profile:{...WG_SRNN_INTERCHANGE_AUTHORITY_PROFILE},
  };
}

export const normalize_interchange_value=normalizeSrnnInterchangeValue;
export const project_interchange_record=projectSrnnInterchangeRecord;
export const digest_interchange_record=digestSrnnInterchangeRecord;
export const interchange_lineage=srnnInterchangeLineage;
export const project_fixture_manifest=projectSrnnInterchangeFixtureManifest;
export const digest_fixture_manifest=digestSrnnInterchangeFixtureManifest;
export const verify_fixture_manifest=verifySrnnInterchangeFixtureManifest;
export const verify_interchange_projection=verifySrnnInterchangeProjection;


export const normalize_record=normalizeSrnnRuntimeInterchangeRecord;
export const lineage_key=srnnRuntimeInterchangeLineageKey;
export const import_requirements=srnnRuntimeImportRequirements;
export const normalize_runtime_interchange_record=normalizeSrnnRuntimeInterchangeRecord;
export const runtime_interchange_lineage_key=srnnRuntimeInterchangeLineageKey;
export const runtime_import_requirements=srnnRuntimeImportRequirements;
