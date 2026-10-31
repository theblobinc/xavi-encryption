const clamp=(v,min=0,max=1)=>Math.min(max,Math.max(min,Number(v)||0));
const enc=value=>encodeURIComponent(String(value||'').trim().toLowerCase()).slice(0,240);
export const EPISODE_PATTERN_TOKEN_VERSION=2;
function relations(value){if(Array.isArray(value))return value.map(row=>Array.isArray(row)?String(row[0]||''):String(row||'')).filter(Boolean);return Object.keys(value||{});}
function token(kind,value,weight){const v=String(value||'').trim();return v?{kind,value:v,weight:Number(weight)||1}:null;}
function uniqueTokens(rows,limit=16){const out=[],seen=new Set();for(const row of rows){if(!row)continue;const key=`${row.kind}\0${row.value.toLowerCase()}`;if(seen.has(key))continue;seen.add(key);out.push(row);if(out.length>=limit)break;}return out;}
function episodeEntryType(semantic={}){return semantic.entryWitnessType||(semantic.recentTypes||[]).at?.(-1)||null;}

export function episodePatternTokensFromEpisode(episode){
  const semantic=episode?.semantic||{},cap=String(episode?.capability||'');
  return uniqueTokens([
    token('cap',cap,2),token('cap-root',cap.split(':')[0],1.2),token('intent',semantic.intent,1.4),token('op',semantic.nextOperation,1.4),token('target',semantic.targetHint,.8),token('entry',episodeEntryType(semantic),1.65),token('sig',semantic.shortTermSignature,.55),
    ...(semantic.chainMotifs||[]).slice(-4).reverse().map(v=>token('motif',v,1.7)),
    ...relations(semantic.workingRelations).slice(0,6).map(v=>token('rel',v,.85)),
  ],16);
}
export function episodePatternTokensFromSemantic(capability,semantic={}){
  const cap=String(capability||'');return uniqueTokens([
    token('cap',cap,2),token('cap-root',cap.split(':')[0],1.2),token('intent',semantic.intent,1.4),token('op',semantic.nextOperation,1.4),token('target',semantic.targetHint,.8),token('entry',episodeEntryType(semantic),1.65),token('sig',semantic.shortTermSignature,.55),
    ...(semantic.chainMotifs||[]).slice(-4).reverse().map(v=>token('motif',v,1.7)),
    ...relations(semantic.workingMemory?.relations).slice(0,6).map(v=>token('rel',v,.85)),
  ],16);
}

export class WitnessEpisodePatternIndex {
  constructor({store,ledger,namespace='default',maxBucket=48}={}){if(!store)throw new TypeError('WitnessEpisodePatternIndex requires store');this.store=store;this.ledger=ledger||null;this.namespace=String(namespace);this.maxBucket=Math.max(8,Number(maxBucket)||48);this.schema='xavi-witness-episode-pattern-index/v1';this.tokenVersion=EPISODE_PATTERN_TOKEN_VERSION;this.count=0;}
  _bucketKey(t){return `episode-pattern:${enc(this.namespace)}:${t.kind}:${enc(t.value)}`;}
  _markerKey(recordId){return `episode-pattern-indexed:${enc(this.namespace)}:${recordId}`;}
  async _removeIndex(recordId,{decrement=true}={}){
    if(!recordId)return{removed:false,reason:'missing-record-id',authority:false};
    const markerKey=this._markerKey(recordId),marker=await this.store.get('records',markerKey).catch(()=>null);
    if(marker?.schema!=='xavi-witness-episode-pattern-marker/v1')return{removed:false,reason:'not-indexed',recordId,authority:false};
    let bucketsChanged=0;
    for(const tokenRow of marker.tokens||[]){const t={kind:tokenRow.kind,value:tokenRow.value},key=this._bucketKey(t),bucket=await this.store.get('records',key).catch(()=>null);if(bucket?.schema!=='xavi-witness-episode-pattern-bucket/v1')continue;const prior=Array.isArray(bucket.entries)?bucket.entries:[],entries=prior.filter(row=>row.recordId!==recordId);if(entries.length===prior.length)continue;if(entries.length)await this.store.set('records',key,{...bucket,entries,updatedAt:Date.now()});else await this.store.delete('records',key).catch(()=>{});bucketsChanged++;}
    await this.store.delete('records',markerKey).catch(()=>{});if(decrement)this.count=Math.max(0,this.count-1);
    return{removed:true,recordId,bucketsChanged,count:this.count,tokenVersion:Number(marker.tokenVersion||1),authority:false};
  }
  async init(){
    const rows=await this.store.values('records');let indexed=0,migrated=0;this.count=0;
    for(const row of rows){const record=row?.record;if(record?.schema!=='xavi-auto-retained-memory/v1'||record?.kind!=='witness-episode'||record?.payload?.schema!=='xavi-witness-episode-memory/v1'||row?.retiredAt)continue;const marker=await this.store.get('records',this._markerKey(row.id)).catch(()=>null);if(marker&&Number(marker.tokenVersion||1)>=this.tokenVersion){this.count++;continue;}if(marker){await this._removeIndex(row.id,{decrement:false});migrated++;}const result=await this.index({recordId:row.id,witnessDigest:row.witnessDigest,episode:record.payload,observedAt:row.retainedAt});if(result.indexed)indexed++;}
    return{schema:this.schema,indexed,migrated,count:this.count,tokenVersion:this.tokenVersion,authority:false};
  }
  stats(){return{schema:this.schema,count:this.count,maxBucket:this.maxBucket,tokenVersion:this.tokenVersion,authority:false};}
  async index({recordId,witnessDigest,episode,observedAt=Date.now()}={}){
    if(!recordId||!witnessDigest||episode?.schema!=='xavi-witness-episode-memory/v1')return{indexed:false,reason:'invalid-episode',authority:false};
    const marker=await this.store.get('records',this._markerKey(recordId)).catch(()=>null);if(marker&&Number(marker.tokenVersion||1)>=this.tokenVersion)return{indexed:false,reason:'already-indexed',recordId,witnessDigest,tokenVersion:this.tokenVersion,authority:false};
    if(marker)await this._removeIndex(recordId,{decrement:false});
    const tokens=episodePatternTokensFromEpisode(episode);if(!tokens.length)return{indexed:false,reason:'no-pattern-tokens',authority:false};
    for(const t of tokens){const key=this._bucketKey(t),current=await this.store.get('records',key).catch(()=>null),entries=(current?.entries||[]).filter(row=>row.recordId!==recordId);entries.push({recordId,witnessDigest,capability:episode.capability||null,strategyId:episode.strategyId||null,observedAt:Number(observedAt||Date.now())});await this.store.set('records',key,{schema:'xavi-witness-episode-pattern-bucket/v1',namespace:this.namespace,kind:t.kind,value:t.value,weight:t.weight,tokenVersion:this.tokenVersion,entries:entries.slice(-this.maxBucket),updatedAt:Date.now(),authority:false});}
    await this.store.set('records',this._markerKey(recordId),{schema:'xavi-witness-episode-pattern-marker/v1',recordId,witnessDigest,tokenVersion:this.tokenVersion,tokens:tokens.map(t=>({kind:t.kind,value:t.value})),indexedAt:Date.now(),authority:false});this.count++;
    return{indexed:true,recordId,witnessDigest,tokenCount:tokens.length,tokenVersion:this.tokenVersion,authority:false};
  }
  async retire(recordId){return this._removeIndex(recordId,{decrement:true});}
  async recall({capability='',semantic={}}={}, {limit=8,minPatternScore=.18,witness=true}={}){
    const tokens=episodePatternTokensFromSemantic(capability,semantic),totalWeight=tokens.reduce((n,t)=>n+t.weight,0)||1,acc=new Map();
    const buckets=await Promise.all(tokens.map(async t=>({t,b:await this.store.get('records',this._bucketKey(t)).catch(()=>null)})));
    for(const {t,b} of buckets){if(b?.schema!=='xavi-witness-episode-pattern-bucket/v1')continue;for(const entry of b.entries||[]){const row=acc.get(entry.recordId)||{...entry,matchedWeight:0,matches:[]};row.matchedWeight+=t.weight;row.matches.push({kind:t.kind,value:t.value,weight:t.weight});acc.set(entry.recordId,row);}}
    const candidates=[...acc.values()].map(row=>({...row,patternScore:clamp(row.matchedWeight/totalWeight)})).filter(row=>row.patternScore>=minPatternScore).sort((a,b)=>b.patternScore-a.patternScore||b.observedAt-a.observedAt).slice(0,Math.max(Number(limit)||8,1)*2);
    const diagnostics={schema:'xavi-episode-pattern-recall-diagnostics/v1',bucketCandidates:acc.size,scoredCandidates:candidates.length,missingRecord:0,retired:0,wrongKind:0,accepted:0,returned:0,authority:false};
    const hits=[];
    for(const candidate of candidates){if(hits.length>=Math.max(1,Number(limit)||8))break;const stored=await this.store.get('records',candidate.recordId).catch(()=>null);if(!stored){diagnostics.missingRecord++;continue;}if(stored.retiredAt||stored.active===false){diagnostics.retired++;continue;}if(stored.record?.kind!=='witness-episode'){diagnostics.wrongKind++;continue;}const utility=await this.store.get('memoryUtility',candidate.witnessDigest).catch(()=>null),memoryUtility=clamp(utility?.value??0,-1,1),planReliability=utility?.planReliability==null?null:Number(utility.planReliability),branchCalibrationReliability=utility?.branchCalibrationReliability==null?null:Number(utility.branchCalibrationReliability),branchCalibrationAttempts=utility?.branchCalibrationAttempts==null?null:Number(utility.branchCalibrationAttempts),branchCalibrationUpdatedAt=utility?.branchCalibrationUpdatedAt==null?null:Number(utility.branchCalibrationUpdatedAt),branchCalibrationRecentReliability=utility?.branchCalibrationRecentReliability==null?null:Number(utility.branchCalibrationRecentReliability),branchCalibrationRecentWeight=utility?.branchCalibrationRecentWeight==null?null:Number(utility.branchCalibrationRecentWeight),branchCalibrationRecentUpdatedAt=utility?.branchCalibrationRecentUpdatedAt==null?null:Number(utility.branchCalibrationRecentUpdatedAt),branchCalibrationDrift=utility?.branchCalibrationDrift==null?null:Number(utility.branchCalibrationDrift),trustScore=clamp(.62+.16*memoryUtility);hits.push({id:candidate.recordId,recordId:candidate.recordId,witnessDigest:candidate.witnessDigest,score:2*candidate.patternScore-1,trustScore,memoryUtility,planReliability,branchCalibrationReliability,branchCalibrationAttempts,branchCalibrationUpdatedAt,branchCalibrationRecentReliability,branchCalibrationRecentWeight,branchCalibrationRecentUpdatedAt,branchCalibrationDrift,utility,row:stored,retention:stored.retention||{},epistemicStatus:stored.retention?.epistemicStatus||'observed',patternScore:candidate.patternScore,patternMatches:candidate.matches,metadata:{episodePattern:true,source:'witness-pattern'},authority:false});}
    diagnostics.accepted=hits.length;diagnostics.returned=hits.length;
    let receipt=null;if(witness&&this.ledger)receipt=await this.ledger.append('memory-episode-pattern-recall',{capability,tokenVersion:this.tokenVersion,tokenCount:tokens.length,candidateCount:acc.size,diagnostics,returned:hits.map(row=>({recordId:row.recordId,witnessDigest:row.witnessDigest,patternScore:row.patternScore,planReliability:row.planReliability,branchCalibrationReliability:row.branchCalibrationReliability,branchCalibrationAttempts:row.branchCalibrationAttempts,branchCalibrationUpdatedAt:row.branchCalibrationUpdatedAt,branchCalibrationRecentReliability:row.branchCalibrationRecentReliability,branchCalibrationRecentWeight:row.branchCalibrationRecentWeight,branchCalibrationRecentUpdatedAt:row.branchCalibrationRecentUpdatedAt,branchCalibrationDrift:row.branchCalibrationDrift,matches:row.patternMatches.slice(0,8)})),authority:false});
    return{schema:'xavi-witness-episode-pattern-recall/v1',namespace:this.namespace,tokenVersion:this.tokenVersion,tokenCount:tokens.length,candidateCount:acc.size,hits,receipt,diagnostics,authority:false};
  }
}
