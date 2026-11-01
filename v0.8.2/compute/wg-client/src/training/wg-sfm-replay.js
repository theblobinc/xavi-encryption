export class WitnessSfmReplayTrainer {
  constructor(xavi,{maxUpdates=64}={}){
    if(!xavi?.sfm||!xavi?.replay) throw new TypeError('WitnessSfmReplayTrainer requires WG-SFM and witness replay');
    this.xavi=xavi;this.maxUpdates=Math.max(1,Number(maxUpdates)||64);this.schema='xavi-wg-sfm-replay-trainer/v1';
  }
  markerKey(routeWitnessDigest){return `wg-sfm-replay-applied:${routeWitnessDigest}`;}
  async _alreadyCrossTrained(){
    const rows=await this.xavi.store.values('witness');const set=new Set();
    for(const row of rows){if(row?.type==='wg-sfm-cross-trained'&&row.body?.routeWitnessDigest)set.add(row.body.routeWitnessDigest);}
    return set;
  }
  async run({limit=1000,maxUpdates=this.maxUpdates,includeNegative=true}={}){
    const dataset=await this.xavi.replay.build({limit,persist:false});const crossTrained=await this._alreadyCrossTrained();const updates=[];let skipped=0;
    for(const example of dataset.examples){
      if(updates.length>=Math.max(1,Number(maxUpdates)||this.maxUpdates))break;
      const t=example.training||{},promotionDigest=t.policyPromotionDigest||t.backfillPromotionDigest||null;
      if(!example.labels?.trainingEligible||!t.appliedOnline||!promotionDigest){skipped++;continue;}
      if(!includeNegative&&example.labels?.negative){skipped++;continue;}
      if(crossTrained.has(example.routeWitnessDigest)){skipped++;continue;}
      if(await this.xavi.store.get('records',this.markerKey(example.routeWitnessDigest))){skipped++;continue;}
      const context={type:'witness-replay',capability:example.capability||null,strategyId:example.strategyId||null,runtime:example.runtime||null,before:(example.before||[]).slice(-8).map(row=>({type:row.type,semanticSignature:row.semanticSignature||null,metaObjectSignature:row.metaObjectSignature||null})),action:example.action||null,prediction:example.prediction||null,observed:{nextWitnessType:example.observed?.nextWitnessType||null,terminalType:example.observed?.terminalType||null}};
      const inference=this.xavi.sfm.infer(context,{domain:'replay'});
      const reward=Number(t.reward??(example.labels?.positive?1:-1));
      const result=await this.xavi.sfm.learnValidated({inference,reward,outcome:{ok:Boolean(example.labels?.positive),validated:true},routeWitnessDigest:example.routeWitnessDigest,outcomeWitnessDigest:example.outcomeWitnessDigest||null,learningWitnessDigest:t.learningAssessmentDigest||null,promotionWitnessDigest:promotionDigest,runtime:example.runtime||null,source:'replay',sourceExampleId:example.id});
      if(!result.updated){skipped++;continue;}
      const marker={schema:this.schema,routeWitnessDigest:example.routeWitnessDigest,exampleId:example.id,promotionWitnessDigest:promotionDigest,crossTrainingWitnessDigest:result.witness?.digest||null,runtime:example.runtime||null,positive:Boolean(example.labels?.positive),negative:Boolean(example.labels?.negative),reward,appliedAt:Date.now(),authority:false};
      await this.xavi.store.set('records',this.markerKey(example.routeWitnessDigest),marker);
      const receipt=await this.xavi.ledger.append('wg-sfm-replay-trained',marker);
      updates.push({...marker,receiptDigest:receipt.digest,rnnTeaching:result.rnnTeaching});crossTrained.add(example.routeWitnessDigest);
    }
    return{schema:this.schema,datasetCount:dataset.count,trainingEligible:dataset.trainingEligible,appliedOnline:dataset.appliedOnline,updated:updates.length,skipped,updates,authority:false};
  }
}
