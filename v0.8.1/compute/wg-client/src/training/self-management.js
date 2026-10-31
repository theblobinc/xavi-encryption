/**
 * Autonomous witnessed semantic-policy lifecycle.
 *
 * This controller may promote/demote learned policy, but it never broadens code,
 * browser, observer, sandbox, or trust authority. All mutations still pass through
 * the existing witnessed validation/checkpoint/BrowserAuthority paths.
 */
export class SelfManagementController {
  constructor(xavi, options={}) {
    if (!xavi?.backfill || !xavi?.semantic) throw new TypeError('SelfManagementController requires semantic backfill support');
    this.xavi=xavi;
    this.enabled=options.enabled !== false;
    this.autoPromotion=options.autoPromotion !== false;
    this.autoDemotion=options.autoDemotion !== false;
    this.autoCanary=options.autoCanary !== false;
    this.autoCalibration=options.autoCalibration !== false;
    this.autoSfmReplay=options.autoSfmReplay !== false;
    this.sfmReplayMaxUpdates=Math.max(1,Number(options.sfmReplayMaxUpdates??32)||32);
    this.intervalMs=Math.max(5000, Number(options.intervalMs ?? 30000) || 30000);
    this.initialDelayMs=Math.max(0, Number(options.initialDelayMs ?? this.intervalMs) || 0);
    this.minExamples=Math.max(1, Number(options.minExamples ?? 5) || 5);
    this.maxOverallRegression=Math.abs(Number(options.maxOverallRegression ?? 0.02) || 0);
    this.maxComponentRegression=Math.abs(Number(options.maxComponentRegression ?? 0.03) || 0);
    this.prepareOptions={
      holdoutFraction:0.25,
      minTrain:3,
      minHoldout:2,
      minImprovement:0.001,
      maxComponentRegression:0.03,
      ...(options.prepareOptions || {}),
    };
    this.timer=null;
    this.initialTimer=null;
    this.electionTimer=null;
    this.inFlight=null;
    this.lastRun=null;
    this.lastError=null;
    this.schema='xavi-semantic-self-management/v1';
    this.schedulerLeaseSchema='xavi-semantic-self-management-scheduler-lease/v1';
    this.schedulerLeaseMs=Math.max(250,Number(options.schedulerLeaseMs??Math.max(60000,this.intervalMs*3))||Math.max(60000,this.intervalMs*3));
    this.schedulerElectionRetryMs=Math.max(50,Number(options.schedulerElectionRetryMs??Math.min(this.intervalMs,Math.floor(this.schedulerLeaseMs/3)))||1000);
    this.schedulerOwner=String(options.schedulerOwner||globalThis.crypto?.randomUUID?.()||`${Date.now()}:${Math.random()}`);
    this.schedulerLease=null;
    this.schedulerHeartbeat=null;
    this.schedulerHeartbeatTail=Promise.resolve();
    this.schedulerActivationPromise=null;
    this.schedulerReleasePromise=Promise.resolve();
    this.lastSchedulerState={role:'inactive',reason:'not-activated',authority:false};
  }

  _schedulerLeaseSupported(){return typeof this.xavi?.store?.get==='function'&&typeof this.xavi?.store?.compareAndSet==='function';}
  _schedulerLeaseKey(){return `semantic-self-management-scheduler-lease:${this.xavi?.namespace||'default'}`;}
  _newLeaseId(){return globalThis.crypto?.randomUUID?.()||`${Date.now()}:${Math.random()}`;}
  _leaseOwned(row=this.schedulerLease){return Boolean(row&&row.owner===this.schedulerOwner&&row.leaseId===this.schedulerLease?.leaseId&&row.released!==true&&Number(row.expiresAt||0)>Date.now());}

  config(){
    return {schema:this.schema,enabled:this.enabled,autoPromotion:this.autoPromotion,autoDemotion:this.autoDemotion,autoCanary:this.autoCanary,autoCalibration:this.autoCalibration,autoSfmReplay:this.autoSfmReplay,sfmReplayMaxUpdates:this.sfmReplayMaxUpdates,intervalMs:this.intervalMs,initialDelayMs:this.initialDelayMs,minExamples:this.minExamples,maxOverallRegression:this.maxOverallRegression,maxComponentRegression:this.maxComponentRegression,prepareOptions:{...this.prepareOptions},schedulerLeaseSupported:this._schedulerLeaseSupported(),schedulerLeaseMs:this.schedulerLeaseMs,schedulerElectionRetryMs:this.schedulerElectionRetryMs,authority:false};
  }

  schedulerStatus(){
    const lease=this.schedulerLease;
    return {schema:this.schedulerLeaseSchema,supported:this._schedulerLeaseSupported(),role:this.lastSchedulerState?.role||'inactive',reason:this.lastSchedulerState?.reason||null,leaseId:lease?.leaseId??null,expiresAt:lease?.expiresAt??null,running:Boolean(this.timer||this.initialTimer),standby:Boolean(this.electionTimer)&&!lease,authority:false};
  }

  _arm({immediate=false}={}){
    if(!this.enabled||this.timer||this.initialTimer)return this;
    const run=()=>{this.tick().catch(()=>{});};
    if(immediate)queueMicrotask(run);
    else if(this.initialDelayMs>0){this.initialTimer=setTimeout(()=>{this.initialTimer=null;run();},this.initialDelayMs);this.initialTimer?.unref?.();}
    this.timer=setInterval(run,this.intervalMs);this.timer?.unref?.();
    return this;
  }

  _clearSchedule(){
    if(this.initialTimer){clearTimeout(this.initialTimer);this.initialTimer=null;}
    if(this.timer){clearInterval(this.timer);this.timer=null;}
    if(this.electionTimer){clearTimeout(this.electionTimer);this.electionTimer=null;}
  }

  async _acquireSchedulerLease(){
    if(!this._schedulerLeaseSupported())return{unsupported:true,lease:null,current:null};
    const key=this._schedulerLeaseKey();
    for(let attempt=0;attempt<16;attempt++){
      const now=Date.now(),current=await this.xavi.store.get('records',key).catch(()=>null);
      if(current&&current.released!==true&&Number(current.expiresAt||0)>now&&current.owner!==this.schedulerOwner)return{lease:null,current};
      const leaseId=this._newLeaseId(),next={schema:this.schedulerLeaseSchema,namespace:this.xavi?.namespace||'default',owner:this.schedulerOwner,leaseId,acquiredAt:now,refreshedAt:now,expiresAt:now+this.schedulerLeaseMs,released:false,authority:false};
      const result=await this.xavi.store.compareAndSet('records',key,current,next);
      if(result?.updated)return{lease:next,current:next};
    }
    return{lease:null,current:await this.xavi.store.get('records',key).catch(()=>null)};
  }

  async _refreshSchedulerLease(){
    if(!this._schedulerLeaseSupported())return null;
    const lease=this.schedulerLease;if(!lease)throw Object.assign(new Error('self-management scheduler lease is not held'),{code:'SELF_MANAGEMENT_SCHEDULER_LEASE_NOT_HELD'});
    const key=this._schedulerLeaseKey(),current=await this.xavi.store.get('records',key).catch(()=>null),now=Date.now();
    if(!current||current.owner!==this.schedulerOwner||current.leaseId!==lease.leaseId||current.released===true||Number(current.expiresAt||0)<=now)throw Object.assign(new Error('self-management scheduler lease lost'),{code:'SELF_MANAGEMENT_SCHEDULER_LEASE_LOST',current});
    const next={...current,refreshedAt:now,expiresAt:now+this.schedulerLeaseMs};
    const result=await this.xavi.store.compareAndSet('records',key,current,next);
    if(!result?.updated)throw Object.assign(new Error('self-management scheduler lease lost'),{code:'SELF_MANAGEMENT_SCHEDULER_LEASE_LOST',current:result?.current});
    Object.assign(lease,next);return lease;
  }

  _startSchedulerHeartbeat(){
    if(!this._schedulerLeaseSupported()||!this.schedulerLease||this.schedulerHeartbeat)return;
    const intervalMs=Math.max(50,Math.floor(this.schedulerLeaseMs/3));
    this.schedulerHeartbeat=setInterval(()=>{
      this.schedulerHeartbeatTail=this.schedulerHeartbeatTail.catch(()=>{}).then(()=>this._refreshSchedulerLease()).catch(error=>this._handleSchedulerLeaseLoss(error));
    },intervalMs);
    this.schedulerHeartbeat?.unref?.();
  }

  async _stopSchedulerHeartbeat(){
    if(this.schedulerHeartbeat){clearInterval(this.schedulerHeartbeat);this.schedulerHeartbeat=null;}
    await this.schedulerHeartbeatTail.catch(()=>{});
  }

  _scheduleElection(current=null,{immediate=false}={}){
    if(!this.enabled||this.schedulerLease||this.electionTimer)return;
    const remaining=Math.max(0,Number(current?.expiresAt||0)-Date.now()+5),delay=immediate?0:Math.max(50,Math.min(this.schedulerElectionRetryMs,remaining||this.schedulerElectionRetryMs));
    this.lastSchedulerState={role:'standby',reason:'scheduler-lease-held',currentLeaseId:current?.leaseId??null,currentExpiresAt:current?.expiresAt??null,authority:false};
    this.electionTimer=setTimeout(()=>{this.electionTimer=null;this.activate().catch(error=>{this.lastError={message:String(error?.message||error).slice(0,1000),at:Date.now()};this._scheduleElection(null);});},delay);
    this.electionTimer?.unref?.();
  }

  async _handleSchedulerLeaseLoss(error){
    this._clearSchedule();
    if(this.schedulerHeartbeat){clearInterval(this.schedulerHeartbeat);this.schedulerHeartbeat=null;}
    this.schedulerLease=null;
    this.lastSchedulerState={role:'standby',reason:'scheduler-lease-lost',error:String(error?.message||error).slice(0,1000),authority:false};
    this._scheduleElection(error?.current||null);
  }

  async _releaseSchedulerLease(){
    await this._stopSchedulerHeartbeat();
    const lease=this.schedulerLease;this.schedulerLease=null;
    if(!lease||!this._schedulerLeaseSupported())return;
    const key=this._schedulerLeaseKey(),current=await this.xavi.store.get('records',key).catch(()=>null);
    if(current?.owner!==this.schedulerOwner||current?.leaseId!==lease.leaseId||current?.released===true)return;
    const now=Date.now();await this.xavi.store.compareAndSet('records',key,current,{...current,released:true,releasedAt:now,expiresAt:now}).catch(()=>{});
  }

  async activate({immediate=false}={}){
    if(!this.enabled)return this;
    await this.schedulerReleasePromise.catch(()=>{});
    if(!this._schedulerLeaseSupported()){this.lastSchedulerState={role:'local',reason:'store-cas-unavailable',authority:false};this._arm({immediate});return this;}
    if(this.schedulerLease){
      try{await this._refreshSchedulerLease();this.lastSchedulerState={role:'leader',reason:'lease-refreshed',authority:false};this._startSchedulerHeartbeat();this._arm({immediate});return this;}
      catch(error){await this._handleSchedulerLeaseLoss(error);}
    }
    if(this.schedulerActivationPromise)return this.schedulerActivationPromise;
    this.schedulerActivationPromise=(async()=>{
      const acquired=await this._acquireSchedulerLease();
      if(!acquired.lease){this._scheduleElection(acquired.current,{immediate:false});return this;}
      this.schedulerLease=acquired.lease;
      if(this.electionTimer){clearTimeout(this.electionTimer);this.electionTimer=null;}
      this.lastSchedulerState={role:'leader',reason:'lease-acquired',authority:false};
      this._startSchedulerHeartbeat();
      this._arm({immediate});
      return this;
    })().finally(()=>{this.schedulerActivationPromise=null;});
    return this.schedulerActivationPromise;
  }

  start({immediate=false}={}){
    if(!this.enabled)return this;
    if(!this._schedulerLeaseSupported()){this.lastSchedulerState={role:'local',reason:'store-cas-unavailable',authority:false};return this._arm({immediate});}
    this.activate({immediate}).catch(error=>{this.lastError={message:String(error?.message||error).slice(0,1000),at:Date.now()};});
    return this;
  }

  stop(){
    this._clearSchedule();
    this.schedulerReleasePromise=this._releaseSchedulerLease().catch(error=>{this.lastError={message:String(error?.message||error).slice(0,1000),at:Date.now()};});
    this.lastSchedulerState={role:'inactive',reason:'stopped',authority:false};
    return this;
  }

  async status(){
    const backfill=await this.xavi.backfill.status();
    return {schema:this.schema,config:this.config(),running:Boolean(this.timer||this.initialTimer),inFlight:Boolean(this.inFlight),scheduler:this.schedulerStatus(),lastRun:this.lastRun,lastError:this.lastError,backfill,authority:false};
  }

  async tick(){
    if(!this.enabled)return{schema:this.schema,skipped:true,reason:'disabled',authority:false};
    if(this.inFlight)return this.inFlight;
    this.inFlight=this._tickWithSchedulerLease().finally(()=>{this.inFlight=null;});
    return this.inFlight;
  }

  async _tickWithSchedulerLease(){
    if(!this._schedulerLeaseSupported())return this._tick();
    let temporary=false;
    if(!this.schedulerLease){
      const acquired=await this._acquireSchedulerLease();
      if(!acquired.lease){this.lastSchedulerState={role:'standby',reason:'scheduler-lease-held',currentLeaseId:acquired.current?.leaseId??null,currentExpiresAt:acquired.current?.expiresAt??null,authority:false};return{schema:this.schema,skipped:true,reason:'scheduler-lease-held',scheduler:this.schedulerStatus(),authority:false};}
      this.schedulerLease=acquired.lease;temporary=!this.timer&&!this.initialTimer;
      this.lastSchedulerState={role:'leader',reason:temporary?'manual-cycle-lease':'lease-acquired',authority:false};
      this._startSchedulerHeartbeat();
    }
    try{
      await this._refreshSchedulerLease();
      return await this._tick({refreshSchedulerLease:()=>this._refreshSchedulerLease()});
    }catch(error){
      if(error?.code==='SELF_MANAGEMENT_SCHEDULER_LEASE_LOST'||error?.code==='SELF_MANAGEMENT_SCHEDULER_LEASE_NOT_HELD'){
        await this._handleSchedulerLeaseLoss(error);return{schema:this.schema,skipped:true,reason:'scheduler-lease-lost',error:String(error?.message||error),authority:false};
      }
      throw error;
    }finally{
      if(temporary&&this.schedulerLease){await this._releaseSchedulerLease();this.lastSchedulerState={role:'inactive',reason:'manual-cycle-complete',authority:false};}
    }
  }

  async _tick({refreshSchedulerLease=async()=>null}={}){
    const startedAt=Date.now();
    try{
      let calibration=null,canary=null,reversion=null,cycle=null,sfmReplay=null;
      await refreshSchedulerLease();
      if(this.autoCalibration)calibration=await this.xavi.rebuildSemanticCalibration();
      await refreshSchedulerLease();
      let status=await this.xavi.backfill.status();
      const active=status.activePromotionWitnessDigest;
      if(active&&status.checkpoint&&!status.checkpoint.revertedAt&&this.autoCanary){
        await refreshSchedulerLease();
        canary=await this.xavi.backfill.canary(active,{minExamples:this.minExamples,maxOverallRegression:this.maxOverallRegression,maxComponentRegression:this.maxComponentRegression,witness:false});
        if(canary.checks?.enoughExamples){
          await refreshSchedulerLease();
          canary=await this.xavi.backfill.canary(active,{minExamples:this.minExamples,maxOverallRegression:this.maxOverallRegression,maxComponentRegression:this.maxComponentRegression,witness:true});
          if(!canary.healthy){
            if(this.autoDemotion&&canary.checks?.revertable){await refreshSchedulerLease();reversion=await this.xavi.backfill.revert(active,{reason:'automatic-canary-regression'});await refreshSchedulerLease();status=await this.xavi.backfill.status();}
          }else if(this.autoPromotion&&status.dataset?.backfillEligible>0){await refreshSchedulerLease();cycle=await this.xavi.backfill.cycle({...this.prepareOptions});await refreshSchedulerLease();status=await this.xavi.backfill.status();}
        }
      }else if(this.autoPromotion&&status.dataset?.backfillEligible>0){await refreshSchedulerLease();cycle=await this.xavi.backfill.cycle({...this.prepareOptions});await refreshSchedulerLease();status=await this.xavi.backfill.status();}
      if(this.autoSfmReplay&&this.xavi.sfmReplay){await refreshSchedulerLease();sfmReplay=await this.xavi.sfmReplay.run({maxUpdates:this.sfmReplayMaxUpdates});}
      await refreshSchedulerLease();
      const result={schema:this.schema,startedAt,finishedAt:Date.now(),sfmReplay:sfmReplay?{updated:Number(sfmReplay.updated||0),skipped:Number(sfmReplay.skipped||0),datasetCount:Number(sfmReplay.datasetCount||0)}:null,calibration:calibration?{rebuilt:Boolean(calibration.rebuilt),skipped:Boolean(calibration.skipped),assessmentCount:Number(calibration.assessmentCount||0),receiptDigest:calibration.receipt?.digest||null}:null,canary,reversion,cycle,status,scheduler:this.schedulerStatus(),authority:false};
      this.lastRun={startedAt:result.startedAt,finishedAt:result.finishedAt,action:reversion?'demoted':cycle?.promotion?.promoted?'promoted':canary?'canary':'maintenance',promotionWitnessDigest:cycle?.promotion?.promotionWitness?.digest||null,reversionWitnessDigest:reversion?.reversionWitness?.digest||null,canaryWitnessDigest:canary?.canaryWitnessDigest||null,schedulerLeaseId:this.schedulerLease?.leaseId??null};
      this.lastError=null;
      await this.xavi.store.set('records','semantic-self-management-status',{...this.lastRun,scheduler:this.schedulerStatus(),config:this.config(),updatedAt:Date.now(),authority:false}).catch(()=>{});
      return result;
    }catch(error){
      if(error?.code==='SELF_MANAGEMENT_SCHEDULER_LEASE_LOST'||error?.code==='SELF_MANAGEMENT_SCHEDULER_LEASE_NOT_HELD')throw error;
      const message=String(error?.message||error).slice(0,1000);
      this.lastError={message,at:Date.now()};
      await this.xavi.store.set('records','semantic-self-management-status',{lastRun:this.lastRun,lastError:this.lastError,scheduler:this.schedulerStatus(),config:this.config(),updatedAt:Date.now(),authority:false}).catch(()=>{});
      await this.xavi.ledger.append('semantic-self-management-error',{error:message,authority:false}).catch(()=>{});
      return {schema:this.schema,startedAt,finishedAt:Date.now(),error:message,scheduler:this.schedulerStatus(),authority:false};
    }
  }

  async close(){this._clearSchedule();await this._releaseSchedulerLease().catch(()=>{});await this.schedulerReleasePromise.catch(()=>{});}
}
