import { randomId } from './utils.js';
export class InvestigationQueue {
  constructor({store}={}) { this.store=store; }
  async add(subject,reason,details={}) { const id=randomId('investigation'); const row={id,status:'open',subject,reason:String(reason),details,createdAt:Date.now()}; await this.store.set('investigations',id,row); return row; }
  async list(status='open') { return (await this.store.values('investigations').catch(()=>[])).filter(r=>!status||r.status===status); }
  async resolve(id,resolution={}) { const row=await this.store.get('investigations',id); if(!row) throw new Error(`unknown investigation: ${id}`); const next={...row,status:'resolved',resolution,resolvedAt:Date.now()}; await this.store.set('investigations',id,next); return next; }
}
