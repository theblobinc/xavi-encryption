const sameValue=(a,b)=>JSON.stringify(a)===JSON.stringify(b);
const clone=v=>v===undefined?undefined:structuredClone(v);

export class MemoryStore {
  constructor() { this.tables = new Map(); }
  table(name) { if (!this.tables.has(name)) this.tables.set(name, new Map()); return this.tables.get(name); }
  async get(table, key) { return this.table(table).get(key); }
  async getMany(table, keys=[]) { const t=this.table(table); return [...keys].map(key=>t.get(key)); }
  async set(table, key, value) { this.table(table).set(key, structuredClone(value)); return value; }
  async append(table, value) { const t = this.table(table); const key = value.id || `${Date.now()}:${t.size}`; t.set(key, structuredClone(value)); return key; }
  async values(table) { return [...this.table(table).values()].map(v => structuredClone(v)); }
  async delete(table, key) { return this.table(table).delete(key); }
  async compareAndSet(table,key,expected,next){ const t=this.table(table),current=t.get(key); if(!sameValue(current,expected))return{updated:false,current:clone(current)}; t.set(key,clone(next)); return{updated:true,current:clone(next)}; }
}
