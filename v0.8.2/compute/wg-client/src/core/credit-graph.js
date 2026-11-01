export class CreditGraph {
  constructor({decay=0.82,maxDepth=8}={}) { this.decay=decay; this.maxDepth=maxDepth; this.parents=new Map(); }
  link(child,parent,weight=1) {
    if (!child || !parent || child===parent) return this;
    const list=this.parents.get(child)||[]; list.push({id:parent,weight:Number.isFinite(weight)?weight:1}); this.parents.set(child,list); return this;
  }
  distribute(terminalId,reward) {
    const credit=new Map([[terminalId,Number(reward)||0]]); const queue=[{id:terminalId,value:Number(reward)||0,depth:0}]; const seen=new Set();
    while (queue.length) {
      const cur=queue.shift(); const token=`${cur.id}:${cur.depth}`; if (seen.has(token)||cur.depth>=this.maxDepth) continue; seen.add(token);
      for (const parent of this.parents.get(cur.id)||[]) {
        const value=cur.value*this.decay*parent.weight; credit.set(parent.id,(credit.get(parent.id)||0)+value); queue.push({id:parent.id,value,depth:cur.depth+1});
      }
    }
    return Object.fromEntries(credit);
  }
}
