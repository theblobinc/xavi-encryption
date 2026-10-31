import { mkdir, readFile, writeFile, rename, readdir, unlink, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { createHash, randomUUID } from 'node:crypto';
const replacer=(_k,v)=>ArrayBuffer.isView(v)?{$typed:v.constructor.name,data:Array.from(v)}:v;
const reviver=(_k,v)=>v&&v.$typed&&Array.isArray(v.data)?(v.$typed==='Float32Array'?Float32Array.from(v.data):v.data):v;
const keyHash=k=>createHash('sha256').update(String(k)).digest('hex');
const sameValue=(a,b)=>JSON.stringify(a,replacer)===JSON.stringify(b,replacer);
const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
export class NodeFileStore {
  constructor({root='.xavi-browser-memory'}={}){this.root=root;}
  async init(){await mkdir(this.root,{recursive:true});return this;}
  async _dir(table){const d=join(this.root,String(table));await mkdir(d,{recursive:true});return d;}
  async _path(table,key){return join(await this._dir(table),`${keyHash(key)}.json`);}
  async get(table,key){try{const p=await this._path(table,key),row=JSON.parse(await readFile(p,'utf8'),reviver);return row?.key===String(key)?row.value:undefined;}catch(e){if(e?.code==='ENOENT')return undefined;throw e;}}
  async getMany(table,keys=[]){return Promise.all([...keys].map(key=>this.get(table,key)));}
  async set(table,key,value){const p=await this._path(table,key),tmp=`${p}.${process.pid}.${randomUUID()}.tmp`,body=JSON.stringify({key:String(key),value},replacer);await writeFile(tmp,body);await rename(tmp,p);return value;}
  async append(table,value){const key=value?.id||`${Date.now()}:${randomUUID()}`;await this.set(table,key,value);return key;}
  async values(table){const d=await this._dir(table),out=[];for(const name of await readdir(d)){if(!name.endsWith('.json'))continue;try{const row=JSON.parse(await readFile(join(d,name),'utf8'),reviver);out.push(row.value);}catch{}}return out;}
  async delete(table,key){try{await unlink(await this._path(table,key));return true;}catch(e){if(e?.code==='ENOENT')return false;throw e;}}

  async _withRecordLock(path,fn,{timeoutMs=5000,staleMs=30000}={}){
    const lock=`${path}.lock`,deadline=Date.now()+timeoutMs;
    for(;;){
      try{await writeFile(lock,JSON.stringify({pid:process.pid,createdAt:Date.now()}),{flag:'wx'});break;}
      catch(error){
        if(error?.code!=='EEXIST')throw error;
        try{
          let abandoned=false;
          try{const owner=JSON.parse(await readFile(lock,'utf8'));const pid=Number(owner?.pid);if(Number.isInteger(pid)&&pid>0){try{process.kill(pid,0);}catch(signalError){if(signalError?.code==='ESRCH')abandoned=true;}}}catch(e){if(e?.code==='ENOENT')continue;}
          const info=await stat(lock);if(abandoned||Date.now()-Number(info.mtimeMs||0)>staleMs){await unlink(lock).catch(()=>{});continue;}
        }catch(e){if(e?.code==='ENOENT')continue;throw e;}
        if(Date.now()>=deadline)throw new Error(`NodeFileStore record lock timeout: ${lock}`);
        await sleep(5);
      }
    }
    try{return await fn();}finally{await unlink(lock).catch(()=>{});}
  }
  async compareAndSet(table,key,expected,next){
    const p=await this._path(table,key);
    return this._withRecordLock(p,async()=>{
      let current;
      try{const row=JSON.parse(await readFile(p,'utf8'),reviver);current=row?.key===String(key)?row.value:undefined;}catch(error){if(error?.code!=='ENOENT')throw error;}
      if(!sameValue(current,expected))return{updated:false,current};
      const tmp=`${p}.${process.pid}.${randomUUID()}.tmp`,body=JSON.stringify({key:String(key),value:next},replacer);await writeFile(tmp,body);await rename(tmp,p);return{updated:true,current:next};
    });
  }
}
