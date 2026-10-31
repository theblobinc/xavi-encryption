import { createServer } from 'node:http';
import { MediaTriageService } from '../media/complexity.js';

async function bodyJson(req,{maxBytes=65536}={}){let n=0;const chunks=[];for await(const c of req){n+=c.length;if(n>maxBytes)throw Object.assign(new Error('request body too large'),{statusCode:413});chunks.push(c);}if(!n)return{};try{return JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{throw Object.assign(new Error('invalid JSON'),{statusCode:400});}}
function send(res,status,payload){const body=JSON.stringify(payload);res.writeHead(status,{'content-type':'application/json; charset=utf-8','content-length':Buffer.byteLength(body),'cache-control':'no-store'});res.end(body);}

export function createMediaEndpoint({xavi,allowedRoots=[process.cwd()],host='127.0.0.1',port=18321,maxBodyBytes=65536}={}){
  if(!xavi)throw new TypeError('xavi runtime required');
  const triage=xavi.media instanceof MediaTriageService?xavi.media:new MediaTriageService(xavi,{allowedRoots});xavi.media=triage;
  const server=createServer(async(req,res)=>{
    try{
      const url=new URL(req.url,'http://localhost');
      if(req.method==='GET'&&url.pathname==='/healthz')return send(res,200,{ok:true,service:'xavi-media-triage',schema:'xavi-media-endpoint/v1'});
      if(req.method==='POST'&&url.pathname==='/v1/media/analyze'){
        const body=await bodyJson(req,{maxBytes:maxBodyBytes});if(!body.path)return send(res,400,{ok:false,error:'path is required'});
        const result=await triage.analyze(body.path,{retain:Boolean(body.retain),taskHint:body.taskHint||'',retainStructure:body.retainStructure!==false});
        return send(res,200,{ok:true,result});
      }
      return send(res,404,{ok:false,error:'not found'});
    }catch(error){return send(res,error.statusCode||400,{ok:false,error:String(error?.message||error)});}
  });
  return {server,triage,listen:()=>new Promise((resolve,reject)=>{server.once('error',reject);server.listen(port,host,()=>{server.off('error',reject);resolve(server.address());});}),close:()=>new Promise((resolve,reject)=>server.close(err=>err?reject(err):resolve()))};
}
