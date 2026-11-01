function resolveElement(target){if(typeof target==='function')return target();if(typeof target==='string')return document.querySelector(target);return target;}
export const SAFE_IFRAME_PROFILES=Object.freeze({
  publisherOpaque:'allow-scripts allow-forms allow-popups allow-popups-to-escape-sandbox allow-top-navigation-by-user-activation allow-downloads allow-modals allow-presentation allow-storage-access-by-user-activation',
  staticIsolated:'',
  formsOnly:'allow-forms allow-popups allow-popups-to-escape-sandbox'
});

export function createPublisherIframeStrategy({
  id,target,fetchDocument=null,makeUrl=ctx=>ctx.url,profile='publisherOpaque',allow='autoplay; encrypted-media; fullscreen; picture-in-picture',referrerPolicy='strict-origin-when-cross-origin',
  readyMessageType='xavi-page-preview-ready',minTextLength=1,minHeight=120,prior=0,when=null,className='',requireReadyMessage=true
}={}){
  if(!id)throw new TypeError('publisher iframe strategy id required');
  if(!Object.hasOwn(SAFE_IFRAME_PROFILES,profile))throw new TypeError(`unknown safe iframe profile: ${profile}`);
  return {id,prior,when,capabilities:['preview'],async run(context,{signal}={}){
    const host=resolveElement(target);if(!host)throw new Error(`iframe target unavailable for strategy ${id}`);
    const frame=document.createElement('iframe');frame.className=className;frame.dataset.xaviStrategy=id;frame.loading='eager';frame.referrerPolicy=referrerPolicy;
    frame.setAttribute('sandbox',SAFE_IFRAME_PROFILES[profile]);if(allow)frame.setAttribute('allow',allow);
    const started=performance.now();
    return new Promise(async(resolve,reject)=>{
      let done=false;
      const cleanup=()=>{window.removeEventListener('message',onMessage);frame.removeEventListener('load',onLoad);frame.removeEventListener('error',onError);signal?.removeEventListener('abort',onAbort);};
      const finish=(value)=>{if(done)return;done=true;cleanup();resolve({...value,iframe:frame,profile,latencyMs:performance.now()-started});};
      const fail=(error)=>{if(done)return;done=true;cleanup();frame.remove();reject(error);};
      const onMessage=event=>{if(event.source!==frame.contentWindow)return;const data=event.data;if(!data||data.type!==readyMessageType)return;const textLength=Number(data.text_length??data.textLength??0),height=Number(data.height??data.document_height??0),visible=data.visible!==false;if(!visible||(textLength<minTextLength&&height<minHeight))return;finish({loaded:true,ready:true,path:'postmessage',textLength,height,visible,data});};
      const onLoad=()=>{if(!requireReadyMessage)finish({loaded:true,ready:true,path:'load'});};
      const onError=()=>fail(new Error(`iframe load error: ${id}`));
      const onAbort=()=>fail(new DOMException('Aborted','AbortError'));
      window.addEventListener('message',onMessage);frame.addEventListener('load',onLoad,{once:true});frame.addEventListener('error',onError,{once:true});signal?.addEventListener('abort',onAbort,{once:true});host.replaceChildren(frame);
      try{if(typeof fetchDocument==='function'){const result=await fetchDocument(context,{signal});if(signal?.aborted)return;frame.srcdoc=String(result?.html??result??'');}else{frame.src=String(await makeUrl(context));}}catch(error){fail(error);}
    });
  }};
}
