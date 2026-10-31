export class SecurityMonitor {
  constructor(faculty,{root=globalThis.document,onAssessment=()=>{},debounceMs=150}={}){this.faculty=faculty;this.root=root;this.onAssessment=onAssessment;this.debounceMs=debounceMs;this.observer=null;this.timer=null;}
  start(){if(typeof MutationObserver==='undefined'||!this.root)return false;this.observer=new MutationObserver(()=>{clearTimeout(this.timer);this.timer=setTimeout(()=>this.onAssessment(this.faculty.scanDocument(this.root)),this.debounceMs);});this.observer.observe(this.root,{subtree:true,childList:true,attributes:true,attributeFilter:['href','src','action','sandbox','allow','rel']});return true;}
  stop(){this.observer?.disconnect();this.observer=null;clearTimeout(this.timer);}
}
