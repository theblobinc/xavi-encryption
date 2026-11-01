#!/usr/bin/env python3
from __future__ import annotations
import fcntl,hashlib,json,os,time,uuid
from pathlib import Path
from xavi_duo_fs import atomic_write, append_fsync, fsync_dir
from vendor import duo_core as duo
SCHEMA='XAVI-DUO/WG-WITNESS-BRIDGE/v3'
def canonical(v): return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
def digest(v): return 'sha256:'+hashlib.sha256(canonical(v)).hexdigest()
class WitnessBridge:
    def __init__(self,root,namespace='xavi-duo-encrypt'):
        self.root=Path(root); self.namespace=namespace; self.log=self.root/'witness.jsonl'; self.head=self.root/'head.json'; self.lock=self.root/'append.lock'
    def init(self):
        self.root.mkdir(parents=True,exist_ok=True); os.chmod(self.root,0o700); fsync_dir(self.root); self._recover(); return self
    def _log_head(self):
        if not self.log.exists() or self.log.stat().st_size==0: return {'sequence':0,'head':None}
        last=None
        with self.log.open('rb') as f:
            for line in f:
                if line.strip(): last=line
        if last is None: return {'sequence':0,'head':None}
        try: row=json.loads(last)
        except Exception as exc: raise RuntimeError('witness log tail is corrupt') from exc
        if row.get('digest')!=digest({k:v for k,v in row.items() if k!='digest'}): raise RuntimeError('witness log tail digest mismatch')
        return {'sequence':int(row['sequence']),'head':row['digest']}
    def _recover(self):
        expected=self._log_head(); current=None
        if self.head.exists():
            try: current=json.loads(self.head.read_text())
            except Exception: current=None
        if current!=expected:
            atomic_write(self.head,(json.dumps(expected,sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
        return expected
    def append(self,event_type,body):
        if body.get('authority') is True: raise ValueError('bridge evidence cannot grant authority')
        body=dict(body)
        if 'duo_numeral' in body:
            body['duo_numeral']=duo.validate_numeral_context(body['duo_numeral'])
        with open(self.lock,'a+b') as lf:
            fcntl.flock(lf,fcntl.LOCK_EX); state=self._recover()
            sequence=int(state['sequence'])+1
            receipt={'schema':SCHEMA,'schemaVersion':'xavi-browser-witness/v1','id':'xavi-duo-'+uuid.uuid4().hex,'namespace':self.namespace,'sequence':sequence,'duo_sequence':duo.numeral_context(sequence,1),'type':str(event_type),'observedAt':int(time.time()*1000),'parentDigest':state.get('head'),'body':{**body,'authority':False},'authority':False}
            rd=digest(receipt); committed={**receipt,'digest':rd}
            append_fsync(self.log,canonical(committed)+b'\n',0o600)
            atomic_write(self.head,(json.dumps({'sequence':committed['sequence'],'head':rd},sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
            return committed
    def append_duo(self,event_type,body,*,external_count:int,modulus:int):
        payload={**dict(body),'duo_numeral':duo.numeral_context(int(external_count),int(modulus))}
        return self.append(event_type,payload)
