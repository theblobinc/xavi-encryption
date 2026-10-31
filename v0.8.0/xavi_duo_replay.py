#!/usr/bin/env python3
from __future__ import annotations
import fcntl,json,os,time
from pathlib import Path
from xavi_duo_fs import atomic_write, fsync_dir
from xavi_duo_replay_anchor import ReplayAnchorError,ReplayRollbackDetected,claim_replay_anchor
class ReplayError(RuntimeError): pass
class ReplayGuard:
    def __init__(self,path):
        self.path=Path(path); self.lock=self.path.with_suffix(self.path.suffix+'.lock'); self.quarantine=self.path.with_suffix(self.path.suffix+'.quarantine')
    def init(self):
        self.path.parent.mkdir(parents=True,exist_ok=True); os.chmod(self.path.parent,0o700); fsync_dir(self.path.parent); return self
    def claim(self,session_id,sequence,message_id,expires_at,*,project_id=None,anchor=None,require_anchor=False):
        now=int(time.time())
        session_id=str(session_id); message_id=str(message_id)
        if not session_id or len(session_id)>128: raise ReplayError('invalid session id')
        if not message_id or len(message_id)>256: raise ReplayError('invalid message id')
        if now>int(expires_at): raise ReplayError('session expired')
        if int(expires_at)-now>86400: raise ReplayError('session expiry exceeds 24h policy')
        if self.quarantine.exists(): raise ReplayError('replay state is quarantined')
        anchor_receipt=None
        if require_anchor and anchor is None: raise ReplayError('independent replay anchor required')
        if anchor is not None:
            if not project_id: raise ReplayError('project id required for replay anchor')
            try: anchor_receipt=claim_replay_anchor(anchor,project_id=str(project_id),session_id=session_id,sequence=int(sequence))
            except ReplayRollbackDetected as exc:
                atomic_write(self.quarantine,(json.dumps({'schema':'XAVI-DUO/REPLAY-QUARANTINE/v1','project_id':str(project_id),'session_id':session_id,'sequence':int(sequence),'reason':'external-anchor-rollback','authority':False},sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
                raise ReplayError('external replay rollback detected; state quarantined') from exc
            except ReplayAnchorError as exc:
                raise ReplayError('external replay anchor failed') from exc
        with open(self.lock,'a+') as lf:
            fcntl.flock(lf,fcntl.LOCK_EX); state={}
            if self.path.exists():
                try: state=json.loads(self.path.read_text())
                except Exception as exc: raise ReplayError('replay state is corrupt') from exc
            row=state.get(session_id,{'last_sequence':0,'message_ids':[]})
            expected=int(row['last_sequence'])+1
            if int(sequence)!=expected: raise ReplayError(f'expected sequence {expected}')
            if message_id in row['message_ids']: raise ReplayError('duplicate message id')
            ids=(row['message_ids']+[message_id])[-4096:]
            state[session_id]={'last_sequence':int(sequence),'message_ids':ids,'updated_at':now,'expires_at':int(expires_at)}
            state={k:v for k,v in state.items() if int(v.get('expires_at',now+1))>=now-60}
            atomic_write(self.path,(json.dumps(state,sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
        return {'schema':'XAVI-DUO/REPLAY-CLAIM/v3','session_id':session_id,'sequence':int(sequence),'message_id':message_id,'expires_at':int(expires_at),'external_anchor':anchor_receipt,'authority':False}
