#!/usr/bin/env python3
"""Deterministic standalone release builder for XAVI-DUO Encryption.

Builds a source archive and wheel from an explicit release allowlist.  It
snapshots every source file, verifies the source did not change during the
snapshot, normalizes archive metadata, and emits a canonical artifact manifest.
Signing is deliberately separate (xavi-duo-release) so private release keys are
never required by the build process.
"""
from __future__ import annotations
import argparse, gzip, hashlib, importlib.util, json, os, shutil, subprocess, sys, tarfile, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
DEFAULT_EPOCH=1793332800  # 2026-10-30T00:00:00Z

def sha256_path(p:Path)->str:
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()

def load_allowlist():
    spec=importlib.util.spec_from_file_location('release_file_list',ROOT/'scripts'/'release_file_list.py')
    m=importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return [(rel,Path(p)) for rel,p in m.files()]

def tree_digest(rows:list[tuple[Path,str]])->str:
    h=hashlib.sha256()
    for rel,digest in sorted(rows,key=lambda x:x[0].as_posix()):
        h.update(rel.as_posix().encode()); h.update(b'\0'); h.update(digest.encode()); h.update(b'\n')
    return 'sha256:'+h.hexdigest()

def snapshot(stage:Path,epoch:int):
    before=[(rel,p,sha256_path(p)) for rel,p in load_allowlist()]
    for rel,p,digest in before:
        q=stage/rel; q.parent.mkdir(parents=True,exist_ok=True); shutil.copyfile(p,q)
        mode=0o755 if os.access(p,os.X_OK) else 0o644
        os.chmod(q,mode); os.utime(q,(epoch,epoch),follow_symlinks=False)
        if sha256_path(q)!=digest: raise RuntimeError(f'snapshot copy mismatch: {rel}')
    after={rel:sha256_path(p) for rel,p in load_allowlist()}
    if len(after)!=len(before): raise RuntimeError('release allowlist changed during snapshot')
    for rel,p,digest in before:
        if after.get(rel)!=digest: raise RuntimeError(f'source changed during snapshot: {rel}')
    rows=[(rel,digest) for rel,p,digest in before]
    sums=''.join(f'{digest}  {rel.as_posix()}\n' for rel,digest in sorted(rows,key=lambda x:x[0].as_posix()))
    s=stage/'SHA256SUMS'; s.write_text(sums,encoding='utf-8'); os.chmod(s,0o644); os.utime(s,(epoch,epoch))
    return rows

def make_tar(stage:Path,out:Path,root_name:str,epoch:int):
    with out.open('wb') as raw:
        with gzip.GzipFile(filename='',mode='wb',fileobj=raw,mtime=epoch,compresslevel=9) as gz:
            with tarfile.open(fileobj=gz,mode='w',format=tarfile.PAX_FORMAT) as tf:
                files=sorted((p for p in stage.rglob('*') if p.is_file()),key=lambda p:p.relative_to(stage).as_posix())
                for p in files:
                    rel=p.relative_to(stage); data=p.read_bytes()
                    ti=tarfile.TarInfo(f'{root_name}/{rel.as_posix()}')
                    ti.size=len(data); ti.mtime=epoch; ti.uid=0; ti.gid=0; ti.uname=''; ti.gname=''
                    ti.mode=0o755 if os.access(p,os.X_OK) else 0o644
                    import io; tf.addfile(ti,io.BytesIO(data))

def build_wheel(outdir:Path,epoch:int)->Path:
    env=os.environ.copy(); env['SOURCE_DATE_EPOCH']=str(epoch); env['PYTHONHASHSEED']='0'
    subprocess.run([sys.executable,'-m','pip','wheel','--no-deps','--no-cache-dir','.', '-w',str(outdir)],cwd=ROOT,env=env,check=True,stdout=subprocess.DEVNULL)
    wheels=sorted(outdir.glob('xavi_duo_encryption-*.whl'))
    if len(wheels)!=1: raise RuntimeError(f'expected one wheel, got {len(wheels)}')
    return wheels[0]

def main():
    ap=argparse.ArgumentParser(description='Build deterministic XAVI-DUO standalone release artifacts')
    ap.add_argument('--outdir',required=True); ap.add_argument('--date',default='2026-10-30'); ap.add_argument('--epoch',type=int,default=int(os.environ.get('SOURCE_DATE_EPOCH',DEFAULT_EPOCH)))
    a=ap.parse_args(); outdir=Path(a.outdir).resolve(); outdir.mkdir(parents=True,exist_ok=True)
    version=(ROOT/'VERSION').read_text().strip(); root_name=f'XAVI_DUO_Encryption_v{version}_{a.date}'
    for p in outdir.glob(root_name+'*'): p.unlink() if p.is_file() else None
    with tempfile.TemporaryDirectory(prefix='xavi-duo-release-snapshot-') as td:
        stage=Path(td)/root_name; stage.mkdir()
        rows=snapshot(stage,a.epoch)
        archive=outdir/(root_name+'.tar.gz'); make_tar(stage,archive,root_name,a.epoch)
    wheel=build_wheel(outdir,a.epoch)
    gate=ROOT/f'RELEASE_GATE_v{version}.json'
    manifest={
      'schema':'XAVI-DUO/RELEASE-ARTIFACT-MANIFEST/v1','project':'XAVI-DUO Encryption','version':version,'release_date':a.date,
      'source_date_epoch':a.epoch,'source_file_count_excluding_SHA256SUMS':len(rows),'source_tree_sha256':tree_digest(rows),
      'source_archive':{'name':archive.name,'sha256':'sha256:'+sha256_path(archive),'bytes':archive.stat().st_size},
      'wheel':{'name':wheel.name,'sha256':'sha256:'+sha256_path(wheel),'bytes':wheel.stat().st_size},
      'release_gate':({'name':gate.name,'sha256':'sha256:'+sha256_path(gate)} if gate.exists() else None),
      'internal_manifest':{'name':'RELEASE_MANIFEST.json','sha256':'sha256:'+sha256_path(ROOT/'RELEASE_MANIFEST.json')},
      'signature_required':'ML-DSA-87','authority':False,
    }
    mp=outdir/(root_name+'.RELEASE.json'); mp.write_text(json.dumps(manifest,sort_keys=True,separators=(',',':'))+'\n',encoding='utf-8'); os.chmod(mp,0o644)
    print(json.dumps({'status':'PASS','archive':str(archive),'wheel':str(wheel),'manifest':str(mp),**manifest},indent=2,sort_keys=True))
if __name__=='__main__': main()
