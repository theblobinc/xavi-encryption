#!/usr/bin/env python3
from pathlib import Path
import argparse, hashlib
ROOT=Path(__file__).resolve().parents[1]
EXCLUDED_DIRS={'.git','.state','.tfhe-gpu-state','state','__pycache__','.pytest_cache','.mypy_cache','.ruff_cache','build','dist','.venv','venv','validation','release'}
EXCLUDED_FILES={'SHA256SUMS','server.pid'}
EXCLUDED_SUFFIXES={'.pem','.xdek'}
EXCLUDED_NAMES={'client-key.bin','private.bin'}
def files():
    for p in sorted(ROOT.rglob('*')):
        if not p.is_file(): continue
        rel=p.relative_to(ROOT)
        if any(part in EXCLUDED_DIRS or part.endswith('.egg-info') for part in rel.parts): continue
        if rel.name in EXCLUDED_FILES or rel.name in EXCLUDED_NAMES or rel.suffix.lower() in EXCLUDED_SUFFIXES: continue
        if rel.name.startswith('RELEASE_GATE_v') and rel.name != f"RELEASE_GATE_v{(ROOT/'VERSION').read_text().strip()}.json": continue
        if '.backup-' in rel.name or rel.name.endswith('~'): continue
        yield rel,p
def sha(p):
    h=hashlib.sha256()
    with p.open('rb') as f:
        for b in iter(lambda:f.read(1024*1024),b''): h.update(b)
    return h.hexdigest()
def main():
    a=argparse.ArgumentParser(); a.add_argument('--hash'); a.add_argument('--list',action='store_true'); x=a.parse_args(); rows=list(files())
    if x.hash: (ROOT/x.hash).write_text(''.join(f'{sha(p)}  {rel.as_posix()}\n' for rel,p in rows))
    if x.list or not x.hash:
        for rel,_ in rows: print(rel.as_posix())
if __name__=='__main__': main()
