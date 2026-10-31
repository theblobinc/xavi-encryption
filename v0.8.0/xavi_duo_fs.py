#!/usr/bin/env python3
from __future__ import annotations
import os, tempfile
from contextlib import contextmanager
from pathlib import Path

class DurableIOError(RuntimeError): pass

def fsync_dir(path: Path|str) -> None:
    # POSIX directory fsync closes the rename durability gap. Platforms that do
    # not expose durable directory handles retain atomic replace semantics but
    # must not claim crash-durable directory metadata.
    if os.name!='posix': return
    p=Path(path)
    fd=os.open(p, os.O_RDONLY | getattr(os,'O_DIRECTORY',0))
    try: os.fsync(fd)
    finally: os.close(fd)

def atomic_write(path: Path|str, data: bytes, mode: int=0o600) -> None:
    dest=Path(path); dest.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=dest.name+'.tmp-',dir=dest.parent)
    tmp_path=Path(tmp)
    try:
        
        if hasattr(os,'fchmod'): os.fchmod(fd,mode)
        with os.fdopen(fd,'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(tmp_path,dest)
        fsync_dir(dest.parent)
    finally:
        try: tmp_path.unlink()
        except FileNotFoundError: pass


def atomic_create(path: Path|str, data: bytes, mode: int=0o600) -> None:
    """Durably create a file exactly once; never replace an existing name."""
    dest=Path(path); dest.parent.mkdir(parents=True,exist_ok=True)
    fd,tmp=tempfile.mkstemp(prefix=dest.name+'.new-',dir=dest.parent)
    tmp_path=Path(tmp)
    try:
        if hasattr(os,'fchmod'): os.fchmod(fd,mode)
        with os.fdopen(fd,'wb') as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        try:
            os.link(tmp_path,dest)
        except FileExistsError:
            raise
        fsync_dir(dest.parent)
    finally:
        try: tmp_path.unlink()
        except FileNotFoundError: pass

def read_regular_file(path: Path|str, *, max_bytes: int, private: bool=False) -> bytes:
    """Bounded, no-symlink regular-file read for key/custody material."""
    p=Path(path)
    if p.is_symlink(): raise DurableIOError('refusing symlink file')
    flags=os.O_RDONLY | getattr(os,'O_NOFOLLOW',0)
    fd=os.open(p,flags)
    try:
        st=os.fstat(fd)
        import stat as _stat
        if not _stat.S_ISREG(st.st_mode): raise DurableIOError('refusing non-regular file')
        if st.st_size>max_bytes: raise DurableIOError('file exceeds bound')
        if private and (st.st_mode & 0o077): raise DurableIOError('private file permissions are too broad')
        chunks=[]; left=max_bytes+1
        while left>0:
            b=os.read(fd,min(1024*1024,left))
            if not b: break
            chunks.append(b); left-=len(b)
        data=b''.join(chunks)
        if len(data)>max_bytes: raise DurableIOError('file exceeds bound')
        return data
    finally: os.close(fd)

def append_fsync(path: Path|str, data: bytes, mode: int=0o600) -> None:
    p=Path(path); p.parent.mkdir(parents=True,exist_ok=True)
    fd=os.open(p,os.O_WRONLY|os.O_APPEND|os.O_CREAT,mode)
    try:
        with os.fdopen(fd,'ab',closefd=True) as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        fsync_dir(p.parent)
    except Exception:
        try: os.close(fd)
        except OSError: pass
        raise

@contextmanager
def secure_tempdir(prefix: str='xavi-duo-'):
    uid=str(os.getuid()) if hasattr(os,'getuid') else None
    candidates=[Path('/dev/shm')] + ([Path('/run/user')/uid] if uid else []) + [Path(tempfile.gettempdir())]
    base=None
    for c in candidates:
        try:
            if c.is_dir() and os.access(c,os.W_OK|os.X_OK): base=c; break
        except OSError: pass
    td=tempfile.TemporaryDirectory(prefix=prefix,dir=str(base) if base else None)
    try:
        p=Path(td.name); os.chmod(p,0o700); yield p
    finally: td.cleanup()
