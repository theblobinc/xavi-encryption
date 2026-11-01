#!/usr/bin/env python3
"""XAVI-DUO Encryption v2 (XDE2).

Security boundary:
- Confidentiality/integrity: ChaCha20-Poly1305 from ``cryptography``.
- Key separation: HKDF-SHA256.
- DUO-Math Rev009 corrected A-J/a-j adjustable-mod wire representation.

The DUO layer is intentionally *not* treated as an independent cryptographic
primitive.  Its hidden modulus/offset schedule makes the wire representation
polymorphic while the standard AEAD remains the security foundation.

License: MIT OR Apache-2.0
"""
from __future__ import annotations

import base64
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
from pathlib import Path
from typing import Iterable
from xavi_duo_fs import DurableIOError, atomic_write, fsync_dir, read_regular_file
from xavi_duo_nonce_anchor import NonceAnchorError,NonceRollbackDetected,require_independent_anchor

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

HERE = Path(__file__).resolve().parent
import sys
sys.path.insert(0, str(HERE / "vendor"))
import duo_core as duo  # Rev009 canonical corrected copy

MAGIC = "XDE2"
KEY_MAGIC = "XDEK2"
PROTOCOL_AAD = b"XAVI-DUO-ENC/v2"
HKDF_SALT = b"XAVI-DUO-ENC/v2/HKDF-SHA256"
KEY_BYTES = 32
NONCE_BYTES = 12
TAG_BYTES = 16
MAX_MODULUS = 65535
OFFSET_MIN = 1 << 40
OFFSET_MAX = (1 << 62) - 257
MAX_PLAINTEXT = 16 * 1024 * 1024
MAX_AAD = 64 * 1024
MAX_PAD_TO = 1024 * 1024
MAX_CELL_CHARS = 20
PAYLOAD_MAGIC = b"XDP2"
PAYLOAD_HEADER_BYTES = 12
MAX_PADDED_PAYLOAD = MAX_PLAINTEXT + MAX_PAD_TO + PAYLOAD_HEADER_BYTES
MAX_CELLS = MAX_PADDED_PAYLOAD + TAG_BYTES
MAX_FRAME_BYTES = 64 * 1024 * 1024
CELL_RE = re.compile(r"^[1-9][A-J]*[a-j]*$")

class XDEError(ValueError):
    pass

class AuthenticationError(XDEError):
    pass


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _derive(master: bytes, info: bytes) -> bytes:
    if len(master) != KEY_BYTES:
        raise XDEError("master key must be exactly 32 bytes")
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=HKDF_SALT, info=info).derive(master)


def derive_keys(master: bytes) -> tuple[bytes, bytes]:
    return _derive(master, b"aead"), _derive(master, b"duo-format")


def derive_receipt_key(master: bytes) -> bytes:
    return _derive(master, b"receipt-auth")


def _cell_params(k_fmt: bytes, nonce: bytes, index: int) -> tuple[int, int]:
    if len(nonce) != NONCE_BYTES or index < 0:
        raise XDEError("invalid nonce/index")
    msg = b"XDE2-cell" + nonce + index.to_bytes(8, "big")
    d = hmac.new(k_fmt, msg, hashlib.sha256).digest()
    modulus = 2 + (int.from_bytes(d[:4], "big") % (MAX_MODULUS - 1))
    span = OFFSET_MAX - OFFSET_MIN + 1
    offset = OFFSET_MIN + (int.from_bytes(d[4:12], "big") % span)
    return modulus, offset


def _nonce_to_duo(nonce: bytes) -> str:
    if len(nonce) != NONCE_BYTES:
        raise XDEError("nonce must be 12 bytes")
    return ".".join(duo.duo_count(b + 1) for b in nonce)


def _nonce_from_duo(text: str) -> bytes:
    parts = text.split(".") if text else []
    if len(parts) != NONCE_BYTES:
        raise XDEError("frame nonce must contain 12 DUO byte cells")
    out = bytearray()
    for part in parts:
        if len(part) > 3:
            raise XDEError('DUO nonce cell exceeds canonical byte-glyph length')
        try:
            n = duo.parse_duo_count(part)
        except Exception as exc:
            raise XDEError("invalid DUO nonce cell") from exc
        if not 1 <= n <= 256:
            raise XDEError("DUO nonce cell outside byte+1 range")
        out.append(n - 1)
    return bytes(out)


def _format_blob(blob: bytes, k_fmt: bytes, nonce: bytes) -> list[str]:
    cells: list[str] = []
    for i, b in enumerate(blob):
        modulus, offset = _cell_params(k_fmt, nonce, i)
        count = offset + b + 1
        token = duo.token_at(count, modulus)["token"]
        if not CELL_RE.fullmatch(token) or "0" in token:
            raise AssertionError((i, modulus, count, token))
        cells.append(token)
    return cells


def _unformat_cells(cells: Iterable[str], k_fmt: bytes, nonce: bytes) -> bytes:
    out = bytearray()
    for i, token in enumerate(cells):
        if i >= MAX_CELLS: raise XDEError('too many DUO payload cells')
        if len(token) > MAX_CELL_CHARS: raise XDEError(f'DUO payload cell too long at index {i}')
        if not CELL_RE.fullmatch(token):
            raise XDEError(f"invalid DUO payload cell at index {i}")
        modulus, offset = _cell_params(k_fmt, nonce, i)
        state = duo.invert_token(token, modulus)
        if state is None:
            raise XDEError(f"DUO payload cell absent from derived modulus at index {i}")
        b = state["count"] - offset - 1
        if not 0 <= b <= 255:
            raise XDEError(f"DUO payload cell outside byte window at index {i}")
        out.append(b)
    return bytes(out)


def _context_commitment_key(master:bytes)->bytes:
    return _derive(master,b'duo-context-commitment')

def _frame_parts_for_context(frame:str):
    if not isinstance(frame,str): raise XDEError('frame must be text')
    text=frame.strip()
    if len(text.encode('utf-8','strict'))>MAX_FRAME_BYTES: raise XDEError('XDE2 frame exceeds production size limit')
    parts=text.split('|',2)
    if len(parts)!=3 or parts[0]!=MAGIC: raise XDEError('invalid XDE2 frame')
    nonce=_nonce_from_duo(parts[1])
    cells=parts[2].split('.') if parts[2] else []
    if len(cells)>MAX_CELLS: raise XDEError('XDE2 frame contains too many payload cells')
    return nonce,cells

def hidden_duo_context(master:bytes, frame:str, index:int)->dict:
    """Authorized diagnostic view of one hidden rotating-modulus cell context."""
    nonce,cells=_frame_parts_for_context(frame)
    if not isinstance(index,int) or index<0 or index>=len(cells): raise XDEError('cell index outside frame')
    token=cells[index]
    if len(token)>MAX_CELL_CHARS or not CELL_RE.fullmatch(token): raise XDEError('invalid DUO payload cell')
    _,k_fmt=derive_keys(master); modulus,offset=_cell_params(k_fmt,nonce,index)
    state=duo.invert_token(token,modulus)
    if state is None: raise XDEError('DUO payload cell absent from derived modulus')
    byte_value=state['count']-offset-1
    if not 0<=byte_value<=255: raise XDEError('DUO payload cell outside byte window')
    ctx=duo.numeral_context(state['count'],modulus)
    return {
        'schema':'XAVI-DUO/XDE2-CELL-CONTEXT/v1',
        'index':index,'offset':offset,'ciphertext_byte':byte_value,
        'duo':ctx,'authority':False,
    }

def duo_context_commitment(master:bytes, frame:str)->str:
    """Keyed commitment to the complete hidden DUO interpretation of a frame.

    This commits to the per-cell modulus, offset, N, S, c, r, H(r), R(c),
    symbol and formatted ciphertext byte without revealing those values on wire.
    """
    nonce,cells=_frame_parts_for_context(frame)
    key=_context_commitment_key(master)
    mac=hmac.new(key,b'XDE2-duo-context/v1\x00'+nonce,hashlib.sha256)
    _,k_fmt=derive_keys(master)
    for i,token in enumerate(cells):
        if len(token)>MAX_CELL_CHARS or not CELL_RE.fullmatch(token): raise XDEError(f'invalid DUO payload cell at index {i}')
        modulus,offset=_cell_params(k_fmt,nonce,i); state=duo.invert_token(token,modulus)
        if state is None: raise XDEError(f'DUO payload cell absent from derived modulus at index {i}')
        byte_value=state['count']-offset-1
        if not 0<=byte_value<=255: raise XDEError(f'DUO payload cell outside byte window at index {i}')
        row={'index':i,'offset':offset,'ciphertext_byte':byte_value,'duo':duo.numeral_context(state['count'],modulus)}
        raw=json.dumps(row,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf-8')
        mac.update(len(raw).to_bytes(8,'big')); mac.update(raw)
    return 'hmac-sha256:'+mac.hexdigest()

def _pack_payload(plaintext: bytes, pad_to: int = 0) -> bytes:
    if len(plaintext) > MAX_PLAINTEXT:
        raise XDEError(f"v2 plaintext limit is {MAX_PLAINTEXT} bytes")
    if pad_to < 0 or (pad_to and pad_to < 16):
        raise XDEError("pad_to must be 0 or >= 16 bytes")
    if pad_to > MAX_PAD_TO:
        raise XDEError(f'pad_to exceeds production limit of {MAX_PAD_TO} bytes')
    body = PAYLOAD_MAGIC + len(plaintext).to_bytes(8, "big") + plaintext
    if pad_to:
        target = ((len(body) + pad_to - 1) // pad_to) * pad_to
        if target > MAX_PADDED_PAYLOAD: raise XDEError('padded payload exceeds production limit')
        body += os.urandom(target - len(body))
    return body


def _unpack_payload(body: bytes) -> bytes:
    if len(body) < PAYLOAD_HEADER_BYTES or body[:4] != PAYLOAD_MAGIC:
        raise XDEError("invalid authenticated payload envelope")
    n = int.from_bytes(body[4:12], "big")
    if n > MAX_PLAINTEXT or 12 + n > len(body):
        raise XDEError("invalid authenticated plaintext length")
    return body[12:12+n]


def encrypt_bytes(master: bytes, plaintext: bytes, *, aad: bytes = b"", nonce: bytes | None = None, pad_to: int = 0) -> str:
    if len(aad) > MAX_AAD: raise XDEError(f'AAD limit is {MAX_AAD} bytes')
    nonce = os.urandom(NONCE_BYTES) if nonce is None else bytes(nonce)
    if len(nonce) != NONCE_BYTES:
        raise XDEError("nonce must be 12 bytes")
    k_enc, k_fmt = derive_keys(master)
    payload = _pack_payload(plaintext, pad_to)
    blob = ChaCha20Poly1305(k_enc).encrypt(nonce, payload, PROTOCOL_AAD + b"\x00" + aad)
    cells = _format_blob(blob, k_fmt, nonce)
    frame = MAGIC + "|" + _nonce_to_duo(nonce) + "|" + ".".join(cells)
    if len(frame.encode('utf-8')) > MAX_FRAME_BYTES:
        raise XDEError('XDE2 frame exceeds production size limit; use chunked/bulk transport')
    if "0" in frame:
        raise AssertionError("XDE2 textual wire format must contain no ASCII zero glyph")
    return frame


def decrypt_bytes(master: bytes, frame: str, *, aad: bytes = b"") -> bytes:
    if len(aad) > MAX_AAD: raise XDEError(f'AAD limit is {MAX_AAD} bytes')
    if not isinstance(frame,str): raise XDEError('frame must be text')
    if len(frame.encode('utf-8',errors='strict')) > MAX_FRAME_BYTES: raise XDEError('XDE2 frame exceeds production size limit')
    frame = frame.strip()
    if "0" in frame:
        raise XDEError("ASCII zero glyph is forbidden in XDE2 wire format")
    parts = frame.split("|", 2)
    if len(parts) != 3 or parts[0] != MAGIC:
        raise XDEError("invalid XDE2 frame")
    nonce = _nonce_from_duo(parts[1])
    cells = parts[2].split(".") if parts[2] else []
    if len(cells) > MAX_CELLS: raise XDEError('XDE2 frame contains too many payload cells')
    if any(len(c)>MAX_CELL_CHARS for c in cells): raise XDEError('XDE2 payload cell exceeds length limit')
    if len(cells) < TAG_BYTES:
        raise XDEError("payload is shorter than an AEAD tag")
    k_enc, k_fmt = derive_keys(master)
    try:
        blob = _unformat_cells(cells, k_fmt, nonce)
    except XDEError as exc:
        raise AuthenticationError("authentication failed: wrong key/AAD or modified ciphertext") from exc
    try:
        payload = ChaCha20Poly1305(k_enc).decrypt(nonce, blob, PROTOCOL_AAD + b"\x00" + aad)
        return _unpack_payload(payload)
    except InvalidTag as exc:
        raise AuthenticationError("authentication failed: wrong key/AAD or modified ciphertext") from exc


def frame_info(frame: str) -> dict:
    text = frame.strip()
    parts = text.split("|", 2)
    if len(parts) != 3 or parts[0] != MAGIC:
        raise XDEError("invalid frame")
    nonce = _nonce_from_duo(parts[1])
    cells = parts[2].split(".") if parts[2] else []
    return {
        "magic": parts[0],
        "nonce_bytes": len(nonce),
        "payload_cells": len(cells),
        "encrypted_payload_bytes": max(0, len(cells) - TAG_BYTES),
        "ascii_zero_free": "0" not in text,
        "duo_cell_grammar_ok": all(CELL_RE.fullmatch(c) for c in cells),
    }


def create_keyfile(path: str | os.PathLike, *, force: bool = False) -> dict:
    p=Path(path); journal=Path(str(p)+'.nonce'); head=Path(str(p)+'.nonce.head')
    if force: raise XDEError('security key-state overwrite is disabled; choose a new key path')
    if p.exists() or journal.exists() or head.exists(): raise FileExistsError(f'key or nonce state already exists: {p}')
    master=os.urandom(KEY_BYTES)
    data={'format':KEY_MAGIC,'version':1,'key_id':_b64e(os.urandom(16)),'master_key_b64':_b64e(master),'nonce_prefix_b64':_b64e(os.urandom(8)),'initial_counter':1,'max_counter':(1<<32)-1}
    p.parent.mkdir(parents=True,exist_ok=True)
    try:
        fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as f:
            json.dump(data,f,indent=2,sort_keys=True); f.write('\n'); f.flush(); os.fsync(f.fileno())
        jfd=os.open(journal,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(jfd,'w',encoding='ascii') as jf:
            jf.write('XDE-NONCE/v1\n1\n'); jf.flush(); os.fsync(jf.fileno())
        os.chmod(p,0o600); os.chmod(journal,0o600)
        h={'schema':'XDE-NONCE-HEAD/v1','next_counter':1,'journal_bytes':journal.stat().st_size,'tail_sha256':hashlib.sha256(b'1\n').hexdigest()}
        atomic_write(head,(json.dumps(h,sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
        fsync_dir(p.parent)
    except Exception:
        for q in (p,journal,head):
            try:q.unlink()
            except FileNotFoundError:pass
        raise
    return {k:v for k,v in data.items() if k!='master_key_b64'}

def _validate_keydata(data: dict) -> tuple[bytes, bytes]:
    if data.get("format") != KEY_MAGIC or data.get("version") != 1:
        raise XDEError("unsupported key file")
    master = _b64d(data["master_key_b64"])
    prefix = _b64d(data["nonce_prefix_b64"])
    if len(master) != 32 or len(prefix) != 8:
        raise XDEError("invalid key file contents")
    return master, prefix


MAX_KEYFILE_BYTES = 64 * 1024
MAX_NONCE_HEAD_BYTES = 64 * 1024


def _require_private_file(path: str | os.PathLike) -> None:
    """Reject symlinks, non-regular files and group/world-accessible security state."""
    p = Path(path)
    try:
        st = os.lstat(p)
    except OSError as exc:
        raise XDEError(f"unable to stat security state: {p}") from exc
    if stat.S_ISLNK(st.st_mode):
        raise XDEError(f"security state must not be a symlink: {p}")
    if not stat.S_ISREG(st.st_mode):
        raise XDEError(f"security state must be a regular file: {p}")
    mode = stat.S_IMODE(st.st_mode)
    if mode & 0o077:
        raise XDEError(f"security state must not be group/world accessible: {p} mode={mode:03o}")


def _open_private_regular(path: str | os.PathLike, flags: int) -> int:
    """Open sensitive mutable state without following the final symlink component."""
    p = Path(path)
    try:
        fd = os.open(p, flags | getattr(os, "O_NOFOLLOW", 0))
    except OSError as exc:
        raise XDEError(f"unable to open security state safely: {p}") from exc
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise XDEError(f"security state must be a regular file: {p}")
        mode = stat.S_IMODE(st.st_mode)
        if mode & 0o077:
            raise XDEError(f"security state must not be group/world accessible: {p} mode={mode:03o}")
        return fd
    except Exception:
        os.close(fd)
        raise


def read_key_data(path: str | os.PathLike) -> dict:
    try:
        raw = read_regular_file(path, max_bytes=MAX_KEYFILE_BYTES, private=True)
        data = json.loads(raw.decode("utf-8", "strict"))
    except (DurableIOError, UnicodeError, json.JSONDecodeError) as exc:
        raise XDEError("invalid or unsafe key file") from exc
    _validate_keydata(data)
    return data


def read_master_key(path: str | os.PathLike) -> bytes:
    data=read_key_data(path)
    return _validate_keydata(data)[0]


def _journal_path(path: str | os.PathLike) -> Path:
    return Path(str(path) + ".nonce")


def _nonce_head_path(path: str | os.PathLike) -> Path:
    return Path(str(path)+'.nonce.head')

def _journal_tail_line(f) -> bytes:
    f.seek(0,os.SEEK_END); size=f.tell()
    if size<=0:return b''
    n=min(size,128); f.seek(size-n); chunk=f.read(n)
    if isinstance(chunk,str):chunk=chunk.encode('ascii')
    lines=chunk.splitlines(keepends=True); return lines[-1] if lines else b''

def _scan_nonce_journal(f) -> tuple[int,int,str]:
    f.seek(0); raw=f.read()
    if isinstance(raw,bytes):raw=raw.decode('ascii','strict')
    lines=raw.splitlines()
    if len(lines)<2 or lines[0]!='XDE-NONCE/v1' or any(not x.isdigit() for x in lines[1:]): raise XDEError('nonce journal malformed; fail closed and rotate/recover key state')
    vals=[int(x) for x in lines[1:]]
    if vals[0]!=1 or any(b!=a+1 for a,b in zip(vals,vals[1:])): raise XDEError('nonce journal chronology invalid; fail closed')
    tail=(str(vals[-1])+'\n').encode('ascii')
    return vals[-1],len(raw.encode('ascii')),hashlib.sha256(tail).hexdigest()

def claim_nonce(path: str | os.PathLike, *, anchor=None, require_external_anchor: bool=False) -> tuple[bytes, bytes, dict]:
    """O(1) steady-state nonce claim with append-first crash recovery."""
    data=read_key_data(path); master,prefix=_validate_keydata(data); jp=_journal_path(path); hp=_nonce_head_path(path); quarantine=Path(str(path)+'.nonce.rollback')
    if quarantine.exists(): raise XDEError('nonce state is quarantined after rollback detection; rotate/recover key state')
    if require_external_anchor:
        try: require_independent_anchor(anchor)
        except NonceAnchorError as exc: raise XDEError(str(exc)) from exc
    journal_fd = _open_private_regular(jp, os.O_RDWR)
    with os.fdopen(journal_fd,'r+',encoding='ascii') as f:
        fcntl.flock(f.fileno(),fcntl.LOCK_EX); actual=os.fstat(f.fileno()).st_size; head=None
        if hp.exists():
            try:
                head_raw = read_regular_file(hp, max_bytes=MAX_NONCE_HEAD_BYTES, private=True)
                head = json.loads(head_raw.decode('utf-8','strict'))
            except (DurableIOError, UnicodeError, json.JSONDecodeError) as exc:
                raise XDEError('nonce head malformed or unsafe; fail closed') from exc
            if head.get('schema')!='XDE-NONCE-HEAD/v1':raise XDEError('unsupported nonce head')
            recorded=int(head.get('journal_bytes',-1))
            if actual<recorded:raise XDEError('nonce journal rollback detected; rotate/recover key state')
            if actual==recorded:
                if hashlib.sha256(_journal_tail_line(f)).hexdigest()!=head.get('tail_sha256'):raise XDEError('nonce journal tail mismatch; fail closed')
            else:
                counter,actual,tail_hash=_scan_nonce_journal(f); head={'schema':'XDE-NONCE-HEAD/v1','next_counter':counter,'journal_bytes':actual,'tail_sha256':tail_hash}; atomic_write(hp,(json.dumps(head,sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
        else:
            counter,actual,tail_hash=_scan_nonce_journal(f); head={'schema':'XDE-NONCE-HEAD/v1','next_counter':counter,'journal_bytes':actual,'tail_sha256':tail_hash}; atomic_write(hp,(json.dumps(head,sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
        counter=int(head['next_counter']); max_counter=int(data.get('max_counter',(1<<32)-1))
        if not 1<=counter<max_counter:raise XDEError('key nonce counter exhausted; rotate the key')
        nonce=prefix+counter.to_bytes(4,'big'); successor=counter+1; line=str(successor)+'\n'
        f.seek(0,os.SEEK_END); f.write(line); f.flush(); os.fsync(f.fileno()); new_size=f.tell()
        new_head={'schema':'XDE-NONCE-HEAD/v1','next_counter':successor,'journal_bytes':new_size,'tail_sha256':hashlib.sha256(line.encode('ascii')).hexdigest()}
        atomic_write(hp,(json.dumps(new_head,sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
        anchor_receipt=None
        if anchor is not None:
            try: anchor_receipt=anchor.claim(data['key_id'],counter)
            except NonceRollbackDetected as exc:
                marker={'schema':'XDE-NONCE-ROLLBACK/v1','key_id':data['key_id'],'counter_rejected':counter,'reason':'external-anchor-rollback','authority':False}
                atomic_write(quarantine,(json.dumps(marker,sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
                raise XDEError('external nonce anchor detected rollback; key quarantined') from exc
            except NonceAnchorError as exc:
                raise XDEError('external nonce anchor failed; nonce consumed but not returned') from exc
        fcntl.flock(f.fileno(),fcntl.LOCK_UN)
    return master,nonce,{'key_id':data['key_id'],'counter_used':counter,'nonce_journal':str(jp),'nonce_head':str(hp),'nonce_anchor':anchor_receipt,'claim_complexity':'O(1)-steady-state'}

def self_test() -> dict:
    master = bytes(range(32))
    nonce = bytes.fromhex("000102030405060708090a0b")
    for plain in [b"", b"Hi", b"DUO-Math", bytes(range(256))]:
        frame = encrypt_bytes(master, plain, aad=b"self-test", nonce=nonce, pad_to=0)
        assert "0" not in frame
        assert decrypt_bytes(master, frame, aad=b"self-test") == plain
        # determinism only when nonce is explicitly fixed
        assert encrypt_bytes(master, plain, aad=b"self-test", nonce=nonce, pad_to=0) == frame
    frame = encrypt_bytes(master, b"auth", aad=b"A", nonce=nonce)
    try:
        decrypt_bytes(master, frame, aad=b"B")
    except AuthenticationError:
        pass
    else:
        raise AssertionError("AAD tampering was not rejected")
    return {"status": "PASS", "codec": "Rev009-AJ-aj", "aead": "ChaCha20-Poly1305", "wire": MAGIC}
