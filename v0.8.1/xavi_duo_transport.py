#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json,queue,socket,ssl,struct,urllib.error,urllib.parse,urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable,Protocol,BinaryIO
from xavi_duo_fs import atomic_write

MAX_FRAME_BYTES=64*1024*1024
MAX_NAME_BYTES=255
class TransportError(RuntimeError): pass

class Transport(Protocol):
    def put(self,name:str,payload:bytes)->dict: ...
    def get(self,name:str,*,max_bytes:int=MAX_FRAME_BYTES)->bytes: ...

def _safe_name(name:str)->str:
    if not isinstance(name,str) or not name or len(name.encode())>MAX_NAME_BYTES: raise TransportError('invalid transport object name')
    if name in {'.','..'} or '/' in name or '\\' in name or '\x00' in name: raise TransportError('unsafe transport object name')
    return name

def _bounded(payload:bytes,max_bytes:int=MAX_FRAME_BYTES)->bytes:
    if not isinstance(payload,(bytes,bytearray,memoryview)): raise TransportError('transport payload must be bytes')
    b=bytes(payload)
    if len(b)>max_bytes: raise TransportError('transport payload exceeds bound')
    return b

def receipt(kind,name,payload):
    b=bytes(payload)
    return {'schema':'XAVI-DUO/TRANSPORT-RECEIPT/v1','transport':kind,'name':name,'bytes':len(b),'sha256':'sha256:'+hashlib.sha256(b).hexdigest()}

@dataclass
class FileTransport:
    root: Path|str
    mode: int=0o600
    def __post_init__(self):
        self.root=Path(self.root).resolve();self.root.mkdir(parents=True,exist_ok=True)
    def _path(self,name): return self.root/_safe_name(name)
    def put(self,name,payload):
        b=_bounded(payload);atomic_write(self._path(name),b,self.mode);return receipt('file',name,b)
    def get(self,name,*,max_bytes=MAX_FRAME_BYTES):
        p=self._path(name);st=p.stat()
        if st.st_size>max_bytes: raise TransportError('transport object exceeds bound')
        with p.open('rb') as f:b=f.read(max_bytes+1)
        if len(b)>max_bytes: raise TransportError('transport object exceeds bound')
        return b

class QueueTransport:
    def __init__(self,q=None): self.q=q or queue.Queue(); self.pending={}
    def put(self,name,payload):
        name=_safe_name(name);b=_bounded(payload);self.q.put((name,b));return receipt('queue',name,b)
    def get(self,name,*,max_bytes=MAX_FRAME_BYTES):
        name=_safe_name(name)
        if name in self.pending:return _bounded(self.pending.pop(name),max_bytes)
        while True:
            n,b=self.q.get()
            if n==name:return _bounded(b,max_bytes)
            self.pending[n]=b

class CallbackTransport:
    def __init__(self,put_cb:Callable[[str,bytes],None],get_cb:Callable[[str,int],bytes]): self.put_cb=put_cb;self.get_cb=get_cb
    def put(self,name,payload):
        name=_safe_name(name);b=_bounded(payload);self.put_cb(name,b);return receipt('callback',name,b)
    def get(self,name,*,max_bytes=MAX_FRAME_BYTES): return _bounded(self.get_cb(_safe_name(name),max_bytes),max_bytes)

def write_frame(stream:BinaryIO,name:str,payload:bytes)->dict:
    name=_safe_name(name);b=_bounded(payload)
    hdr=json.dumps({'schema':'XAVI-DUO/TRANSPORT-FRAME/v1','name':name,'bytes':len(b),'sha256':'sha256:'+hashlib.sha256(b).hexdigest()},sort_keys=True,separators=(',',':')).encode()
    if len(hdr)>4096: raise TransportError('frame header too large')
    stream.write(struct.pack('!I',len(hdr)));stream.write(hdr);stream.write(b)
    if hasattr(stream,'flush'):stream.flush()
    return receipt('stream',name,b)

def _read_exact(stream:BinaryIO,n:int)->bytes:
    chunks=[];left=n
    while left:
        b=stream.read(left)
        if not b: raise TransportError('unexpected EOF')
        chunks.append(b);left-=len(b)
    return b''.join(chunks)

def read_frame(stream:BinaryIO,*,max_bytes=MAX_FRAME_BYTES)->tuple[str,bytes]:
    n=struct.unpack('!I',_read_exact(stream,4))[0]
    if n>4096:raise TransportError('frame header too large')
    try:h=json.loads(_read_exact(stream,n).decode('utf-8','strict'))
    except Exception as exc:raise TransportError('invalid frame header') from exc
    if h.get('schema')!='XAVI-DUO/TRANSPORT-FRAME/v1':raise TransportError('invalid frame schema')
    name=_safe_name(h.get('name'));size=int(h.get('bytes',-1))
    if size<0 or size>max_bytes:raise TransportError('frame payload exceeds bound')
    b=_read_exact(stream,size)
    if h.get('sha256')!='sha256:'+hashlib.sha256(b).hexdigest():raise TransportError('frame digest mismatch')
    return name,b

@dataclass
class SocketTransport:
    host: str|None=None
    port: int|None=None
    unix_path: str|None=None
    tls: bool=True
    ssl_context: ssl.SSLContext|None=None
    timeout: float=15.0
    def _connect(self):
        if self.unix_path:
            if not hasattr(socket,'AF_UNIX'): raise TransportError('Unix sockets unavailable on this platform')
            s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.settimeout(self.timeout);s.connect(self.unix_path);return s
        if not self.host or not self.port:raise TransportError('socket transport requires host/port or unix_path')
        s=socket.create_connection((self.host,int(self.port)),timeout=self.timeout)
        if not self.tls:return s
        ctx=self.ssl_context or ssl.create_default_context();return ctx.wrap_socket(s,server_hostname=self.host)
    def _rpc(self,verb,name,payload=b'',max_bytes=MAX_FRAME_BYTES):
        with self._connect() as s:
            f=s.makefile('rwb',buffering=0);write_frame(f,'request.json',json.dumps({'verb':verb,'name':_safe_name(name)},separators=(',',':')).encode())
            if verb=='PUT':write_frame(f,name,_bounded(payload,max_bytes))
            rn,rb=read_frame(f,max_bytes=max_bytes)
            if rn=='error.json':raise TransportError(json.loads(rb).get('error','remote transport error'))
            if verb=='GET' and rn!=name:raise TransportError('socket response name mismatch')
            return rb
    def put(self,name,payload):
        b=_bounded(payload);self._rpc('PUT',name,b);return receipt('socket',name,b)
    def get(self,name,*,max_bytes=MAX_FRAME_BYTES):return self._rpc('GET',name,max_bytes=max_bytes)

@dataclass
class HTTPTransport:
    base_url: str
    ssl_context: ssl.SSLContext|None=None
    bearer_token: str|None=None
    timeout: float=30.0
    allow_insecure_http: bool=False
    def __post_init__(self):
        u=urllib.parse.urlparse(self.base_url)
        if u.scheme not in {'https','http'}:raise TransportError('HTTP transport requires http(s) URL')
        if u.scheme!='https' and not self.allow_insecure_http:raise TransportError('plaintext HTTP disabled')
        self.base_url=self.base_url.rstrip('/')+'/'
    @classmethod
    def mtls(cls,base_url,*,ca_file=None,cert_file=None,key_file=None,timeout=30.0):
        ctx=ssl.create_default_context(cafile=ca_file)
        if cert_file:ctx.load_cert_chain(cert_file,key_file)
        return cls(base_url,ssl_context=ctx,timeout=timeout)
    def _url(self,name):return urllib.parse.urljoin(self.base_url,urllib.parse.quote(_safe_name(name),safe=''))
    def _headers(self):
        h={'User-Agent':'xavi-duo-encryption/0.8.1','Accept':'application/octet-stream'}
        if self.bearer_token:h['Authorization']='Bearer '+self.bearer_token
        return h
    def put(self,name,payload):
        b=_bounded(payload);h=self._headers();h['Content-Type']='application/octet-stream';h['X-Content-SHA256']=hashlib.sha256(b).hexdigest()
        req=urllib.request.Request(self._url(name),data=b,method='PUT',headers=h)
        try:
            with urllib.request.urlopen(req,context=self.ssl_context,timeout=self.timeout) as r:
                if r.status not in {200,201,204}:raise TransportError(f'HTTP PUT failed: {r.status}')
        except urllib.error.URLError as exc:raise TransportError('HTTP PUT failed') from exc
        return receipt('https' if self.base_url.startswith('https:') else 'http',name,b)
    def get(self,name,*,max_bytes=MAX_FRAME_BYTES):
        req=urllib.request.Request(self._url(name),method='GET',headers=self._headers())
        try:
            with urllib.request.urlopen(req,context=self.ssl_context,timeout=self.timeout) as r:
                if r.status!=200:raise TransportError(f'HTTP GET failed: {r.status}')
                if r.headers.get('Content-Length') and int(r.headers['Content-Length'])>max_bytes:raise TransportError('HTTP object exceeds bound')
                b=r.read(max_bytes+1)
        except urllib.error.URLError as exc:raise TransportError('HTTP GET failed') from exc
        return _bounded(b,max_bytes)

def transport_from_uri(uri:str,**kwargs):
    u=urllib.parse.urlparse(uri)
    if u.scheme=='file':return FileTransport(urllib.request.url2pathname(u.path))
    if u.scheme in {'http','https'}:return HTTPTransport(uri,**kwargs)
    if u.scheme=='unix':return SocketTransport(unix_path=urllib.request.url2pathname(u.path),tls=False,**kwargs)
    if u.scheme in {'tcp','tls'}:
        if not u.hostname or not u.port:raise TransportError('tcp/tls URI requires host and port')
        return SocketTransport(host=u.hostname,port=u.port,tls=(u.scheme=='tls'),**kwargs)
    raise TransportError(f'unsupported transport URI scheme: {u.scheme}')
