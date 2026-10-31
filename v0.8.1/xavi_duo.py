#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from xavi_duo_crypto import (
    AuthenticationError, XDEError, claim_nonce, create_keyfile, decrypt_bytes,
    derive_receipt_key, duo_context_commitment, encrypt_bytes, frame_info, read_key_data, read_master_key, self_test,
    MAX_PLAINTEXT, MAX_AAD, MAX_FRAME_BYTES,
)
from xavi_duo_evidence import authenticate_receipt, receipt_body, verify_receipt
from pqc_provider import provider_status, provider_self_test
from mlkem_provider import keygen as mlkem_keygen, MLKEMProviderError
from xavi_duo_pq import encrypt_for as pq_encrypt_for, decrypt_for as pq_decrypt_for, MAX_ENVELOPE_BYTES
from xavi_duo_accelerator import discover_host as accelerator_discover, get_profile as accelerator_get_profile, oci_security_args as accelerator_container_args
from xavi_duo_provider_runtime import container_engine
from xavi_duo_fs import atomic_write, read_regular_file, DurableIOError
from xavi_duo_nonce_anchor import HTTPSNonceAnchor

MAX_RECEIPT_BYTES=1024*1024

def _read_bytes(path,limit):
    try: return read_regular_file(Path(path),max_bytes=limit,private=False)
    except DurableIOError as exc: raise XDEError(str(exc)) from exc

def _read_text(path,limit):
    try: return _read_bytes(path,limit).decode('utf-8',errors='strict')
    except UnicodeDecodeError as exc: raise XDEError('input is not valid UTF-8') from exc

def _read_json(path,limit):
    try: return json.loads(_read_text(path,limit))
    except json.JSONDecodeError as exc: raise XDEError('invalid JSON input') from exc

def _check_aad(text):
    if len(text.encode('utf-8'))>MAX_AAD: raise XDEError(f'AAD limit is {MAX_AAD} bytes')
    return text.encode('utf-8')

def main():
    ap=argparse.ArgumentParser(prog="xavi-duo",description="XAVI-DUO Encryption / XDE2 + XDE2-PQ2")
    sub=ap.add_subparsers(dest="cmd",required=True)
    p=sub.add_parser("keygen"); p.add_argument("--out",required=True); p.add_argument("--force",action="store_true")
    p=sub.add_parser("encrypt"); p.add_argument("--key",required=True); p.add_argument("--in",dest="inp",required=True); p.add_argument("--out",required=True); p.add_argument("--aad",default=""); p.add_argument("--pad-to",type=int,default=0); p.add_argument("--receipt"); p.add_argument("--high-assurance",action="store_true"); p.add_argument("--nonce-anchor-url"); p.add_argument("--nonce-anchor-ca"); p.add_argument("--nonce-anchor-cert"); p.add_argument("--nonce-anchor-key")
    p=sub.add_parser("decrypt"); p.add_argument("--key",required=True); p.add_argument("--in",dest="inp",required=True); p.add_argument("--out",required=True); p.add_argument("--aad",default=""); p.add_argument("--receipt")
    p=sub.add_parser("inspect"); p.add_argument("--in",dest="inp",required=True)
    p=sub.add_parser("verify-receipt"); p.add_argument("--key",required=True); p.add_argument("--frame",required=True); p.add_argument("--receipt",required=True); p.add_argument("--aad",default="")
    p=sub.add_parser("pq-keygen"); p.add_argument("--private",required=True); p.add_argument("--public",required=True)
    p=sub.add_parser("pq-encrypt"); p.add_argument("--public",required=True); p.add_argument("--in",dest="inp",required=True); p.add_argument("--out",required=True); p.add_argument("--aad",default=""); p.add_argument("--pad-to",type=int,default=0); p.add_argument("--witness")
    p=sub.add_parser("pq-decrypt"); p.add_argument("--private",required=True); p.add_argument("--in",dest="inp",required=True); p.add_argument("--out",required=True); p.add_argument("--aad",default=""); p.add_argument("--witness")
    sub.add_parser("provider-status")
    sub.add_parser("provider-self-test")
    sub.add_parser("self-test")
    sub.add_parser("accelerator-status")
    p=sub.add_parser("accelerator-plan"); p.add_argument("--profile",required=True); p.add_argument("--selector"); p.add_argument("--runtime-user"); p.add_argument("--runtime",choices=["auto","podman","docker"],default="auto"); p.add_argument("--allow-missing-devices",action="store_true")
    a=ap.parse_args()
    try:
        if a.cmd=="keygen": print(json.dumps(create_keyfile(a.out,force=a.force),indent=2)); return
        if a.cmd=="self-test": print(json.dumps(self_test(),indent=2)); return
        if a.cmd=="provider-status": print(json.dumps(provider_status(),indent=2)); return
        if a.cmd=="accelerator-status": print(json.dumps(accelerator_discover(),indent=2,sort_keys=True)); return
        if a.cmd=="accelerator-plan":
            prof=accelerator_get_profile(a.profile); runtime=container_engine(a.runtime)
            if not runtime: raise RuntimeError("no supported OCI runtime available")
            args=accelerator_container_args(prof,selector=a.selector,runtime_user=a.runtime_user,existing_only=not a.allow_missing_devices,runtime=runtime)
            print(json.dumps({"profile":prof,"runtime":runtime,"container_args":args},indent=2,sort_keys=True)); return
        if a.cmd=="provider-self-test": print(json.dumps(provider_self_test(),indent=2)); return
        if a.cmd=="pq-keygen": print(json.dumps(mlkem_keygen(a.private,a.public),indent=2)); return
        if a.cmd=="pq-encrypt":
            aad=_check_aad(a.aad); pt=_read_bytes(a.inp,MAX_PLAINTEXT); env,witness=pq_encrypt_for(a.public,pt,aad=aad,pad_to=a.pad_to)
            atomic_write(Path(a.out),(json.dumps(env,sort_keys=True,separators=(',',':'))+'\n').encode(),0o600)
            if a.witness: atomic_write(Path(a.witness),(json.dumps(witness,indent=2,sort_keys=True)+'\n').encode(),0o600)
            print(json.dumps({'status':'encrypted','schema':env['schema'],'recipient_key_id':env['recipient_key_id'],'out':a.out,'witness':a.witness},indent=2)); return
        if a.cmd=="pq-decrypt":
            aad=_check_aad(a.aad); env=_read_json(a.inp,MAX_ENVELOPE_BYTES); pt,witness=pq_decrypt_for(a.private,env,aad=aad)
            atomic_write(Path(a.out),pt,0o600)
            if a.witness: atomic_write(Path(a.witness),(json.dumps(witness,indent=2,sort_keys=True)+'\n').encode(),0o600)
            print(json.dumps({'status':'authenticated','schema':env['schema'],'plaintext_bytes':len(pt),'out':a.out,'witness':a.witness},indent=2)); return
        if a.cmd=="verify-receipt":
            aad=_check_aad(a.aad); master=read_master_key(a.key); frame=_read_text(a.frame,MAX_FRAME_BYTES).strip(); receipt=_read_json(a.receipt,MAX_RECEIPT_BYTES); ok=verify_receipt(receipt,derive_receipt_key(master),frame=frame,aad=aad,duo_context_commitment=duo_context_commitment(master,frame)); print(json.dumps({"verified":ok,"receipt_id":receipt.get("receipt_id")},indent=2)); raise SystemExit(0 if ok else 3)
        if a.cmd=="inspect": print(json.dumps(frame_info(_read_text(a.inp,MAX_FRAME_BYTES).strip()),indent=2)); return
        if a.cmd=="encrypt":
            aad=_check_aad(a.aad); anchor=None
            if a.nonce_anchor_url:
                if a.high_assurance: anchor=HTTPSNonceAnchor.mtls(a.nonce_anchor_url,ca_file=a.nonce_anchor_ca,cert_file=a.nonce_anchor_cert,key_file=a.nonce_anchor_key)
                else: anchor=HTTPSNonceAnchor(a.nonce_anchor_url)
            master,nonce,meta=claim_nonce(a.key,anchor=anchor,require_external_anchor=a.high_assurance)
            pt=_read_bytes(a.inp,MAX_PLAINTEXT)
            frame=encrypt_bytes(master,pt,aad=aad,nonce=nonce,pad_to=a.pad_to)
            atomic_write(Path(a.out),(frame+"\n").encode(),0o600)
            if a.receipt:
                body=receipt_body(frame=frame,aad=aad,key_id=meta["key_id"],counter=meta["counter_used"],pad_to=a.pad_to,duo_context_commitment=duo_context_commitment(master,frame))
                receipt=authenticate_receipt(body,derive_receipt_key(master))
                atomic_write(Path(a.receipt),(json.dumps(receipt,indent=2,sort_keys=True)+"\n").encode(),0o600)
            print(json.dumps({**meta,**frame_info(frame),"out":a.out,"receipt":a.receipt},indent=2)); return
        aad=_check_aad(a.aad); master=read_master_key(a.key)
        frame=_read_text(a.inp,MAX_FRAME_BYTES).strip()
        if a.receipt:
            receipt=_read_json(a.receipt,MAX_RECEIPT_BYTES);
            if not verify_receipt(receipt,derive_receipt_key(master),frame=frame,aad=aad,duo_context_commitment=duo_context_commitment(master,frame)): raise AuthenticationError("evidence receipt verification failed")
        pt=decrypt_bytes(master,frame,aad=aad)
        atomic_write(Path(a.out),pt,0o600)
        print(json.dumps({"status":"authenticated","plaintext_bytes":len(pt),"out":a.out},indent=2))
    except (XDEError,AuthenticationError,MLKEMProviderError,FileExistsError,OSError,ValueError,RuntimeError) as e:
        print(f"xavi-duo: {e}",file=sys.stderr); raise SystemExit(2)

if __name__=="__main__": main()
