import json, hashlib, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT))
from xavi_duo_crypto import encrypt_bytes, decrypt_bytes, frame_info
master=bytes(range(32)); nonce=bytes.fromhex('000102030405060708090a0b'); aad=b'XDE2 test vector'; plaintext=b'Hi'
frame=encrypt_bytes(master,plaintext,aad=aad,nonce=nonce,pad_to=0)
assert decrypt_bytes(master,frame,aad=aad)==plaintext
obj={'schema':'XAVI-DUO/XDE2-TEST-VECTOR/v1','master_key_hex':master.hex(),'nonce_hex':nonce.hex(),'aad_utf8':aad.decode(),'plaintext_hex':plaintext.hex(),'frame':frame,'frame_sha256':hashlib.sha256(frame.encode()).hexdigest(),'info':frame_info(frame)}
out=ROOT/'vectors/xde2-vector-001.json'; out.write_text(json.dumps(obj,indent=2)+'\n'); print(out)
