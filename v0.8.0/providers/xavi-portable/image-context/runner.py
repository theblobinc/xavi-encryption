import base64,hashlib,json,os,subprocess,sys
from xavi_duo_crypto import decrypt_bytes
key=base64.urlsafe_b64decode(os.environ['XAVI_TEST_KEY_B64'].encode())
frame=os.environ['XAVI_TASK_FRAME']
aad=os.environ.get('XAVI_TASK_AAD','xavi-duo-polymorphic-v030').encode()
plain=decrypt_bytes(key,frame,aad=aad)
req=json.loads(plain)
p=subprocess.run([sys.executable,'/app/polymorphic-task.py'],input=json.dumps(req).encode(),stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True)
result=json.loads(p.stdout)
canon=json.dumps(result['rows'],sort_keys=True,separators=(',',':')).encode()
print(json.dumps({'schema':'XAVI-DUO/ENCRYPTED-REMOTE-EXECUTION/v1','transport':'XDE2','authenticated':True,'implementation':result['implementation'],'rows':result['rows'],'canonical_result_sha256':hashlib.sha256(canon).hexdigest(),'authority':False},sort_keys=True,separators=(',',':')))
