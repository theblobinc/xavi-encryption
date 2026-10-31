#!/usr/bin/env python3
import base64,json,subprocess,os
name=f'xavi-wg-fhe-client-{os.getpid()}'
cmd=['podman','run','--rm','--name',name,'-i','--network','none','--read-only','--cap-drop','all','--security-opt','no-new-privileges','--pids-limit','64','--memory','512m','--cpus','2','--tmpfs','/keys:rw,mode=0777','--entrypoint','/usr/local/bin/xvoid-tfhe-client','localhost/xavi-void-tfhe-split:1.2-dev5','--key-dir','/keys']
p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
def q(o):
 p.stdin.write(json.dumps(o,separators=(',',':'))+'\n');p.stdin.flush();line=p.stdout.readline()
 if not line: raise RuntimeError(p.stderr.read())
 r=json.loads(line)
 if not r.get('ok'): raise RuntimeError(r)
 return r['result']
try:
 caps=q({'op':'capabilities'}); server=q({'op':'export_server_key'})['data']; ct=q({'op':'encrypt_bit','value':True})['data']; q({'op':'close'}); subprocess.run(['podman','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=False);
 try: p.wait(timeout=10)
 except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)
finally:
 if p.poll() is None:p.kill()
assert caps['role']=='client' and caps['has_client_secret'] is True and caps['supports_server_key_export'] is True
print(json.dumps({'status':'PASS','role':caps['role'],'has_client_secret':caps['has_client_secret'],'key_id':caps['key_id'],'server_key_bytes':len(base64.b64decode(server)),'ciphertext_bytes':len(base64.b64decode(ct)),'key_storage':'tmpfs-ephemeral'},sort_keys=True))
