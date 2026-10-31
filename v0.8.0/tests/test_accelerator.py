import json, tempfile, unittest
from pathlib import Path
from xavi_duo_accelerator import get_profile, select_profile, podman_security_args, AcceleratorPolicyError, compatible, discover_host
from xavi_duo_compute import select_execution

class AcceleratorTests(unittest.TestCase):
 def test_nvidia_readonly_profile(self):
  p=get_profile('nvidia-cdi-compute-v1')
  self.assertTrue(p['sandbox']['read_only_rootfs'])
  self.assertEqual([x['path'] for x in p['sandbox']['writable_injection_overlays']],['/usr/lib/x86_64-linux-gnu','/etc'])
  self.assertTrue(all(x['type']=='tmpfs' and not x['persistent'] for x in p['sandbox']['writable_injection_overlays']))
  a=podman_security_args(p,selector='all',runtime_user='10001:999')
  wire=' '.join(a)
  self.assertIn('--read-only',a); self.assertIn('nvidia.com/gpu=all',a); self.assertIn('10001:999',a)
  self.assertIn('/usr/lib/x86_64-linux-gnu:rw,exec,mode=755,tmpcopyup',wire)
  self.assertIn('/etc:rw,exec,mode=755,tmpcopyup',wire)
  self.assertIn('--network none',wire); self.assertIn('--cap-drop all',wire); self.assertIn('no-new-privileges',wire)
 def test_named_user_rejected_for_nvidia_profile(self):
  p=get_profile('nvidia-cdi-compute-v1')
  with self.assertRaises(AcceleratorPolicyError): podman_security_args(p,runtime_user='xvoid')
 def test_vendor_neutral_selection(self):
  self.assertEqual(select_profile('rocm',vendor='amd')['id'],'amd-rocm-device-v1')
  self.assertEqual(select_profile('level-zero',vendor='intel')['id'],'intel-level-zero-device-v1')
  self.assertEqual(select_profile('webgpu')['id'],'generic-render-node-v1')
 def test_generic_cdi_is_data_driven(self):
  p=get_profile('generic-cdi-v1')
  a=podman_security_args(p,selector='future.example/accelerator=0',existing_only=False)
  self.assertEqual(a[-2:],['--device','future.example/accelerator=0'])
 def test_compute_and_accelerator_plan(self):
  x=select_execution('fhe.word64',accelerator_abi='cuda',accelerator_vendor='nvidia',remote=True)
  self.assertEqual(x['provider']['id'],'tfhe-cuda-evaluator')
  self.assertEqual(x['accelerator']['id'],'nvidia-cdi-compute-v1')
  self.assertTrue(compatible(x['provider'],x['accelerator']))
 def test_device_node_access_fails_closed(self):
  import os
  with tempfile.TemporaryDirectory() as td:
   dev=Path(td)/'fake-render'; dev.write_bytes(b'x'); dev.chmod(0)
   profile={'sandbox':{'read_only_rootfs':True,'network':'none','cap_drop':'all','no_new_privileges':True,'writable_injection_overlays':[]},'injection':{'type':'device-glob','device_globs':[str(dev)]}}
   try:
    with self.assertRaises(AcceleratorPolicyError): podman_security_args(profile)
   finally: dev.chmod(0o600)
 def test_discovery_schema(self):
  d=discover_host(); self.assertEqual(d['schema'],'XAVI-DUO/ACCELERATOR-DISCOVERY/v1'); self.assertIn('drm',d); self.assertIn('cdi_devices',d); self.assertIn('device_access',d)

if __name__=='__main__': unittest.main()
