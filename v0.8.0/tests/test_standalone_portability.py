import json,os,tempfile,tomllib,unittest
from pathlib import Path
from unittest.mock import patch
import xavi_duo_compute as compute
import xavi_duo_accelerator as accelerator
from xavi_duo_custody import parse_custody_ref
from xavi_duo_provider_runtime import container_engine, inspect_native

ROOT=Path(__file__).resolve().parents[1]
PYPROJECT=tomllib.loads((ROOT/'pyproject.toml').read_text())
PACKAGED_MODULES=set(PYPROJECT['tool']['setuptools']['py-modules'])
CORE=[*(m+'.py' for m in sorted(PACKAGED_MODULES)),'providers/xavi-exec/remote-fhe-worker.py']
FORBIDDEN=('prod3','prod4','10.77.','/srv/xavi','/mnt/store','/datastore3','xavi-prod','tbi-production','registry.xavi.local')

class StandalonePortabilityTests(unittest.TestCase):
 def test_py_modules_cover_runtime_surface(self):
  candidates={p.stem for p in ROOT.glob('*.py') if p.stem.startswith('xavi_duo') or p.stem in {'mlkem_provider','pqc_provider'}}
  self.assertEqual(candidates-PACKAGED_MODULES,set())
  self.assertEqual(PACKAGED_MODULES-candidates,set())

 def test_core_has_no_cluster_dependency_literals(self):
  hits=[]
  for rel in CORE:
   text=(ROOT/rel).read_text(errors='strict')
   for needle in FORBIDDEN:
    if needle in text: hits.append((rel,needle))
  self.assertEqual(hits,[])

 def test_default_compute_registry_is_host_neutral(self):
  reg=json.loads((ROOT/'COMPUTE_PROVIDERS.json').read_text())
  self.assertEqual(reg['schema'],'XAVI-DUO/COMPUTE-PROVIDERS/v2')
  self.assertTrue(reg['policy']['availability_is_discovered_at_runtime'])
  for row in reg['providers']:
   self.assertEqual(row.get('deployment_scope'),'host-neutral')
   self.assertNotIn('node_hint',row)
   self.assertNotIn('performance',row)
   self.assertNotIn('prod3',str(row.get('status','')))
   self.assertNotIn('prod4',str(row.get('status','')))

 def test_compute_registry_can_be_replaced_per_deployment(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'compute.json'
   p.write_text(json.dumps({'schema':'XAVI-DUO/COMPUTE-PROVIDERS/v2','providers':[{'id':'portable-test','kind':'wasm','capabilities':['duo.native'],'contains_client_secret':False,'device':'portable','remote_safe':True,'status':'portable-interface','deployment_scope':'host-neutral'}]}))
   with patch.dict(os.environ,{'XAVI_DUO_COMPUTE_REGISTRY':str(p)},clear=False):
    self.assertEqual(compute.get_provider('portable-test')['id'],'portable-test')


 def test_accelerator_registry_can_be_replaced_per_deployment(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'accelerators.json'
   p.write_text(json.dumps({'schema':'XAVI-DUO/ACCELERATOR-PROVIDERS/v2','profiles':[{'id':'portable-accel','vendor':'any','abis':['future-abi'],'remote_safe':True,'status':'interface-ready','deployment_scope':'host-neutral','sandbox':{'read_only_rootfs':True,'network':'none','cap_drop':'all','no_new_privileges':True,'writable_injection_overlays':[]},'injection':{'type':'remote-rpc'}}]}))
   with patch.dict(os.environ,{'XAVI_DUO_ACCELERATOR_REGISTRY':str(p)},clear=False):
    self.assertEqual(accelerator.get_profile('portable-accel')['id'],'portable-accel')

 def test_container_runtime_is_optional_and_engine_neutral(self):
  with patch('xavi_duo_provider_runtime.shutil.which',return_value=None):
   self.assertIsNone(container_engine('auto'))
  with patch('xavi_duo_provider_runtime.shutil.which',side_effect=lambda n:'/usr/bin/'+n if n=='docker' else None):
   self.assertEqual(container_engine('auto'),'docker')

 def test_native_provider_requires_hash_pin(self):
  with tempfile.TemporaryDirectory() as td:
   p=Path(td)/'provider'; p.write_bytes(b'#!/bin/sh\nexit 0\n'); p.chmod(0o700)
   row=inspect_native(p,allowed_sha256=[])
   self.assertFalse(row['available']); self.assertIn('allowlisted',row['error'])

 def test_authority_custody_is_generic_with_legacy_alias(self):
  self.assertEqual(parse_custody_ref('authority://node/key').scheme,'authority')
  legacy=parse_custody_ref('authority://node/key')
  self.assertEqual(legacy.scheme,'authority'); self.assertEqual(legacy.raw,'authority://node/key')

if __name__=='__main__': unittest.main()
