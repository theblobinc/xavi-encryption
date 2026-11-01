#!/usr/bin/env python3
from __future__ import annotations
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import xavi_duo_provider_runtime as pr


class ProviderRuntimeV082Tests(unittest.TestCase):
    def info(self):
        return {
            'available': True,
            'backend': 'oci',
            'runtime': 'podman',
            'run_ref': 'sha256:deadbeef',
        }

    def test_timeout_forcibly_removes_named_provider_container(self):
        calls=[]
        def fake_run(argv, **kwargs):
            calls.append((list(argv), dict(kwargs)))
            if 'run' in argv:
                raise subprocess.TimeoutExpired(argv, kwargs.get('timeout', 1))
            return subprocess.CompletedProcess(argv, 0, '', '')
        with tempfile.TemporaryDirectory() as td, patch.object(pr.subprocess, 'run', side_effect=fake_run):
            with self.assertRaises(subprocess.TimeoutExpired):
                pr.run_provider(self.info(), Path(td), ['version'], timeout=1)
        run_argv=calls[0][0]
        self.assertIn('--name', run_argv)
        name=run_argv[run_argv.index('--name')+1]
        self.assertTrue(name.startswith('xavi-duo-provider-'))
        cleanup=[argv for argv,_ in calls[1:] if 'rm' in argv]
        self.assertEqual(len(cleanup),1)
        self.assertEqual(cleanup[0][-3:], ['rm','-f',name])

    def test_systemd_scope_failure_retries_with_cgroupfs_and_unique_name(self):
        calls=[]
        def fake_run(argv, **kwargs):
            calls.append((list(argv), dict(kwargs)))
            if 'run' not in argv:
                return subprocess.CompletedProcess(argv,0,'','')
            run_calls=sum(1 for a,_ in calls if 'run' in a)
            if run_calls==1:
                return subprocess.CompletedProcess(argv,125,'','failed to create systemd unit scope')
            return subprocess.CompletedProcess(argv,0,'OpenSSL 3.5','')
        with tempfile.TemporaryDirectory() as td, patch.object(pr.subprocess, 'run', side_effect=fake_run):
            cp=pr.run_provider(self.info(), Path(td), ['version'], timeout=5)
        self.assertEqual(cp.returncode,0)
        runs=[argv for argv,_ in calls if 'run' in argv]
        self.assertEqual(len(runs),2)
        first_name=runs[0][runs[0].index('--name')+1]
        second_name=runs[1][runs[1].index('--name')+1]
        self.assertNotEqual(first_name,second_name)
        self.assertNotIn('--cgroup-manager',runs[0])
        self.assertIn('--cgroup-manager',runs[1])
        self.assertEqual(runs[1][runs[1].index('--cgroup-manager')+1],'cgroupfs')

    def test_hardened_args_retain_isolation_controls(self):
        argv=pr.hardened_oci_args('podman',Path('/tmp/work'),'sha256:abc',container_name='xavi-duo-provider-test')
        for flag in ['--rm','--name','--network','--read-only','--cap-drop','--security-opt','--pids-limit','--memory','--cpus']:
            self.assertIn(flag,argv)
        self.assertEqual(argv[argv.index('--network')+1],'none')
        self.assertEqual(argv[argv.index('--cap-drop')+1],'all')
        self.assertEqual(argv[argv.index('--security-opt')+1],'no-new-privileges')

if __name__=='__main__':
    unittest.main()
